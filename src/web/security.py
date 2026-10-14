"""Request-level security for the admin web: session resolution, IP binding, CSRF, RBAC,
response headers and fail-closed audit logging (spec §9.1, plan Phase 9).
"""
from __future__ import annotations

import functools
import hmac
import logging
import secrets
from collections.abc import Callable
from typing import Any

from flask import Response, abort, current_app, g, redirect, request, url_for

from src.shared.models import EventType, ScanEvent

from .events_client import EventsUnavailable
from .local_accounts import credential_fingerprint

log = logging.getLogger(__name__)

SESSION_COOKIE = "__Host-usbscan"          # __Host-: Secure, Path=/, no Domain (RFC 6265bis)
LOGIN_COOKIE = "__Host-usbscan-login"      # double-submit token for the pre-session login form
OIDC_COOKIE = "__Host-usbscan-oidc"        # binds a pending OIDC login to this browser
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


def client_ip() -> str:
    return request.remote_addr or "unknown"


# SameSite: the OIDC callback is a cross-site top-level navigation from the IdP, which
# never carries Strict cookies, and the redirect chain after it is still treated as
# cross-site. Session and OIDC-binding cookies are therefore Lax (sent on top-level GET
# only); every state-changing request is a POST with a CSRF token. The login-form
# cookie is only ever used same-site and stays Strict.
_SAMESITE = {LOGIN_COOKIE: "Strict"}


def set_cookie(resp: Response, name: str, value: str, max_age: int | None = None) -> None:
    resp.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=True,
                    samesite=_SAMESITE.get(name, "Lax"))


def clear_cookie(resp: Response, name: str) -> None:
    resp.delete_cookie(name, path="/", secure=True, httponly=True, samesite=_SAMESITE.get(name, "Lax"))


# --- audit ----------------------------------------------------------------------------------

def audit(event_type: EventType, payload: dict[str, Any]) -> None:
    """Write an audit event to the events service. Raises EventsUnavailable: fail closed."""
    payload = {**payload, "ip": client_ip()}
    current_app.extensions["usbscan"].events.audit(ScanEvent(event_type, None, payload))


def audit_auth(result: str, *, user: str = "", role: str = "", method: str = "", reason: str = "") -> None:
    audit(EventType.WEB_AUTH, {"result": result, "user": user[:128], "role": role, "method": method,
                               "reason": reason[:100]})


# --- session ---------------------------------------------------------------------------------

def load_session() -> Response | None:
    """before_request: resolve the session cookie into ``g.user`` (or None)."""
    g.user = None
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None
    state = current_app.extensions["usbscan"]
    sess, reason = state.sessions.lookup(token)
    if sess is None:
        return None
    reason = None
    if not hmac.compare_digest(sess.ip, client_ip()):
        # IP binding: a session cookie replayed from another address is revoked outright.
        reason = f"ip_changed_from:{sess.ip}"
    elif sess.method.startswith("local"):
        # Local accounts are re-checked on every request against the entry the session was
        # issued from: any change made with src.web.accounts_admin (passphrase, authenticator,
        # role, disable, remove) or turning local sign-in off ends the session, including a
        # session that a login in flight created after the change.
        acct = state.accounts.current().get(sess.user) if state.accounts is not None else None
        if (acct is None or acct.disabled or acct.role != sess.role
                or not hmac.compare_digest(sess.cred, credential_fingerprint(acct))):
            reason = "account_changed"
    if reason is not None:
        state.sessions.delete(sess.token_hash)
        try:
            audit_auth("session_rejected", user=sess.user, role=sess.role, method=sess.method, reason=reason)
        except EventsUnavailable:
            log.error("audit unavailable while rejecting a session")
        resp = Response("Session invalid. Please sign in again.", status=401, mimetype="text/plain")
        clear_cookie(resp, SESSION_COOKIE)
        return resp
    g.user = sess
    return None


def require_role(role: str) -> Callable:
    """Login required (302 to /login, or 401 + HX-Redirect for HTMX) and minimum role (403)."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if g.get("user") is None:
                if request.headers.get("HX-Request") == "true":
                    return Response(status=401, headers={"HX-Redirect": url_for("auth.login")})
                return redirect(url_for("auth.login"))
            if ROLE_RANK[g.user.role] < ROLE_RANK[role]:
                abort(403)
            return fn(*args, **kwargs)
        wrapper.min_role = role  # type: ignore[attr-defined]
        return wrapper
    return deco


def has_role(role: str) -> bool:
    user = g.get("user")
    return user is not None and ROLE_RANK[user.role] >= ROLE_RANK[role]


# --- CSRF -----------------------------------------------------------------------------------

def check_csrf() -> None:
    """before_request for unsafe methods: synchroniser token (session) or double-submit
    token (login form, before a session exists). Missing or wrong -> 400."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    user = g.get("user")
    if user is not None:
        expected = user.csrf
    else:
        expected = request.cookies.get(LOGIN_COOKIE, "")
    if not sent or not expected or not hmac.compare_digest(sent, expected):
        abort(400)


def login_token() -> str:
    """Per-browser token for the login form (double-submit; set by the login page)."""
    token = request.cookies.get(LOGIN_COOKIE)
    if not token or len(token) > 128:
        token = secrets.token_urlsafe(32)
    g.login_token = token
    return token


# --- headers -----------------------------------------------------------------------------------

def security_headers(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=()"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    if not request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    if getattr(g, "login_token", None):
        set_cookie(resp, LOGIN_COOKIE, g.login_token, max_age=3600)
    return resp
