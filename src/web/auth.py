"""Login / logout routes (spec §10.2, plan Phase 9).

Every refusal shows the same generic message; the specific reason goes to the audit log
only (no account enumeration). A login is completed only after its audit event has been
written (fail closed when the events service is unavailable).
"""
from __future__ import annotations

import logging
import secrets

from flask import Blueprint, Response, current_app, g, make_response, redirect, render_template, request, url_for

from .events_client import EventsUnavailable
from . import totp
from .local_accounts import verify as verify_local
from .oidc import OidcError, pkce_pair
from .security import (
    OIDC_COOKIE, SESSION_COOKIE, audit_auth, clear_cookie, client_ip, login_token, require_role, set_cookie,
)

log = logging.getLogger(__name__)
bp = Blueprint("auth", __name__)
GENERIC_FAILURE = "Sign-in failed."


def _state():
    return current_app.extensions["usbscan"]


def _unavailable() -> Response:
    return make_response(render_template("error.html", title="Unavailable",
                                         message="The audit log is unavailable; sign-in is disabled."), 503)


def _start_session(user: str, role: str, method: str) -> Response:
    try:
        audit_auth("success", user=user, role=role, method=method)
    except EventsUnavailable:
        return _unavailable()
    token, _ = _state().sessions.create(user, role, method, client_ip())
    resp = redirect(url_for("views.dashboard"))
    set_cookie(resp, SESSION_COOKIE, token)
    return resp


def _fail(user: str, method: str, reason: str, status: int = 401) -> Response:
    try:
        audit_auth("failure", user=user, method=method, reason=reason)
    except EventsUnavailable:
        return _unavailable()
    return make_response(render_template("login.html", error=GENERIC_FAILURE, **_login_ctx()), status)


def _login_ctx() -> dict:
    st = _state()
    return {"oidc_enabled": st.oidc is not None, "local_enabled": st.accounts is not None,
            "totp_required": st.cfg.auth.web.local.require_totp, "login_token": login_token()}


@bp.get("/login")
def login() -> Response:
    if g.get("user") is not None:
        return redirect(url_for("views.dashboard"))
    return make_response(render_template("login.html", error=None, **_login_ctx()))


@bp.post("/login/local")
def login_local() -> Response:
    """Username + passphrase (+ TOTP when required). Every failure reason is audited but the
    browser always sees the same message; each failure counts towards the lockout."""
    st = _state()
    if st.accounts is None:
        return make_response(render_template("login.html", error=GENERIC_FAILURE, **_login_ctx()), 404)
    username = request.form.get("username", "")[:64].strip().lower()
    passphrase = request.form.get("passphrase", "")
    code = request.form.get("totp", "")[:16]
    lc = st.cfg.auth.web.local
    keys = [f"user:{username}", f"ip:{client_ip()}"]
    if st.sessions.locked(*keys):
        verify_local({}, username, passphrase)           # same cost as a real attempt
        return _fail(username, "local", "locked_out", 429)
    acct = verify_local(st.accounts.current(), username, passphrase)
    reason = None
    if acct is None:
        reason = "bad_credentials"
    elif acct.disabled:
        reason = "account_disabled"
    elif lc.require_totp:
        counter = totp.verify(acct.totp_seed, code) if acct.totp_seed else None
        if not acct.totp_seed:
            reason = "totp_not_enrolled"
        elif counter is None:
            reason = "totp_invalid"
        elif not st.sessions.accept_totp(acct.username, counter):
            reason = "totp_replayed"
    if reason is not None:
        st.sessions.record_failure(keys, lc.max_failed_attempts, lc.lockout_minutes * 60)
        return _fail(username, "local", reason)
    st.sessions.clear_failures(*keys)
    return _start_session(acct.username, acct.role, "local+totp" if lc.require_totp else "local")


@bp.post("/auth/oidc/start")
def oidc_start() -> Response:
    st = _state()
    if st.oidc is None:
        return make_response(render_template("login.html", error=GENERIC_FAILURE, **_login_ctx()), 404)
    state, nonce, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = pkce_pair()
    try:
        url = st.oidc.authorization_url(state, nonce, challenge)
    except OidcError as exc:
        log.error("OIDC provider unavailable: %s", exc.reason)
        return _fail("", "oidc", exc.reason, 503)
    st.sessions.put_pending(state, binding, nonce, verifier)
    resp = redirect(url)
    set_cookie(resp, OIDC_COOKIE, binding, max_age=600)
    return resp


@bp.get("/auth/oidc/callback")
def oidc_callback() -> Response:
    st = _state()
    if st.oidc is None:
        return make_response(render_template("login.html", error=GENERIC_FAILURE, **_login_ctx()), 404)
    pending = st.sessions.take_pending(request.args.get("state", ""), request.cookies.get(OIDC_COOKIE, ""))
    if pending is None:
        resp = _fail("", "oidc", "state_invalid", 400)
    elif request.args.get("error"):
        resp = _fail("", "oidc", "provider_error:" + request.args.get("error", "")[:40])
    else:
        resp = _complete_oidc(pending)
    clear_cookie(resp, OIDC_COOKIE)
    return resp


def _complete_oidc(pending) -> Response:
    st = _state()
    code = request.args.get("code", "")
    if not code or len(code) > 2048:
        return _fail("", "oidc", "code_missing", 400)
    try:
        claims = st.oidc.validate(st.oidc.exchange(code, pending.verifier), pending.nonce)
    except OidcError as exc:
        return _fail("", "oidc", exc.reason)
    user = st.oidc.username(claims)
    if st.cfg.auth.web.require_mfa and not st.oidc.has_mfa(claims):
        return _fail(user, "oidc", "mfa_missing", 403)
    role = st.oidc.role(claims)
    if role is None:
        return _fail(user, "oidc", "no_role", 403)
    return _start_session(user, role, "oidc")


@bp.post("/logout")
@require_role("viewer")
def logout() -> Response:
    sess = g.user
    _state().sessions.delete(sess.token_hash)
    try:
        audit_auth("logout", user=sess.user, role=sess.role, method=sess.method)
    except EventsUnavailable:
        log.error("audit unavailable while logging out %s", sess.user)
    resp = redirect(url_for("auth.login"))
    clear_cookie(resp, SESSION_COOKIE)
    return resp
