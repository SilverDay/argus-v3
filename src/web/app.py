"""Admin web application factory (spec §9.1, §10.2; plan Phase 9).

Run behind a TLS reverse proxy with a WSGI server, never directly exposed:
    gunicorn --bind 127.0.0.1:8080 --workers 2 'src.web.wsgi:app'
Debug mode is refused outside tests. Read-only by owner decision: no route changes
station state; the only POST routes are sign-in and sign-out.
"""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from typing import Any

from flask import Flask, Response, g, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from src.shared.config import Config
from src.shared.models import EventType
from src.shared.secret_refs import resolve_secret

from . import auth, views
from .events_client import EventsClient, EventsUnavailable
from .local_accounts import Account, parse_accounts
from .oidc import OidcProvider
from .security import ROLE_RANK, audit, check_csrf, load_session, security_headers
from .sessions import SessionStore

log = logging.getLogger(__name__)


@dataclass
class WebState:
    cfg: Config
    events: Any
    sessions: SessionStore
    oidc: OidcProvider | None
    accounts: dict[str, Account] | None


def build_state(cfg: Config, *, events: Any = None, oidc: OidcProvider | None = None,
                accounts: dict[str, Account] | None = None) -> WebState:
    w, a = cfg.admin_web, cfg.auth.web
    os.makedirs(w.state_dir, mode=0o700, exist_ok=True)
    sessions = SessionStore(os.path.join(w.state_dir, "web.db"), idle_seconds=w.session_idle_minutes * 60,
                            max_seconds=w.session_max_hours * 3600)
    if a.oidc_enabled and oidc is None:
        secret = resolve_secret(a.oidc.client_secret_ref).decode().strip() if a.oidc.client_secret_ref else None
        oidc = OidcProvider(a.oidc, secret, w.public_url.rstrip("/") + "/auth/oidc/callback")
    if not a.oidc_enabled:
        oidc = None
    if a.local_fallback_allowed and not a.oidc_enabled and accounts is None:
        accounts = parse_accounts(resolve_secret(a.local.accounts_ref, strip=False).decode())
    if a.oidc_enabled or not a.local_fallback_allowed:
        accounts = None                                    # local fallback only without OIDC (spec §10.2)
    return WebState(cfg, events or EventsClient(cfg.events.socket_path), sessions, oidc, accounts)


def create_app(cfg: Config, *, testing: bool = False, state: WebState | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(SECRET_KEY=secrets.token_bytes(32), MAX_CONTENT_LENGTH=64 * 1024, TESTING=testing,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      TEMPLATES_AUTO_RELOAD=False, PREFERRED_URL_SCHEME="https")
    if app.debug and not testing:
        raise RuntimeError("Flask debug mode must not be enabled outside tests (FLASK_DEBUG)")
    if cfg.admin_web.trusted_proxies:
        n = cfg.admin_web.trusted_proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=0, x_prefix=0)  # type: ignore[method-assign]
    app.extensions["usbscan"] = state or build_state(cfg)

    app.before_request(load_session)
    app.before_request(check_csrf)

    @app.after_request
    def _access_audit(resp: Response) -> Response:
        view = app.view_functions.get(request.endpoint or "")
        user = g.get("user")
        if user is not None and getattr(view, "audited", False):
            try:
                audit(EventType.WEB_ACCESS, {"user": user.user, "role": user.role, "method": request.method,
                                             "path": request.path[:200], "query": request.query_string.decode(
                                                 "ascii", "replace")[:200], "status": resp.status_code})
            except EventsUnavailable:
                # Fail closed: no data leaves without an audit record.
                resp = Response(render_template("error.html", title="Unavailable",
                                                message="The audit log is unavailable."), status=503)
        return resp

    app.after_request(security_headers)

    @app.context_processor
    def _ctx() -> dict[str, Any]:
        user = g.get("user")
        return {"user": user, "csrf_token": user.csrf if user else "",
                "can": (lambda role: user is not None and ROLE_RANK[user.role] >= ROLE_RANK[role]),
                "station_id": cfg.station.station_id}

    for code, title in ((400, "Bad request"), (403, "Forbidden"), (404, "Not found"), (503, "Unavailable")):
        def handler(_exc: Exception, code: int = code, title: str = title) -> tuple[str, int]:
            return render_template("error.html", title=title, message=None), code
        app.register_error_handler(code, handler)

    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    return app
