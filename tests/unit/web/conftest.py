"""Admin web test harness: real events service on a Unix socket, mock OIDC provider."""
from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
import urllib.parse
from typing import Any

import bcrypt
import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from src.events.server import EventsServer
from src.events.store import EventStore
from src.shared.config import load_config_from_dict
from src.web.app import build_state, create_app
from src.web.events_client import EventsClient
from src.web.local_accounts import parse_accounts
from src.web.oidc import OidcProvider

ISSUER = "https://idp.example.org/realms/mgmt"
CLIENT_ID = "usb-scan-station"
PUBLIC = "https://station-001.mgmt.example.org"
ME = os.getuid()


class EventsThread:
    """EventsServer in its own event loop thread (the web app is synchronous)."""

    def __init__(self, path: str, db: str) -> None:
        self.store = EventStore(db, "station-001")
        self.path = path
        self.loop = asyncio.new_event_loop()
        self.server = EventsServer(self.store, path, writer_uids=set(), reader_uids=set(), web_uids={ME})
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        asyncio.run_coroutine_threadsafe(self.server.start(), self.loop).result(5)

    def stop(self) -> None:
        asyncio.run_coroutine_threadsafe(self.server.close(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()
        self.store.close()

    def events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        evs = [e.to_dict() for e in self.store.recent(500)]
        return [e for e in evs if event_type is None or e["event_type"] == event_type]


class FakeIdP:
    """Discovery, JWKS and token endpoint. ``claims`` / ``header`` shape the next ID token."""

    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1", "use": "sig", "alg": "RS256"})
        self.published = [self.key]
        self.claims: dict[str, Any] = {}
        self.header: dict[str, Any] = {"alg": "RS256", "kid": "k1"}
        self.sign_key: Any = self.key
        self.issuer_in_metadata = ISSUER
        self.token_requests: list[httpx.Request] = []
        self.nonce = ""

    def id_token(self) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u-1", "exp": now + 300, "iat": now,
                  "nonce": self.nonce, "preferred_username": "alice", "groups": ["scan-admins"],
                  "amr": ["pwd", "mfa"], **self.claims}
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(self.header, claims, self.sign_key, algorithms=[self.header["alg"]])

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == ISSUER + "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": self.issuer_in_metadata, "authorization_endpoint": ISSUER + "/auth",
                "token_endpoint": ISSUER + "/token", "jwks_uri": ISSUER + "/certs"})
        if url == ISSUER + "/certs":
            return httpx.Response(200, json=KeySet(self.published).as_dict(private=False))
        if url == ISSUER + "/token" and request.method == "POST":
            self.token_requests.append(request)
            return httpx.Response(200, json={"access_token": "at", "token_type": "Bearer", "id_token": self.id_token()})
        return httpx.Response(404)


def make_cfg(tmp_path, *, oidc: bool = True, **overrides: Any):
    raw: dict[str, Any] = {
        "station": {"data_dir": str(tmp_path)},
        "events": {"socket_path": str(tmp_path / "events.sock")},
        "admin_web": {"enabled": True, "public_url": PUBLIC, "trusted_proxies": 0, "state_dir": str(tmp_path / "web")},
        "host": {"management_networks": ["10.0.0.0/8", "192.0.2.0/24", "127.0.0.0/8"]},
        "auth": {"web": {"oidc_enabled": oidc, "require_mfa": True, "local_fallback_allowed": not oidc,
                         "oidc": {"issuer": ISSUER, "client_id": CLIENT_ID,
                                  "roles": {"admin": ["scan-admins"], "operator": ["scan-ops"],
                                            "viewer": ["scan-view"]}},
                         "local": {"accounts_ref": "file:/nonexistent/accounts", "max_failed_attempts": 3}}},
    }
    for section, values in overrides.items():
        raw.setdefault(section, {}).update(values)
    return load_config_from_dict(raw)


@pytest.fixture(scope="session")
def account_hashes():
    return {name: bcrypt.hashpw(f"{name}-passphrase-1".encode(), bcrypt.gensalt(12)).decode()
            for name in ("ada", "olaf", "vic")}


@pytest.fixture
def events(tmp_path):
    ev = EventsThread(str(tmp_path / "events.sock"), str(tmp_path / "events.db"))
    yield ev
    ev.stop()


@pytest.fixture
def idp():
    return FakeIdP()


def _build(tmp_path, cfg, events_client, idp=None, accounts=None):
    oidc = None
    if cfg.auth.web.oidc_enabled:
        oidc = OidcProvider(cfg.auth.web.oidc, "client-secret", PUBLIC + "/auth/oidc/callback",
                            transport=httpx.MockTransport(idp.handler))
    state = build_state(cfg, events=events_client, oidc=oidc, accounts=accounts)
    app = create_app(cfg, testing=True, state=state)
    return app, state


@pytest.fixture
def web(tmp_path, events, idp):
    """OIDC-configured app; returns (app, state)."""
    cfg = make_cfg(tmp_path)
    app, state = _build(tmp_path, cfg, EventsClient(events.path), idp)
    yield app, state
    state.sessions.close()


@pytest.fixture
def local_web(tmp_path, events, account_hashes):
    cfg = make_cfg(tmp_path, oidc=False)
    accounts = parse_accounts(f"ada:admin:{account_hashes['ada']}\nolaf:operator:{account_hashes['olaf']}\n"
                              f"vic:viewer:{account_hashes['vic']}\n")
    app, state = _build(tmp_path, cfg, EventsClient(events.path), accounts=accounts)
    yield app, state
    state.sessions.close()


def client(app, ip: str = "10.0.0.5", **environ: str):
    c = app.test_client()
    c.environ_base.update({"REMOTE_ADDR": ip, "wsgi.url_scheme": "https", **environ})
    return c


def login_token(c) -> str:
    resp = c.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', resp.get_data(as_text=True))
    assert m, "login form token missing"
    return m.group(1)


def oidc_login(c, idp: FakeIdP, nonce: str | None = None):
    """Run the full browser flow; returns (callback response, authorization params)."""
    resp = c.post("/auth/oidc/start", data={"csrf_token": login_token(c)})
    assert resp.status_code == 302, resp.get_data(as_text=True)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(resp.headers["Location"]).query))
    idp.nonce = q["nonce"] if nonce is None else nonce
    return c.get(f"/auth/oidc/callback?state={urllib.parse.quote(q['state'])}&code=authcode"), q


def as_role(app, idp, role: str, ip: str = "10.0.0.5"):
    groups = {"admin": "scan-admins", "operator": "scan-ops", "viewer": "scan-view"}[role]
    idp.claims = {"groups": [groups]}
    c = client(app, ip)
    resp, _ = oidc_login(c, idp)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/"), resp.get_data(as_text=True)
    return c


def csrf_of(c) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/").get_data(as_text=True))
    assert m
    return m.group(1)


def payloads(events: EventsThread, event_type: str) -> list[dict[str, Any]]:
    return [e["payload"] for e in events.events(event_type)]


__all__ = ["json", "client", "login_token", "oidc_login", "as_role", "csrf_of", "payloads", "make_cfg"]
