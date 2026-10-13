import base64
import time
import urllib.parse

import pytest
from joserfc.jwk import OctKey, RSAKey

from src.web.app import create_app
from src.web.local_accounts import AccountsError, parse_accounts
from src.web.security import LOGIN_COOKIE, OIDC_COOKIE, SESSION_COOKIE
from tests.unit.web.conftest import (
    CLIENT_ID, ISSUER, PUBLIC, as_role, client, csrf_of, login_token, make_cfg, oidc_login, payloads,
)

GET_ROUTES = ["/", "/partials/status", "/history", "/history/1", "/history/export.csv", "/stats", "/api/stats",
              "/config", "/audit"]


# --- unauthenticated --------------------------------------------------------------------------

@pytest.mark.parametrize("path", GET_ROUTES)
def test_unauthenticated_redirects_to_login(web, path):
    app, _ = web
    resp = client(app).get(path)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")


def test_htmx_unauthenticated_gets_hx_redirect(web):
    app, _ = web
    resp = client(app).get("/partials/status", headers={"HX-Request": "true"})
    assert resp.status_code == 401 and resp.headers["HX-Redirect"] == "/login"


def test_every_route_is_protected(web):
    """Guard against a future route without @require_role."""
    app, _ = web
    open_endpoints = {"static", "auth.login", "auth.login_local", "auth.oidc_start", "auth.oidc_callback"}
    for rule in app.url_map.iter_rules():
        if rule.endpoint in open_endpoints:
            continue
        assert hasattr(app.view_functions[rule.endpoint], "min_role"), rule.endpoint


# --- OIDC ----------------------------------------------------------------------------------------

def test_oidc_login_flow(web, idp, events):
    app, state = web
    c = client(app)
    resp, q = oidc_login(c, idp)
    assert q["code_challenge_method"] == "S256" and q["client_id"] == CLIENT_ID
    assert q["redirect_uri"] == PUBLIC + "/auth/oidc/callback" and "openid" in q["scope"].split()
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")
    cookies = resp.headers.getlist("Set-Cookie")
    sess = next(h for h in cookies if h.startswith(SESSION_COOKIE + "="))
    assert "Secure" in sess and "HttpOnly" in sess and "SameSite=Lax" in sess and "Path=/" in sess
    assert "Domain" not in sess
    assert c.get("/").status_code == 200
    (tok_req,) = idp.token_requests
    body = dict(urllib.parse.parse_qsl(tok_req.content.decode()))
    assert body["grant_type"] == "authorization_code" and body["code"] == "authcode" and body["code_verifier"]
    assert base64.b64decode(tok_req.headers["authorization"].split()[1]) == f"{CLIENT_ID}:client-secret".encode()
    (ok,) = payloads(events, "web_auth")
    assert ok["result"] == "success" and ok["user"] == "alice" and ok["role"] == "admin" and ok["method"] == "oidc"


def test_state_is_single_use_and_browser_bound(web, idp):
    app, _ = web
    c = client(app)
    resp = c.post("/auth/oidc/start", data={"csrf_token": login_token(c)})
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(resp.headers["Location"]).query))
    idp.nonce = q["nonce"]
    other = client(app)                                   # attacker's browser, no binding cookie
    assert other.get(f"/auth/oidc/callback?state={q['state']}&code=x").status_code == 400
    other.set_cookie(OIDC_COOKIE, "guessed-binding", domain="localhost")
    assert other.get(f"/auth/oidc/callback?state={q['state']}&code=x").status_code == 400
    # A leaked state cannot cancel the real login; the bound browser completes it once.
    assert c.get(f"/auth/oidc/callback?state={q['state']}&code=x").status_code == 302
    assert c.get(f"/auth/oidc/callback?state={q['state']}&code=x").status_code == 400


@pytest.mark.parametrize("claims,status,reason", [
    ({"aud": "someone-else"}, 401, "claims_invalid"),
    ({"iss": "https://evil.example.org"}, 401, "claims_invalid"),
    ({"exp": int(time.time()) - 600}, 401, "claims_invalid"),
    ({"amr": ["pwd"]}, 403, "mfa_missing"),
    ({"amr": None}, 403, "mfa_missing"),
    ({"groups": ["unrelated"]}, 403, "no_role"),
    ({"aud": [CLIENT_ID, "other"]}, 401, "azp_mismatch"),
])
def test_id_token_rejections(web, idp, events, claims, status, reason):
    app, _ = web
    idp.claims = claims
    resp, _ = oidc_login(client(app), idp)
    assert resp.status_code == status
    assert "Sign-in failed." in resp.get_data(as_text=True)
    assert not any(h.startswith(SESSION_COOKIE + "=") for h in resp.headers.getlist("Set-Cookie"))
    (fail,) = payloads(events, "web_auth")
    assert fail["result"] == "failure" and fail["reason"].startswith(reason)


def test_nonce_mismatch_rejected(web, idp, events):
    app, _ = web
    resp, _ = oidc_login(client(app), idp, nonce="replayed-nonce")
    assert resp.status_code == 401
    assert payloads(events, "web_auth")[0]["reason"].startswith("claims_invalid")


def test_symmetric_or_unsigned_tokens_rejected(web, idp, events):
    app, _ = web
    idp.header = {"alg": "HS256", "kid": "k1"}
    idp.sign_key = OctKey.generate_key(256)
    resp, _ = oidc_login(client(app), idp)
    assert resp.status_code == 401


def test_wrong_signing_key_rejected(web, idp):
    app, _ = web
    idp.sign_key = RSAKey.generate_key(2048, parameters={"kid": "k1"})   # same kid, attacker key
    resp, _ = oidc_login(client(app), idp)
    assert resp.status_code == 401


def test_key_rotation_refetches_jwks(web, idp):
    app, _ = web
    as_role(app, idp, "viewer")                          # JWKS cached with k1
    new = RSAKey.generate_key(2048, parameters={"kid": "k2", "use": "sig", "alg": "RS256"})
    idp.published = [idp.key, new]
    idp.sign_key, idp.header = new, {"alg": "RS256", "kid": "k2"}
    resp, _ = oidc_login(client(app), idp)
    assert resp.status_code == 302


def test_discovery_issuer_mismatch_refused(web, idp, events):
    app, _ = web
    idp.issuer_in_metadata = "https://evil.example.org"
    c = client(app)
    resp = c.post("/auth/oidc/start", data={"csrf_token": login_token(c)})
    assert resp.status_code == 503
    assert payloads(events, "web_auth")[0]["reason"] == "issuer_mismatch"


# --- RBAC -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("role,allowed,denied", [
    ("viewer", ["/", "/stats", "/api/stats", "/config", "/partials/status"], ["/history", "/audit",
                                                                             "/history/export.csv"]),
    ("operator", ["/history", "/history/export.json"], ["/audit"]),
    ("admin", ["/audit", "/history"], []),
])
def test_rbac(web, idp, role, allowed, denied):
    app, _ = web
    c = as_role(app, idp, role)
    for path in allowed:
        assert c.get(path).status_code == 200, (role, path)
    for path in denied:
        assert c.get(path).status_code == 403, (role, path)


# --- CSRF / session ---------------------------------------------------------------------------------

def test_csrf_required_on_post(web, idp):
    app, _ = web
    c = as_role(app, idp, "viewer")
    assert c.post("/logout").status_code == 400
    assert c.post("/logout", data={"csrf_token": "wrong"}).status_code == 400
    assert c.post("/logout", data={"csrf_token": csrf_of(c)}).status_code == 302
    assert c.get("/").status_code == 302                 # session is gone


def test_login_form_csrf(web):
    app, _ = web
    c = client(app)
    assert c.post("/auth/oidc/start").status_code == 400                  # no token
    c.get("/login")
    assert c.post("/auth/oidc/start", data={"csrf_token": "forged"}).status_code == 400
    fresh = client(app)                                                  # no login cookie at all
    assert fresh.post("/auth/oidc/start", data={"csrf_token": "x" * 43}).status_code == 400


def test_ip_binding(web, idp, events):
    app, state = web
    c = as_role(app, idp, "admin", ip="10.0.0.5")
    token = c.get_cookie(SESSION_COOKIE).value
    thief = client(app, "10.9.9.9")
    thief.set_cookie(SESSION_COOKIE, token, domain="localhost")
    assert thief.get("/").status_code == 401
    assert c.get("/").status_code == 302                  # revoked for the original address too
    rejected = [p for p in payloads(events, "web_auth") if p["result"] == "session_rejected"]
    assert rejected and rejected[0]["ip"] == "10.9.9.9"


def test_trusted_proxy_client_address(tmp_path, events, idp):
    import httpx

    from src.web.app import build_state
    from src.web.events_client import EventsClient
    from src.web.oidc import OidcProvider
    cfg = make_cfg(tmp_path, admin_web={"trusted_proxies": 1})
    oidc = OidcProvider(cfg.auth.web.oidc, "s", PUBLIC + "/auth/oidc/callback", transport=httpx.MockTransport(idp.handler))
    state = build_state(cfg, events=EventsClient(events.path), oidc=oidc)
    app = create_app(cfg, testing=True, state=state)
    c = client(app, "127.0.0.1", HTTP_X_FORWARDED_FOR="192.0.2.7")
    oidc_login(c, idp)
    state.sessions.close()
    assert payloads(events, "web_auth")[0]["ip"] == "192.0.2.7"


def test_session_idle_timeout(web, idp):
    app, state = web
    c = as_role(app, idp, "viewer")
    real = state.sessions.clock
    state.sessions.clock = lambda: real() + 16 * 60
    assert c.get("/").status_code == 302


def test_session_token_stored_hashed(web, idp):
    app, state = web
    c = as_role(app, idp, "viewer")
    token = c.get_cookie(SESSION_COOKIE).value
    rows = state.sessions._db.execute("SELECT token_hash FROM sessions").fetchall()
    assert rows and all(token not in r[0] for r in rows)


# --- local fallback -------------------------------------------------------------------------------------

def local_login(c, user, passphrase):
    return c.post("/login/local", data={"csrf_token": login_token(c), "username": user, "passphrase": passphrase})


def test_local_login_and_generic_failures(local_web, events):
    app, _ = local_web
    c = client(app)
    bad_user = local_login(c, "nobody", "whatever-passphrase")
    bad_pass = local_login(c, "ada", "wrong-passphrase")
    assert bad_user.status_code == bad_pass.status_code == 401
    strip = lambda r: r.get_data(as_text=True).replace(login_token(c), "")   # noqa: E731
    assert strip(bad_user) == strip(bad_pass)            # no account enumeration
    ok = local_login(client(app), "ada", "ada-passphrase-1")
    assert ok.status_code == 302
    assert [p["result"] for p in payloads(events, "web_auth")] == ["failure", "failure", "success"]
    assert payloads(events, "web_auth")[2]["role"] == "admin"


def test_local_lockout_persists(local_web):
    app, state = local_web
    for _ in range(3):
        assert local_login(client(app, "10.1.1.1"), "olaf", "nope-nope-nope").status_code == 401
    assert local_login(client(app, "10.1.1.2"), "olaf", "olaf-passphrase-1").status_code == 429   # account locked
    assert local_login(client(app, "10.1.1.1"), "vic", "vic-passphrase-1").status_code == 429     # address locked
    assert local_login(client(app, "10.1.1.3"), "vic", "vic-passphrase-1").status_code == 302


def test_local_passphrase_length_limit(local_web):
    app, _ = local_web
    assert local_login(client(app), "ada", "x" * 73).status_code == 401


def test_oidc_disables_local_accounts(web):
    app, _ = web
    c = client(app)
    assert local_login(c, "ada", "ada-passphrase-1").status_code == 404


def test_accounts_file_validation(account_hashes):
    weak = "$2b$04$" + account_hashes["ada"][7:]
    for text in (f"ada:root:{account_hashes['ada']}", f"Ada Smith:admin:{account_hashes['ada']}",
                 f"ada:admin:{weak}", "ada:admin:plaintext", f"a:admin:{account_hashes['ada']}\na:viewer:{account_hashes['vic']}"):
        with pytest.raises(AccountsError):
            parse_accounts(text)


# --- fail closed / hardening ------------------------------------------------------------------------------

def test_login_fails_closed_without_audit(web, idp, events):
    app, _ = web
    events.stop_server = True
    import asyncio
    asyncio.run_coroutine_threadsafe(events.server.close(), events.loop).result(5)
    resp, _ = oidc_login(client(app), idp)
    assert resp.status_code == 503
    assert not any(h.startswith(SESSION_COOKIE + "=") for h in resp.headers.getlist("Set-Cookie"))
    asyncio.run_coroutine_threadsafe(events.server.start(), events.loop).result(5)


def test_data_view_fails_closed_without_audit(web, idp, events):
    import asyncio
    app, _ = web
    c = as_role(app, idp, "admin")
    asyncio.run_coroutine_threadsafe(events.server.close(), events.loop).result(5)
    assert c.get("/config").status_code == 503
    asyncio.run_coroutine_threadsafe(events.server.start(), events.loop).result(5)
    assert c.get("/config").status_code == 200


def test_security_headers(web, idp):
    app, _ = web
    resp = client(app).get("/login")
    h = resp.headers
    assert "script-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert "unsafe-inline" not in h["Content-Security-Policy"] and "unsafe-eval" not in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Cache-Control"] == "no-store" and h["Referrer-Policy"] == "no-referrer"
    login = next(c for c in h.getlist("Set-Cookie") if c.startswith(LOGIN_COOKIE))
    assert "SameSite=Strict" in login and "Secure" in login


def test_no_inline_scripts_or_styles(web, idp):
    """CSP has no 'unsafe-inline': templates must not contain inline script/style/handlers."""
    import pathlib
    import re as _re
    root = pathlib.Path(__file__).resolve().parents[3] / "src" / "web" / "templates"
    for tpl in root.glob("*.html"):
        text = tpl.read_text()
        assert not _re.search(r"<script(?![^>]*\bsrc=)", text), tpl
        assert "<style" not in text and " style=" not in text, tpl
        assert not _re.search(r"\son[a-z]+=", text), tpl
        assert "hx-on" not in text and "|safe" not in text, tpl


def test_debug_mode_refused(tmp_path, events, monkeypatch, web):
    _, state = web
    monkeypatch.setenv("FLASK_DEBUG", "1")
    with pytest.raises(RuntimeError, match="debug"):
        create_app(make_cfg(tmp_path), testing=False, state=state)


def test_oidc_cookie_cleared_after_callback(web, idp):
    app, _ = web
    resp, _ = oidc_login(client(app), idp)
    assert any(h.startswith(OIDC_COOKIE + "=;") for h in resp.headers.getlist("Set-Cookie"))
    assert ISSUER
