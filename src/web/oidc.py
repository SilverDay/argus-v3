"""OpenID Connect authorization-code flow with PKCE (spec §10.2), httpx + joserfc.

The authlib Flask client is built on ``requests`` (project rule: httpx only), so the flow is
implemented directly; joserfc (authlib's JOSE library) verifies the ID token.

* Discovery: ``{issuer}/.well-known/openid-configuration``; the document's ``issuer`` must
  equal the configured issuer exactly and every endpoint must be https (OIDC Discovery §4.3).
* Request: response_type=code, state, nonce, PKCE S256, optional ``acr_values``.
* Token exchange: client_secret_basic (RFC 6749 §2.3.1: form-encoded id/secret) or a public
  client relying on PKCE when no secret is configured. No redirects followed.
* ID token (OIDC Core §3.1.3.7): signature over the provider JWKS with an asymmetric
  algorithm from the allow-list; iss, aud (and azp when several audiences), exp, iat, sub,
  nonce. A JWKS is re-fetched once when a key id is unknown (key rotation).
* MFA (spec §10.2, §6.2 require_mfa): ``amr`` must contain one of ``mfa_amr_values`` or
  ``acr`` must be one of ``mfa_acr_values``; otherwise the login is refused.
* TLS verification is always on; ``ca_file`` only adds trust anchors.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import ssl
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet

from src.shared.config import OidcConfig

CACHE_SECONDS = 3600
ROLE_ORDER = ("viewer", "operator", "admin")


class OidcError(Exception):
    """Login refused. ``reason`` is for the audit log only, never shown to the user."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _https(url: Any) -> bool:
    if not isinstance(url, str):
        return False
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and bool(parts.hostname)


class OidcProvider:
    def __init__(self, cfg: OidcConfig, client_secret: str | None, redirect_uri: str, *,
                 transport: httpx.BaseTransport | None = None, clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.clock = clock
        if transport is not None:
            kwargs: dict[str, Any] = {"transport": transport}
        else:
            ctx = ssl.create_default_context()
            if cfg.ca_file:
                ctx.load_verify_locations(cafile=cfg.ca_file)
            kwargs = {"verify": ctx}
        self._http = httpx.Client(timeout=float(cfg.timeout_seconds), follow_redirects=False, **kwargs)
        self._meta: tuple[float, dict[str, Any]] | None = None
        self._jwks: tuple[float, KeySet] | None = None

    def __repr__(self) -> str:
        return f"OidcProvider(issuer={self.cfg.issuer!r}, <secret hidden>)"

    def close(self) -> None:
        self._http.close()

    # --- discovery ---------------------------------------------------------------------------

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            resp = self._http.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError:
            raise OidcError("provider_unreachable") from None
        if resp.status_code != 200:
            raise OidcError(f"provider_http_{resp.status_code}")
        try:
            body = resp.json()
        except ValueError:
            raise OidcError("provider_bad_json") from None
        if not isinstance(body, dict):
            raise OidcError("provider_bad_json")
        return body

    def metadata(self) -> dict[str, Any]:
        if self._meta and self.clock() - self._meta[0] < CACHE_SECONDS:
            return self._meta[1]
        meta = self._get_json(self.cfg.issuer.rstrip("/") + "/.well-known/openid-configuration")
        if meta.get("issuer") != self.cfg.issuer:
            raise OidcError("issuer_mismatch")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not _https(meta.get(key)):
                raise OidcError(f"metadata_{key}")
        self._meta = (self.clock(), meta)
        return meta

    def keys(self, refresh: bool = False) -> KeySet:
        if not refresh and self._jwks and self.clock() - self._jwks[0] < CACHE_SECONDS:
            return self._jwks[1]
        try:
            ks = KeySet.import_key_set(self._get_json(self.metadata()["jwks_uri"]))
        except (JoseError, ValueError, TypeError):
            raise OidcError("jwks_invalid") from None
        self._jwks = (self.clock(), ks)
        return ks

    # --- flow ---------------------------------------------------------------------------------

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.cfg.scopes), "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        }
        if self.cfg.mfa_acr_values:
            params["acr_values"] = " ".join(self.cfg.mfa_acr_values)
        endpoint = self.metadata()["authorization_endpoint"]
        sep = "&" if urllib.parse.urlsplit(endpoint).query else "?"
        return endpoint + sep + urllib.parse.urlencode(params)

    def exchange(self, code: str, verifier: str) -> str:
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                "code_verifier": verifier}
        headers = {"Accept": "application/json"}
        if self.client_secret:
            ident = (urllib.parse.quote_plus(self.cfg.client_id) + ":" +
                     urllib.parse.quote_plus(self.client_secret)).encode()
            headers["Authorization"] = "Basic " + base64.b64encode(ident).decode()
        else:
            data["client_id"] = self.cfg.client_id
        try:
            resp = self._http.post(self.metadata()["token_endpoint"], data=data, headers=headers)
        except httpx.HTTPError:
            raise OidcError("token_endpoint_unreachable") from None
        if resp.status_code != 200:
            raise OidcError(f"token_http_{resp.status_code}")
        try:
            body = resp.json()
        except ValueError:
            raise OidcError("token_bad_json") from None
        token = body.get("id_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise OidcError("no_id_token")
        return token

    def validate(self, id_token: str, nonce: str) -> dict[str, Any]:
        allowed = list(self.cfg.allowed_algorithms)
        try:
            try:
                token = jwt.decode(id_token, self.keys(), algorithms=allowed)
            except InvalidKeyIdError:
                token = jwt.decode(id_token, self.keys(refresh=True), algorithms=allowed)
        except OidcError:
            raise
        except (JoseError, ValueError, TypeError) as exc:
            raise OidcError(f"id_token_invalid:{type(exc).__name__}") from None
        claims = token.claims
        registry = jwt.JWTClaimsRegistry(
            now=lambda: int(self.clock()), leeway=self.cfg.clock_skew_seconds,
            iss={"essential": True, "value": self.cfg.issuer},
            aud={"essential": True, "value": self.cfg.client_id},
            sub={"essential": True}, exp={"essential": True}, iat={"essential": True},
            nonce={"essential": True, "value": nonce})
        try:
            registry.validate(claims)
        except JoseError as exc:
            raise OidcError(f"claims_invalid:{type(exc).__name__}") from None
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.cfg.client_id:
            raise OidcError("azp_mismatch")
        return claims

    # --- policy -------------------------------------------------------------------------------

    def has_mfa(self, claims: dict[str, Any]) -> bool:
        amr = claims.get("amr")
        if isinstance(amr, list) and any(v in amr for v in self.cfg.mfa_amr_values):
            return True
        return claims.get("acr") in self.cfg.mfa_acr_values

    def role(self, claims: dict[str, Any]) -> str | None:
        raw = claims.get(self.cfg.role_claim)
        values = {raw} if isinstance(raw, str) else {v for v in raw if isinstance(v, str)} if isinstance(raw, list) else set()
        granted = None
        for role in ROLE_ORDER:                               # highest matching role wins
            if values & set(getattr(self.cfg.roles, role)):
                granted = role
        return granted

    def username(self, claims: dict[str, Any]) -> str:
        name = claims.get(self.cfg.username_claim)
        if not isinstance(name, str) or not name:
            name = str(claims.get("sub"))
        return "".join(c for c in name if c.isprintable())[:128]
