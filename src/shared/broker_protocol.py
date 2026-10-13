"""Broker RPC wire protocol, shared by src/broker (server) and the orchestrator client.

One JSON object per line. Every request and response carries an HMAC-SHA256 tag
over its canonical JSON encoding (sorted keys, no whitespace), with distinct
domain-separation prefixes so a response can never be replayed as a request.

Request:  {"v":1,"nonce":"<32 hex>","ts":<unix int>,"cmd":"...","args":{...},"mac":"<hex>"}
Response: {"v":1,"nonce":"<request nonce>","ok":true,"result":{...},"mac":"<hex>"}
          {"v":1,"nonce":"<request nonce>","ok":false,"error":"<code>","detail":"...","mac":"<hex>"}

The server rejects stale timestamps and reused nonces (replay protection).
The HMAC is defence in depth on top of SO_PEERCRED uid authentication.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024
MIN_KEY_BYTES = 32
_REQ_DOMAIN = b"usb-scan-broker-request\x00"
_RESP_DOMAIN = b"usb-scan-broker-response\x00"
_NONCE = re.compile(r"^[0-9a-f]{32}$")

# Error codes. Messages never include host paths supplied by the caller.
E_BAD_REQUEST = "bad_request"
E_UNAUTHORIZED = "unauthorized"
E_REPLAY = "replay"
E_UNKNOWN_COMMAND = "unknown_command"
E_INVALID_ARGUMENT = "invalid_argument"
E_NOT_FOUND = "not_found"
E_DEVICE_IN_USE = "device_in_use"
E_DEVICE_CHANGED = "device_changed"
E_SESSION_CONFLICT = "session_conflict"
E_UNSUPPORTED = "unsupported_filesystem"
E_MOUNT_FAILED = "mount_failed"
E_UNMOUNT_FAILED = "unmount_failed"
E_EJECT_FAILED = "eject_failed"
E_INTERNAL = "internal_error"


class ProtocolError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def check_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
        raise ProtocolError(E_INTERNAL, f"HMAC key must be at least {MIN_KEY_BYTES} bytes")
    return key


def canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def _mac(key: bytes, domain: bytes, body: dict[str, Any]) -> str:
    return hmac.new(key, domain + canonical(body), hashlib.sha256).hexdigest()


def _encode(obj: dict[str, Any]) -> bytes:
    line = canonical(obj) + b"\n"
    if len(line) > MAX_MESSAGE_BYTES:
        raise ProtocolError(E_INTERNAL, "message too large")
    return line


def _parse(line: bytes) -> dict[str, Any]:
    if len(line) > MAX_MESSAGE_BYTES:
        raise ProtocolError(E_BAD_REQUEST, "message too large")
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ProtocolError(E_BAD_REQUEST, "malformed JSON") from None
    if not isinstance(obj, dict):
        raise ProtocolError(E_BAD_REQUEST, "expected an object")
    return obj


# --- client side -------------------------------------------------------------

def build_request(key: bytes, cmd: str, args: dict[str, Any] | None = None,
                  *, now: float | None = None) -> tuple[bytes, str]:
    """Return (encoded line, nonce)."""
    body = {
        "v": PROTOCOL_VERSION,
        "nonce": secrets.token_hex(16),
        "ts": int(now if now is not None else time.time()),
        "cmd": cmd,
        "args": args or {},
    }
    body["mac"] = _mac(key, _REQ_DOMAIN, body)
    return _encode(body), body["nonce"]


def parse_response(key: bytes, line: bytes, expected_nonce: str) -> dict[str, Any]:
    """Verify a response; return ``result`` or raise ProtocolError with the server's code."""
    obj = _parse(line)
    mac = obj.pop("mac", None)
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(key, _RESP_DOMAIN, obj)):
        raise ProtocolError(E_UNAUTHORIZED, "response MAC invalid")
    if obj.get("v") != PROTOCOL_VERSION or obj.get("nonce") != expected_nonce:
        raise ProtocolError(E_BAD_REQUEST, "response does not match request")
    if obj.get("ok") is True:
        result = obj.get("result")
        if not isinstance(result, dict):
            raise ProtocolError(E_BAD_REQUEST, "response result missing")
        return result
    code = obj.get("error")
    raise ProtocolError(code if isinstance(code, str) else E_INTERNAL, str(obj.get("detail", "")))


# --- server side -------------------------------------------------------------

class NonceCache:
    """Remembers nonces for 2x the allowed clock skew to reject replays."""

    def __init__(self, max_skew: float, max_entries: int = 10_000) -> None:
        self.max_skew = max_skew
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}

    def check_and_add(self, nonce: str, now: float) -> bool:
        horizon = now - 2 * self.max_skew
        if len(self._seen) >= self.max_entries or any(t < horizon for t in self._seen.values()):
            self._seen = {n: t for n, t in self._seen.items() if t >= horizon}
        if nonce in self._seen or len(self._seen) >= self.max_entries:
            return False
        self._seen[nonce] = now
        return True


def verify_request(key: bytes, line: bytes, nonces: NonceCache,
                   *, now: float | None = None) -> tuple[str, str, dict[str, Any]]:
    """Return (nonce, cmd, args). Raises ProtocolError; the nonce is in ``detail`` when known."""
    now = now if now is not None else time.time()
    obj = _parse(line)
    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not _NONCE.match(nonce):
        raise ProtocolError(E_BAD_REQUEST, "missing or invalid nonce")
    mac = obj.pop("mac", None)
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(key, _REQ_DOMAIN, obj)):
        raise ProtocolError(E_UNAUTHORIZED, nonce)
    if set(obj) != {"v", "nonce", "ts", "cmd", "args"} or obj["v"] != PROTOCOL_VERSION:
        raise ProtocolError(E_BAD_REQUEST, nonce)
    ts, cmd, args = obj["ts"], obj["cmd"], obj["args"]
    if isinstance(ts, bool) or not isinstance(ts, int) or not isinstance(cmd, str) or not isinstance(args, dict):
        raise ProtocolError(E_BAD_REQUEST, nonce)
    if abs(now - ts) > nonces.max_skew:
        raise ProtocolError(E_REPLAY, nonce)
    if not nonces.check_and_add(nonce, now):
        raise ProtocolError(E_REPLAY, nonce)
    return nonce, cmd, args


def build_response(key: bytes, nonce: str, *, result: dict[str, Any] | None = None,
                   error: str | None = None, detail: str = "") -> bytes:
    body: dict[str, Any] = {"v": PROTOCOL_VERSION, "nonce": nonce}
    if error is None:
        body["ok"] = True
        body["result"] = result or {}
    else:
        body["ok"] = False
        body["error"] = error
        if detail:
            body["detail"] = detail[:512]
    body["mac"] = _mac(key, _RESP_DOMAIN, body)
    return _encode(body)
