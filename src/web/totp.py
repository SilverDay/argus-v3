"""Time-based one-time passwords for local admin accounts (RFC 6238 over RFC 4226 HOTP).

HMAC-SHA1, 30-second steps, 6 digits: the parameters every common authenticator app uses
by default. Seeds are 160 random bits (RFC 4226 §4 recommends at least 128, preferably
160), base32-encoded without padding.

``verify`` accepts the current step and one step either side (clock drift) and returns the
matched step counter. The caller stores the last accepted counter per account and refuses
counters that are not newer, so an observed code cannot be replayed (RFC 6238 §5.2).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1
SEED_BYTES = 20


def new_seed() -> str:
    return base64.b32encode(secrets.token_bytes(SEED_BYTES)).decode("ascii").rstrip("=")


def _key(seed_b32: str) -> bytes:
    s = seed_b32.strip().upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def verify(seed_b32: str, code: str, now: float | None = None) -> int | None:
    """Return the matching time-step counter, or None. Constant work for every input."""
    now = time.time() if now is None else now
    candidate = code.strip() if isinstance(code, str) else ""
    valid_format = len(candidate) == DIGITS and candidate.isascii() and candidate.isdigit()
    probe = candidate if valid_format else ""         # never equal to a 6-digit code
    key = _key(seed_b32)
    current = int(now // STEP_SECONDS)
    match = None
    for counter in range(current - WINDOW, current + WINDOW + 1):
        if hmac.compare_digest(hotp(key, counter), probe) and match is None:
            match = counter
    return match


def provisioning_uri(seed_b32: str, username: str, issuer: str) -> str:
    """otpauth:// URI for authenticator apps (Key URI format used by common authenticators)."""
    label = urllib.parse.quote(f"{issuer}:{username}", safe="")
    query = urllib.parse.urlencode({"secret": seed_b32, "issuer": issuer, "algorithm": "SHA1",
                                    "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"
