"""Local named accounts for isolated management networks (spec §10.2).

Accounts file (secret reference ``auth.web.local.accounts_ref``), one per line:
    username:role:bcrypt_hash          # '#' comments and blank lines allowed
Hashes must be bcrypt ($2b$) with cost >= 12. Each account is an individual person —
there is no shared account or shared PIN for remote administration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import bcrypt

ROLES = ("viewer", "operator", "admin")
_USER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_BCRYPT = re.compile(r"\$2b\$(\d{2})\$[./A-Za-z0-9]{53}")
MAX_PASSPHRASE_BYTES = 72          # bcrypt 5.0 raises ValueError above this
MIN_COST = 12
# Verified against when the username is unknown, so both paths cost one bcrypt check.
_DUMMY = bcrypt.hashpw(b"timing-equaliser", bcrypt.gensalt(MIN_COST))


class AccountsError(ValueError):
    pass


@dataclass(frozen=True)
class Account:
    username: str
    role: str
    hash: bytes


def parse_accounts(text: str) -> dict[str, Account]:
    accounts: dict[str, Account] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            raise AccountsError(f"line {n}: expected username:role:hash")
        user, role, digest = parts
        if not _USER.fullmatch(user):
            raise AccountsError(f"line {n}: invalid username")
        if role not in ROLES:
            raise AccountsError(f"line {n}: role must be one of {ROLES}")
        m = _BCRYPT.fullmatch(digest)
        if not m or int(m.group(1)) < MIN_COST:
            raise AccountsError(f"line {n}: bcrypt ($2b$) hash with cost >= {MIN_COST} required")
        if user in accounts:
            raise AccountsError(f"line {n}: duplicate username")
        accounts[user] = Account(user, role, digest.encode())
    return accounts


def verify(accounts: dict[str, Account], username: str, passphrase: str) -> Account | None:
    """Constant-shape check: one bcrypt verification whether or not the user exists."""
    try:
        secret = passphrase.encode("utf-8") if isinstance(passphrase, str) else b""
    except UnicodeEncodeError:
        secret = b""
    acct = accounts.get(username)
    if not secret or len(secret) > MAX_PASSPHRASE_BYTES:
        bcrypt.checkpw(b"x", _DUMMY)
        return None
    ok = bcrypt.checkpw(secret, acct.hash if acct else _DUMMY)
    return acct if ok and acct is not None else None
