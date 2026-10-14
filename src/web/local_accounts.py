"""Local named accounts (spec §10.2; owner decision 1.5.10: OIDC and/or local accounts).

Accounts file (``auth.web.local.accounts_ref``, a ``file:`` reference, 0640 root:usbscan-web),
written only by ``python -m src.web.accounts_admin``. One account per line:

    username:role:bcrypt_hash[:totp_seed[:disabled]]      # '#' comments and blank lines allowed

* bcrypt ($2b$) with cost >= 12; ``totp_seed`` is the RFC 6238 seed in base32 (empty = not
  enrolled); the literal ``disabled`` blocks the account without deleting it.
* Each account is an individual person; there is no shared account or shared PIN.

The web process re-reads the file when it changes (``AccountsFile``), so account changes
apply without a restart. A file that no longer parses disables every local login (fail
closed) until it is fixed.
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import threading
from dataclasses import dataclass

import bcrypt

from src.shared.secret_refs import SecretError, resolve_secret

log = logging.getLogger(__name__)

ROLES = ("viewer", "operator", "admin")
_USER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_BCRYPT = re.compile(r"\$2b\$(\d{2})\$[./A-Za-z0-9]{53}")
_SEED = re.compile(r"[A-Z2-7]{26,64}")
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
    totp_seed: str = ""
    disabled: bool = False

    def line(self) -> str:
        fields = [self.username, self.role, self.hash.decode("ascii")]
        if self.totp_seed or self.disabled:
            fields.append(self.totp_seed)
        if self.disabled:
            fields.append("disabled")
        return ":".join(fields)


def parse_accounts(text: str) -> dict[str, Account]:
    accounts: dict[str, Account] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if not 3 <= len(parts) <= 5:
            raise AccountsError(f"line {n}: expected username:role:hash[:totp_seed[:disabled]]")
        user, role, digest = parts[:3]
        seed = parts[3] if len(parts) > 3 else ""
        flag = parts[4] if len(parts) > 4 else ""
        if not _USER.fullmatch(user):
            raise AccountsError(f"line {n}: invalid username")
        if role not in ROLES:
            raise AccountsError(f"line {n}: role must be one of {ROLES}")
        m = _BCRYPT.fullmatch(digest)
        if not m or int(m.group(1)) < MIN_COST:
            raise AccountsError(f"line {n}: bcrypt ($2b$) hash with cost >= {MIN_COST} required")
        if seed:
            try:
                ok = bool(_SEED.fullmatch(seed)) and len(base64.b32decode(seed + "=" * (-len(seed) % 8))) >= 16
            except binascii.Error:
                ok = False
            if not ok:
                raise AccountsError(f"line {n}: TOTP seed must be base32 with at least 128 bits")
        if flag not in ("", "disabled"):
            raise AccountsError(f"line {n}: unknown flag")
        if user in accounts:
            raise AccountsError(f"line {n}: duplicate username")
        accounts[user] = Account(user, role, digest.encode(), seed, flag == "disabled")
    return accounts


def format_accounts(accounts: dict[str, Account]) -> str:
    header = "# USB Scan Station admin web accounts - managed by: python -m src.web.accounts_admin\n"
    return header + "".join(a.line() + "\n" for a in sorted(accounts.values(), key=lambda a: a.username))


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


class AccountsFile:
    """The accounts behind a ``file:`` reference, re-read whenever the file changes."""

    def __init__(self, ref: str) -> None:
        self.ref = ref
        self._lock = threading.Lock()
        self._sig: tuple[int, ...] | None = None
        self._accounts: dict[str, Account] = {}

    def current(self) -> dict[str, Account]:
        with self._lock:
            try:
                # ctime also changes on chmod/chown, so a permission change forces the
                # re-read, where resolve_secret re-checks the file mode.
                st = os.stat(self.ref.partition(":")[2], follow_symlinks=False)
                sig = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode)
                if sig != self._sig:
                    self._accounts = parse_accounts(resolve_secret(self.ref, strip=False).decode("utf-8"))
                    self._sig = sig
                    log.info("local accounts loaded: %d", len(self._accounts))
            except (OSError, ValueError, SecretError) as exc:     # AccountsError/UnicodeDecodeError are ValueErrors
                if self._sig is not None or self._accounts:
                    log.error("local accounts file unusable (%s): local sign-in disabled", type(exc).__name__)
                self._accounts, self._sig = {}, None
            return self._accounts


class StaticAccounts:
    """Fixed account set (tests)."""

    def __init__(self, accounts: dict[str, Account]) -> None:
        self._accounts = accounts

    def current(self) -> dict[str, Account]:
        return self._accounts
