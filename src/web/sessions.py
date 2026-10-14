"""Server-side sessions and login throttling (SQLite in admin_web.state_dir, 0600).

* The cookie holds a random 256-bit token; the database stores only its SHA-256, so a
  copy of the database does not yield usable session cookies.
* Sessions end on idle timeout, absolute timeout, logout, or a change of client address
  (IP binding, plan Phase 9). A new token is issued at every login (no fixation).
* Pending OIDC logins (state, nonce, PKCE verifier) are single-use, expire after 10
  minutes and are bound to the browser by a separate random cookie. Only the bound
  browser can consume one, so a leaked ``state`` cannot be used to cancel a login.
* Failed local logins are counted per account and per client address; reaching the limit
  locks that key for ``lockout_minutes``. The counters live on disk (survive restarts).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

PENDING_TTL = 600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, role TEXT NOT NULL, method TEXT NOT NULL,
    ip TEXT NOT NULL, csrf TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_pending (
    state_hash TEXT PRIMARY KEY, binding_hash TEXT NOT NULL, nonce TEXT NOT NULL,
    verifier TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_failures (
    key TEXT PRIMARY KEY, count INTEGER NOT NULL, locked_until REAL NOT NULL DEFAULT 0, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS totp_used (user TEXT PRIMARY KEY, counter INTEGER NOT NULL);
"""


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class Session:
    token_hash: str
    user: str
    role: str
    method: str
    ip: str
    csrf: str
    created: float
    last_seen: float


@dataclass(frozen=True)
class Pending:
    nonce: str
    verifier: str


class SessionStore:
    def __init__(self, path: str, *, idle_seconds: int, max_seconds: int,
                 clock: Callable[[], float] = time.time) -> None:
        self.idle = idle_seconds
        self.max = max_seconds
        self.clock = clock
        if not os.path.exists(path):
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- sessions -------------------------------------------------------------------------

    def create(self, user: str, role: str, method: str, ip: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = self.clock()
        sess = Session(_h(token), user, role, method, ip, secrets.token_urlsafe(32), now, now)
        with self._lock:
            self._db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                             (sess.token_hash, user, role, method, ip, sess.csrf, now, now))
            self._db.execute("DELETE FROM sessions WHERE last_seen < ? OR created < ?",
                             (now - self.idle, now - self.max))
        return token, sess

    def lookup(self, token: str) -> tuple[Session | None, str]:
        """Return (session, "") or (None, reason). Expired sessions are deleted."""
        if not token or len(token) > 128:
            return None, "missing"
        th = _h(token)
        now = self.clock()
        with self._lock:
            row = self._db.execute("SELECT * FROM sessions WHERE token_hash=?", (th,)).fetchone()
            if row is None:
                return None, "unknown"
            sess = Session(*row)
            if now - sess.last_seen > self.idle or now - sess.created > self.max or now < sess.created:
                self._db.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
                return None, "expired"
            self._db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, th))
        return sess, ""

    def delete(self, token_hash: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    # --- pending OIDC logins ----------------------------------------------------------------

    def put_pending(self, state: str, binding: str, nonce: str, verifier: str) -> None:
        now = self.clock()
        with self._lock:
            self._db.execute("DELETE FROM oidc_pending WHERE created < ?", (now - PENDING_TTL,))
            self._db.execute("INSERT INTO oidc_pending VALUES (?,?,?,?,?)",
                             (_h(state), _h(binding), nonce, verifier, now))

    def take_pending(self, state: str, binding: str) -> Pending | None:
        """Consume the pending login for ``state`` if ``binding`` is this browser's cookie."""
        if not state or not binding or len(state) > 256 or len(binding) > 256:
            return None
        with self._lock:
            row = self._db.execute("SELECT binding_hash, nonce, verifier, created FROM oidc_pending"
                                   " WHERE state_hash=?", (_h(state),)).fetchone()
            if row is None or not secrets.compare_digest(row[0], _h(binding)):
                return None
            self._db.execute("DELETE FROM oidc_pending WHERE state_hash=?", (_h(state),))
        _, nonce, verifier, created = row
        if self.clock() - created > PENDING_TTL:
            return None
        return Pending(nonce, verifier)

    # --- login throttling --------------------------------------------------------------------

    def locked(self, *keys: str) -> bool:
        now = self.clock()
        with self._lock:
            for key in keys:
                row = self._db.execute("SELECT locked_until FROM login_failures WHERE key=?", (key,)).fetchone()
                if row and row[0] > now:
                    return True
        return False

    def record_failure(self, keys: list[str], max_failures: int, lockout_seconds: int) -> None:
        now = self.clock()
        with self._lock:
            for key in keys:
                row = self._db.execute("SELECT count, locked_until FROM login_failures WHERE key=?", (key,)).fetchone()
                count = 1 if row is None or (row[1] and row[1] <= now) else row[0] + 1
                locked = now + lockout_seconds if count >= max_failures else 0
                self._db.execute("INSERT OR REPLACE INTO login_failures VALUES (?,?,?,?)", (key, count, locked, now))

    def accept_totp(self, user: str, counter: int) -> bool:
        """Record a used TOTP step; refuse a step that is not newer than the last one (replay)."""
        with self._lock:
            row = self._db.execute("SELECT counter FROM totp_used WHERE user=?", (user,)).fetchone()
            if row is not None and counter <= row[0]:
                return False
            self._db.execute("INSERT OR REPLACE INTO totp_used VALUES (?,?)", (user, counter))
            return True

    def clear_failures(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._db.execute("DELETE FROM login_failures WHERE key=?", (key,))
