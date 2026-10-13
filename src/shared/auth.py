"""Operator PIN handling and persistent lockout (spec §5.3, §10.1).

* PINs are hashed with bcrypt at cost >= 12 and never stored or logged in clear.
* Lockout state lives in SQLite, not process memory, so restarting the GUI or
  orchestrator cannot reset the failure counter (AC-S05). In Phase 8 the store
  moves behind the events service; ``LockoutStore`` is the seam for that.
* Every attempt is persisted as a failure *before* the hash is checked and only
  upgraded to success afterwards, so a crash mid-verification fails closed.
* While locked out no hash is computed: rate limiting does not depend on bcrypt cost.
* Clock jumps (owner decision "fail closed + cap"): within one boot, lockout expiry is
  measured with CLOCK_BOOTTIME, so wall-clock changes neither shorten nor extend it.
  Across a reboot only wall time is comparable; if it is *behind* the lockout record,
  the lockout is re-armed once from now — i.e. extended by at most one lockout period.
"""
from __future__ import annotations

import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

import bcrypt

MIN_BCRYPT_COST = 12
BCRYPT_MAX_BYTES = 72
DEFAULT_MIN_LENGTH = 6
DEFAULT_MAX_LENGTH = 12
_BCRYPT_HASH = re.compile(r"^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$")


class AuthError(Exception):
    """Raised for unusable credentials or stores. Messages never contain the PIN."""


# --- PIN policy ------------------------------------------------------------

def validate_pin_format(
    pin: str,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = DEFAULT_MAX_LENGTH,
    deny_list: Iterable[str] = (),
) -> str | None:
    """Return an error message if ``pin`` violates policy, else ``None``."""
    if not isinstance(pin, str) or not (pin.isascii() and pin.isdigit()):
        return "PIN must contain only digits 0-9"
    if len(pin) < min_length:
        return f"PIN must have at least {min_length} digits"
    if len(pin) > max_length:
        return f"PIN must have at most {max_length} digits"
    if len(set(pin)) == 1:
        return "PIN must not repeat a single digit"
    steps = {(int(b) - int(a)) % 10 for a, b in zip(pin, pin[1:])}
    if steps == {1} or steps == {9}:
        return "PIN must not be a sequential run of digits"
    if pin in set(deny_list):
        return "PIN is on the deny list"
    return None


def load_deny_list(path: str) -> frozenset[str]:
    """Load one PIN per line; blank lines and '#' comments are ignored."""
    if not path:
        return frozenset()
    with open(path, encoding="utf-8") as fh:
        return frozenset(line.strip() for line in fh if line.strip() and not line.startswith("#"))


def _encode_checked(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise AuthError("PIN must be a string")
    data = pin.encode("utf-8")
    if len(data) > BCRYPT_MAX_BYTES:
        raise AuthError("PIN exceeds bcrypt input limit")
    return data


def hash_cost(hashed: str) -> int | None:
    m = _BCRYPT_HASH.match(hashed or "")
    return int(m.group(1)) if m else None


def hash_pin(pin: str, *, cost: int = MIN_BCRYPT_COST, **policy) -> str:
    """Validate ``pin`` against policy and return its bcrypt hash."""
    if cost < MIN_BCRYPT_COST:
        raise AuthError(f"bcrypt cost must be >= {MIN_BCRYPT_COST}")
    problem = validate_pin_format(pin, **policy)
    if problem:
        raise AuthError(problem)
    return bcrypt.hashpw(_encode_checked(pin), bcrypt.gensalt(rounds=cost)).decode("ascii")


def verify_pin(pin: str, hashed: str, *, min_cost: int = MIN_BCRYPT_COST) -> bool:
    """Constant-time bcrypt check. Malformed input or a weak hash returns False."""
    cost = hash_cost(hashed)
    if cost is None or cost < min_cost:
        return False
    try:
        data = _encode_checked(pin)
    except AuthError:
        return False
    if not data:
        return False
    try:
        return bcrypt.checkpw(data, hashed.encode("ascii"))
    except ValueError:
        return False


# --- Lockout persistence ----------------------------------------------------

@dataclass(frozen=True)
class AuthRecord:
    id: int
    kind: str            # "attempt" | "clear" | "clock_lock"
    success: bool
    timestamp: float     # UNIX seconds, UTC
    lockout_triggered: bool
    boot_id: str = ""
    boottime: float = 0.0


@dataclass(frozen=True)
class Instant:
    wall: float          # time.time()
    boot_id: str         # /proc/sys/kernel/random/boot_id
    boottime: float      # CLOCK_BOOTTIME seconds (monotonic, includes suspend)


def _read_boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def system_boot_clock() -> tuple[str, float]:
    return _read_boot_id(), time.clock_gettime(time.CLOCK_BOOTTIME)


class LockoutStore(Protocol):
    def recent(self, level: str, interface: str, limit: int) -> list[AuthRecord]: ...
    def add_attempt(self, level: str, interface: str, now: Instant, max_failures: int,
                    lockout_seconds: float) -> tuple[int, bool]: ...
    def mark_success(self, record_id: int) -> None: ...
    def add_clear(self, level: str, interface: str, now: Instant) -> None: ...
    def add_clock_lock(self, level: str, interface: str, now: Instant) -> None: ...


def _elapsed(r: AuthRecord, now: Instant) -> float:
    if r.boot_id and r.boot_id == now.boot_id:
        return now.boottime - r.boottime
    return now.wall - r.timestamp


def _lockout_state(rows: list[AuthRecord], now: Instant, lockout_seconds: float) -> tuple[bool, int, bool]:
    """Return (locked, consecutive_failures, clock_anomaly) from newest-first records."""
    failures = 0
    for r in rows:
        if r.kind == "clear" or r.success:
            break
        if r.lockout_triggered:
            elapsed = _elapsed(r, now)
            if elapsed < 0:
                return True, failures + 1, True     # wall clock behind the record after reboot
            if elapsed < lockout_seconds:
                return True, failures + 1, False
            break  # lockout expired: counter starts again
        failures += 1
    return False, failures, False


class SqliteLockoutStore:
    """auth_events table (spec §3.7 / plan Phase 8 schema, plus a ``kind`` column)."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK (kind IN ('attempt', 'clear', 'clock_lock')),
            interface TEXT NOT NULL,
            level TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            timestamp_utc REAL NOT NULL,
            lockout_triggered INTEGER NOT NULL DEFAULT 0,
            boot_id TEXT NOT NULL DEFAULT '',
            boottime REAL NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS auth_events_lookup ON auth_events (level, interface, id);
    """

    def __init__(self, db_path: str) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False, timeout=10)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(self.SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _recent(self, level: str, interface: str, limit: int) -> list[AuthRecord]:
        cur = self._db.execute(
            "SELECT id, kind, success, timestamp_utc, lockout_triggered, boot_id, boottime FROM auth_events "
            "WHERE level = ? AND interface = ? ORDER BY id DESC LIMIT ?",
            (level, interface, limit),
        )
        return [AuthRecord(i, k, bool(s), float(t), bool(lt), b, float(bt)) for i, k, s, t, lt, b, bt in cur]

    def _insert(self, kind: str, level: str, interface: str, now: Instant, triggered: bool) -> int:
        cur = self._db.execute(
            "INSERT INTO auth_events (kind, interface, level, success, timestamp_utc, lockout_triggered, "
            "boot_id, boottime) VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
            (kind, interface, level, now.wall, int(triggered), now.boot_id, now.boottime),
        )
        return int(cur.lastrowid)

    def recent(self, level: str, interface: str, limit: int) -> list[AuthRecord]:
        with self._lock:
            return self._recent(level, interface, limit)

    def add_attempt(self, level: str, interface: str, now: Instant, max_failures: int,
                    lockout_seconds: float) -> tuple[int, bool]:
        """Atomically record a (provisional) failure; return (id, lockout_triggered)."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                _, failures, _ = _lockout_state(self._recent(level, interface, max_failures + 1), now,
                                                lockout_seconds)
                triggered = failures + 1 >= max_failures
                record_id = self._insert("attempt", level, interface, now, triggered)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            return record_id, triggered

    def mark_success(self, record_id: int) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE auth_events SET success = 1, lockout_triggered = 0 WHERE id = ?", (record_id,))

    def add_clear(self, level: str, interface: str, now: Instant) -> None:
        with self._lock:
            self._insert("clear", level, interface, now, False)

    def add_clock_lock(self, level: str, interface: str, now: Instant) -> None:
        """Re-arm a lockout from ``now`` after a backwards clock across reboot (one period max)."""
        with self._lock:
            self._insert("clock_lock", level, interface, now, True)


@dataclass(frozen=True)
class AuthOutcome:
    success: bool
    locked_out: bool
    lockout_triggered: bool = False


class AuthManager:
    """Verify operator PINs with persistent, restart-proof lockout."""

    def __init__(
        self,
        store: LockoutStore,
        hash_loader: Callable[[str], str],
        *,
        max_failures: int = 5,
        lockout_seconds: float = 15 * 60,
        min_cost: int = MIN_BCRYPT_COST,
        clock: Callable[[], float] = time.time,
        boot_clock: Callable[[], tuple[str, float]] = system_boot_clock,
    ) -> None:
        if max_failures < 1:
            raise ValueError("max_failures must be >= 1")
        self._store = store
        self._hash_loader = hash_loader
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._min_cost = min_cost
        self._clock = clock
        self._boot_clock = boot_clock

    def _now(self) -> Instant:
        boot_id, boottime = self._boot_clock()
        return Instant(self._clock(), boot_id, boottime)

    def is_locked_out(self, level: str = "operator", interface: str = "touchscreen") -> bool:
        now = self._now()
        rows = self._store.recent(level, interface, self._max_failures + 1)
        locked, _, anomaly = _lockout_state(rows, now, self._lockout_seconds)
        if anomaly:
            self._store.add_clock_lock(level, interface, now)
        return locked

    def attempt(self, pin: str, level: str = "operator", interface: str = "touchscreen") -> AuthOutcome:
        if self.is_locked_out(level, interface):
            return AuthOutcome(success=False, locked_out=True)
        record_id, triggered = self._store.add_attempt(
            level, interface, self._now(), self._max_failures, self._lockout_seconds)
        try:
            hashed = self._hash_loader(level)
        except Exception:
            # No usable hash means nobody can authenticate; the failure stays recorded.
            return AuthOutcome(success=False, locked_out=triggered, lockout_triggered=triggered)
        if verify_pin(pin, hashed, min_cost=self._min_cost):
            self._store.mark_success(record_id)
            return AuthOutcome(success=True, locked_out=False)
        return AuthOutcome(success=False, locked_out=triggered, lockout_triggered=triggered)

    def verify(self, pin: str, level: str = "operator", interface: str = "touchscreen") -> bool:
        return self.attempt(pin, level, interface).success

    def clear_lockout(self, level: str = "operator", interface: str = "touchscreen") -> None:
        """Administrative action only (named admin via web UI / maintenance CLI)."""
        self._store.add_clear(level, interface, self._now())
