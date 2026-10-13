"""Durable audit event store (spec §3.7): SQLite WAL, hash chain, delivery queue.

* ``synchronous=FULL``: an append returns only after the WAL is on stable storage,
  because the orchestrator ejects the device right after the verdict is acknowledged
  (spec §3.2 step 10). ``NORMAL`` may lose the last transactions on power loss.
* Every event gets the next sequence number (``seq``, gap-free) and a chain hash:
  ``SHA-256(canonical JSON [prev_hash, seq, event_id, event_type, scan_id, station_id,
  timestamp_utc, received_utc, payload])``. JSON-array encoding makes field boundaries
  unambiguous. The first event chains to ``SHA-256("usb-scan-events-genesis\\0" + station)``.
* Duplicate ``event_id``s are acknowledged without a second insert (idempotent replay).
* ``verify()`` walks the chain from the anchor and reports gaps, broken links and
  modified rows. A local attacker with write access can recompute the whole chain, so
  the chain is backed by HMAC checkpoints and off-device forwarding (spec §3.7; §13
  "audit deletion or rollback").
* Retention pruning removes old, fully delivered events from the start of the chain and
  moves the anchor (seq + hash of the last removed event) forward.
* Writes are refused while free space is below ``min_free_mb`` (StoreFull).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.shared.models import EventType, ScanEvent, format_utc, utc_now
from src.shared.scan_summary import scan_summary

SCHEMA_VERSION = "1"
GENESIS_DOMAIN = b"usb-scan-events-genesis\x00"
CHECKPOINT_DOMAIN = "usb-scan-checkpoint-v1"
MB = 1024 ** 2

Router = Callable[[EventType, dict[str, Any]], list[str]]


class StoreError(Exception):
    pass


class StoreCorrupt(StoreError):
    """SQLite integrity check failed: the service must not start."""


class StoreFull(StoreError):
    """Free space below the configured minimum: writes are refused."""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def genesis_hash(station_id: str) -> str:
    return hashlib.sha256(GENESIS_DOMAIN + station_id.encode()).hexdigest()


def record_hash(prev_hash: str, seq: int, event_id: str, event_type: str, scan_id: str | None,
                station_id: str, timestamp_utc: str, received_utc: str, payload_json: str) -> str:
    material = canonical([prev_hash, seq, event_id, event_type, scan_id, station_id, timestamp_utc,
                          received_utc, payload_json])
    return hashlib.sha256(material.encode()).hexdigest()


def checkpoint_mac(key: bytes, station_id: str, seq: int, head_hash: str, created_utc: str) -> str:
    material = canonical([CHECKPOINT_DOMAIN, station_id, seq, head_hash, created_utc]).encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    event_id: str
    event_type: str
    scan_id: str | None
    station_id: str
    timestamp_utc: str
    received_utc: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "event_id": self.event_id, "event_type": self.event_type, "scan_id": self.scan_id,
                "station_id": self.station_id, "timestamp_utc": self.timestamp_utc,
                "received_utc": self.received_utc, "payload": self.payload, "prev_hash": self.prev_hash,
                "hash": self.hash}


@dataclass
class VerifyResult:
    ok: bool
    checked: int = 0
    first_bad_seq: int | None = None
    reason: str = ""
    checkpoints: int = 0


@dataclass
class Delivery:
    channel: str
    attempts: int
    event: StoredEvent


@dataclass
class AppendResult:
    seq: int
    duplicate: bool = False
    channels: list[str] = field(default_factory=list)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    scan_id TEXT,
    station_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    received_utc TEXT NOT NULL,
    received_at REAL NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_type ON events(event_type, seq);
CREATE TABLE IF NOT EXISTS delivery (
    channel TEXT NOT NULL,
    seq INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt REAL NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    updated_utc TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (channel, seq)
);
CREATE INDEX IF NOT EXISTS delivery_queue ON delivery(channel, status, seq);
"""


class EventStore:
    def __init__(self, path: str, station_id: str, *, min_free_mb: int = 256,
                 router: Router | None = None, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self.station_id = station_id
        self.min_free_mb = min_free_mb
        self.router = router or (lambda event_type, payload: [])
        self.clock = clock
        self._lock = threading.Lock()
        if not os.path.exists(path):
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            rows = self._db.execute("PRAGMA integrity_check").fetchall()
            if rows != [("ok",)]:
                raise StoreCorrupt("integrity_check: " + "; ".join(str(r[0]) for r in rows[:5]))
            self._db.executescript(_SCHEMA)
            self._init_meta()
        except BaseException:
            self._db.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- meta ----------------------------------------------------------------------

    def _meta(self, key: str, default: str = "") -> str:
        row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def _set_meta(self, key: str, value: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    def _init_meta(self) -> None:
        if self._meta("schema_version"):
            if self._meta("schema_version") != SCHEMA_VERSION:
                raise StoreError(f"unsupported schema version {self._meta('schema_version')}")
            return
        self._db.execute("BEGIN IMMEDIATE")
        self._set_meta("schema_version", SCHEMA_VERSION)
        self._set_meta("genesis_station_id", self.station_id)
        self._set_meta("anchor_seq", "0")
        self._set_meta("anchor_hash", genesis_hash(self.station_id))
        self._set_meta("last_seq", "0")
        self._set_meta("tamper", "")
        self._db.execute("COMMIT")

    # --- append --------------------------------------------------------------------

    def _check_space(self) -> None:
        vfs = os.statvfs(os.path.dirname(os.path.abspath(self.path)))
        if vfs.f_bavail * vfs.f_frsize < self.min_free_mb * MB:
            raise StoreFull("free space below events.min_free_mb")

    def _head_locked(self) -> tuple[int, str]:
        row = self._db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        if row is None:
            return int(self._meta("anchor_seq", "0")), self._meta("anchor_hash")
        return int(row[0]), str(row[1])

    def append(self, event: ScanEvent) -> AppendResult:
        record = event.to_dict()
        payload_json = canonical(record["payload"])
        with self._lock:
            existing = self._db.execute("SELECT seq FROM events WHERE event_id=?", (event.event_id,)).fetchone()
            if existing:
                return AppendResult(int(existing[0]), duplicate=True)
            self._check_space()
            channels = list(self.router(event.event_type, record["payload"]))
            self._db.execute("BEGIN IMMEDIATE")
            try:
                head_seq, head_hash = self._head_locked()
                seq = head_seq + 1
                now = self.clock()
                received = format_utc(utc_now())
                digest = record_hash(head_hash, seq, event.event_id, record["event_type"], event.scan_id,
                                     self.station_id, record["timestamp_utc"], received, payload_json)
                self._db.execute(
                    "INSERT INTO events (seq, event_id, event_type, scan_id, station_id, timestamp_utc, received_utc,"
                    " received_at, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (seq, event.event_id, record["event_type"], event.scan_id, self.station_id,
                     record["timestamp_utc"], received, now, payload_json, head_hash, digest))
                for ch in channels:
                    self._db.execute("INSERT INTO delivery (channel, seq, status) VALUES (?, ?, 'pending')", (ch, seq))
                self._set_meta("last_seq", str(seq))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return AppendResult(seq, channels=channels)

    # --- reads ---------------------------------------------------------------------

    @staticmethod
    def _row(row: tuple) -> StoredEvent:
        seq, event_id, event_type, scan_id, station_id, ts, received, payload, prev_hash, digest = row
        return StoredEvent(int(seq), event_id, event_type, scan_id, station_id, ts, received, json.loads(payload),
                           prev_hash, digest)

    _COLS = "seq, event_id, event_type, scan_id, station_id, timestamp_utc, received_utc, payload, prev_hash, hash"

    def head(self) -> tuple[int, str]:
        with self._lock:
            return self._head_locked()

    def get(self, seq: int) -> StoredEvent | None:
        with self._lock:
            row = self._db.execute(f"SELECT {self._COLS} FROM events WHERE seq=?", (seq,)).fetchone()
        return self._row(row) if row else None

    def recent(self, limit: int = 50, after_seq: int = 0, event_types: list[str] | None = None) -> list[StoredEvent]:
        limit = max(1, min(int(limit), 500))
        sql = f"SELECT {self._COLS} FROM events WHERE seq > ?"
        args: list[Any] = [int(after_seq)]
        if event_types:
            sql += f" AND event_type IN ({','.join('?' * len(event_types))})"
            args.extend(event_types)
        sql += " ORDER BY seq LIMIT ?" if after_seq else " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        events = [self._row(r) for r in rows]
        return events if after_seq else events[::-1]

    def before(self, before_seq: int, limit: int = 50, event_types: list[str] | None = None) -> list[StoredEvent]:
        """Newest-first page of events older than ``before_seq`` (0 = from the head)."""
        limit = max(1, min(int(limit), 500))
        sql = f"SELECT {self._COLS} FROM events WHERE 1=1"
        args: list[Any] = []
        if before_seq:
            sql += " AND seq < ?"
            args.append(int(before_seq))
        if event_types:
            sql += f" AND event_type IN ({','.join('?' * len(event_types))})"
            args.extend(event_types)
        with self._lock:
            rows = self._db.execute(sql + " ORDER BY seq DESC LIMIT ?", [*args, limit]).fetchall()
        return [self._row(r) for r in rows]

    # --- scan history / statistics (admin web, read-only) -----------------------------

    def scans(self, *, verdicts: list[str] | None = None, since: float | None = None, until: float | None = None,
              serial: str | None = None, before_seq: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """Newest-first VERDICT summaries. Date filters use the store's receive time (epoch)."""
        limit = max(1, min(int(limit), 1000))
        sql = "SELECT seq, received_at, payload FROM events WHERE event_type='verdict'"
        args: list[Any] = []
        if verdicts:
            sql += f" AND json_extract(payload, '$.verdict') IN ({','.join('?' * len(verdicts))})"
            args.extend(verdicts)
        if since is not None:
            sql += " AND received_at >= ?"
            args.append(float(since))
        if until is not None:
            sql += " AND received_at < ?"
            args.append(float(until))
        if serial:
            sql += " AND json_extract(payload, '$.device.serial') = ?"
            args.append(serial)
        if before_seq:
            sql += " AND seq < ?"
            args.append(int(before_seq))
        with self._lock:
            rows = self._db.execute(sql + " ORDER BY seq DESC LIMIT ?", [*args, limit]).fetchall()
        return [scan_summary(int(seq), float(at), json.loads(payload)) for seq, at, payload in rows]

    def stats(self, days: int) -> dict[str, Any]:
        days = max(1, min(int(days), 366))
        since = self.clock() - days * 86_400
        with self._lock:
            per_day = self._db.execute(
                "SELECT date(received_at, 'unixepoch') AS day, json_extract(payload, '$.verdict'),"
                " COUNT(*), SUM(COALESCE(json_extract(payload, '$.threat_count'),"
                " json_array_length(payload, '$.threats')))"
                " FROM events WHERE event_type='verdict' AND received_at >= ? GROUP BY day, 2 ORDER BY day",
                (since,)).fetchall()
            top = self._db.execute(
                "SELECT json_extract(t.value, '$.signature_name') AS sig, COUNT(*) FROM events,"
                " json_each(events.payload, '$.threats') AS t WHERE events.event_type='verdict'"
                " AND events.received_at >= ? GROUP BY sig ORDER BY 2 DESC, sig LIMIT 10", (since,)).fetchall()
        days_out: dict[str, dict[str, Any]] = {}
        for day, verdict, n, threats in per_day:
            d = days_out.setdefault(day, {"day": day, "scans": 0, "threats": 0, "verdicts": {}})
            d["scans"] += int(n)
            d["threats"] += int(threats or 0)
            d["verdicts"][str(verdict)] = int(n)
        return {"days": days, "per_day": list(days_out.values()),
                "top_signatures": [{"signature": str(sig), "count": int(n)} for sig, n in top]}

    def last_of_type(self, event_type: EventType) -> StoredEvent | None:
        with self._lock:
            row = self._db.execute(f"SELECT {self._COLS} FROM events WHERE event_type=? ORDER BY seq DESC LIMIT 1",
                                   (event_type.value,)).fetchone()
        return self._row(row) if row else None

    # --- verification ----------------------------------------------------------------

    def verify(self) -> VerifyResult:
        with self._lock:
            anchor_seq = int(self._meta("anchor_seq", "0"))
            expected_prev = self._meta("anchor_hash")
            last_seq = int(self._meta("last_seq", "0"))
            cur = self._db.execute(f"SELECT {self._COLS} FROM events WHERE seq > ? ORDER BY seq", (anchor_seq,))
            expected_seq = anchor_seq + 1
            checked = 0
            for row in cur:
                seq, event_id, event_type, scan_id, station_id, ts, received, payload, prev_hash, digest = row
                if seq != expected_seq:
                    return VerifyResult(False, checked, expected_seq, "gap")
                if prev_hash != expected_prev:
                    return VerifyResult(False, checked, seq, "broken_link")
                if record_hash(prev_hash, seq, event_id, event_type, scan_id, station_id, ts, received,
                               payload) != digest:
                    return VerifyResult(False, checked, seq, "modified")
                expected_prev = digest
                expected_seq += 1
                checked += 1
            if expected_seq - 1 != last_seq:
                return VerifyResult(False, checked, expected_seq, "truncated")
        return VerifyResult(True, checked)

    def tamper_state(self) -> dict[str, Any] | None:
        with self._lock:
            raw = self._meta("tamper")
        return json.loads(raw) if raw else None

    def set_tamper(self, result: VerifyResult) -> None:
        with self._lock:
            self._set_meta("tamper", canonical({"first_bad_seq": result.first_bad_seq, "reason": result.reason,
                                               "detected_utc": format_utc(utc_now())}))

    def reanchor(self) -> tuple[int, str]:
        """After an investigated tamper alarm: verification restarts at the current head.
        The damaged history stays in the database for forensics."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            seq, digest = self._head_locked()
            self._set_meta("anchor_seq", str(seq))
            self._set_meta("anchor_hash", digest)
            self._set_meta("last_seq", str(seq))
            self._set_meta("tamper", "")
            self._db.execute("COMMIT")
        return seq, digest

    # --- checkpoints ------------------------------------------------------------------

    def checkpoint(self, key: bytes) -> AppendResult:
        """Append an AUDIT_CHECKPOINT event authenticating the current chain head."""
        seq, head_hash = self.head()
        created = format_utc(utc_now())
        payload = {"checkpoint_seq": seq, "head_hash": head_hash, "created_utc": created,
                   "mac": checkpoint_mac(key, self.station_id, seq, head_hash, created)}
        return self.append(ScanEvent(EventType.AUDIT_CHECKPOINT, None, payload))

    def verify_checkpoints(self, key: bytes) -> VerifyResult:
        """Check every retained checkpoint: valid MAC, and the event it names still has the
        authenticated hash. Detects a chain rewritten by someone without the key."""
        checkpoints = self.recent(500, after_seq=0, event_types=[EventType.AUDIT_CHECKPOINT.value])
        with self._lock:
            anchor = int(self._meta("anchor_seq", "0"))
        for cp in checkpoints:
            p = cp.payload
            try:
                seq, head, created, mac = int(p["checkpoint_seq"]), str(p["head_hash"]), str(p["created_utc"]), str(p["mac"])
            except (KeyError, TypeError, ValueError):
                return VerifyResult(False, 0, cp.seq, "checkpoint_malformed")
            if not hmac.compare_digest(mac, checkpoint_mac(key, cp.station_id, seq, head, created)):
                return VerifyResult(False, 0, cp.seq, "checkpoint_mac")
            if seq > anchor:
                ev = self.get(seq)
                if ev is None or ev.hash != head:
                    return VerifyResult(False, 0, seq, "checkpoint_mismatch")
        return VerifyResult(True, len(checkpoints))

    def last_checkpoint_age(self) -> float | None:
        with self._lock:
            row = self._db.execute("SELECT received_at FROM events WHERE event_type=? ORDER BY seq DESC LIMIT 1",
                                   (EventType.AUDIT_CHECKPOINT.value,)).fetchone()
        return None if row is None else self.clock() - float(row[0])

    # --- delivery queue -----------------------------------------------------------------

    def next_delivery(self, channel: str) -> tuple[Delivery | None, float]:
        """Head of the channel's queue (lowest pending seq) and when it is due.

        Ordering is strict: a later event is never sent before an earlier pending one.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT d.attempts, d.next_attempt, " + ", ".join(f"e.{c.strip()}" for c in self._COLS.split(",")) +
                " FROM delivery d JOIN events e ON e.seq = d.seq WHERE d.channel=? AND d.status='pending'"
                " ORDER BY d.seq LIMIT 1", (channel,)).fetchone()
        if row is None:
            return None, 0.0
        return Delivery(channel, int(row[0]), self._row(row[2:])), float(row[1])

    def mark_delivered(self, channel: str, seq: int) -> None:
        with self._lock:
            self._db.execute("UPDATE delivery SET status='delivered', updated_utc=? WHERE channel=? AND seq=?",
                             (format_utc(utc_now()), channel, seq))

    def mark_failed(self, channel: str, seq: int, error: str, next_attempt: float, dead: bool) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE delivery SET attempts=attempts+1, last_error=?, next_attempt=?, status=?, updated_utc=?"
                " WHERE channel=? AND seq=?",
                (error[:200], next_attempt, "dead" if dead else "pending", format_utc(utc_now()), channel, seq))

    def queue_stats(self) -> dict[str, dict[str, int]]:
        with self._lock:
            rows = self._db.execute("SELECT channel, status, COUNT(*) FROM delivery GROUP BY channel, status").fetchall()
        stats: dict[str, dict[str, int]] = {}
        for channel, status, n in rows:
            stats.setdefault(channel, {"pending": 0, "delivered": 0, "dead": 0})[status] = int(n)
        return stats

    # --- retention ------------------------------------------------------------------------

    def prune(self, retention_days: int) -> int:
        """Remove events older than the retention period from the start of the chain, but never
        an event that still has a pending delivery (nor anything after it)."""
        cutoff = self.clock() - retention_days * 86_400
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                pending = self._db.execute("SELECT MIN(seq) FROM delivery WHERE status='pending'").fetchone()[0]
                limit_seq = (int(pending) - 1) if pending is not None else None
                sql = "SELECT seq, hash FROM events WHERE received_at < ?"
                args: list[Any] = [cutoff]
                if limit_seq is not None:
                    sql += " AND seq <= ?"
                    args.append(limit_seq)
                last = self._db.execute(sql + " ORDER BY seq DESC LIMIT 1", args).fetchone()
                anchor = int(self._meta("anchor_seq", "0"))
                if last is None or int(last[0]) <= anchor:
                    self._db.execute("COMMIT")
                    return 0
                upto, digest = int(last[0]), str(last[1])
                n = self._db.execute("DELETE FROM events WHERE seq <= ?", (upto,)).rowcount
                self._db.execute("DELETE FROM delivery WHERE seq <= ?", (upto,))
                self._set_meta("anchor_seq", str(upto))
                self._set_meta("anchor_hash", digest)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return n

    def status(self) -> dict[str, Any]:
        seq, digest = self.head()
        with self._lock:
            anchor = int(self._meta("anchor_seq", "0"))
        age = self.last_checkpoint_age()
        try:
            self._check_space()
            full = False
        except StoreFull:
            full = True
        return {"head_seq": seq, "head_hash": digest, "anchor_seq": anchor, "tamper": self.tamper_state(),
                "store_full": full,
                "queues": self.queue_stats(), "last_checkpoint_age_s": None if age is None else round(age)}
