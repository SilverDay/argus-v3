"""Append-only, hash-chained JSON-lines audit log of privileged broker actions.

Each record carries a sequence number and ``hash = SHA-256(prev_hash || canonical record)``
so deletion or modification of earlier lines is detectable. Off-device anchoring
of the chain is the events service's job (spec §3.7, Phase 8).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def record_hash(prev_hash: str, record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(prev_hash.encode() + _canonical(body)).hexdigest()


def verify_chain(lines: list[str]) -> int | None:
    """Return the index of the first invalid line, or None if the chain is intact."""
    prev, seq = GENESIS, 0
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return i
        if rec.get("action") == "chain_restart":
            prev, seq = rec.get("prev_hash", GENESIS), rec.get("seq", 0) - 1
        if rec.get("seq") != seq + 1 or rec.get("prev_hash") != prev or rec.get("hash") != record_hash(prev, rec):
            return i
        prev, seq = rec["hash"], rec["seq"]
    return None


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        restart_reason = self._load_tail()
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o640)
        if restart_reason:
            self.write("chain_restart", reason=restart_reason)

    def _load_tail(self) -> str | None:
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 65536))
                tail = fh.read().splitlines()
        except FileNotFoundError:
            return None
        if not tail:
            return None
        try:
            last = json.loads(tail[-1])
            if last.get("hash") == record_hash(last.get("prev_hash", ""), last):
                self._seq, self._prev = int(last["seq"]), str(last["hash"])
                return None
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass
        return "unverifiable_tail"

    def write(self, action: str, **fields: Any) -> None:
        with self._lock:
            record = {
                "seq": self._seq + 1,
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "action": action,
                "prev_hash": self._prev,
                **fields,
            }
            record["hash"] = record_hash(self._prev, record)
            os.write(self._fd, _canonical(record) + b"\n")
            os.fsync(self._fd)
            self._seq, self._prev = record["seq"], record["hash"]

    def close(self) -> None:
        with self._lock:
            os.close(self._fd)
