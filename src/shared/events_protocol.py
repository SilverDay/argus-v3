"""Events service wire protocol: one JSON object per line over a Unix socket.

Request:  {"op": "<op>", ...}
Response: {"ok": true, ...} | {"ok": false, "error": "<code>"}

Peers are authenticated by SO_PEERCRED (no shared secret): the socket is local only and
writer/reader roles are bound to service uids.
"""
from __future__ import annotations

import json
from typing import Any

MAX_LINE_BYTES = 1024 * 1024          # a verdict carries the full ScanResult
WRITE_OPS = frozenset({"append"})
READ_OPS = frozenset({"ping", "status", "last_verdict", "last_health", "recent", "page", "scans", "scan",
                      "stats"})

E_BAD_REQUEST = "bad_request"
E_FORBIDDEN = "forbidden"
E_INVALID_EVENT = "invalid_event"
E_STORE_FULL = "store_full"
E_INTERNAL = "internal_error"
RETRYABLE = frozenset({E_STORE_FULL, E_INTERNAL})


class EventsProtocolError(ValueError):
    pass


def encode(obj: dict[str, Any]) -> bytes:
    line = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise EventsProtocolError("message too large")
    return line


def decode(line: bytes) -> dict[str, Any]:
    if len(line) > MAX_LINE_BYTES:
        raise EventsProtocolError("message too large")
    try:
        obj = json.loads(line)
    except ValueError:
        raise EventsProtocolError("malformed JSON") from None
    if not isinstance(obj, dict):
        raise EventsProtocolError("expected a JSON object")
    return obj
