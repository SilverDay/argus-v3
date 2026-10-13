"""Orchestrator <-> YARA worker wire protocol (newline-delimited JSON, Unix socket).

Requests (orchestrator -> worker):
  {"op": "hello"}                      -> {"ok": true, "rules_version": "<v>:<digest16>"}
  {"op": "scan", "id": <int>}  + 1 fd  -> {"id": <int>, "status": <status>, "matches": [...], "reason": "..."}
  {"op": "bye"}                        -> {"ok": true}
File content is never sent; each scan request carries exactly one read-only file
descriptor as SCM_RIGHTS ancillary data. Errors: {"ok": false, "error": "<code>"}.

status: clean | match | timeout | too_large | error
match item: {"rule": str, "namespace": str, "tags": [str], "severity": "high"|"medium"|"low"}
"""
from __future__ import annotations

import json
from typing import Any

MAX_LINE = 64 * 1024
MAX_MATCHES = 64
STATUSES = frozenset({"clean", "match", "timeout", "too_large", "error"})
SEVERITIES = frozenset({"high", "medium", "low"})


class YaraProtocolError(ValueError):
    pass


def encode(obj: dict[str, Any]) -> bytes:
    line = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if len(line) > MAX_LINE:
        raise YaraProtocolError("message too large")
    return line


def decode(line: bytes) -> dict[str, Any]:
    if len(line) > MAX_LINE:
        raise YaraProtocolError("message too large")
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise YaraProtocolError("malformed JSON") from None
    if not isinstance(obj, dict):
        raise YaraProtocolError("expected an object")
    return obj


def severity_from_meta(meta: dict[str, Any]) -> str:
    """Rule authors set meta: severity = "high" for THREAT-level rules; default medium."""
    value = str(meta.get("severity", "")).strip().lower()
    if value in ("high", "critical"):
        return "high"
    if value in ("low", "info", "informational"):
        return "low"
    return "medium"
