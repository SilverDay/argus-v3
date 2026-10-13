"""Compact summary of a committed VERDICT record (history lists, dashboard, export)."""
from __future__ import annotations

from typing import Any


def scan_summary(seq: int, received_at: float, payload: dict[str, Any]) -> dict[str, Any]:
    cov = payload.get("coverage") or {}
    threats = payload.get("threats") or []
    dev = payload.get("device") or {}
    meta = payload.get("metadata") or {}
    return {
        "seq": seq, "scan_id": meta.get("scan_id"), "started_utc": meta.get("session_start_utc"),
        "finished_utc": meta.get("session_end_utc"), "received_at": received_at,
        "verdict": payload.get("verdict"), "threat_count": payload.get("threat_count", len(threats)),
        "signatures": sorted({str(t.get("signature_name", "")) for t in threats})[:5],
        "files_discovered": cov.get("files_discovered"), "files_scanned": cov.get("files_scanned"),
        "partitions": f"{cov.get('partitions_scanned', 0)}/{cov.get('partitions_discovered', 0)}",
        "device": {k: str(dev.get(k, "")) for k in ("vendor_id", "product_id", "serial")},
        "reason_codes": list(payload.get("reason_codes") or [])[:8],
    }
