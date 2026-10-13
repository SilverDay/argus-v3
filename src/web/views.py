"""Read-only admin views (owner decision, Phase 9: no privileged actions from the web UI).

Access matrix (roles are cumulative: viewer < operator < admin):
  viewer    dashboard, live status, statistics, configuration (secret values are never
            loaded; secret fields hold references only)
  operator  + scan history, scan details, CSV/JSON export
  admin     + audit log, file paths and device serial numbers
File paths and serials are personal/sensitive data (spec §3.7) and are shown to admins only.
Data views are access-audited (``web_access``); the 5-second status poll is not.
"""
from __future__ import annotations

import csv
import dataclasses
import io
import json
import shutil
import time
import urllib.parse
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import yaml
from flask import Blueprint, Response, abort, current_app, g, render_template, request, stream_with_context

from src.shared.models import Verdict
from src.shared.scan_summary import scan_summary
from src.shared.version import VERSION

from .events_client import EventsUnavailable
from .security import has_role, require_role

bp = Blueprint("views", __name__)
AUDIT_TYPES = ["web_auth", "web_access", "auth_result", "tamper_detected", "tamper_acknowledged",
               "audit_checkpoint", "alert_delivery", "health_gate_failed", "scan_interrupted",
               "synthetic_scan"]
VERDICTS = [v.value for v in Verdict]
PAGE = 50
EXPORT_MAX_ROWS = 100_000
_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _st():
    return current_app.extensions["usbscan"]


def audited(fn):
    """Mark a view for ``web_access`` auditing (done in after_request, fail closed)."""
    fn.audited = True
    return fn


def _events(op: str, **args: Any) -> dict[str, Any]:
    try:
        return _st().events.query(op, **args)
    except EventsUnavailable:
        abort(503)


# --- dashboard ---------------------------------------------------------------------------------

def _cpu_temp() -> float | None:
    try:
        with open(_st().cfg.orchestrator.thermal_zone_path) as fh:
            return round(int(fh.read().strip()) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def _disk() -> dict[str, Any] | None:
    try:
        du = shutil.disk_usage(_st().cfg.station.data_dir)
    except OSError:
        return None
    return {"free_mb": du.free // 2**20, "total_mb": du.total // 2**20,
            "used_pct": round(100 * (du.total - du.free) / du.total, 1) if du.total else None}


def _status_context() -> dict[str, Any]:
    ctx: dict[str, Any] = {"cpu_temp": _cpu_temp(), "disk": _disk(), "version": VERSION,
                           "station_id": _st().cfg.station.station_id, "events_ok": True}
    try:
        ev = _st().events
        last = ev.query("last_verdict")["event"]
        health = ev.query("last_health")["event"]
        ctx["events_status"] = ev.query("status")["status"]
    except EventsUnavailable:
        ctx["events_ok"] = False
        return ctx
    if last:
        ctx["last_scan"] = scan_summary(last["seq"], 0.0, last["payload"])
    if health:
        hp = health["payload"]
        details = hp.get("details") or {}
        db_time = details.get("clamav_db_time")
        ctx["health"] = {
            "passed": hp.get("passed"), "failures": hp.get("failures", []), "warnings": hp.get("warnings", []),
            "reported_utc": health["timestamp_utc"], "clamav_engine": details.get("clamav_engine"),
            "clamav_db_version": details.get("clamav_db_version"),
            "signature_age_h": round((time.time() - db_time) / 3600, 1) if isinstance(db_time, (int, float)) else None,
            "yara_rules_version": details.get("yara_rules_version"),
        }
    return ctx


@bp.get("/")
@require_role("viewer")
@audited
def dashboard() -> str:
    return render_template("dashboard.html", **_status_context())


@bp.get("/partials/status")
@require_role("viewer")
def status_partial() -> str:
    return render_template("_status.html", **_status_context())


# --- history -----------------------------------------------------------------------------------

def _day(value: str | None, end: bool = False) -> float | None:
    if not value:
        return None
    try:
        d = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        abort(400)
    return d.timestamp() + (86_400 if end else 0)


def _filters() -> dict[str, Any]:
    verdicts = [v for v in request.args.getlist("verdict") if v in VERDICTS]
    f: dict[str, Any] = {"verdicts": verdicts or None, "since": _day(request.args.get("from")),
                         "until": _day(request.args.get("to"), end=True)}
    serial = request.args.get("serial", "").strip()
    if serial and has_role("admin"):                        # serials are admin-only data
        f["serial"] = serial[:128]
    return {k: v for k, v in f.items() if v is not None}


def _redact_summary(row: dict[str, Any]) -> dict[str, Any]:
    if not has_role("admin"):
        row = {**row, "device": {**row["device"], "serial": "(hidden)" if row["device"].get("serial") else ""}}
    return row


@bp.get("/history")
@require_role("operator")
@audited
def history() -> str:
    before = request.args.get("before", "0")
    if not before.isdigit():
        abort(400)
    rows = _events("scans", limit=PAGE, before_seq=int(before), **_filters())["scans"]
    base_qs = urllib.parse.urlencode([(k, v) for k, v in request.args.items(multi=True) if k != "before"])
    return render_template("history.html", scans=[_redact_summary(r) for r in rows], verdicts=VERDICTS,
                           args=request.args, base_qs=base_qs,
                           next_before=rows[-1]["seq"] if len(rows) == PAGE else None)


@bp.get("/history/<int:seq>")
@require_role("operator")
@audited
def scan_detail(seq: int) -> str:
    ev = _events("scan", seq=seq)["event"]
    if ev is None:
        abort(404)
    p = ev["payload"]
    admin = has_role("admin")
    threats = [{"engine": t.get("engine"), "signature": t.get("signature_name"), "severity": t.get("severity"),
                "sha256": t.get("sha256"), "file": t.get("file_path") if admin else None}
               for t in p.get("threats", [])]
    violations = p.get("policy_violations", []) if admin else []
    device = dict(p.get("device") or {})
    if not admin and device.get("serial"):
        device["serial"] = "(hidden)"
    return render_template("scan_detail.html", ev=ev, p=p, threats=threats, violations=violations,
                           device=device, admin=admin)


def _csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA) else text      # CSV/formula injection guard


def _export_rows(filters: dict[str, Any]) -> Iterator[dict[str, Any]]:
    before, sent = 0, 0
    while sent < EXPORT_MAX_ROWS:
        rows = _st().events.query("scans", limit=500, before_seq=before, **filters)["scans"]
        if not rows:
            return
        for r in rows:
            yield _redact_summary(r)
        sent += len(rows)
        before = rows[-1]["seq"]


@bp.get("/history/export.<fmt>")
@require_role("operator")
@audited
def export(fmt: str) -> Response:
    if fmt not in ("csv", "json"):
        abort(404)
    filters = _filters()
    _events("ping")                                          # fail before streaming starts
    station = _st().cfg.station.station_id
    span = f"{request.args.get('from') or 'start'}_{request.args.get('to') or 'now'}"
    filename = f"scans_{station}_{span}.{fmt}"
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in filename):
        abort(400)
    cols = ["seq", "scan_id", "started_utc", "finished_utc", "verdict", "threat_count", "signatures",
            "files_discovered", "files_scanned", "partitions", "vendor_id", "product_id", "serial", "reason_codes"]

    def flat(r: dict[str, Any]) -> dict[str, Any]:
        return {**{k: r.get(k) for k in cols[:10]}, "signatures": ";".join(r["signatures"]),
                "vendor_id": r["device"]["vendor_id"], "product_id": r["device"]["product_id"],
                "serial": r["device"]["serial"], "reason_codes": ";".join(r["reason_codes"])}

    def gen_csv() -> Iterator[str]:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in _export_rows(filters):
            w.writerow([_csv_cell(v) for v in flat(r).values()])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
        yield buf.getvalue()

    def gen_json() -> Iterator[str]:
        yield '{"station_id":' + json.dumps(station) + ',"scans":['
        first = True
        for r in _export_rows(filters):
            yield ("" if first else ",") + json.dumps(flat(r))
            first = False
        yield "]}"

    body = gen_csv() if fmt == "csv" else gen_json()
    mime = "text/csv" if fmt == "csv" else "application/json"
    return Response(stream_with_context(body), mimetype=mime,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# --- statistics -------------------------------------------------------------------------------------

@bp.get("/stats")
@require_role("viewer")
@audited
def stats() -> str:
    return render_template("stats.html")


@bp.get("/api/stats")
@require_role("viewer")
def stats_api() -> Response:
    days = request.args.get("days", "30")
    if not days.isdigit() or not 1 <= int(days) <= 366:
        abort(400)
    return current_app.response_class(json.dumps(_events("stats", days=int(days))["stats"]),
                                      mimetype="application/json")


# --- configuration ------------------------------------------------------------------------------------

def _plain(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return {f.name: _plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj


@bp.get("/config")
@require_role("viewer")
@audited
def config_view() -> str:
    # Secret fields only ever hold references (file:/credential:/env:), never values.
    text = yaml.safe_dump(_plain(_st().cfg), sort_keys=False, default_flow_style=False)
    return render_template("config.html", config_text=text)


# --- audit log --------------------------------------------------------------------------------------------

@bp.get("/audit")
@require_role("admin")
@audited
def audit_log() -> str:
    before = request.args.get("before", "0")
    kind = request.args.get("type", "")
    if not before.isdigit() or (kind and kind not in AUDIT_TYPES):
        abort(400)
    events = _events("page", before_seq=int(before), limit=PAGE, types=[kind] if kind else AUDIT_TYPES)["events"]
    rows = [{"seq": e["seq"], "time": e["timestamp_utc"], "type": e["event_type"],
             "summary": json.dumps(e["payload"], sort_keys=True)[:400]} for e in events]
    return render_template("audit.html", rows=rows, types=AUDIT_TYPES, kind=kind,
                           next_before=rows[-1]["seq"] if len(rows) == PAGE else None)


def user_role() -> str:
    return g.user.role if g.get("user") else ""
