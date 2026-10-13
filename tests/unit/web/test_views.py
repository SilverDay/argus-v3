import csv
import io
import json
import uuid

import pytest

from src.orchestrator.event_sink import verdict_event
from src.shared.models import (
    CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, Severity, ThreatEntry, Verdict, utc_now,
)
from tests.unit.web.conftest import as_role, payloads

SERIAL = "4C530001230904107362"


@pytest.fixture
def seeded(events):
    threats = [ThreatEntry("part1/HR/salaries 2026.xlsm", "clamav", "=cmd|' /C calc'!A0", "a" * 64, Severity.HIGH),
               ThreatEntry("part1/tools/x.exe", "yara", "Org.Rule", "b" * 64, Severity.HIGH)]
    r = ScanResult(ScanMetadata(str(uuid.uuid4()), "station-001", "1-1", utc_now(), utc_now()), Verdict.THREAT,
                   CoverageMetrics(files_discovered=5, files_scanned=5, partitions_discovered=1, partitions_scanned=1,
                                   clamav_complete=True), threats, ["blocked_extension:exe:part1/tools/x.exe"],
                   reason_codes=["malware_detected"])
    seq_threat = events.store.append(verdict_event(r, {"vendor_id": "0781", "product_id": "5583", "serial": SERIAL})).seq
    clean = ScanResult(ScanMetadata(str(uuid.uuid4()), "station-001", "1-1", utc_now()), Verdict.CLEAN,
                       CoverageMetrics(files_discovered=1, files_scanned=1))
    seq_clean = events.store.append(verdict_event(clean, {"serial": "OTHER"})).seq
    events.store.append(ScanEvent(EventType.HEALTH, None, {"passed": True, "failures": [], "warnings": [],
                                                           "details": {"clamav_engine": "1.5.4", "clamav_db_version": 27800,
                                                                       "clamav_db_time": 1.0e9,
                                                                       "yara_rules_version": "2026.10.1"}}))
    return {"threat": seq_threat, "clean": seq_clean}


def test_dashboard(web, idp, seeded):
    app, _ = web
    html = as_role(app, idp, "viewer").get("/").get_data(as_text=True)
    assert "verdict-clean" in html and "1.5.4" in html and "27800" in html and "2026.10.1" in html  # latest scan
    assert 'hx-get="/partials/status"' in html and 'hx-trigger="every 5s"' in html
    assert SERIAL not in html and "salaries" not in html


def test_dashboard_without_events_service(web, idp, events):
    import asyncio
    app, _ = web
    c = as_role(app, idp, "viewer")
    asyncio.run_coroutine_threadsafe(events.server.close(), events.loop).result(5)
    assert "Events service unavailable" in c.get("/partials/status").get_data(as_text=True)
    asyncio.run_coroutine_threadsafe(events.server.start(), events.loop).result(5)


def test_history_and_redaction(web, idp, seeded):
    app, _ = web
    op = as_role(app, idp, "operator")
    html = op.get("/history").get_data(as_text=True)
    assert html.count("verdict-threat") >= 1 and SERIAL not in html and "(hidden)" in html
    detail = op.get(f"/history/{seeded['threat']}").get_data(as_text=True)
    assert "Org.Rule" in detail and "b" * 64 in detail
    assert "salaries" not in detail and SERIAL not in detail and "x.exe" not in detail
    admin = as_role(app, idp, "admin")
    detail = admin.get(f"/history/{seeded['threat']}").get_data(as_text=True)
    assert "salaries 2026.xlsm" in detail and SERIAL in detail and "part1/tools/x.exe" in detail
    assert admin.get("/history/99999").status_code == 404


def test_history_filters(web, idp, seeded):
    app, _ = web
    admin = as_role(app, idp, "admin")
    only_clean = admin.get("/history?verdict=CLEAN").get_data(as_text=True)
    assert "verdict-clean" in only_clean and "verdict-threat" not in only_clean
    by_serial = admin.get(f"/history?serial={SERIAL}").get_data(as_text=True)
    assert "verdict-threat" in by_serial and "verdict-clean" not in by_serial
    op = as_role(app, idp, "operator")                    # serial filter ignored for non-admins
    assert "verdict-clean" in op.get(f"/history?serial={SERIAL}").get_data(as_text=True)
    assert admin.get("/history?from=2026-13-45").status_code == 400
    assert admin.get("/history?before=abc").status_code == 400


def test_export_csv_injection_and_redaction(web, idp, seeded):
    app, _ = web
    resp = as_role(app, idp, "operator").get("/history/export.csv?from=2026-01-01")
    assert resp.status_code == 200 and resp.mimetype == "text/csv"
    assert 'filename="scans_station-001_2026-01-01_now.csv"' in resp.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(resp.get_data(as_text=True))))
    threat = next(r for r in rows if r["verdict"] == "THREAT")
    assert threat["signatures"].startswith("'=cmd")             # formula neutralised
    assert threat["serial"] == "(hidden)"
    admin_rows = list(csv.DictReader(io.StringIO(as_role(app, idp, "admin").get("/history/export.csv").get_data(as_text=True))))
    assert next(r for r in admin_rows if r["verdict"] == "THREAT")["serial"] == SERIAL


def test_export_json(web, idp, seeded):
    app, _ = web
    body = json.loads(as_role(app, idp, "admin").get("/history/export.json?verdict=THREAT").get_data(as_text=True))
    assert body["station_id"] == "station-001" and [s["verdict"] for s in body["scans"]] == ["THREAT"]


def test_stats_api(web, idp, seeded):
    app, _ = web
    c = as_role(app, idp, "viewer")
    data = c.get("/api/stats?days=7").get_json()
    assert data["per_day"][0]["scans"] == 2 and data["top_signatures"][0]["count"] == 1
    assert c.get("/api/stats?days=0").status_code == 400 and c.get("/api/stats?days=x").status_code == 400
    page = c.get("/stats").get_data(as_text=True)
    assert "vendor/chart-4.5.1.umd.min.js" in page and "stats.js" in page


def test_config_view_has_no_secret_values(web, idp):
    app, state = web
    html = as_role(app, idp, "viewer").get("/config").get_data(as_text=True)
    assert "hmac_key_ref" in html and "file:/etc/usb-scan/secrets/events-checkpoint.key" in html
    assert "client-secret" not in html                        # the resolved OIDC secret never appears


def test_audit_log_and_access_audit(web, idp, events, seeded):
    app, _ = web
    admin = as_role(app, idp, "admin")
    admin.get("/history")
    admin.get(f"/history/{seeded['threat']}")
    html = admin.get("/audit").get_data(as_text=True)
    assert "web_auth" in html and "web_access" in html
    access = payloads(events, "web_access")
    paths = [a["path"] for a in access]
    assert "/history" in paths and f"/history/{seeded['threat']}" in paths
    assert all(a["user"] == "alice" and a["role"] == "admin" for a in access)
    assert admin.get("/audit?type=bogus").status_code == 400
    filtered = admin.get("/audit?type=web_auth").get_data(as_text=True)
    assert "web_access" not in filtered.split("<tbody>")[1]
    admin.get("/partials/status")                             # polling is not access-audited
    assert "/partials/status" not in [a["path"] for a in payloads(events, "web_access")]


def test_denied_access_is_audited(web, idp, events):
    app, _ = web
    as_role(app, idp, "viewer").get("/audit")
    denied = [a for a in payloads(events, "web_access") if a["path"] == "/audit"]
    assert denied and denied[0]["status"] == 403


def test_static_assets_served(web, idp):
    app, _ = web
    c = as_role(app, idp, "viewer")
    for path in ("/static/app.css", "/static/stats.js", "/static/vendor/htmx-2.0.11.min.js",
                 "/static/vendor/chart-4.5.1.umd.min.js"):
        resp = c.get(path)
        assert resp.status_code == 200, path
        resp.close()


def test_vendored_files_match_recorded_hashes():
    import hashlib
    import pathlib
    import re
    vendor = pathlib.Path(__file__).resolve().parents[3] / "src" / "web" / "static" / "vendor"
    table = (vendor / "VENDOR.md").read_text()
    for name in ("htmx-2.0.11.min.js", "chart-4.5.1.umd.min.js"):
        recorded = re.search(re.escape(name) + r" \|.*\| ([0-9a-f]{64}) \|", table).group(1)
        assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == recorded
