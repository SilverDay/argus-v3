import asyncio
import json
import os
import uuid

import pytest

from src.events.server import EventsServer
from src.events.store import EventStore
from src.orchestrator.event_sink import verdict_event
from src.shared import events_protocol as proto
from src.shared.models import (
    CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, Severity, ThreatEntry, Verdict, utc_now,
)

ME = os.getuid()


def verdict(v=Verdict.CLEAN, sigs=(), serial="S1"):
    threats = [ThreatEntry(f"part1/f{i}", "clamav", s, "a" * 64, Severity.HIGH) for i, s in enumerate(sigs)]
    r = ScanResult(ScanMetadata(str(uuid.uuid4()), "station-001", "1-1", utc_now()), v,
                   CoverageMetrics(files_discovered=3, files_scanned=3, partitions_discovered=1,
                                   partitions_scanned=1), threats)
    return verdict_event(r, {"vendor_id": "0781", "product_id": "5583", "serial": serial})


@pytest.fixture
def store(tmp_path):
    now = [1_800_000_000.0]
    s = EventStore(str(tmp_path / "e.db"), "station-001", clock=lambda: now[0])
    s.now = now
    yield s
    s.close()


def test_scan_history_filters_and_paging(store):
    store.append(verdict())
    store.now[0] += 86_400
    store.append(verdict(Verdict.THREAT, ["Win.A", "Win.B"], serial="S2"))
    store.append(ScanEvent(EventType.SCAN_STARTED, "x", {}))
    store.append(verdict(Verdict.SUSPICIOUS, ["Heur.X"]))
    rows = store.scans()
    assert [r["verdict"] for r in rows] == ["SUSPICIOUS", "THREAT", "CLEAN"]
    assert rows[1]["threat_count"] == 2 and rows[1]["signatures"] == ["Win.A", "Win.B"]
    assert rows[1]["device"]["serial"] == "S2" and rows[0]["partitions"] == "1/1"
    assert [r["verdict"] for r in store.scans(verdicts=["THREAT", "CLEAN"])] == ["THREAT", "CLEAN"]
    assert [r["verdict"] for r in store.scans(serial="S2")] == ["THREAT"]
    assert [r["verdict"] for r in store.scans(since=1_800_000_000 + 3600)] == ["SUSPICIOUS", "THREAT"]
    assert [r["verdict"] for r in store.scans(until=1_800_000_000 + 3600)] == ["CLEAN"]
    page1 = store.scans(limit=2)
    page2 = store.scans(limit=2, before_seq=page1[-1]["seq"])
    assert [r["verdict"] for r in page2] == ["CLEAN"]


def test_stats(store):
    store.append(verdict(Verdict.THREAT, ["Win.A", "Win.A", "Win.B"]))
    store.append(verdict())
    store.now[0] += 86_400
    store.append(verdict(Verdict.THREAT, ["Win.A"]))
    st = store.stats(30)
    assert [d["scans"] for d in st["per_day"]] == [2, 1]
    assert st["per_day"][0]["threats"] == 3 and st["per_day"][0]["verdicts"] == {"CLEAN": 1, "THREAT": 1}
    assert st["top_signatures"][0] == {"signature": "Win.A", "count": 3}


@pytest.fixture
async def server(tmp_path, store):
    srv = EventsServer(store, str(tmp_path / "s.sock"), writer_uids=set(), reader_uids=set(), web_uids={ME})
    await srv.start()
    yield srv
    await srv.close()


async def req(srv, obj):
    reader, writer = await asyncio.open_unix_connection(srv.path, limit=proto.MAX_LINE_BYTES)
    writer.write(proto.encode(obj))
    line = await reader.readline()
    writer.close()
    return json.loads(line)


async def test_web_role_may_only_append_web_audit(server, store):
    ok = ScanEvent(EventType.WEB_AUTH, None, {"result": "success", "user": "alice"})
    assert (await req(server, {"op": "append", "event": ok.to_dict()}))["ok"]
    for forged in (EventType.VERDICT, EventType.AUTH_RESULT, EventType.HEALTH):
        r = await req(server, {"op": "append", "event": ScanEvent(forged, None, {}).to_dict()})
        assert r == {"ok": False, "error": proto.E_FORBIDDEN}, forged


async def test_orchestrator_cannot_forge_web_audit(tmp_path, store):
    srv = EventsServer(store, str(tmp_path / "w.sock"), writer_uids={ME}, reader_uids=set())
    await srv.start()
    r = await req(srv, {"op": "append", "event": ScanEvent(EventType.WEB_ACCESS, None, {}).to_dict()})
    assert r == {"ok": False, "error": proto.E_FORBIDDEN}
    await srv.close()


async def test_query_ops(server, store):
    store.append(verdict(Verdict.THREAT, ["Win.A"]))
    store.append(ScanEvent(EventType.HEALTH, None, {"passed": True, "details": {"clamav_db_version": 1}}))
    scans = (await req(server, {"op": "scans", "verdicts": ["THREAT"], "limit": 10}))["scans"]
    assert len(scans) == 1
    full = (await req(server, {"op": "scan", "seq": scans[0]["seq"]}))["event"]
    assert full["payload"]["threats"][0]["signature_name"] == "Win.A"
    assert (await req(server, {"op": "scan", "seq": 2}))["event"] is None          # not a verdict
    assert (await req(server, {"op": "last_health"}))["event"]["payload"]["passed"] is True
    assert (await req(server, {"op": "stats", "days": 7}))["stats"]["top_signatures"][0]["signature"] == "Win.A"
    page = (await req(server, {"op": "page", "types": ["health"], "limit": 5}))["events"]
    assert [e["event_type"] for e in page] == ["health"]
    for bad in ({"op": "scans", "limit": -1}, {"op": "scans", "verdicts": "THREAT"}, {"op": "scans", "since": "x"},
                {"op": "scan", "seq": True}, {"op": "scans", "serial": "x" * 200}):
        assert (await req(server, bad)) == {"ok": False, "error": proto.E_BAD_REQUEST}, bad
