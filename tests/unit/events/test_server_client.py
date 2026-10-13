import asyncio
import json
import os
import uuid

import pytest

from src.events.server import EventsServer
from src.events.store import EventStore
from src.orchestrator.event_client import EventClient, SpoolFull
from src.shared import events_protocol as proto
from src.shared.models import (
    CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, Verdict, utc_now,
)

ME = os.getuid()


@pytest.fixture
def paths(tmp_path):
    (tmp_path / "state").mkdir()
    return {"db": str(tmp_path / "events.db"), "sock": str(tmp_path / "events.sock"),
            "state": str(tmp_path / "state")}


@pytest.fixture
async def server(paths):
    store = EventStore(paths["db"], "station-001")
    srv = EventsServer(store, paths["sock"], writer_uids={ME}, reader_uids=set())
    await srv.start()
    yield srv
    await srv.close()
    store.close()


async def raw_request(path, obj):
    reader, writer = await asyncio.open_unix_connection(path, limit=proto.MAX_LINE_BYTES)
    writer.write(proto.encode(obj) if isinstance(obj, dict) else obj)
    line = await reader.readline()
    writer.close()
    return json.loads(line) if line else None


def result(verdict=Verdict.CLEAN):
    return ScanResult(ScanMetadata(str(uuid.uuid4()), "station-001", "1-1", utc_now()), verdict, CoverageMetrics())


# --- server ------------------------------------------------------------------------------

async def test_append_query_and_socket_mode(server, paths):
    ev = ScanEvent(EventType.SCAN_STARTED, "s1", {"port": "1-1"})
    r = await raw_request(paths["sock"], {"op": "append", "event": ev.to_dict()})
    assert r == {"ok": True, "seq": 1, "duplicate": False}
    assert (await raw_request(paths["sock"], {"op": "append", "event": ev.to_dict()}))["duplicate"] is True
    recent = await raw_request(paths["sock"], {"op": "recent", "limit": 10})
    assert [e["event_type"] for e in recent["events"]] == ["scan_started"]
    status = (await raw_request(paths["sock"], {"op": "status"}))["status"]
    assert status["head_seq"] == 1 and status["tamper"] is None and status["store_full"] is False
    assert os.stat(paths["sock"]).st_mode & 0o777 == 0o660


@pytest.mark.parametrize("req,error", [
    (b"not json\n", proto.E_BAD_REQUEST),
    ({"op": "drop_table"}, proto.E_BAD_REQUEST),
    ({"op": "append", "event": {"event_type": "verdict"}}, proto.E_INVALID_EVENT),
    ({"op": "append", "event": ScanEvent(EventType.AUDIT_CHECKPOINT, None, {}).to_dict()}, proto.E_FORBIDDEN),
    ({"op": "append", "event": ScanEvent(EventType.TAMPER_ACKNOWLEDGED, None, {}).to_dict()}, proto.E_FORBIDDEN),
    ({"op": "recent", "limit": "all"}, proto.E_BAD_REQUEST),
])
async def test_bad_requests_rejected(server, paths, req, error):
    assert await raw_request(paths["sock"], req) == {"ok": False, "error": error}


async def test_reader_cannot_append_and_strangers_are_dropped(paths):
    store = EventStore(paths["db"], "station-001")
    srv = EventsServer(store, paths["sock"], writer_uids=set(), reader_uids={ME})
    await srv.start()
    ev = ScanEvent(EventType.SCAN_STARTED, "s1", {})
    assert await raw_request(paths["sock"], {"op": "append", "event": ev.to_dict()}) == \
        {"ok": False, "error": proto.E_FORBIDDEN}
    assert (await raw_request(paths["sock"], {"op": "ping"}))["ok"]
    await srv.close()
    srv2 = EventsServer(store, paths["sock"], writer_uids=set(), reader_uids=set())
    await srv2.start()
    try:                                                                    # closed without an answer
        assert await raw_request(paths["sock"], {"op": "ping"}) is None
    except ConnectionResetError:
        pass
    await srv2.close()
    store.close()


async def test_store_full_is_reported(paths):
    store = EventStore(paths["db"], "station-001", min_free_mb=10 ** 9)
    srv = EventsServer(store, paths["sock"], writer_uids={ME}, reader_uids=set())
    await srv.start()
    ev = ScanEvent(EventType.SCAN_STARTED, "s1", {})
    assert await raw_request(paths["sock"], {"op": "append", "event": ev.to_dict()}) == \
        {"ok": False, "error": proto.E_STORE_FULL}
    await srv.close()
    store.close()


# --- orchestrator client --------------------------------------------------------------------

async def test_client_commit_is_acknowledged_in_order(server, paths):
    c = EventClient(paths["sock"], paths["state"])
    await c.publish(ScanEvent(EventType.SCAN_STARTED, "s1", {}))
    await c.publish(ScanEvent(EventType.SCAN_PROGRESS, "s1", {}))           # not an audit event
    await c.commit_result(result(Verdict.THREAT), {"serial": "S1"})
    events = server.store.recent(10)
    assert [e.event_type for e in events] == ["scan_started", "verdict"]
    assert events[1].payload["verdict"] == "THREAT" and events[1].payload["device"] == {"serial": "S1"}
    assert await c.health_failures() == []
    await c.close()


async def test_client_spools_when_service_down_and_replays_in_order(paths):
    c = EventClient(paths["sock"], paths["state"], retry_interval=0.05)
    await c.publish(ScanEvent(EventType.SCAN_STARTED, "s1", {"n": 1}))
    await c.commit_result(result(), {})                                     # durable via the spool
    assert c.spool_pending()
    assert os.stat(c.spool_path).st_mode & 0o777 == 0o600
    assert await c.health_failures() == ["event_store_unavailable"]
    store = EventStore(paths["db"], "station-001")
    srv = EventsServer(store, paths["sock"], writer_uids={ME}, reader_uids=set())
    await srv.start()
    await c.publish(ScanEvent(EventType.LIFECYCLE_CHANGED, "s1", {"n": 3}))  # must come after the spool
    for _ in range(100):
        if store.head()[0] == 3 and not c.spool_pending():
            break
        await asyncio.sleep(0.02)
    assert [e.event_type for e in store.recent(10)] == ["scan_started", "verdict", "lifecycle_changed"]
    assert store.verify().ok
    await c.close()
    await srv.close()
    store.close()


async def test_spool_limit_fails_the_commit(paths):
    c = EventClient(paths["sock"], paths["state"], spool_max_bytes=200)
    with pytest.raises(SpoolFull):
        await c.commit_result(result(), {"serial": "x" * 500})
    await c.close()


async def test_client_reports_tamper(server, paths):
    from src.events.store import VerifyResult
    server.store.set_tamper(VerifyResult(False, 0, 3, "modified"))
    c = EventClient(paths["sock"], paths["state"])
    assert await c.health_failures() == ["audit_chain_broken"]
    await c.close()


async def test_huge_verdict_is_bounded_not_wedged(server, paths):
    """20 000 detections: the record is cut to the byte budget, never spooled forever."""
    from src.shared.models import ThreatEntry
    threats = [ThreatEntry(f"part1/dir/file{i:06d}.exe", "clamav", "Win.Test.Evil", "a" * 64) for i in range(20000)]
    big = result(Verdict.THREAT)
    big.threats = threats
    big.policy_violations = [f"blocked_extension:exe:part1/x{i}.exe" for i in range(20000)]
    c = EventClient(paths["sock"], paths["state"])
    await c.commit_result(big, {})
    assert not c.spool_pending()
    stored = server.store.last_of_type(EventType.VERDICT).payload
    assert stored["verdict"] == "THREAT" and stored["threat_count"] == 20000 and stored["truncated"] is True
    assert 0 < len(stored["threats"]) < 20000 and stored["policy_violation_count"] == 20000
    assert await c.health_failures() == []
    await c.close()


async def test_oversized_event_is_rejected_not_spooled(paths):
    c = EventClient(paths["sock"], paths["state"])          # service not even running
    await c.publish(ScanEvent(EventType.SCAN_STARTED, "s1", {"blob": "x" * (2 * 1024 * 1024)}))
    await c.commit_result(result(), {})                     # later events are unaffected (spooled)
    assert c.spool_pending()
    with open(c.spool_path) as fh:
        assert "blob" not in fh.read()
    await c.close()
