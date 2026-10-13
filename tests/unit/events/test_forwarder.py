import asyncio
import json
import os
import re
import shutil
import subprocess

import httpx
import pytest

from src.events.alerting import Pseudonymizer, WebhookChannel
from src.events.forwarder import (
    SIEM, Forwarder, SiemSyslogSender, SiemWebhookSender, alert_sender, client_tls_context, envelope, sanitize,
)
from src.events.server import EventsServer
from src.events.service import EventsService, acknowledge_tamper, make_router
from src.events.store import EventStore
from src.orchestrator.event_client import EventClient
from src.shared.config import FilenamePrivacy, load_config_from_dict
from src.shared.models import EventType, ScanEvent
from tests.unit.orchestrator.conftest import make_cfg
from tests.unit.orchestrator.test_orchestrator import ADD, run_scan, start

PLAIN = Pseudonymizer(FilenamePrivacy.PLAIN, None)
HASHED = Pseudonymizer(FilenamePrivacy.HASH, b"k")


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def store(tmp_path):
    clock = Clock()
    s = EventStore(str(tmp_path / "events.db"), "station-001", clock=clock,
                   router=lambda t, p: [SIEM] + (["alert:webhook"] if t is EventType.VERDICT else []))
    s.clock_ref = clock
    yield s
    s.close()


# --- retry / ordering / dead letter --------------------------------------------------------------

async def test_backoff_ordering_and_recovery(store):
    sent, fail = [], [2]

    async def sender(ev):
        if fail[0]:
            fail[0] -= 1
            raise ConnectionRefusedError("down")
        sent.append(ev.seq)

    store.append(ScanEvent(EventType.SCAN_STARTED, "s", {}))
    store.append(ScanEvent(EventType.LIFECYCLE_CHANGED, "s", {}))
    clock = store.clock_ref
    f = Forwarder(store, {SIEM: sender}, max_attempts=10, backoff_initial=5, backoff_max=600, clock=clock)
    assert await f.step(SIEM) is False                          # attempt 1 fails
    d, due = store.next_delivery(SIEM)
    assert d.event.seq == 1 and d.attempts == 1 and due == clock.t + 5
    assert await f.step(SIEM) is False and sent == []           # not due yet: seq 2 must wait too
    clock.t += 5
    assert await f.step(SIEM) is False                          # attempt 2 fails, backoff doubles
    assert store.next_delivery(SIEM)[1] == clock.t + 10
    clock.t += 10
    assert await f.step(SIEM) and await f.step(SIEM)
    assert sent == [1, 2] and store.queue_stats()[SIEM]["delivered"] == 2
    assert [f.backoff(n) for n in (1, 2, 3, 10, 20)] == [5, 10, 20, 600, 600]


async def test_dead_letter_records_alert_outcome(store, caplog):
    async def broken(ev):
        raise RuntimeError("http_500")

    store.append(ScanEvent(EventType.VERDICT, "s", {"verdict": "THREAT"}))
    f = Forwarder(store, {"alert:webhook": broken, SIEM: broken}, max_attempts=2, backoff_initial=1, clock=store.clock_ref)
    await f.step("alert:webhook")
    store.clock_ref.t += 1
    assert await f.step("alert:webhook") is True                 # dead-lettered, queue moves on
    assert store.queue_stats()["alert:webhook"]["dead"] == 1
    (rec,) = [e for e in store.recent(10) if e.event_type == "alert_delivery"]
    assert rec.payload == {"channel": "alert:webhook", "status": "dead:http_500", "event_seq": 1,
                           "event_type": "verdict"}
    assert "DEAD LETTER alert:webhook seq=1" in caplog.text
    await f.step(SIEM)
    store.clock_ref.t += 1
    await f.step(SIEM)                                           # SIEM failures never create events
    assert len([e for e in store.recent(20) if e.event_type == "alert_delivery"]) == 1


async def test_run_loop_wakes_on_new_events(store):
    got = []

    async def sender(ev):
        got.append(ev.seq)

    f = Forwarder(store, {SIEM: sender}, idle_wait=30)
    f.start()
    store.append(ScanEvent(EventType.SCAN_STARTED, "s", {}))
    f.wake()
    for _ in range(100):
        if got:
            break
        await asyncio.sleep(0.01)
    await f.stop()
    assert got == [1]


# --- SIEM formatting / privacy -------------------------------------------------------------------

def test_sanitize_paths_and_serials():
    payload = {"threats": [{"file_path": "part1/hr/salary.xlsx", "sha256": "a" * 64}],
               "policy_violations": ["blocked_extension:exe:part1/tools/x.exe", "weird"],
               "device": {"serial": "SER123", "vendor_id": "0781"}, "verdict": "THREAT"}
    out = sanitize(payload, HASHED)
    text = json.dumps(out)
    assert "salary" not in text and "SER123" not in text and "x.exe" not in text
    assert out["threats"][0]["sha256"] == "a" * 64 and out["device"]["vendor_id"] == "0781"
    assert re.fullmatch(r"blocked_extension:exe:hmac:[0-9a-f]{32}", out["policy_violations"][0])
    assert out["policy_violations"][1] == "omitted"
    assert sanitize(payload, PLAIN) == payload


async def test_siem_syslog_persistent_connection_and_reconnect(store):
    conns = []

    class Writer:
        def __init__(self):
            self.data, self.closed, self.fail = [], False, False

        def write(self, d):
            if self.fail:
                raise ConnectionResetError
            self.data.append(d)

        async def drain(self):
            pass

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    async def connect(host, port, ssl=None, server_hostname=None):
        assert server_hostname == "siem.example.org" and ssl is not None
        w = Writer()
        conns.append(w)
        return None, w

    cfg = load_config_from_dict({"events": {"forwarding": {"enabled": True, "host": "siem.example.org"}}})
    sender = SiemSyslogSender(cfg.events.forwarding, PLAIN, connect=connect)
    store.append(ScanEvent(EventType.SCAN_STARTED, "s", {}))
    store.append(ScanEvent(EventType.SCAN_STARTED, "s", {}))
    await sender(store.get(1))
    await sender(store.get(2))
    assert len(conns) == 1 and len(conns[0].data) == 2           # one TLS connection reused
    length, _, msg = conns[0].data[0].partition(b" ")
    assert int(length) == len(msg) and b" EVENT - " in msg
    body = json.loads(msg.split(b" EVENT - ", 1)[1])
    assert body["seq"] == 1 and body["hash"] == store.get(1).hash and body["station_id"] == "station-001"
    conns[0].fail = True
    with pytest.raises(ConnectionResetError):
        await sender(store.get(2))
    assert conns[0].closed
    await sender(store.get(2))                                    # reconnects
    assert len(conns) == 2


async def test_siem_webhook_envelope(store):
    seen = []
    cfg = load_config_from_dict({"events": {"forwarding": {"enabled": True, "transport": "webhook",
                                                           "url": "https://collector.example.org/in"}}})
    sender = SiemWebhookSender(cfg.events.forwarding, PLAIN, "tok", transport=httpx.MockTransport(
        lambda r: (seen.append(r), httpx.Response(202))[1]))
    store.append(ScanEvent(EventType.SCAN_STARTED, "s", {"port": "1-1"}))
    await sender(store.get(1))
    body = json.loads(seen[0].content)
    assert body == envelope(store.get(1), PLAIN) and seen[0].headers["authorization"] == "Bearer tok"
    await sender.aclose()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
def test_mtls_client_identity_loaded(tmp_path):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k.pem"),
                    "-out", str(tmp_path / "c.pem"), "-days", "1", "-subj", "/CN=station-001"],
                   check=True, capture_output=True)
    os.chmod(tmp_path / "k.pem", 0o600)
    cfg = load_config_from_dict({"events": {"forwarding": {
        "enabled": True, "host": "siem.example.org", "client_cert_file": str(tmp_path / "c.pem"),
        "client_key_ref": f"file:{tmp_path / 'k.pem'}"}}})
    ctx = client_tls_context(cfg.events.forwarding)
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    os.chmod(tmp_path / "k.pem", 0o644)                          # world-readable key is refused
    from src.shared.secret_refs import SecretError
    with pytest.raises(SecretError):
        client_tls_context(cfg.events.forwarding)


# --- service ------------------------------------------------------------------------------

def service_cfg(tmp_path, **events):
    return load_config_from_dict({"events": {"db_path": str(tmp_path / "events.db"),
                                             "socket_path": str(tmp_path / "events.sock"), **events}})


async def test_service_checkpoints_and_detects_tamper_on_start(tmp_path):
    import sqlite3
    cfg = service_cfg(tmp_path)
    key = b"k" * 32
    svc = EventsService(cfg, key, lambda ref: b"", writer_uids=frozenset({os.getuid()}),
                        reader_uids=frozenset(), group_gid=None)
    await svc.start()
    await asyncio.sleep(0.05)
    assert svc.store.last_of_type(EventType.AUDIT_CHECKPOINT) is not None     # first checkpoint at start
    svc.store.append(ScanEvent(EventType.SCAN_STARTED, "s", {"n": 1}))
    await svc.close()

    db = sqlite3.connect(str(tmp_path / "events.db"), isolation_level=None)
    db.execute("UPDATE events SET payload='{\"n\":2}' WHERE event_type='scan_started'")
    db.close()
    svc2 = EventsService(cfg, key, lambda ref: b"", writer_uids=frozenset(), reader_uids=frozenset(),
                         group_gid=None)
    await svc2.start()
    tamper = svc2.store.tamper_state()
    assert tamper["reason"] == "modified"
    assert svc2.store.last_of_type(EventType.TAMPER_DETECTED).payload["reason"] == "modified"
    acknowledge_tamper(svc2.store, "admin", "restored from backup")
    assert svc2.store.tamper_state() is None and svc2.store.verify().ok
    await svc2.close()
    with pytest.raises(ValueError):
        EventsService(cfg, b"short", lambda ref: b"", writer_uids=frozenset(), reader_uids=frozenset(),
                      group_gid=None)


def test_router():
    cfg = load_config_from_dict({"events": {"forwarding": {"enabled": True, "host": "siem.example.org"}},
                                 "alerts": {"verdicts": ["THREAT"],
                                            "webhook": {"enabled": True, "url": "https://h.example/x"}}})
    route = make_router(cfg)
    assert route(EventType.VERDICT, {"verdict": "THREAT"}) == ["siem", "alert:webhook"]
    assert route(EventType.VERDICT, {"verdict": "CLEAN"}) == ["siem"]
    assert route(EventType.ALERT_DELIVERY, {}) == ["siem"]
    assert make_router(load_config_from_dict({}))(EventType.VERDICT, {"verdict": "THREAT"}) == []


# --- end to end: scan -> events service -> durable webhook alert ------------------------------------

async def test_threat_scan_alert_delivered_through_events_service(harness, env):
    """Plan acceptance (Phase 7, now via Phase 8): malware scan -> webhook POSTed with THREAT."""
    (env["part1"] / "eicar.com").write_bytes(b"..EVIL..")
    sock = str(env["tmp"] / "events.sock")
    cfg = make_cfg(env, alerts={"webhook": {"enabled": True, "url": "https://soc.example.org/hook"}})
    store = EventStore(str(env["tmp"] / "events.db"), "station-001", router=make_router(cfg))
    posts = []
    hook = WebhookChannel(cfg.alerts.webhook, "tok", transport=httpx.MockTransport(
        lambda r: (posts.append(json.loads(r.content)), httpx.Response(200))[1]))
    fwd = Forwarder(store, {"alert:webhook": alert_sender(hook, HASHED)})
    srv = EventsServer(store, sock, writer_uids={os.getuid()}, reader_uids=set(), on_append=fwd.wake)
    await srv.start()
    fwd.start()
    (env["tmp"] / "state").mkdir()
    client = EventClient(sock, str(env["tmp"] / "state"))
    orch, *_ = harness({"alerts": {"webhook": {"enabled": True, "url": "https://soc.example.org/hook"}}})
    orch.sink = client
    await start(orch)
    await run_scan(orch, ADD)
    for _ in range(200):
        if posts:
            break
        await asyncio.sleep(0.01)
    (alert,) = posts
    assert alert["verdict"] == "THREAT" and alert["threats"][0]["signature"] == "Win.Test.Evil"
    assert "eicar" not in json.dumps(alert) and alert["device"]["serial"].startswith("hmac:")
    types = [e.event_type for e in store.recent(100)]
    assert "verdict" in types and types.index("scan_started") < types.index("verdict")
    assert store.verify().ok
    for _ in range(100):
        if "alert_delivery" in [e.event_type for e in store.recent(100)]:
            break
        await asyncio.sleep(0.01)
    assert store.last_of_type(EventType.ALERT_DELIVERY).payload["status"] == "delivered"
    await client.close()
    await fwd.aclose()
    await srv.close()
    store.close()
