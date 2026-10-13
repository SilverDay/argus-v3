"""Real usb-scan-events process: durability across SIGKILL, spool replay, tamper CLI."""
import asyncio
import os
import pwd
import signal
import sqlite3
import subprocess
import sys
import time
import uuid

import pytest

from src.orchestrator.event_client import EventClient
from src.shared.models import CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, Verdict, utc_now

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def setup(tmp_path):
    key = tmp_path / "checkpoint.key"
    key.write_bytes(os.urandom(32).hex().encode())
    key.chmod(0o600)
    (tmp_path / "state").mkdir()
    me = pwd.getpwuid(os.getuid()).pw_name
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"""
station: {{station_id: it-station}}
logging: {{file: ''}}
events:
  db_path: {tmp_path}/events.db
  socket_path: {tmp_path}/events.sock
  socket_group: {me}
  writer_users: [{me}]
  reader_users: []
  hmac_key_ref: file:{key}
""")
    procs = []

    def start():
        p = subprocess.Popen([sys.executable, "-m", "src.events", "--config", str(cfg)], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procs.append(p)
        for _ in range(200):
            if os.path.exists(tmp_path / "events.sock"):
                return p
            time.sleep(0.02)
        p.kill()
        raise AssertionError(p.communicate()[0])

    def cli(*args):
        return subprocess.run([sys.executable, "-m", "src.events", "--config", str(cfg), *args], cwd=ROOT,
                              capture_output=True, text=True, timeout=30)

    yield {"tmp": tmp_path, "start": start, "cli": cli}
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.communicate()                             # reaps and closes the stdout pipe


def result():
    return ScanResult(ScanMetadata(str(uuid.uuid4()), "it-station", "1-1", utc_now()), Verdict.THREAT,
                      CoverageMetrics())


async def wait_for(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if await cond():
            return True
        await asyncio.sleep(0.05)
    return False


async def test_sigkill_spool_replay_and_tamper_cli(setup):
    tmp = setup["tmp"]
    svc = setup["start"]()
    client = EventClient(str(tmp / "events.sock"), str(tmp / "state"), retry_interval=0.1)
    await client.publish(ScanEvent(EventType.SCAN_STARTED, "s1", {"n": 1}))
    await client.commit_result(result(), {"serial": "S"})
    status = (await client.request({"op": "status"}))["status"]
    assert status["head_seq"] >= 3                   # start-up checkpoint + 2 events

    svc.send_signal(signal.SIGKILL)                  # power-loss-like stop of the service
    svc.wait()
    await client.publish(ScanEvent(EventType.LIFECYCLE_CHANGED, "s1", {"n": 2}))
    await client.commit_result(result(), {})         # returns: durable in the spool
    assert client.spool_pending()
    assert "event_store_unavailable" in await client.health_failures()

    setup["start"]()
    assert await wait_for(lambda: _done(client))
    recent = (await client.request({"op": "recent", "limit": 50, "after_seq": 0}))["events"]
    types = [e["event_type"] for e in recent if e["event_type"] != "audit_checkpoint"]
    assert types == ["scan_started", "verdict", "lifecycle_changed", "verdict"]
    assert await client.health_failures() == []
    await client.close()

    assert setup["cli"]("--verify").returncode == 0
    db = sqlite3.connect(str(tmp / "events.db"), isolation_level=None)
    db.execute("UPDATE events SET payload='{\"n\":9}' WHERE event_type='scan_started'")
    db.close()
    bad = setup["cli"]("--verify")
    assert bad.returncode == 1 and "modified" in bad.stdout


async def _done(client):
    return not client.spool_pending()


async def test_tamper_blocks_readiness_until_acknowledged(setup):
    tmp = setup["tmp"]
    svc = setup["start"]()
    client = EventClient(str(tmp / "events.sock"), str(tmp / "state"))
    await client.commit_result(result(), {})
    svc.terminate()
    svc.wait(10)
    db = sqlite3.connect(str(tmp / "events.db"), isolation_level=None)
    db.execute("DELETE FROM events WHERE event_type='verdict'")
    db.close()
    setup["start"]()
    assert await client.health_failures() == ["audit_chain_broken"]
    ack = setup["cli"]("--acknowledge-tamper", "verified against SIEM copy")
    assert ack.returncode == 0, ack.stdout + ack.stderr
    assert await client.health_failures() == []
    recent = (await client.request({"op": "recent", "limit": 10}))["events"]
    assert {"tamper_detected", "tamper_acknowledged"} <= {e["event_type"] for e in recent}
    await client.close()
