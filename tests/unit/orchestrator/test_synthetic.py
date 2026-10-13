"""Synthetic EICAR scan (spec §3.8, AC-F05)."""
import asyncio
import json
import os

from src.orchestrator.synthetic import EICAR
from src.shared.models import EventType, GUIState
from tests.unit.orchestrator.fakes import FakeClamd, FakeYaraClient
from tests.unit.orchestrator.test_orchestrator import ADD, of_type, start


def stored(sink, event_type):
    with open(sink.events_path) as fh:
        rows = [json.loads(line) for line in fh]
    return [r["payload"] for r in rows if r["event_type"] == event_type.value]


def test_eicar_constant_is_the_standard_68_byte_string():
    assert len(EICAR) == 68
    assert EICAR.startswith(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$") and EICAR.endswith(b"$H+H*")


async def test_synthetic_scan_passes_and_is_logged(harness, env):
    orch, broker, clamd, events, sink = harness()
    await start(orch)
    payload = await orch.run_synthetic("manual")
    assert payload["passed"] is True
    assert payload["verdict"] == "THREAT" and payload["expected_verdict"] == "THREAT"
    assert payload["clamav"] == {"test_file": "found", "signature": "Win.Test.EICAR_HDB-1", "control_file": "clean"}
    assert payload["coverage"]["files_scanned"] == 2 and payload["coverage"]["clamav_complete"] is True
    assert payload["trigger"] == "manual" and "yara" not in payload
    assert of_type(events, EventType.SYNTHETIC_SCAN) == [payload]
    assert stored(sink, EventType.SYNTHETIC_SCAN) == [payload]     # durable event log
    assert broker.calls == []                                      # no device path involved
    workdir = os.path.join(orch.cfg.orchestrator.state_dir, "synthetic")
    assert os.listdir(workdir) == []                               # fixture removed
    assert orch.state is GUIState.IDLE and not of_type(events, EventType.VERDICT)


async def test_missed_detection_fails_closed_until_a_later_pass(harness):
    clamd = FakeClamd()
    clamd.detect_eicar = False
    orch, _, _, events, _ = harness(clamd=clamd)
    await start(orch)
    payload = await orch.run_synthetic("schedule")
    assert payload["passed"] is False and payload["verdict"] == "CLEAN"
    assert orch.state is GUIState.NOT_READY
    assert "synthetic_scan_failed" in orch.health.failures
    assert of_type(events, EventType.HEALTH_GATE_FAILED)[-1]["failures"] == ["synthetic_scan_failed"]
    # a later health check alone does not clear it
    await orch.check_health()
    assert orch.state is GUIState.NOT_READY
    clamd.detect_eicar = True
    assert (await orch.run_synthetic("schedule"))["passed"] is True
    assert orch.state is GUIState.IDLE and orch.health.failures == []


async def test_clamd_error_on_fixture_fails(harness):
    class Broken(FakeClamd):
        async def scan_fd(self, fd, timeout):
            from src.orchestrator.scanner_clamav import ClamResult, ClamStatus
            return ClamResult(ClamStatus.ERROR, "Can't allocate memory")
    orch, *_ = harness(clamd=Broken())
    await start(orch)
    payload = await orch.run_synthetic("manual")
    assert payload["passed"] is False and payload["verdict"] == "INCOMPLETE"
    assert payload["coverage"]["files_failed"] == 2
    assert orch.state is GUIState.NOT_READY


async def test_not_run_while_busy_or_other_gate_failing(harness):
    orch, _, clamd, events, _ = harness()
    await start(orch)
    clamd.gate = asyncio.Event()                  # hold the device scan in SCANNING
    await orch.on_usb_event(ADD)
    for _ in range(100):
        if orch.state is GUIState.SCANNING:
            break
        await asyncio.sleep(0.01)
    assert await orch.run_synthetic("manual") is None
    clamd.gate.set()
    await asyncio.wait_for(orch.active.task, 10)

    orch2, _, clamd2, events2, _ = harness()
    clamd2.alive = False
    await orch2.check_health()
    assert await orch2.run_synthetic("manual") is None     # clamav_unavailable already reported
    assert not of_type(events2, EventType.SYNTHETIC_SCAN)


async def test_yara_results_recorded_not_asserted(harness):
    orch, *_, events, _ = harness({"yara": {"enabled": True, "role": "mandatory"}})
    orch.yara = FakeYaraClient()
    await start(orch)
    payload = await orch.run_synthetic("manual")
    assert payload["passed"] is True
    assert payload["yara"]["test_file"] == "clean" and payload["yara"]["control_file"] == "clean"
    assert payload["coverage"]["yara_complete"] is True


async def test_loop_runs_at_startup_and_on_request(harness):
    orch, *_, events, _ = harness({"health": {"synthetic_scan_interval_hours": 0}})
    await start(orch)
    request = asyncio.Event()
    task = asyncio.create_task(orch.synthetic_loop(request))
    try:
        for _ in range(200):
            if of_type(events, EventType.SYNTHETIC_SCAN):
                break
            await asyncio.sleep(0.01)
        assert [p["trigger"] for p in of_type(events, EventType.SYNTHETIC_SCAN)] == ["startup"]
        request.set()
        for _ in range(200):
            if len(of_type(events, EventType.SYNTHETIC_SCAN)) == 2:
                break
            await asyncio.sleep(0.01)
        assert [p["trigger"] for p in of_type(events, EventType.SYNTHETIC_SCAN)] == ["startup", "manual"]
    finally:
        task.cancel()
