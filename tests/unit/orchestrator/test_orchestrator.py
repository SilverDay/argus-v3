import asyncio
import json
import os

import pytest

from src.orchestrator.usb_monitor import UsbEvent, to_event
from src.shared.auth import AuthManager, SqliteLockoutStore, hash_pin
from src.shared.ipc import PeerCredentials
from src.shared.models import EventType, GUIState, ScanEvent
from tests.unit.orchestrator.fakes import FakeBroker, FakeClamd, make_sysfs

ADD = UsbEvent("add", "1-1", "/sys/devices/usb1/1-1")
REMOVE = UsbEvent("remove", "1-1", "/sys/devices/usb1/1-1")
GUI = PeerCredentials(1, 4242, 4242)
LED = PeerCredentials(2, 5555, 5555)


def states(events):
    return [e.payload["state"] for e in events if e.event_type is EventType.STATE_CHANGED]


def verdicts(events):
    return [e.payload for e in events if e.event_type is EventType.VERDICT]


def of_type(events, t):
    return [e.payload for e in events if e.event_type is t]


async def start(orch):
    await orch.check_health()
    assert orch.state is GUIState.IDLE, orch.health.failures


async def run_scan(orch, ev=ADD):
    await orch.on_usb_event(ev)
    await asyncio.wait_for(orch.active.task, 10)


def committed(sink):
    with open(sink.events_path) as fh:
        return [json.loads(l)["payload"] for l in fh if '"metadata"' in l]


# --- happy paths --------------------------------------------------------------

async def test_clean_scan_full_lifecycle(harness):
    orch, broker, clamd, events, sink = harness()
    await start(orch)
    await run_scan(orch)
    assert states(events)[-6:] == ["VALIDATING", "MOUNTING", "SCANNING", "EVALUATING", "EJECTING", "RESULT"]
    (v,) = verdicts(events)
    assert v["verdict"] == "CLEAN" and v["coverage"]["files_scanned"] == 2
    assert v["coverage"]["clamav_complete"] is True
    assert [c[0] for c in broker.calls] == ["enumerate", "mount", "unmount", "eject"]
    final = of_type(events, EventType.STATE_CHANGED)[-1]
    assert final["safe_to_remove"] is True
    lifecycle = [p["lifecycle"] for p in of_type(events, EventType.LIFECYCLE_CHANGED)]
    assert lifecycle == ["unmounted", "power_off_requested", "safe_to_remove"]
    assert committed(sink)[-1]["verdict"] == "CLEAN"
    assert not os.path.exists(sink.marker_path)
    # Our logical eject produces a udev remove: the result must stay on screen.
    await orch.on_usb_event(REMOVE)
    assert orch.state is GUIState.RESULT and orch.active.detached


async def test_new_insertion_after_logical_eject_starts_new_scan(harness):
    orch, *_, events, sink = harness()
    await start(orch)
    await run_scan(orch)
    await orch.on_usb_event(REMOVE)            # caused by our own eject
    first = orch.active.scan_id
    await run_scan(orch)                       # same port, next stick
    assert orch.active.scan_id != first
    assert [v["verdict"] for v in verdicts(events)] == ["CLEAN", "CLEAN"]
    assert not [p for p in of_type(events, EventType.DEVICE_REJECTED)]


async def test_coverage_metrics_complete_in_record(harness):
    """AC-F07: every required coverage field is in the committed scan record."""
    orch, *_, events, sink = harness()
    await start(orch)
    await run_scan(orch)
    cov = committed(sink)[-1]["coverage"]
    for key in ("partitions_discovered", "partitions_scanned", "partitions_excluded", "files_discovered",
                "files_scanned", "files_skipped", "files_failed", "files_uninspectable", "bytes_enumerated",
                "bytes_read", "skip_reasons", "clamav_complete", "yara_complete", "vt_complete"):
        assert key in cov
    assert cov["bytes_enumerated"] == cov["bytes_read"] == 10


async def test_threat_detected(harness, env):
    (env["part1"] / "x.exe").write_bytes(b"..EVIL..")
    orch, *_, events, sink = harness()
    await start(orch)
    await run_scan(orch)
    (v,) = verdicts(events)
    assert v["verdict"] == "THREAT"
    assert v["threats"] == [{"engine": "clamav", "signature": "Win.Test.Evil", "severity": "high"}]
    assert "x.exe" not in json.dumps(v)          # no file names on the public screen
    full = committed(sink)[-1]
    assert full["threats"][0]["file_path"] == "part1/x.exe" and len(full["threats"][0]["sha256"]) == 64


@pytest.mark.parametrize("content,reason", [(b"LIMIT", "scan_limit"), (b"ENC", "encrypted"),
                                            (b"ERR", "engine_error")])
async def test_engine_limits_make_incomplete(harness, env, content, reason):
    (env["part1"] / "c.zip").write_bytes(content)
    orch, *_, events, sink = harness()
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "INCOMPLETE"
    assert v["coverage"]["skip_reasons"] == {reason: 1}
    assert v["coverage"]["clamav_complete"] is False


async def test_heuristic_only_is_suspicious(harness, env):
    (env["part1"] / "m.doc").write_bytes(b"HEUR")
    orch, *_, events, sink = harness()
    await start(orch)
    await run_scan(orch)
    assert verdicts(events)[0]["verdict"] == "SUSPICIOUS"


async def test_blocked_extension_is_policy_violation(harness, env):
    (env["part1"] / "tool.EXE").write_bytes(b"clean")
    orch, *_, events, sink = harness({"scan": {"block_extensions": ["exe"]}})
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "SUSPICIOUS" and v["policy_violation_count"] == 1


async def test_oversized_file_skipped(harness, env):
    (env["part1"] / "big.iso").write_bytes(b"x" * (1024 * 1024 + 1))
    orch, *_, events, sink = harness({"clamav": {"max_file_size_mb": 1}})
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "INCOMPLETE" and v["coverage"]["skip_reasons"] == {"too_large_for_engine": 1}


async def test_unsupported_partition_prevents_clean(harness, env):
    """AC-F03: an uninspected partition prevents CLEAN under default policy."""
    broker = FakeBroker({"part1": str(env["part1"])}, volumes=[
        {"partition_id": "part1", "status": "supported", "fs_type": "vfat"},
        {"partition_id": "part2", "status": "encrypted", "fs_type": "crypto_LUKS"},
    ])
    orch, *_, events, sink = harness(broker=broker)
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "INCOMPLETE"
    assert v["coverage"]["partitions_discovered"] == 2 and v["coverage"]["partitions_excluded"] == 1
    assert "partition_encrypted" in v["reason_codes"]


# --- rejection ---------------------------------------------------------------

async def test_capacity_exceeded_rejected(harness, env):
    """AC-F04: device over max_device_capacity_gb -> REJECTED with reason code, never CLEAN."""
    broker = FakeBroker({"part1": str(env["part1"])}, capacity=3 * 1024 ** 3)
    orch, *_, events, sink = harness({"device": {"max_device_capacity_gb": 2}}, broker=broker)
    await start(orch)
    await run_scan(orch)
    assert orch.state is GUIState.REJECTED
    assert committed(sink)[-1]["verdict"] == "REJECTED"
    assert committed(sink)[-1]["reason_codes"] == ["capacity_exceeded"]
    assert ("mount",) not in broker.calls and ("release",) in broker.calls


@pytest.mark.parametrize("kw,reason", [
    ({"authorized": "0"}, "usb_policy_blocked"),
    ({"classes": ("08", "03")}, "hid_interface"),
    ({"classes": ("0e",)}, "non_storage_interface"),
    ({"block": False}, "no_storage_device"),
])
async def test_precheck_rejections(harness, env, kw, reason):
    """AC-S02 (orchestrator side): USBGuard-blocked / HID devices show REJECTED and are logged."""
    make_sysfs(env["sysfs"], port="1-2", **kw)
    orch, broker, *_, events, sink = harness()
    await start(orch)
    await run_scan(orch, UsbEvent("add", "1-2", "/sys/devices/usb1/1-2"))
    assert orch.state is GUIState.REJECTED
    assert of_type(events, EventType.DEVICE_REJECTED)[-1]["reason"] == reason
    assert broker.calls == []                      # broker never contacted
    assert committed(sink)[-1]["reason_codes"] == [reason]
    await orch.on_usb_event(UsbEvent("remove", "1-2", "/sys/devices/usb1/1-2"))
    assert orch.state is GUIState.IDLE


async def test_broker_refusal_rejected(harness):
    broker = FakeBroker({})
    broker.fail["enumerate"] = "invalid_argument"
    orch, *_, events, sink = harness(broker=broker)
    await start(orch)
    await run_scan(orch)
    assert orch.state is GUIState.REJECTED and committed(sink)[-1]["reason_codes"] == ["broker_invalid_argument"]


async def test_second_device_rejected(harness, env):
    make_sysfs(env["sysfs"], port="1-2")
    clamd = FakeClamd()
    clamd.gate = asyncio.Event()
    orch, *_, events, sink = harness(clamd=clamd)
    await start(orch)
    await orch.on_usb_event(ADD)
    await asyncio.sleep(0.2)
    await orch.on_usb_event(UsbEvent("add", "1-2", "/x"))
    assert of_type(events, EventType.DEVICE_REJECTED)[-1] == {"reason": "second_device", "port": "1-2"}
    clamd.gate.set()
    await asyncio.wait_for(orch.active.task, 10)
    assert verdicts(events)[0]["verdict"] == "CLEAN"


# --- removal / faults --------------------------------------------------------

async def test_removal_mid_scan_is_incomplete_and_released(harness):
    clamd = FakeClamd()
    clamd.gate = asyncio.Event()
    orch, broker, *_, events, sink = harness(clamd=clamd)
    await start(orch)
    await orch.on_usb_event(ADD)
    await asyncio.sleep(0.2)
    assert orch.state is GUIState.SCANNING
    task = orch.active.task
    await orch.on_usb_event(REMOVE)
    await asyncio.wait_for(task, 10)
    assert verdicts(events)[0]["verdict"] == "INCOMPLETE"
    assert "device_removed" in verdicts(events)[0]["reason_codes"]
    assert ("release",) in broker.calls and ("eject",) not in broker.calls
    assert orch.state is GUIState.IDLE
    assert not os.path.exists(sink.marker_path)


async def test_removal_after_threat_found_stays_threat(harness, env):
    (env["part1"] / "0.exe").write_bytes(b"EVIL")
    clamd = FakeClamd()
    orch, broker, *_, events, sink = harness(clamd=clamd)
    await start(orch)

    original = clamd.scan_fd
    gate = asyncio.Event()

    async def scan_then_block(fd, timeout):
        # The malicious file returns at once; every other file stalls until removal.
        if b"EVIL" not in os.pread(fd, 16, 0):
            await gate.wait()
        return await original(fd, timeout)

    clamd.scan_fd = scan_then_block
    await orch.on_usb_event(ADD)
    for _ in range(50):
        if any(e.event_type is EventType.DETECTION for e in events):
            break
        await asyncio.sleep(0.05)
    task = orch.active.task
    await orch.on_usb_event(REMOVE)
    await asyncio.wait_for(task, 10)
    assert verdicts(events)[0]["verdict"] == "THREAT"


async def test_clamd_failure_mid_scan_is_error(harness):
    clamd = FakeClamd()
    clamd.alive = False
    orch, broker, *_, events, sink = harness(clamd=clamd)
    orch.health.failures = []
    orch.state = GUIState.IDLE          # health already passed; clamd dies afterwards
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "ERROR" and v["coverage"]["clamav_complete"] is False


async def test_unmount_failure_is_eject_failed(harness):
    broker = None
    orch, broker, *_, events, sink = harness()
    broker.fail["unmount"] = "unmount_failed"
    await start(orch)
    await run_scan(orch)
    assert orch.state is GUIState.EJECT_FAILED
    assert of_type(events, EventType.STATE_CHANGED)[-1]["safe_to_remove"] is False
    await orch.on_usb_event(REMOVE)
    assert orch.state is GUIState.IDLE and ("release",) in broker.calls


async def test_eject_failure_after_unmount_still_safe(harness):
    orch, broker, *_, events, sink = harness()
    broker.fail["eject"] = "eject_failed"
    await start(orch)
    await run_scan(orch)
    final = of_type(events, EventType.STATE_CHANGED)[-1]
    assert final["state"] == "RESULT" and final["safe_to_remove"] is True and final["power_off"] is False


async def test_global_timeout_incomplete(harness):
    clamd = FakeClamd()
    clamd.gate = asyncio.Event()
    orch, *_, events, sink = harness({"scan": {"global_timeout_seconds": 60}}, clamd=clamd)
    object.__setattr__(orch.cfg.scan, "global_timeout_seconds", 0.3)
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "INCOMPLETE" and "global_timeout" in v["reason_codes"]


async def test_thermal_limit_halts_scan(harness, env):
    env["temp"].write_text("85000\n")
    orch, *_, events, sink = harness()
    orch.state = GUIState.IDLE
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "ERROR" and any("thermal_limit" in r for r in committed(sink)[-1]["engine_errors"])


async def test_interrupted_scan_recovered_after_restart(harness):
    orch, broker, *_, events, sink = harness()
    sink.mark_active("scan-1", "0f8fad5b-d9cb-469f-a165-70867728950e")
    await orch.recover_interrupted()
    (p,) = of_type(events, EventType.SCAN_INTERRUPTED)
    assert p["safe_to_remove"] is False
    assert ("release",) in broker.calls and not os.path.exists(sink.marker_path)


# --- health (AC-R01) ---------------------------------------------------------

async def test_not_ready_and_recovery(harness):
    clamd = FakeClamd()
    clamd.alive = False
    orch, broker, *_, events, sink = harness(clamd=clamd)
    await orch.check_health()
    assert orch.state is GUIState.NOT_READY
    assert of_type(events, EventType.HEALTH_GATE_FAILED)[-1]["failures"] == ["clamav_unavailable"]
    await orch.on_usb_event(ADD)
    assert orch.active is None
    assert of_type(events, EventType.DEVICE_REJECTED)[-1]["reason"] == "station_not_ready"
    clamd.alive = True
    await orch.check_health()
    assert orch.state is GUIState.IDLE


async def test_stale_signatures_not_ready(harness):
    clamd = FakeClamd()
    clamd.db_time -= 48 * 3600
    orch, *_ = harness(clamd=clamd)
    await orch.check_health()
    assert orch.state is GUIState.NOT_READY and "signatures_stale" in orch.health.failures


async def test_broker_down_not_ready(harness):
    orch, broker, *_ = harness()
    broker.alive = False
    await orch.check_health()
    assert "broker_unavailable" in orch.health.failures


# --- operator hold and PIN ---------------------------------------------------

@pytest.fixture(scope="module")
def pin_hash():
    return hash_pin("482916")


@pytest.fixture
def auth(env, pin_hash):
    store = SqliteLockoutStore(str(env["data"] / "db" / "events.db"))
    yield AuthManager(store, lambda level: pin_hash)
    store.close()


def pin_event(pin):
    return ScanEvent(EventType.OPERATOR_PIN_SUBMIT, None, {"pin": pin})


HOLD = {"operator_hold": {"enabled": True, "max_duration_seconds": 15, "allowed_verdicts": ["CLEAN"]}}


async def test_operator_hold_acknowledged_with_pin(harness, auth):
    orch, broker, *_, events, sink = harness(HOLD, auth=auth)
    await start(orch)
    await orch.on_usb_event(ADD)
    for _ in range(100):
        if orch.state is GUIState.OPERATOR_HOLD:
            break
        await asyncio.sleep(0.02)
    assert orch.state is GUIState.OPERATOR_HOLD
    assert ("unmount",) not in broker.calls
    await orch.on_operator_message(ScanEvent(EventType.OPERATOR_ACK, None), GUI)   # not yet authenticated
    await asyncio.sleep(0.05)
    assert orch.state is GUIState.OPERATOR_HOLD
    await orch.on_operator_message(pin_event("482916"), GUI)
    await orch.on_operator_message(ScanEvent(EventType.OPERATOR_ACK, None), GUI)
    await asyncio.wait_for(orch.active.task, 10)
    assert of_type(events, EventType.OPERATOR_HOLD_EXITED) == [{"reason": "acknowledged"}]
    assert orch.state is GUIState.RESULT
    auth_results = of_type(events, EventType.AUTH_RESULT)
    assert auth_results[-1]["success"] is True and "482916" not in json.dumps(auth_results)
    with open(sink.events_path) as fh:
        assert "482916" not in fh.read()           # PIN never persisted


async def test_operator_hold_timeout(harness, auth):
    orch, *_, events, sink = harness(HOLD, auth=auth)
    object.__setattr__(orch.cfg.operator_hold, "max_duration_seconds", 0.2)
    await start(orch)
    await run_scan(orch)
    assert of_type(events, EventType.OPERATOR_HOLD_EXITED) == [{"reason": "timeout"}]
    assert orch.state is GUIState.RESULT


async def test_no_hold_for_threat(harness, env, auth):
    (env["part1"] / "x").write_bytes(b"EVIL")
    orch, *_, events, sink = harness({"operator_hold": {"enabled": True, "max_duration_seconds": 15,
                                                         "allowed_verdicts": ["CLEAN", "SUSPICIOUS"]}}, auth=auth)
    await start(orch)
    await run_scan(orch)
    assert "OPERATOR_HOLD" not in states(events)


async def test_pin_lockout_via_ipc_and_non_gui_ignored(harness, auth):
    orch, *_, events, sink = harness(auth=auth)
    await start(orch)
    await orch.on_operator_message(pin_event("000001"), LED)        # wrong uid: ignored entirely
    assert of_type(events, EventType.AUTH_RESULT) == []
    for _ in range(5):
        await orch.on_operator_message(pin_event("000001"), GUI)
    await orch.on_operator_message(pin_event("482916"), GUI)
    last = of_type(events, EventType.AUTH_RESULT)[-1]
    assert last == {"success": False, "locked_out": True, "level": "operator", "interface": "touchscreen"}
    await orch.on_operator_message(ScanEvent(EventType.LOCKOUT_QUERY, None), GUI)
    assert of_type(events, EventType.LOCKOUT_STATE)[-1] == {"locked_out": True}


# --- misc -----------------------------------------------------------------------

def test_usb_event_filter():
    assert to_event("add", "1-1.2", "/sys/devices/x/1-1.2", "usb_device", ()) is not None
    assert to_event("add", "usb1", "/sys/devices/x/usb1", "usb_device", ()) is None       # root hub
    assert to_event("add", "1-1:1.0", "/sys/x", "usb_interface", ()) is None
    assert to_event("bind", "1-1", "/sys/x", "usb_device", ()) is None
    assert to_event("add", "1-1", "/sys/devices/int/1-1", "usb_device", ("/sys/devices/int",)) is None


async def test_snapshot_for_new_clients(harness):
    orch, *_ = harness()
    await start(orch)
    (ev,) = orch.snapshot(GUI)
    assert ev.payload["state"] == "IDLE"


# --- FR-USB-04 explicit partition-type exclusion ----------------------------

MSR = "e3c9e316-0b5c-4db8-817d-f92df00215ae"


def _broker_with(env, status, size):
    b = FakeBroker({"part2": str(env["part1"])}, volumes=[
        {"partition_id": "part1", "status": status, "fs_type": "", "part_type": MSR, "size_bytes": size},
        {"partition_id": "part2", "status": "supported", "fs_type": "vfat", "part_type": "0xc", "size_bytes": 10**9},
    ])
    return b


async def test_msr_without_policy_is_incomplete(harness, env):
    orch, *_, events, sink = harness(broker=_broker_with(env, "unrecognized", 16 * 1024 * 1024))
    await start(orch)
    await run_scan(orch)
    assert verdicts(events)[0]["verdict"] == "INCOMPLETE"


async def test_msr_out_of_scope_by_policy_is_clean_and_reported(harness, env):
    cfg = {"device": {"excludable_partition_types": [MSR.upper()]}}
    orch, *_, events, sink = harness(cfg, broker=_broker_with(env, "unrecognized", 16 * 1024 * 1024))
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "CLEAN"
    assert v["coverage"]["partitions_out_of_scope"] == 1 and v["coverage"]["partitions_excluded"] == 0
    assert f"partition_out_of_scope:{MSR}" in v["reason_codes"]


@pytest.mark.parametrize("status,size", [("encrypted", 16 * 1024 * 1024),       # has a signature
                                         ("unrecognized", 512 * 1024 * 1024)])  # above size cap
async def test_policy_never_excludes_signatures_or_large_partitions(harness, env, status, size):
    cfg = {"device": {"excludable_partition_types": [MSR]}}
    orch, *_, events, sink = harness(cfg, broker=_broker_with(env, status, size))
    await start(orch)
    await run_scan(orch)
    assert verdicts(events)[0]["verdict"] == "INCOMPLETE"


# --- YARA (Phase 4) ------------------------------------------------------------

from tests.unit.orchestrator.fakes import FakeYaraClient  # noqa: E402

YARA_ON = {"yara": {"enabled": True, "role": "mandatory"}}
YARA_ADVISORY = {"yara": {"enabled": True, "role": "advisory"}}


def with_yara(harness, cfg, client):
    orch, broker, clamd, events, sink = harness(cfg)
    orch.yara = client
    return orch, broker, clamd, events, sink


async def test_yara_clean_complete(harness):
    client = FakeYaraClient()
    orch, *_, events, sink = with_yara(harness, YARA_ON, client)
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "CLEAN" and v["coverage"]["yara_complete"] is True
    assert client.scanned == 2
    assert "yara_rules=7:abcdef0123456789" in committed(sink)[-1]["reason_codes"]


@pytest.mark.parametrize("marker,verdict", [(b"YHIGH", "THREAT"), (b"YMED", "SUSPICIOUS")])
async def test_yara_match_severity(harness, env, marker, verdict):
    (env["part1"] / "doc.bin").write_bytes(marker)
    orch, *_, events, sink = with_yara(harness, YARA_ON, FakeYaraClient())
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == verdict
    assert v["threats"][0]["engine"] == "yara"
    full = committed(sink)[-1]["threats"][0]
    assert full["file_path"] == "part1/doc.bin" and len(full["sha256"]) == 64


@pytest.mark.parametrize("cfg,verdict", [(YARA_ON, "INCOMPLETE"), (YARA_ADVISORY, "CLEAN")])
async def test_yara_timeout_by_role(harness, env, cfg, verdict):
    (env["part1"] / "slow.bin").write_bytes(b"YTIME")
    orch, *_, events, sink = with_yara(harness, cfg, FakeYaraClient())
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == verdict and v["coverage"]["yara_complete"] is False
    assert "yara_timeout=1" in committed(sink)[-1]["reason_codes"]


@pytest.mark.parametrize("cfg,verdict", [(YARA_ON, "INCOMPLETE"), (YARA_ADVISORY, "CLEAN")])
async def test_yara_worker_dies_mid_scan(harness, env, cfg, verdict):
    (env["part1"] / "boom.bin").write_bytes(b"YDIE")
    orch, *_, events, sink = with_yara(harness, cfg, FakeYaraClient())
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == verdict
    assert any(r.startswith("yara_unavailable:worker_disconnected") for r in committed(sink)[-1]["reason_codes"])


async def test_yara_mandatory_unavailable_not_ready(harness):
    orch, *_ = with_yara(harness, YARA_ON, FakeYaraClient(available=False))
    await orch.check_health()
    assert orch.state is GUIState.NOT_READY and "yara_unavailable" in orch.health.failures


async def test_yara_advisory_unavailable_is_warning_only(harness):
    orch, *_, events, sink = with_yara(harness, YARA_ADVISORY, FakeYaraClient(available=False))
    await start(orch)
    assert "yara_unavailable" in orch.health.warnings
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "CLEAN" and v["coverage"]["yara_complete"] is False


async def test_yara_budget_exceeded_incomplete(harness):
    orch, *_, events, sink = with_yara(harness, YARA_ON, FakeYaraClient())
    object.__setattr__(orch.cfg.yara, "global_budget_seconds", -1)   # already exhausted
    await start(orch)
    await run_scan(orch)
    v = verdicts(events)[0]
    assert v["verdict"] == "INCOMPLETE"
    assert "yara_budget_exceeded" in committed(sink)[-1]["reason_codes"]


async def test_snapshot_includes_verdict_while_result_shown(harness):
    """A GUI that (re)connects during RESULT must get the verdict, not only the state."""
    orch, *_ = harness()
    await start(orch)
    await run_scan(orch)
    events = orch.snapshot(GUI)
    assert [e.event_type for e in events] == [EventType.VERDICT, EventType.STATE_CHANGED]
    assert events[0].payload["verdict"] == "CLEAN" and events[1].payload["state"] == "RESULT"


async def test_many_detections_fit_on_state_socket(harness, env):
    """A stick full of malware must not overflow the 64 KiB state-socket frame."""
    from src.shared.ipc import encode_event
    for i in range(1500):
        (env["part1"] / f"evil{i:04d}.exe").write_bytes(b"..EVIL..")
    sent = []
    orch, *_ = harness()
    orch._broadcast = lambda ev: sent.append(encode_event(ev))      # real wire encoding
    await start(orch)
    await run_scan(orch)
    assert orch.state is GUIState.RESULT
    (payload,) = [json.loads(l)["payload"] for l in sent if b'"verdict","scan_id"' in l or b'"event_type":"verdict"' in l]
    assert payload["verdict"] == "THREAT" and payload["threat_count"] == 1500
    assert len(payload["threats"]) <= 20
