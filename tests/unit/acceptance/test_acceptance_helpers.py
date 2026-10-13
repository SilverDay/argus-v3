"""Evaluation logic of the on-device acceptance run (tests/acceptance/station.py)."""
import sqlite3
import uuid

import pytest

from src.events.store import EventStore
from src.orchestrator.event_sink import verdict_event
from src.shared.mountinfo import MountEntry
from src.shared.models import CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, Verdict, utc_now
from tests.acceptance.station import (
    EventsDB, coverage_problems, persistent_mount_problems, usb_mount_problems,
)


def record(**cov):
    r = ScanResult(ScanMetadata(str(uuid.uuid4()), "station-001", "1-1", utc_now()), Verdict.CLEAN,
                   CoverageMetrics(partitions_discovered=1, partitions_scanned=1, files_discovered=2,
                                   files_scanned=2, clamav_complete=True, **cov))
    return verdict_event(r, {"serial": "S1"}).payload


def mount(point, dev=(179, 2), opts=("rw",), fs="ext4", source="/dev/mmcblk0p2"):
    return MountEntry(1, dev[0], dev[1], point, frozenset(opts), fs, source, frozenset())


def test_committed_record_has_all_coverage_metrics():
    assert coverage_problems(record(), yara_enabled=False, vt_enabled=False) == []
    assert coverage_problems(record(yara_complete=True), yara_enabled=True, vt_enabled=False) == []


def test_coverage_gaps_detected():
    p = record()
    del p["coverage"]["files_skipped"]
    p["coverage"]["skip_reasons"] = None
    problems = coverage_problems(p, yara_enabled=True, vt_enabled=False)
    assert "files_skipped missing or invalid" in problems
    assert "skip_reasons missing" in problems
    assert "yara_complete must be true/false when the engine is enabled" in problems
    assert coverage_problems({"verdict": "CLEAN"}, False, False) == ["coverage missing"]


def test_usb_mount_flags_and_block_ro():
    good = mount("/run/usb-scan/mounts/s/p1", (8, 1), ("ro", "noexec", "nosuid", "nodev", "nosymfollow"), "vfat")
    attrs = {"ro": "1", "partition": "1", "../ro": "1"}
    assert usb_mount_problems(good, attrs.get) == []
    assert usb_mount_problems(good, {**attrs, "../ro": "0"}.get) == ["parent disk not read-only"]
    bad = mount("/run/usb-scan/mounts/s/p1", (8, 1), ("rw", "nosuid"), "vfat")
    problems = usb_mount_problems(bad, {"ro": "0"}.get)
    assert "mount option noexec missing" in problems and "mounted rw" in problems
    assert "block device not read-only (BLKROSET)" in problems


def test_persistent_writable_paths_bounded():
    data, boot, root = (179, 3), (179, 1), (179, 2)
    entries = [
        mount("/", (0, 30), ("rw",), "overlay", "overlayroot"),
        mount("/media/root-ro", root, ("ro",)),
        mount("/boot/firmware", boot, ("ro",), "vfat"),
        mount("/data", data), mount("/var/lib/usb-scan", data), mount("/etc/usb-scan", data),
        mount("/var/log/usb-scan", data), mount("/var/lib/clamav", data),
        mount("/run/usb-scan/mounts/s/p1", (8, 1), ("ro",)),
    ]
    kw = dict(is_block=lambda a, b: a != 0, allowed_rw={data: "data"},
              usb_prefix="/run/usb-scan/mounts/", data_mountpoint="/data")
    problems, writable = persistent_mount_problems(entries, **kw)
    assert problems == []
    assert writable == ["/data", "/etc/usb-scan", "/var/lib/clamav", "/var/lib/usb-scan", "/var/log/usb-scan"]
    problems, _ = persistent_mount_problems(entries + [mount("/srv", root), mount("/home", data)], **kw)
    assert problems == ["/srv is writable on block device 179:2 (/dev/mmcblk0p2)",
                        "unexpected writable path on the data partition: /home"]


def test_events_db_is_read_only_and_sees_committed_events(tmp_path):
    store = EventStore(str(tmp_path / "events.db"), "station-001")
    try:
        store.append(ScanEvent(EventType.STATE_CHANGED, None, {"state": "IDLE"}))
        db = EventsDB(str(tmp_path / "events.db"))
        try:
            seq = db.max_seq()
            store.append(ScanEvent(EventType.SYNTHETIC_SCAN, None, {"trigger": "manual", "passed": True}))
            ev = db.wait_for(seq, ["synthetic_scan"], lambda e: e["payload"]["trigger"] == "manual", 5, 0.05)
            assert ev is not None and ev["payload"]["passed"] is True
            assert db.last("state_changed")["payload"] == {"state": "IDLE"}
            assert db.last("verdict") is None
            assert db.wait_for(ev["seq"], ["synthetic_scan"], lambda e: True, 0.2, 0.05) is None
            with pytest.raises(sqlite3.OperationalError):
                db.db.execute("DELETE FROM events")
        finally:
            db.close()
    finally:
        store.close()
