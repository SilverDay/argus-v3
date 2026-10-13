"""Helpers and checks for the on-device acceptance run (spec §14).

Runs as root on the station. It observes the running stack, mostly read-only:
* the audit DB is opened with SQLite ``mode=ro``. The events socket is not used, because
  root is deliberately not one of its roles;
* socket permission tests run in child processes that drop to the service accounts
  (``probes.py``);
* the disruptive checks (AC-R01, AC-R04, AC-S05) only run with ``--destructive``.

Pure evaluation functions (``coverage_problems``, ``usb_mount_problems``,
``persistent_mount_problems``) are unit-tested in tests/unit/acceptance.
"""
from __future__ import annotations

import json
import os
import pwd
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from src.shared.config import Config
from src.shared.mountinfo import MountEntry, parse_mountinfo

PASS, FAIL, SKIP, PENDING = "PASS", "FAIL", "SKIP", "PENDING"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

COVERAGE_COUNTERS = (
    "partitions_discovered", "partitions_scanned", "partitions_excluded",
    "files_discovered", "files_scanned", "files_skipped", "files_failed", "files_uninspectable",
    "bytes_enumerated", "bytes_read",
)
USB_MOUNT_FLAGS = ("ro", "noexec", "nosuid", "nodev", "nosymfollow")
# Bind mounts from the data partition created by scripts/harden.sh (spec §5.3).
DATA_BINDS = ("/var/lib/usb-scan", "/etc/usb-scan", "/var/log/usb-scan", "/var/lib/clamav")
CORE_UNITS = ("usb-scan-events", "usb-scan-device-broker", "usb-scan-orchestrator", "usb-scan-gui")


@dataclass
class Result:
    check_id: str
    title: str
    status: str = PASS
    details: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def fail(self, msg: str) -> None:
        self.status = FAIL
        self.details.append("FAIL: " + msg)

    def note(self, msg: str) -> None:
        self.details.append(msg)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.check_id, "title": self.title, "status": self.status,
                "details": self.details, "evidence": self.evidence}


# --- pure evaluation (unit-tested) ---------------------------------------------------------

def coverage_problems(payload: dict[str, Any], yara_enabled: bool, vt_enabled: bool) -> list[str]:
    """AC-F07: the committed verdict record carries every required coverage metric."""
    cov = payload.get("coverage")
    if not isinstance(cov, dict):
        return ["coverage missing"]
    out = []
    for name in COVERAGE_COUNTERS:
        v = cov.get(name)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            out.append(f"{name} missing or invalid")
    if not isinstance(cov.get("skip_reasons"), dict):
        out.append("skip_reasons missing")
    if not isinstance(cov.get("clamav_complete"), bool):
        out.append("clamav_complete missing")
    for name, enabled in (("yara_complete", yara_enabled), ("vt_complete", vt_enabled)):
        v = cov.get(name, "absent")
        if enabled and not isinstance(v, bool):
            out.append(f"{name} must be true/false when the engine is enabled")
        if not enabled and v is not None:
            out.append(f"{name} must be null when the engine is disabled")
    if not isinstance(payload.get("verdict"), str):
        out.append("verdict missing")
    return out


def usb_mount_problems(entry: MountEntry, read_attr: Callable[[str], str | None]) -> list[str]:
    """AC-S03: one broker mount. ``read_attr(rel)`` reads /sys/dev/block/<maj:min>/<rel>."""
    out = [f"mount option {f} missing" for f in USB_MOUNT_FLAGS if f not in entry.mount_options]
    if "rw" in entry.mount_options:
        out.append("mounted rw")
    if read_attr("ro") != "1":
        out.append("block device not read-only (BLKROSET)")
    if read_attr("partition") is not None and read_attr("../ro") != "1":
        out.append("parent disk not read-only")
    return out


def persistent_mount_problems(entries: Iterable[MountEntry], *, is_block: Callable[[int, int], bool],
                              allowed_rw: dict[tuple[int, int], str], usb_prefix: str,
                              data_mountpoint: str, extra_allowed: Iterable[str] = ()) -> tuple[list[str], list[str]]:
    """AC-S01: every writable mount backed by a block device is an allowed persistent path.

    Returns (problems, writable persistent mountpoints).
    """
    allowed_points = {data_mountpoint.rstrip("/") or "/", *DATA_BINDS, *extra_allowed}
    problems, writable = [], []
    for e in entries:
        if not is_block(e.major, e.minor):
            continue                                  # tmpfs, overlay, proc, sysfs ...
        rw = "ro" not in e.mount_options
        if e.mountpoint.startswith(usb_prefix):
            continue                                  # judged by AC-S03
        if not rw:
            continue
        dev = (e.major, e.minor)
        if dev not in allowed_rw:
            problems.append(f"{e.mountpoint} is writable on block device {e.major}:{e.minor} ({e.source})")
            continue
        writable.append(e.mountpoint)
        if allowed_rw[dev] == "data" and e.mountpoint not in allowed_points:
            problems.append(f"unexpected writable path on the data partition: {e.mountpoint}")
    return problems, sorted(writable)


# --- station access ------------------------------------------------------------------------

def read_mountinfo(pid: str = "self") -> list[MountEntry]:
    with open(f"/proc/{pid}/mountinfo", encoding="utf-8", errors="surrogateescape") as fh:
        return parse_mountinfo(fh.read())


def sysfs_block_attr(major: int, minor: int, rel: str) -> str | None:
    try:
        with open(os.path.join(f"/sys/dev/block/{major}:{minor}", rel), encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return None


def is_block(major: int, minor: int) -> bool:
    return major != 0 and os.path.exists(f"/sys/dev/block/{major}:{minor}")


def rdev(path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (os.major(st.st_rdev), os.minor(st.st_rdev))


def boot_id() -> str:
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
        return fh.read().strip()


class EventsDB:
    """Read-only view of the events database (no writes, no checkpoints)."""

    def __init__(self, path: str) -> None:
        self.db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)

    def close(self) -> None:
        self.db.close()

    def max_seq(self) -> int:
        return self.db.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()[0]

    def since(self, seq: int, types: Iterable[str] | None = None) -> list[dict[str, Any]]:
        sql = "SELECT seq, event_type, scan_id, timestamp_utc, payload FROM events WHERE seq > ?"
        args: list[Any] = [seq]
        if types is not None:
            types = list(types)
            sql += f" AND event_type IN ({','.join('?' * len(types))})"
            args += types
        rows = self.db.execute(sql + " ORDER BY seq", args).fetchall()
        return [{"seq": s, "type": t, "scan_id": sid, "ts": ts, "payload": json.loads(p)}
                for s, t, sid, ts, p in rows]

    def last(self, event_type: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT seq FROM events WHERE event_type = ? ORDER BY seq DESC LIMIT 1",
                              (event_type,)).fetchone()
        return self.since(row[0] - 1, [event_type])[0] if row else None

    def wait_for(self, seq: int, types: Iterable[str], pred: Callable[[dict[str, Any]], bool],
                 timeout: float, poll: float = 1.0) -> dict[str, Any] | None:
        types = list(types)
        deadline = time.monotonic() + timeout
        while True:
            for ev in self.since(seq, types):
                if pred(ev):
                    return ev
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll)


class Station:
    def __init__(self, cfg: Config, *, config_path: str, python: str = sys.executable) -> None:
        self.cfg = cfg
        self.config_path = config_path
        self.python = python
        self.events = EventsDB(cfg.events.db_path)
        self.state_dir = os.path.join(cfg.host.data_mountpoint, "acceptance")

    # systemd
    @staticmethod
    def systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=check, timeout=120)

    def unit_props(self, unit: str, *props: str) -> dict[str, str]:
        out = self.systemctl("show", unit, "-p", ",".join(props), check=False).stdout
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    def units(self) -> list[str]:
        units = list(CORE_UNITS)
        if self.cfg.yara.enabled:
            units.append("usb-scan-yara")
        if self.cfg.led.driver.value != "stub":
            units.append("usb-scan-led")
        if self.cfg.admin_web.enabled:
            units.append("usb-scan-admin")
        return units

    # privilege-dropped probes
    def probe(self, user: str, *args: str, timeout: float = 60) -> dict[str, Any]:
        pw = pwd.getpwnam(user)
        groups = [g for g in os.getgrouplist(user, pw.pw_gid) if g != pw.pw_gid]
        proc = subprocess.run(
            # -E -s: ignore PYTHON* variables and the user site; -m puts cwd (the repository) first.
            [self.python, "-E", "-s", "-B", "-m", "tests.acceptance.probes", *args],
            cwd=REPO, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            user=pw.pw_uid, group=pw.pw_gid, extra_groups=groups,
            capture_output=True, text=True, timeout=timeout)
        try:
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {"error": f"probe exit {proc.returncode}: {proc.stderr.strip()[-300:]}"}

    # persistent acceptance state (survives the read-only root's reboot)
    def load_state(self, name: str) -> dict[str, Any] | None:
        try:
            with open(os.path.join(self.state_dir, name), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def save_state(self, name: str, data: dict[str, Any]) -> str:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        path = os.path.join(self.state_dir, name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return path

    def process_stats(self, unit: str) -> dict[str, Any]:
        pid = self.unit_props(unit, "MainPID").get("MainPID", "0")
        out: dict[str, Any] = {"pid": int(pid)}
        if pid in ("", "0"):
            return out
        try:
            out["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
            with open(f"/proc/{pid}/status", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        out["rss_kb"] = int(line.split()[1])
        except OSError:
            pass
        return out

    def snapshot(self) -> dict[str, Any]:
        """Baseline for AC-R02/AC-S02/AC-R03 comparisons."""
        units = {}
        for u in self.units():
            props = self.unit_props(u, "NRestarts", "ActiveState", "MainPID")
            units[u] = {"n_restarts": int(props.get("NRestarts", "0") or 0), "active": props.get("ActiveState"),
                        **self.process_stats(u)}
        return {"seq": self.events.max_seq(), "boot_id": boot_id(), "time": time.time(), "units": units,
                "usb_mounts": len(self.usb_mounts())}

    def usb_mounts(self) -> list[MountEntry]:
        prefix = self.cfg.broker.mounts_dir.rstrip("/") + "/"
        return [e for e in read_mountinfo("1") if e.mountpoint.startswith(prefix)]
