"""On-device acceptance run (spec §14). Raspberry Pi station, full stack, as root.

    cd /opt/usb-scan
    sudo .venv/bin/python -m tests.acceptance.run_acceptance baseline
    sudo .venv/bin/python -m tests.acceptance.run_acceptance run [--destructive] [--only AC-F05,...]
    sudo .venv/bin/python -m tests.acceptance.run_acceptance watch-mounts --seconds 300
    sudo .venv/bin/python -m tests.acceptance.run_acceptance scans [--since-seq N]

``run`` writes a JSON report to <data_mountpoint>/acceptance/report-<UTC>.json. Statuses:
* PASS / FAIL;
* SKIP: the precondition is missing, e.g. no scans yet;
* PENDING: a step from MANUAL_TEST_CHECKLIST.md is still needed, e.g. the reboot for AC-S01.
The manual procedure and the sign-off sheet are in tests/acceptance/MANUAL_TEST_CHECKLIST.md.

Disruptive checks (``--destructive``) stop clamd (AC-R01), kill the orchestrator (AC-R04) and
lock out the operator PIN for ``pin.lockout_minutes`` (AC-S05). They need an idle station.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable

from src.shared.config import ConfigError, load_config

from .station import (
    FAIL, PASS, PENDING, REPO, SKIP, Result, Station, boot_id, coverage_problems, is_block, persistent_mount_problems,
    rdev, read_mountinfo, sysfs_block_attr, usb_mount_problems,
)

BASELINE = "baseline.json"
S01_MARKER = "/etc/.usb-scan-acceptance-marker"     # on the root overlay: must vanish at reboot
S01_STATE = "s01-marker.json"
R04_LIMIT_SECONDS = 30                               # spec §11 / AC-R04
R02_MAX_FD_GROWTH = 16                               # acceptance threshold (no descriptor leak)


def _idle(st: Station) -> bool:
    ev = st.events.last("state_changed")
    return ev is not None and ev["payload"].get("state") == "IDLE"


# --- non-disruptive checks -----------------------------------------------------------------

def check_pre(st: Station) -> Result:
    r = Result("PRE", "Services active, station IDLE")
    for unit in st.units():
        props = st.unit_props(unit, "ActiveState", "NRestarts")
        r.evidence[unit] = props
        if props.get("ActiveState") != "active":
            r.fail(f"{unit} is {props.get('ActiveState')}")
    for unit in ("usbguard", "clamav-daemon"):
        state = st.unit_props(unit, "ActiveState").get("ActiveState")
        r.evidence[unit] = state
        if state != "active":
            r.fail(f"{unit} is {state}")
    if not _idle(st):
        r.fail("last recorded station state is not IDLE")
    try:
        with open("/proc/device-tree/model", encoding="ascii", errors="replace") as fh:
            r.evidence["model"] = fh.read().strip("\0\n")
    except OSError:
        r.evidence["model"] = "unknown"
    return r


def check_f05(st: Station) -> Result:
    r = Result("AC-F05", "Synthetic EICAR scan, deterministic result in the event log")
    if not _idle(st):
        r.status = SKIP
        r.note("station not IDLE")
        return r
    seq = st.events.max_seq()
    st.systemctl("kill", "-s", "SIGUSR1", "--kill-whom=main", "usb-scan-orchestrator")
    ev = st.events.wait_for(seq, ["synthetic_scan"], lambda e: e["payload"].get("trigger") == "manual", 60)
    if ev is None:
        r.fail("no synthetic_scan event within 60 s")
        return r
    p = ev["payload"]
    r.evidence = {"seq": ev["seq"], "payload": p}
    if not (p.get("passed") is True and p.get("verdict") == "THREAT" and p.get("expected_verdict") == "THREAT"):
        r.fail(f"synthetic scan result: passed={p.get('passed')} verdict={p.get('verdict')}")
    if p.get("clamav", {}).get("test_file") != "found" or p.get("clamav", {}).get("control_file") != "clean":
        r.fail(f"unexpected ClamAV outcome {p.get('clamav')}")
    return r


def check_f07(st: Station, since: int) -> Result:
    r = Result("AC-F07", "Coverage metrics in every committed scan record")
    verdicts = st.events.since(since, ["verdict"])
    if not verdicts:
        r.status = SKIP
        r.note("no committed scans since the baseline; run the reference media first (checklist)")
        return r
    bad = {}
    for ev in verdicts:
        problems = coverage_problems(ev["payload"], st.cfg.yara.enabled, st.cfg.virustotal.enabled)
        if problems:
            bad[ev["seq"]] = problems
    r.evidence = {"records_checked": len(verdicts), "problems": bad}
    if bad:
        r.fail(f"{len(bad)} of {len(verdicts)} records incomplete")
    return r


def check_s01(st: Station) -> Result:
    r = Result("AC-S01", "Read-only root; writable persistent paths bounded; verified after reboot")
    try:
        with open("/proc/cmdline", encoding="ascii") as fh:
            cmdline = fh.read().split()
    except OSError:
        cmdline = []
    entries = read_mountinfo("1")
    root = [e for e in entries if e.mountpoint == "/"][-1]
    r.evidence["root"] = {"fstype": root.fs_type, "source": root.source}
    if "overlayroot=tmpfs:recurse=0" not in cmdline:
        r.fail("kernel command line lacks overlayroot=tmpfs:recurse=0 (maintenance mode?)")
    if root.fs_type != "overlay":
        r.fail(f"/ is {root.fs_type}, not the overlay")
    data_dev = rdev(f"/dev/disk/by-label/{st.cfg.host.data_partition_label}")
    if data_dev is None:
        r.fail(f"data partition LABEL={st.cfg.host.data_partition_label} not found")
    allowed = {data_dev: "data"} if data_dev else {}
    extra = []
    if st.cfg.quarantine.quarantine_on_threat:
        q = rdev("/dev/mapper/usbscan-quarantine")
        if q:
            allowed[q] = "quarantine"
            extra.append(st.cfg.quarantine.path)
    problems, writable = persistent_mount_problems(
        entries, is_block=is_block, allowed_rw=allowed, usb_prefix=st.cfg.broker.mounts_dir.rstrip("/") + "/",
        data_mountpoint=st.cfg.host.data_mountpoint, extra_allowed=extra)
    r.evidence["writable_persistent_mounts"] = writable
    for p in problems:
        r.fail(p)
    for path in ("/var/lib/usb-scan", "/etc/usb-scan", "/var/log/usb-scan", "/var/lib/clamav",
                 st.cfg.host.data_mountpoint):
        if path not in writable:
            r.fail(f"{path} is not a writable mount from the data partition")
    boot = [e for e in entries if e.mountpoint == "/boot/firmware"]
    if boot and "ro" not in boot[-1].mount_options:
        r.fail("/boot/firmware is writable")

    # Reboot evidence: a marker on the overlay must be gone after the next boot.
    prev = st.load_state(S01_STATE)
    now = boot_id()
    if prev and prev.get("boot_id") != now:
        r.evidence["reboot_check"] = {"marker_boot_id": prev.get("boot_id"), "current_boot_id": now}
        if os.path.exists(S01_MARKER):
            r.fail(f"{S01_MARKER} written before the reboot still exists (root is persistent)")
        else:
            r.note("marker written before the reboot is gone: root changes are not persistent")
        prev = None
    if prev is None:
        with open(S01_MARKER, "w", encoding="ascii") as fh:
            fh.write("usb-scan acceptance AC-S01\n")
        st.save_state(S01_STATE, {"boot_id": now, "time": time.time()})
        if r.status == PASS and "reboot_check" not in r.evidence:
            r.status = PENDING
            r.note("marker written; reboot and run again to complete AC-S01")
    elif r.status == PASS:
        r.status = PENDING
        r.note("waiting for a reboot since the marker was written")
    return r


def _internal_disk_sysfs(st: Station) -> str:
    """sysfs device path of the disk holding /boot/firmware (the internal SD/NVMe)."""
    for e in read_mountinfo("1"):
        if e.mountpoint in ("/boot/firmware", "/boot") and is_block(e.major, e.minor):
            part = os.path.realpath(f"/sys/dev/block/{e.major}:{e.minor}")
            return os.path.realpath(os.path.join(os.path.dirname(part), "device"))
    return "/sys/devices/platform"


def check_s04(st: Station, config: str) -> Result:
    r = Result("AC-S04", "No arbitrary broker commands, host paths or internal disks; socket peers restricted")
    cfg = st.cfg
    matrix = [   # (socket, user, expected)
        (cfg.broker.socket_path, "usbscan", "accepted"),
        (cfg.broker.socket_path, "nobody", "refused"),
        (cfg.broker.socket_path, "usbscan-gui", "refused"),
        (cfg.broker.socket_path, "usbscan-web", "refused"),
        (cfg.broker.socket_path, "usbscan-led", "refused"),
        (cfg.broker.socket_path, "usbscan-events", "refused"),
        (cfg.broker.socket_path, "yarascan", "refused"),
        (cfg.events.socket_path, "nobody", "refused"),
        (cfg.events.socket_path, "usbscan-gui", "refused"),
        (cfg.events.socket_path, "usbscan-led", "refused"),
        (cfg.orchestrator.state_socket, "nobody", "refused"),
        (cfg.orchestrator.state_socket, "usbscan-web", "refused"),
        (cfg.clamav.socket_path, "nobody", "refused"),
        (cfg.clamav.socket_path, "usbscan-gui", "refused"),
        (cfg.clamav.socket_path, "usbscan-web", "refused"),
    ]
    if cfg.yara.enabled:
        matrix += [(cfg.yara.socket_path, u, "refused") for u in ("nobody", "usbscan-gui", "usbscan-web")]
    rows = []
    for sock, user, expected in matrix:
        try:
            got = st.probe(user, "connect", sock)
        except KeyError:
            rows.append({"socket": sock, "user": user, "result": "user absent"})
            continue
        rows.append({"socket": sock, "user": user, "expected": expected, **got})
        if got.get("result") != expected:
            r.fail(f"{user} -> {sock}: {got.get('result')} ({got.get('detail') or got.get('error')}), expected {expected}")
    r.evidence["peer_matrix"] = rows
    internal = _internal_disk_sysfs(st)
    neg = st.probe("usbscan", "broker-negative", "--config", config, "--internal-sysfs", internal)
    r.evidence["broker_requests"] = neg
    if not neg.get("ok"):
        r.fail(f"broker accepted a request it must refuse: {neg.get('error') or [c for c in neg.get('cases', []) if not c['ok']]}")
    return r


def check_s02(st: Station, base: dict | None) -> Result:
    r = Result("AC-S02", "HID / HID+storage composite blocked by USBGuard and recorded")
    if base is None:
        r.status = SKIP
        r.note("no baseline: run 'baseline', insert the keyboard and the composite device, then run again")
        return r
    rejected = [e for e in st.events.since(base["seq"], ["device_rejected"])]
    blocked = [e for e in rejected if e["payload"].get("reason") == "usb_policy_blocked"]
    hid_late = [e for e in rejected if e["payload"].get("reason") in ("hid_interface", "non_storage_interface")]
    started = {e["scan_id"] for e in st.events.since(base["seq"], ["scan_started"])}
    r.evidence = {"device_rejected": [{"seq": e["seq"], **e["payload"]} for e in rejected]}
    try:
        rules = subprocess.run(["usbguard", "list-rules"], capture_output=True, text=True, timeout=30)
        r.evidence["usbguard_list_rules"] = rules.stdout.strip().splitlines()
        hid = [line for line in rules.stdout.splitlines() if "03:*:*" in line]
        if rules.returncode != 0 or not hid or not all(" block " in f" {line} " for line in hid):
            r.fail("usbguard does not report the HID 'block' rule (spec 1.5.8)")
    except (OSError, subprocess.TimeoutExpired) as exc:
        r.fail(f"usbguard list-rules failed: {exc}")
    if hid_late:
        r.fail("a HID interface reached the orchestrator authorised (USBGuard did not block it)")
    if any(e["scan_id"] in started for e in blocked):
        r.fail("a blocked device entered scan state")
    if not blocked:
        r.status = FAIL if r.status == FAIL else PENDING
        r.note("no usb_policy_blocked rejection recorded since the baseline; insert the HID test devices "
               "(checklist 3.2.1/3.2.2)")
    gone = [e for e in rejected if e["payload"].get("reason") == "device_gone"]
    if gone:
        r.note(f"{len(gone)} device_gone rejection(s): device removed before it was recorded; "
               "with the 'block' rule this only happens when the device is pulled within the debounce time")
    return r


def check_s06(st: Station) -> Result:
    r = Result("AC-S06", "Randomised PIN pad layout on every presentation (production GUI code, offscreen)")
    out = st.probe("usbscan-gui", "pin-layout", "--config", st.config_path, "100", timeout=300)
    r.evidence = out
    if "error" in out:
        r.fail(out["error"])
        return r
    if not out.get("all_digits_once"):
        r.fail("a layout does not show every digit exactly once")
    if out.get("repeats_in_a_row"):
        r.fail(f"{out['repeats_in_a_row']} consecutive presentations repeated the layout")
    if out.get("distinct", 0) <= 90:
        r.fail(f"only {out.get('distinct')} distinct layouts in 100 presentations")
    r.note("visual check on the touchscreen is in the manual checklist")
    return r


def check_r03(st: Station) -> Result:
    r = Result("AC-R03", "After power loss: scan marked interrupted, no false safe-to-remove, chain intact")
    starts = st.events.since(0, ["scan_started"])
    verdict_ids = {e["scan_id"] for e in st.events.since(0, ["verdict"])}
    orphans = [e for e in starts if e["scan_id"] not in verdict_ids]
    if not orphans:
        r.status = SKIP
        r.note("no scan without a verdict found; cut power during a scan first (checklist)")
    else:
        interrupted = {e["scan_id"] for e in st.events.since(0, ["scan_interrupted"])}
        safe = {e["scan_id"] for e in st.events.since(0, ["state_changed"])
                if e["payload"].get("safe_to_remove") is True}
        for e in orphans:
            if e["scan_id"] not in interrupted:
                r.fail(f"scan {e['scan_id']} (seq {e['seq']}) has neither a verdict nor an interrupted record")
            if e["scan_id"] in safe:
                r.fail(f"scan {e['scan_id']} was reported safe to remove without a verdict")
        r.evidence["interrupted_scans"] = [e["scan_id"] for e in orphans]
    verify = subprocess.run(["runuser", "-u", "usbscan-events", "--", st.python, "-E", "-s", "-m", "src.events",
                             "--config", st.config_path, "--verify"],
                            cwd=REPO, capture_output=True, text=True, timeout=600)
    r.evidence["events_verify"] = (verify.stdout + verify.stderr).strip().splitlines()[-5:]
    if verify.returncode != 0:
        r.fail("audit chain / database verification failed")
    return r


def check_r02(st: Station, base: dict | None, cycles: int) -> Result:
    r = Result("AC-R02", f"{cycles} insert/scan/remove cycles without leaks, confusion or restarts")
    if base is None:
        r.status = SKIP
        r.note("no baseline")
        return r
    verdicts = st.events.since(base["seq"], ["verdict"])
    ids = [e["scan_id"] for e in verdicts]
    r.evidence["scans_since_baseline"] = len(ids)
    if len(ids) < cycles:
        r.status = PENDING
        r.note(f"{len(ids)} of {cycles} cycles recorded so far")
    if len(set(ids)) != len(ids):
        r.fail("a scan id was committed twice (device identity confusion)")
    started = {e["scan_id"] for e in st.events.since(base["seq"], ["scan_started"])}
    rejected = {e["scan_id"] for e in st.events.since(base["seq"], ["device_rejected"])}
    stray = [i for i in ids if i not in started and i not in rejected]
    if stray:
        r.fail(f"{len(stray)} verdicts without a matching scan start")
    now = st.snapshot()
    r.evidence["baseline_units"], r.evidence["now_units"] = base["units"], now["units"]
    for unit, b in base["units"].items():
        n = now["units"].get(unit, {})
        if n.get("n_restarts") != b.get("n_restarts") or n.get("pid") != b.get("pid"):
            r.fail(f"{unit} restarted during the cycles")
        if "fds" in b and "fds" in n and n["fds"] - b["fds"] > R02_MAX_FD_GROWTH:
            r.fail(f"{unit} open descriptors grew {b['fds']} -> {n['fds']}")
    if now["usb_mounts"]:
        r.fail(f"{now['usb_mounts']} USB mounts left after the last removal")
    leftovers = os.listdir(st.cfg.broker.mounts_dir) if os.path.isdir(st.cfg.broker.mounts_dir) else []
    r.evidence["mounts_dir_entries"] = leftovers
    return r


# --- disruptive checks ---------------------------------------------------------------------

def _state_wait(st: Station, seq: int, pred: Callable[[dict], bool], timeout: float) -> dict | None:
    return st.events.wait_for(seq, ["state_changed"], lambda e: pred(e["payload"]), timeout)


def check_r01(st: Station) -> Result:
    r = Result("AC-R01", "NOT_READY when clamd is unavailable, back to IDLE after recovery")
    interval = st.cfg.orchestrator.health_interval_seconds
    seq = st.events.max_seq()
    t0 = time.monotonic()
    units = ["clamav-daemon.socket", "clamav-daemon.service"]
    try:
        st.systemctl("stop", *units)
        ev = _state_wait(st, seq, lambda p: p.get("state") == "NOT_READY"
                         and "clamav_unavailable" in p.get("failures", []), 2 * interval + 30)
        if ev is None:
            r.fail("no NOT_READY with clamav_unavailable")
        else:
            r.evidence["not_ready_after_s"] = round(time.monotonic() - t0, 1)
            seq = ev["seq"]
    finally:
        st.systemctl("start", *units, check=False)
    t1 = time.monotonic()
    ev = _state_wait(st, seq, lambda p: p.get("state") == "IDLE", 600)
    if ev is None:
        r.fail("station did not return to IDLE within 600 s after clamd was started")
    else:
        r.evidence["idle_after_s"] = round(time.monotonic() - t1, 1)
    r.note("disk-space and signature-age gates: see the checklist (config override procedure)")
    return r


def _recover(st: Station, unit: str, signal: str) -> dict:
    """Send ``signal`` to the unit's main process; time until a new process reports a state."""
    before = st.unit_props(unit, "MainPID")
    seq = st.events.max_seq()
    t0 = time.monotonic()
    st.systemctl("kill", "-s", signal, "--kill-whom=main", unit)
    ev = _state_wait(st, seq, lambda p: p.get("state") in ("IDLE", "NOT_READY"), 180)
    elapsed = time.monotonic() - t0
    after = st.unit_props(unit, "MainPID", "NRestarts", "ActiveState", "Result")
    return {"signal": signal, "pid_before": before.get("MainPID"), "after": after,
            "recovered_after_s": round(elapsed, 1), "state": ev["payload"] if ev else None,
            "recovered": ev is not None and after.get("MainPID") not in ("0", before.get("MainPID"))}


def check_r04(st: Station) -> Result:
    r = Result("AC-R04", f"Crashed and hung orchestrator recovered within {R04_LIMIT_SECONDS} s")
    unit = "usb-scan-orchestrator"
    r.evidence["unit"] = st.unit_props(unit, "WatchdogUSec", "TimeoutAbortUSec", "RestartUSec",
                                       "StartLimitBurst", "StartLimitIntervalUSec")
    # Crash: the process dies -> Restart=always. Hang: SIGSTOP stops the watchdog pings ->
    # SIGABRT after WatchdogSec (cannot act on a stopped process) -> SIGKILL after
    # TimeoutAbortSec -> restart. SIGSTOP is therefore the worst case of a hang.
    for name, sig in (("crash", "SIGKILL"), ("hang", "SIGSTOP")):
        res = _recover(st, unit, sig)
        r.evidence[name] = res
        if not res["recovered"]:
            r.fail(f"{name}: orchestrator not restarted or no IDLE/NOT_READY state "
                   f"(unit {res['after'].get('ActiveState')}/{res['after'].get('Result')}; "
                   "after a start-limit trip: systemctl reset-failed usb-scan-orchestrator)")
        elif res["recovered_after_s"] > R04_LIMIT_SECONDS:
            r.fail(f"{name}: recovery took {res['recovered_after_s']} s")
        if name == "crash":
            time.sleep(10)      # let the new process finish start-up so its watchdog is armed
    r.note("two restarts; run at most once per 5 minutes (start limit 3 in 5 min)")
    return r


def check_s05(st: Station, config: str) -> Result:
    r = Result("AC-S05", "PIN lockout persists across a GUI restart")
    q = st.probe("usbscan-gui", "lockout", "--config", config, "query")
    if "error" in q:
        r.fail(f"lockout query failed: {q['error']}")
        return r
    if q.get("locked_out"):
        r.status = SKIP
        r.note("operator already locked out; wait pin.lockout_minutes and run again")
        return r
    n = st.cfg.pin.max_failed_attempts
    attempts = st.probe("usbscan-gui", "lockout", "--config", config, "fail", str(n), timeout=120)
    r.evidence["attempts"] = attempts.get("attempts", attempts)
    if "error" in attempts or not attempts["attempts"][-1].get("locked_out"):
        r.fail("lockout not triggered after max_failed_attempts")
        return r
    st.systemctl("restart", "usb-scan-gui")
    time.sleep(5)
    r.evidence["gui_active"] = st.unit_props("usb-scan-gui", "ActiveState").get("ActiveState")
    q2 = st.probe("usbscan-gui", "lockout", "--config", config, "query")
    r.evidence["after_gui_restart"] = q2
    if q2.get("locked_out") is not True:
        r.fail("lockout cleared by a GUI restart")
    r.note(f"the operator overlay stays locked for {st.cfg.pin.lockout_minutes} min")
    return r


# --- commands ------------------------------------------------------------------------------

def cmd_run(st: Station, opts) -> int:
    base = st.load_state(BASELINE)
    since = base["seq"] if base else 0
    checks: list[tuple[str, Callable[[], Result]]] = [
        ("PRE", lambda: check_pre(st)),
        ("AC-F05", lambda: check_f05(st)),
        ("AC-F07", lambda: check_f07(st, since)),
        ("AC-S01", lambda: check_s01(st)),
        ("AC-S02", lambda: check_s02(st, base)),
        ("AC-S04", lambda: check_s04(st, opts.config)),
        ("AC-S06", lambda: check_s06(st)),
        ("AC-R02", lambda: check_r02(st, base, opts.cycles)),
        ("AC-R03", lambda: check_r03(st)),
    ]
    if opts.destructive:
        checks += [("AC-S05", lambda: check_s05(st, opts.config)),
                   ("AC-R01", lambda: check_r01(st)),
                   ("AC-R04", lambda: check_r04(st))]
    only = set(filter(None, (opts.only or "").split(",")))
    results = []
    for cid, fn in checks:
        if only and cid not in only:
            continue
        try:
            res = fn()
        except Exception as exc:     # a broken check is a failed check, never a pass
            res = Result(cid, "check raised", FAIL, [f"{type(exc).__name__}: {exc}"])
        results.append(res)
        print(f"{res.status:8} {res.check_id:7} {res.title}")
        for line in res.details:
            print(f"         {line}")
    report = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "boot_id": boot_id(),
              "station_id": st.cfg.station.station_id, "destructive": opts.destructive,
              "baseline": base, "results": [x.to_dict() for x in results]}
    path = st.save_state(f"report-{report['time_utc'].replace(':', '')}.json", report)
    print(f"report: {path}")
    return 1 if any(x.status == FAIL for x in results) else 0


def cmd_watch_mounts(st: Station, opts) -> int:
    """AC-S03: observe every broker mount while reference media are scanned."""
    seen: dict[tuple[str, int], list[str]] = {}
    deadline = time.monotonic() + opts.seconds
    print(f"watching {st.cfg.broker.mounts_dir} for {opts.seconds} s: insert the reference media now")
    while time.monotonic() < deadline:
        for e in st.usb_mounts():
            key = (e.mountpoint, e.mount_id)
            if key not in seen:
                problems = usb_mount_problems(e, lambda rel, e=e: sysfs_block_attr(e.major, e.minor, rel))
                seen[key] = problems
                print(f"{'FAIL' if problems else 'ok  '} {e.fs_type:6} {','.join(sorted(e.mount_options))} "
                      f"{e.mountpoint} {'; '.join(problems)}")
        time.sleep(0.2)
    report = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "mounts": [{"mountpoint": k[0], "problems": v} for k, v in seen.items()]}
    print(f"report: {st.save_state('ac-s03-mounts.json', report)}")
    if not seen:
        print("PENDING AC-S03: no mount observed")
        return 2
    failed = any(seen.values())
    print(f"{'FAIL' if failed else 'PASS'} AC-S03: {len(seen)} mounts observed")
    return 1 if failed else 0


def cmd_scans(st: Station, opts) -> int:
    for e in st.events.since(opts.since_seq, ["verdict", "device_rejected", "scan_interrupted"]):
        p = e["payload"]
        if e["type"] == "verdict":
            c = p.get("coverage", {})
            print(f"{e['seq']:>7} {e['ts']} VERDICT {p.get('verdict'):10} reasons={','.join(p.get('reason_codes', []))} "
                  f"parts={c.get('partitions_scanned')}/{c.get('partitions_discovered')} "
                  f"files={c.get('files_scanned')}/{c.get('files_discovered')} clamav_complete={c.get('clamav_complete')} "
                  f"threats={p.get('threat_count')}")
        else:
            print(f"{e['seq']:>7} {e['ts']} {e['type'].upper()} {json.dumps(p, sort_keys=True)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_acceptance")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--destructive", action="store_true")
    run.add_argument("--only", help="comma-separated check ids, e.g. AC-F05,AC-S04")
    run.add_argument("--cycles", type=int, default=100)
    sub.add_parser("baseline")
    wm = sub.add_parser("watch-mounts")
    wm.add_argument("--seconds", type=int, default=300)
    sc = sub.add_parser("scans")
    sc.add_argument("--since-seq", type=int, default=0)
    opts = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("run_acceptance: must run as root on the station", file=sys.stderr)
        return 2
    try:
        cfg = load_config(opts.config)
    except ConfigError as exc:
        print(f"run_acceptance: {exc}", file=sys.stderr)
        return 2
    st = Station(cfg, config_path=opts.config)
    try:
        if opts.cmd == "baseline":
            print(f"baseline: {st.save_state(BASELINE, st.snapshot())}")
            return 0
        return {"run": cmd_run, "watch-mounts": cmd_watch_mounts, "scans": cmd_scans}[opts.cmd](st, opts)
    finally:
        st.events.close()


if __name__ == "__main__":
    sys.exit(main())
