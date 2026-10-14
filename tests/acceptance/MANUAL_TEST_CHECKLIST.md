# Acceptance test procedure and sign-off (spec §14)

Station: ____________  Image/commit: ____________  Tester: ____________  Date: ____________

This procedure combines the automated on-device checks (`run_acceptance.py`) with the steps
that need a person, reference media or a power cut. Record evidence (report file names,
`seq` numbers, photos of the screen) in the tables. A criterion is accepted only when all its
rows are PASS.

## 0. Preparation

| # | Step | Done |
|---|---|---|
| 0.1 | Station provisioned per docs/deployment.md (§1–§6) and hardened (§7a). Rebooted with the read-only root: `scripts/maintenance-mode.sh status` shows the overlay active | ☐ |
| 0.2 | Admin access via SSH from a management network or the serial console. A USB keyboard is rejected by design | ☐ |
| 0.3 | ClamAV signatures current. The admin dashboard or the last `health` event shows `signature_age_hours` below `clamav.max_signature_age_hours` | ☐ |
| 0.4 | Reference media prepared on a workstation (table below). Keep them labelled. | ☐ |
| 0.5 | `cd /opt/usb-scan && sudo .venv/bin/python -m tests.acceptance.run_acceptance baseline`. Records the event sequence, unit restart counters, descriptors and memory under `<data_mountpoint>/acceptance/` | ☐ |

All commands below run from `/opt/usb-scan` as root (`sudo -i`). `RA` stands for
`.venv/bin/python -m tests.acceptance.run_acceptance`.

### Reference media

| ID | Medium | Content | Expected |
|---|---|---|---|
| M1 | FAT32 stick, 8–32 GB | a few hundred ordinary documents/images, no archives with passwords | CLEAN |
| M2 | FAT32 stick | M1 content plus `eicar.com` (EICAR test string, from eicar.org) | THREAT |
| M3 | stick with two partitions: FAT32 + ext4 | clean files on both | CLEAN, `partitions_scanned=2` |
| M4 | stick with FAT32 + an unsupported/unknown partition (e.g. a raw partition with no filesystem, or HFS+) | clean files on the FAT32 partition | INCOMPLETE (`partition_not_inspected` + `partition_<status>`, e.g. `partition_unsupported`), never CLEAN |
| M5 | disk larger than `device.max_device_capacity_gb`. Alternatively, lower the setting temporarily below M1's size and restart the orchestrator | any | REJECTED `capacity_exceeded` |
| M6 | large stick (≥ 16 GB of data) | many files | used for AC-F06 (scan long enough to interrupt) |
| H1 | USB keyboard | – | blocked by USBGuard |
| H2 | composite HID + mass storage device (e.g. a "BadUSB" test device, a keyboard with a card reader, or a hub-less combo) | – | rejected by USBGuard, never scanned |

## 1. Automated checks (non-disruptive)

Run `RA run`. Attach the printed report path. Some checks need the manual steps
below first; run `RA run` again at the end.

| Check | What it verifies | Result | Report / evidence |
|---|---|---|---|
| PRE | units active, usbguard and clamd active, station IDLE, board model | | |
| AC-F05 | SIGUSR1 → `synthetic_scan` event: EICAR found, control clean, verdict THREAT, `passed=true` | | |
| AC-F07 | every `verdict` record since the baseline carries all coverage metrics (`yara_complete`/`vt_complete` typed per enabled engine) | | |
| AC-S01 | `/` is the overlay; `overlayroot=tmpfs:recurse=0`; writable block-device mounts are only the data partition and its four bind mounts (+ quarantine); `/boot/firmware` ro. A marker is written to the root overlay; after the reboot (step 4.3) it must be gone | | |
| AC-S02 | needs step 3.2 | | |
| AC-S04 | socket peer matrix (broker, events, state, clamd, yara) for nobody/GUI/web/LED/events/yara accounts; broker refuses unknown commands, `/dev` paths, the internal disk's sysfs path, traversal, unknown sessions, forged HMAC | | |
| AC-S06 | the production PIN overlay (offscreen) shows 100 different layouts in 100 presentations, every digit once | | |
| AC-R02 | needs step 4.1 | | |
| AC-R03 | needs step 4.2. Also runs `src.events --verify` | | |

## 2. Automated checks (disruptive)

Station idle and nobody waiting to scan. Run `RA run --destructive --only AC-S05,AC-R01,AC-R04`.
- AC-S05 locks the operator overlay for `pin.lockout_minutes`.
- Leave at least 5 minutes between repeated runs of AC-R04 (start limit: 3 restarts in 5 min).

| Check | What it verifies | Result | Evidence |
|---|---|---|---|
| AC-S05 | wrong PINs (a value the PIN policy forbids, so it can never be the real PIN) sent as the GUI account until lockout; `usb-scan-gui` restarted; a new GUI connection still reads `locked_out=true` | | |
| AC-R01 (clamd) | `clamav-daemon.socket` + `.service` stopped → NOT_READY `clamav_unavailable` within 2 health intervals; started → IDLE | | |
| AC-R04 (crash + hang) | SIGKILL, then SIGSTOP (watchdog path) to the orchestrator → each time a new PID reports IDLE/NOT_READY within 30 s | | |

## 3. Manual functional and security steps

### 3.1 Functional scans (AC-F01 … AC-F04, AC-F06)

For each medium:
1. Insert it.
2. Wait for the result screen.
3. Photograph the screen.
4. Remove the medium after "safe to remove".

Then run `RA scans --since-seq <baseline seq>` and copy the matching line.

| AC | Medium | Expected | Screen shows (verdict, warning) | `RA scans` line (seq, verdict, reasons, coverage) | Result |
|---|---|---|---|---|---|
| AC-F01 | M1 | CLEAN; `files_scanned` = `files_discovered`; `clamav_complete=True`; no skipped/excluded partitions; "safe to remove" only after unmount | | | |
| AC-F02 | M2 | THREAT; ClamAV signature named in the record (`Win.Test.EICAR_HDB-1` or similar); red screen with a clear "do not use" warning; no file path on the public screen | | | |
| AC-F03 | M3 | CLEAN with `partitions_discovered=2`, `partitions_scanned=2` | | | |
| AC-F03 | M4 | INCOMPLETE with `partition_not_inspected` and `partition_<status>` (default `require_full_coverage: true`); `partitions_excluded=1` | | | |
| AC-F04 | M5 | REJECTED `capacity_exceeded`; restore the setting afterwards | | | |
| AC-F06 (mandatory engine) | M6 | Insert, wait for SCANNING, then `systemctl stop clamav-daemon.socket clamav-daemon.service`. Expected: ERROR (`appliance_fault` / `required_engine_failed`) or INCOMPLETE, never CLEAN. Then `systemctl start clamav-daemon.socket clamav-daemon.service` | | | |
| AC-F06 (advisory engine) | M1, with YARA `role: advisory` and the YARA worker stopped (`systemctl stop usb-scan-yara`) | CLEAN still possible; the record shows `yara_complete=false` and a `yara_unavailable` reason; restore afterwards | | | |

### 3.2 USB policy (AC-S02, AC-S03)

| # | Step | Expected | Observed | Result |
|---|---|---|---|---|
| 3.2.1 | Insert H1 (keyboard). Type on it. | No input reaches the kiosk. The station shows a rejection or stays IDLE. Never VALIDATING/SCANNING. | | |
| 3.2.2 | Insert H2 (HID+storage composite) | Rejected before any scan state. The record is `device_rejected` with reason `usb_policy_blocked`. No `scan_started` and no mount. | | |
| 3.2.3 | `RA run --only AC-S02` | PASS. Evidence: the `device_rejected` records and `usbguard list-rules` output. | | |
| 3.2.4 | `RA watch-mounts --seconds 300`, then insert M1 and M3 (FAT32 and ext4) | Every mount `ro,noexec,nosuid,nodev,nosymfollow`, block device and disk read-only. Exit code 0, "PASS AC-S03". | | |
| 3.2.5 | While M1 is mounted (during SCANNING): `touch <mount>/x` as root and as usbscan | Read-only file system / permission denied | | |

Note on 3.2.2: the HID rule uses USBGuard `block` (spec 1.5.8). The device stays enumerated
but unauthorised; no driver binds to any of its interfaces. The station shows REJECTED until
it is removed. A `device_gone` reason instead of `usb_policy_blocked` is a FAIL.

### 3.3 Operator PIN pad (AC-S06 visual)

| Step | Expected | Result |
|---|---|---|
| Long-press the operator area five times, cancelling each time | The digit layout differs every time; all ten digits shown; 48×48 px targets | |

## 4. Reliability (AC-R01 … AC-R04)

| # | Step | Expected | Observed | Result |
|---|---|---|---|---|
| 4.1 | AC-R02: 100 cycles. Alternate M1 and M2: insert → result → remove; then `RA run --only AC-R02` | PASS: ≥ 100 verdicts since the baseline, unique scan ids, every verdict matched by a scan start or rejection, no unit restart, no leftover USB mounts, descriptor growth ≤ 16 | | |
| 4.2 | AC-R03: insert M6, wait for SCANNING, **pull the power**. Restore power. After boot run `RA run --only AC-R03` and look at the screen. | PASS: the scan has a `scan_interrupted` record (`safe_to_remove=false`), no "safe to remove" for it, `src.events --verify` OK; station boots to IDLE; config and DB intact | | |
| 4.3 | AC-S01 reboot: `systemctl reboot`, then `RA run --only AC-S01` | PASS: marker from before the reboot is gone | | |
| 4.4 | AC-R01 signatures: note `signature_age_hours` from the last health event. Set `clamav.max_signature_age_hours` to a value below it, then `systemctl restart usb-scan-orchestrator` | NOT_READY `signatures_stale`; restore the value, restart → IDLE | | |
| 4.5 | AC-R01 disk space: `df -m /var/lib/usb-scan`. Set `health.min_free_disk_mb` above the free space, restart the orchestrator | NOT_READY `disk_space_low`; restore, restart → IDLE | | |
| 4.7 | Boot to IDLE: power-cycle and measure time from power-on to the IDLE screen | Record the value (FR target from the spec) | | |

Notes:
- 4.4 and 4.5 change `/etc/usb-scan/scan_station.yaml`, which is on the persistent
  partition. Restore the original values. Leave 5 minutes between orchestrator restarts
  (start limit).
- AC-R04 (section 2) covers the crash (SIGKILL) and the hang (SIGSTOP: watchdog abort
  after `WatchdogSec=15`, SIGKILL after `TimeoutAbortSec=5`, restart after `RestartSec=2`).
  Both must finish within 30 s (spec §11, 1.5.8).

## 5. After the run

| Step | Done |
|---|---|
| `aa-logprof` to review AppArmor complain-mode denials collected during the run; then `scripts/harden.sh --apparmor-enforce` and re-run sections 1–2 | ☐ |
| `journalctl -k \| grep usbscan-drop-out` reviewed: no drops for freshclam/NTP/DNS | ☐ |
| Reports in `<data_mountpoint>/acceptance/` archived with this sheet | ☐ |
| Acceptance state removed: `rm -r <data_mountpoint>/acceptance` (after archiving) | ☐ |

## Traceability: criterion → automated tests

| AC | Unit / integration tests (CI, no hardware) | On-device |
|---|---|---|
| F01 | `tests/unit/orchestrator/test_orchestrator.py::test_clean_scan_full_lifecycle`, `tests/integration/test_scan_pipeline.py::test_clean_volume` | 3.1 M1 |
| F02 | `test_threat_detected`, `test_scan_pipeline.py::test_eicar_is_threat` | 3.1 M2 |
| F03 | `test_unsupported_partition_prevents_clean`, `test_msr_*`, `test_policy_never_excludes_*` | 3.1 M3/M4 |
| F04 | `test_capacity_exceeded_rejected` | 3.1 M5 |
| F05 | `tests/unit/orchestrator/test_synthetic.py`, `test_scan_pipeline.py::test_synthetic_scan_against_real_clamd` | AC-F05 |
| F06 | `test_clamd_failure_mid_scan_is_error`, `test_yara_timeout_by_role`, `test_yara_worker_dies_mid_scan`, `test_optional_modules.py::test_vt_advisory_*`, `test_config.py::test_clamav_cannot_be_advisory` | 3.1 AC-F06 |
| F07 | `test_coverage_metrics_complete_in_record`, `tests/unit/acceptance/test_acceptance_helpers.py` | AC-F07 |
| S01 | `tests/unit/host/test_render.py`, `test_acceptance_helpers.py::test_persistent_writable_paths_bounded` | AC-S01, 4.3 |
| S02 | `test_precheck_rejections` (usb_policy_blocked, hid_interface), USBGuard rules parser check (Phase 10) | 3.2.1–3.2.3 |
| S03 | `tests/integration/test_broker_loopback.py::test_readonly_mount_flags`, `tests/unit/broker/test_commands.py::test_enumerate_lists_partitions_and_sets_readonly`, `test_resolve_open.py` | 3.2.4–3.2.5 |
| S04 | `tests/unit/broker/test_server.py`, `test_commands.py`, `tests/unit/broker/test_acceptance_probe.py` | AC-S04 |
| S05 | `tests/unit/shared/test_auth.py::test_lockout_persists_across_restart`, `test_pin_lockout_via_ipc_and_non_gui_ignored` | AC-S05 |
| S06 | `tests/unit/gui/test_gui.py::test_pin_layout_randomised_every_presentation` | AC-S06, 3.3 |
| R01 | `test_not_ready_and_recovery`, `test_stale_signatures_not_ready`, `test_low_disk_space_not_ready_and_recovery`, `test_invalid_clock_not_ready`, `test_broker_down_not_ready`, `test_synthetic.py::test_missed_detection_fails_closed_until_a_later_pass` | AC-R01, 4.4, 4.5 |
| R02 | – (needs hardware) | 4.1 |
| R03 | `test_interrupted_scan_recovered_after_restart`, events store durability tests | 4.2 |
| R04 | – (systemd) | AC-R04 |

## Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Tester | | | |
| Security owner | | | |
