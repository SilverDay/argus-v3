# Acceptance testing (Phase 12)

Files:
- `tests/acceptance/run_acceptance.py`: on-device CLI (`baseline`, `run [--destructive]`,
  `watch-mounts`, `scans`). Writes JSON reports to `<host.data_mountpoint>/acceptance/`.
- `tests/acceptance/station.py`: station access and the pure evaluation functions.
- `tests/acceptance/probes.py`: probes run as service accounts (socket peer tests, broker
  negative requests, PIN lockout, PIN pad layouts).
- `tests/acceptance/test_acceptance.py`: the same checks under `pytest tests/acceptance/`
  (skipped off-station; disruptive ones need `USB_SCAN_ACCEPTANCE_DESTRUCTIVE=1`).
- `tests/acceptance/MANUAL_TEST_CHECKLIST.md`: procedure, reference media, evidence and
  sign-off sheet, traceability to the CI tests.

## Design choices

- **The audit DB is read with SQLite `mode=ro`, not through events.sock.** Root is
  deliberately none of the socket's roles, and the acceptance tool must not need a change to
  the production access policy. `mode=ro` refuses writes (unit-tested).
- **State is observed from the audit log.** Every state change except progress is
  committed, so the tool needs no state.sock subscription. That subscription is reserved for
  the GUI and LED accounts.
- **Probes drop to the real service accounts.** The child process uses the account's uid,
  primary gid and supplementary groups (`subprocess` `user`/`group`/`extra_groups`), so
  socket file permissions and SO_PEERCRED checks are exercised exactly as in production.
  The broker probe runs as `usbscan` with the real key. A refusal therefore comes from the
  broker's own validation, not from a missing peer right. Its expectations were checked
  against the real broker server (`tests/unit/broker/test_acceptance_probe.py`).
- **PIN lockout probe.** It sends a PIN that the PIN policy forbids (single repeated digit).
  `pin_admin` can therefore never have set it. The probe refuses to run if the policy would
  allow it. No PIN is printed.
- **AC-S06 drives the production `MainWindow` offscreen as `usbscan-gui`.** pytest is not
  needed on the station. The hardened firewall gives root no HTTPS egress, so pip cannot
  install test packages there.
- **AC-S01 reboot evidence.** A marker file is written to the root overlay, and its boot id
  is stored on the data partition. A run after a reboot checks that the marker is gone.
- **Results.** PENDING and SKIP are never reported as PASS, and a check that raises counts as
  FAIL.

## Gaps found and closed in this phase

| Gap | Change |
|---|---|
| Spec §3.8 synthetic scan (SHALL; AC-F05) was not implemented | `src/orchestrator/synthetic.py`, `synthetic_scan` event, health failure `synthetic_scan_failed` (orchestrator-design-notes.md) |
| Socket-activated clamd: systemd's default `SocketMode=0666` would apply instead of `LocalSocketMode` | `systemd/clamav-daemon.socket.d/usb-scan.conf` (0660, group clamav); AC-S04 checks the clamd socket too |
| No unit tests for the `disk_space_low` and `clock_invalid` gates | added (AC-R01) |

## Owner decisions (spec 1.5.8, 14 October 2026)

1. **AC-R04 covers crash and hang within 30 s.**
   - The orchestrator unit uses `WatchdogSec=15` (pinged every 7.5 s), `TimeoutAbortSec=5`
     and `RestartSec=2`.
   - Without `TimeoutAbortSec` a watchdog abort waits `TimeoutStopSec` (30 s), because
     systemd leaves `DefaultTimeoutAbortSec` unset.
   - The acceptance check sends SIGKILL (crash), then SIGSTOP (hang). SIGSTOP is the worst
     case: the stopped process cannot act on SIGABRT, so it is killed after
     `TimeoutAbortSec`.
   - Broker and events service keep `WatchdogSec=30`.
2. **The USBGuard HID rule uses `block`, not `reject`.**
   - `reject` also removes the device (USBGuard rules documentation), so the orchestrator
     could only log `device_gone`.
   - `block` keeps the device enumerated but unauthorised: no driver binds to any interface,
     so the protection is the same.
   - The audit chain then always records REJECTED / `usb_policy_blocked`. The station
     shows REJECTED until the device is removed.
3. **VirusTotal hash sharing is approved as a per-site opt-in.**
   - It stays disabled by default and is hash-only (no uploads).
   - A site enables it after its own privacy approval (spec §15.2 #3).
4. **The GUI ships English (source) and German.**
