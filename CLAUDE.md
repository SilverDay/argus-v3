# USB Scan Station

Autonomous USB malware scanning appliance — Raspberry Pi 5, Trixie OS.
Zero user interaction. PySide6 kiosk GUI + ClamAV + optional YARA/VirusTotal.
Spec: docs/USB-Scan-Station-Spec-v1.5.md
Plan: docs/USB-Scan-Station-Implementation-Plan-v1.5.md

## Architecture

- `src/broker/` — Privileged device broker. Runs as root. Custom minimal service;
  NO udisks2, NO dasbus, NO D-Bus. Exposes strictly allowlisted JSON/RPC over a
  root-owned Unix socket. The orchestrator NEVER calls udisks2 or mounts directly.
- `src/orchestrator/` — Scan daemon (usbscand). Unprivileged (user: usbscan).
  Coordinates scan pipeline; calls broker via RPC; drives IPC to GUI and events service.
- `src/yara_worker/` — Isolated YARA scan process (user: yarascan).
  Receives scan work via its own Unix socket. Has read-only mount namespace access.
  Killed by orchestrator watchdog on global budget expiry.
- `src/gui/` — PySide6 fullscreen kiosk (user: usbscan-gui). Pure display client.
  Zero scan logic. Subscribes to orchestrator state socket.
- `src/led/` — GPIO LED controller (group: gpio). lgpio/rpi-lgpio ONLY (NOT RPi.GPIO).
- `src/web/` — Flask + HTMX admin UI (user: usbscan-web). OIDC/SSO + MFA for remote
  admin. Local named-account fallback only for isolated networks. No shared PIN for admin.
- `src/events/` — Durable event/logging service (user: usbscan-events).
  SQLite WAL, event hash chain, SIEM forwarding queue.
- `src/shared/` — Config loader, data models, IPC protocol, auth, logging, secret refs.
  No hardware deps; must run on a dev laptop.

## Stack

Python 3.13, PySide6 6.11.x, ClamAV (clamd socket), yara-python 4.5.x,
Flask 3.1.x + HTMX, SQLite WAL, lgpio (system pkg) / rpi-lgpio, bcrypt 5.0.0,
httpx 0.27+. USBGuard (system service). No udisks2. No dasbus. No RPi.GPIO.

## Key Design Rules — Violations Will Be Rejected

- **NO udisks2, NO dasbus, NO D-Bus mounts.** All mount operations go through
  `src/broker/` via authenticated Unix socket RPC.
- **Broker receives sysfs identifiers or partition UUIDs, never raw /dev/ paths.**
- **GUI is a pure display client.** Zero scan logic in src/gui/. State driven entirely
  by ScanEvent objects received on the IPC socket.
- **PINs are NEVER stored in plaintext.** bcrypt hash at cost 12 minimum. Never log or
  print a PIN at any verbosity level. PIN length: minimum 6 digits (spec §10.1).
- **No secrets or credential hashes in scan_station.yaml.** Secret fields are
  references (`file:`, `credential:`, `env:`) resolved by `src/shared/secret_refs.py`.
- **USB mounts are always read-only** (ro, noexec, nosuid, nodev, nosymfollow + FS-specific
  opts; block device set read-only first). See docs/broker-design-notes.md.
- **ClamAV via FILDES:** the orchestrator opens files and passes fds to clamd; clamd needs
  no mount access. clamd.conf must have AlertExceedsMax/AlertEncrypted (config/clamd.conf.recommended).
- **All external HTTP calls use TLS with certificate verification.** httpx, not
  requests. Never disable verification.
- **Trixie venv:** MUST use `--system-site-packages` for lgpio. Do NOT pip install lgpio.
- **bcrypt 5.0.0:** inputs >72 bytes raise ValueError — validate length first.
- **Trixie sudo:** passwordless sudo is disabled by default; do not re-enable it.
- **Operator PIN scope:** strictly local touchscreen overlay for operator functions only.
  Cannot authorize scans, mounts, config changes, or remote sessions.
- **Fail closed:** missing inspection is never CLEAN (spec §3.3).

## Verdicts (7 total — src/shared/models.py)

CLEAN | THREAT | SUSPICIOUS | INCOMPLETE | ERROR | REJECTED | NOT_READY

## Coverage Metrics (required in every ScanResult)

partitions_discovered, partitions_scanned, partitions_excluded,
files_discovered, files_scanned, files_skipped, files_failed, files_uninspectable,
bytes_enumerated, bytes_read, skip_reasons, clamav_complete,
yara_complete (if enabled), vt_complete (if enabled)

## IPC Sockets

- Broker RPC:         /run/usb-scan/broker.sock     (0660 root:usbscan, SO_PEERCRED + HMAC)
- Orchestrator → GUI: /run/usb-scan/state.sock      (0660 usbscan:usbscan-gui)
- Orchestrator → LED: /run/usb-scan/led.sock        (0660 usbscan:gpio)
- YARA worker:        /run/usb-scan/yara.sock       (0660 usbscan:yarascan)
- Events service:     /run/usb-scan/events.sock     (0660 usbscan:usbscan-events)

## Test Commands

pytest tests/unit/              # no hardware required
pytest tests/integration/       # requires clamd running and loopback device
pytest tests/acceptance/        # full stack, Pi only

## Skills

.claude/skills/device-broker/, clamav-integration/, pyside6-statemachine/

## Spec Reference

docs/USB-Scan-Station-Spec-v1.5.md — authoritative. When in doubt, check the spec.
§3.3 verdict semantics · §3.4 coverage metrics · §3.5 operator_hold ·
§5.4 service privileges · §6.2 config validation · §8.2 USBGuard/broker · §10.1 PIN
Design notes / deviations: docs/broker-design-notes.md, docs/orchestrator-design-notes.md

## Commit Style

feat: | fix: | test: | chore: | docs: | refactor:
One feature per commit. Never commit secrets, PIN hashes, or TLS private keys.
