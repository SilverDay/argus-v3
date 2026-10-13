# USB Scan Station — Implementation Plan
## Claude Code Edition

**Version:** 1.5  
**Based on:** Software Specification v1.5  
**Approach:** Phased, Claude Code agentic workflow  
**© SilverDay Media — Internal / Confidential**

---

## How to Use This Document

Work through phases sequentially. Each phase ends with a working, testable state. Start every Claude Code session by opening the project root (where `CLAUDE.md` lives) — Claude will load context automatically. Use **Plan Mode** (`Shift+Tab`) before each phase to let Claude map out the work before touching files.

> **Rule of thumb:** One phase = one Claude Code session. Run `/clear` between phases to prevent context drift. For investigation sub-tasks, use a subagent and report back — keep the main session focused on building.

---

## Phase 0 — Project Scaffold & Claude Code Setup

**Goal:** Correct directory structure, `CLAUDE.md`, skills, git, and virtual environment. Claude Code can navigate from here.

**Duration estimate:** 1–2 hours  
**Mode:** Manual + Claude Code `/init`

### Directory Structure

```
usb-scan-station/
├── CLAUDE.md
├── .claude/
│   ├── settings.json
│   └── skills/
│       ├── clamav-integration.md
│       ├── device-broker.md
│       └── pyqt6-statemachine.md
├── src/
│   ├── broker/             # Privileged device broker (runs as root, minimal surface)
│   ├── orchestrator/       # Scan daemon usbscand (runs as usbscan, unprivileged)
│   ├── yara_worker/        # Isolated YARA scan process (runs as yarascan)
│   ├── gui/                # PySide6 kiosk GUI (runs as usbscan-gui)
│   ├── led/                # GPIO LED service (runs as gpio group)
│   ├── web/                # Flask admin UI (runs as usbscan-web)
│   ├── events/             # Durable event/logging service (runs as usbscan-events)
│   └── shared/             # Config, models, IPC, auth, logging — used by all services
├── tests/
│   ├── unit/
│   ├── integration/
│   └── acceptance/
├── config/
│   └── scan_station.yaml   # Template — no secrets or hashes
├── systemd/
├── scripts/
└── docs/
```

### Steps

1. Create the repository:

```bash
mkdir usb-scan-station && cd usb-scan-station
git init
# TRIXIE: --system-site-packages makes lgpio (system package) available in the venv
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
```

2. Create the directory skeleton (run each separately — brace expansion issues with some shells):

```bash
mkdir -p src/broker src/orchestrator src/yara_worker src/gui src/led src/web src/events src/shared
mkdir -p tests/unit/shared tests/unit/broker tests/unit/orchestrator tests/unit/gui tests/unit/led tests/unit/web tests/unit/events
mkdir -p tests/integration tests/acceptance
mkdir -p .claude/skills config systemd scripts docs
```

3. Create `requirements.txt` (pinned, no udisks2/dasbus):

```
# GUI
PySide6>=6.11.1

# Scan engines
yara-python>=4.5.4

# Web admin
Flask>=3.1.3
Flask-Session>=0.8.0

# Auth
bcrypt>=5.0.0

# USB monitoring (udev events only — no D-Bus mount calls)
pyudev>=0.24.4

# GPIO (Pi 5 — do NOT pip install lgpio; this is for rpi-lgpio wrapper only)
rpi-lgpio>=0.6

# HTTP / VirusTotal
httpx>=0.27.0

# Config
pyyaml>=6.0.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0
pytest-qt>=4.4.0
```

> **Note:** `lgpio` itself is a system package on Trixie. The venv's `--system-site-packages` flag makes it available. `rpi-lgpio` is the Python wrapper. Do NOT `pip install lgpio`.

4. Run `/init` in Claude Code, then replace the generated `CLAUDE.md` with the content in the next section.

5. Create the skill files (content in following sections), then commit:

```bash
git add . && git commit -m "chore: initial project scaffold (spec v1.5)"
```

---

## CLAUDE.md

Place in the project root. Keep under 200 lines — link to skill files for depth.

```markdown
# USB Scan Station

Autonomous USB malware scanning appliance — Raspberry Pi 5, Trixie OS.
Zero user interaction. PySide6 kiosk GUI + ClamAV + optional YARA/VirusTotal.
Spec: docs/USB-Scan-Station-Spec-v1.5.md

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
- `src/shared/` — Config loader, data models, IPC protocol, auth, logging. No hardware deps.

## Stack

Python 3.13, PySide6 6.11.1, ClamAV (clamd socket, 1.5.x), yara-python 4.5.x,
Flask 3.1.x + HTMX, SQLite WAL, lgpio (system pkg) / rpi-lgpio, bcrypt 5.0.0,
httpx 0.27+. USBGuard (system service). No udisks2. No dasbus. No RPi.GPIO.

## Key Design Rules — Violations Will Be Rejected

- **NO udisks2, NO dasbus, NO D-Bus mounts.** All mount operations go through
  `src/broker/` via authenticated Unix socket RPC.
- **Broker receives sysfs identifiers or partition UUIDs, never raw /dev/ paths.**
  The orchestrator maps udev events to sysfs identifiers before calling the broker.
- **GUI is a pure display client.** Zero scan logic in src/gui/. State driven entirely
  by ScanEvent objects received on the IPC socket.
- **PINs are NEVER stored in plaintext.** bcrypt hash at cost 12 minimum. Never log or
  print a PIN at any verbosity level.
- **USB mounts are always read-only** (ro, noexec, nosuid, nodev + FS-specific safe opts).
  The broker creates a per-session mount namespace. Namespace is destroyed on unmount.
- **All external HTTP calls use TLS with certificate verification.** No exceptions.
  httpx, not requests. Verify CA bundle. No verify=False anywhere.
- **Trixie venv:** MUST use `--system-site-packages` for lgpio. Do NOT pip install lgpio.
- **bcrypt 5.0.0 limit:** inputs >72 bytes raise ValueError. Not an issue for 6-digit PINs
  but validate input length in auth.py regardless.
- **Trixie sudo:** passwordless sudo is disabled by default. Scripts requiring root must
  use `sudo` interactively or systemd ExecStartPre with explicit capability grants.
- **Remote admin auth:** OIDC/SSO + MFA (named accounts). No shared admin PIN for remote
  access. Local named-account fallback only when OIDC is explicitly disabled and the
  network is isolated.
- **Operator PIN scope:** strictly local touchscreen overlay for operator functions only.
  Cannot authorize scans, mounts, config changes, or remote sessions.

## Verdicts (7 total — src/shared/models.py)

CLEAN | THREAT | SUSPICIOUS | INCOMPLETE | ERROR | REJECTED | NOT_READY

## Coverage Metrics (required in every ScanResult)

partitions_discovered, partitions_scanned, partitions_excluded,
files_discovered, files_scanned, files_skipped, files_failed, files_uninspectable,
bytes_enumerated, bytes_read, clamav_complete, yara_complete (if enabled), vt_complete (if enabled)

## IPC Sockets

- Broker RPC:         /run/usb-scan/broker.sock     (root-owned, 0600)
- Orchestrator → GUI: /run/usb-scan/state.sock      (usbscan-owned, 0660 usbscan:usbscan-gui)
- Orchestrator → LED: /run/usb-scan/led.sock        (0660 usbscan:gpio)
- YARA worker:        /run/usb-scan/yara.sock        (0660 usbscan:yarascan)
- Events service:     /run/usb-scan/events.sock      (0660 usbscan:usbscan-events)

## Test Commands

pytest tests/unit/              # no hardware required
pytest tests/integration/       # requires clamd running and loopback device
pytest tests/acceptance/        # full stack, Pi only

## Spec Reference

docs/USB-Scan-Station-Spec-v1.5.md — authoritative. When in doubt, check the spec.
Section 3.3: Verdict semantics
Section 3.4: Coverage metrics
Section 3.5: operator_hold semantics
Section 5.4: Service privilege table
Section 8.2: USBGuard policy and broker constraints

## Commit Style

feat: | fix: | test: | chore: | docs: | refactor:
One feature per commit. Never commit secrets, PIN hashes, or TLS private keys.
```

---

## .claude/skills/device-broker.md

```markdown
---
name: device-broker
description: Custom privileged device broker architecture. Use when working on
  src/broker/, orchestrator mounter calls, or any USB mount/unmount/eject logic.
  CRITICAL: replaces udisks2/dasbus entirely. No D-Bus.
---

# Device Broker

## Purpose
The broker is the ONLY component that mounts filesystems. It runs as root with a
minimal allowlisted RPC interface. The orchestrator communicates with it via an
authenticated Unix socket — it never calls mount(8), udisks2, or D-Bus directly.

## Socket
Path: /run/usb-scan/broker.sock
Owner: root:root, mode 0600
Protocol: newline-delimited JSON with HMAC-SHA256 authentication per message.

## Allowed Commands (strict allowlist — all others return {"error": "unknown_command"})
- {"cmd": "enumerate", "sysfs_path": "..."}
  → Returns partition list with UUIDs and filesystem types.
- {"cmd": "mount", "partition_uuid": "...", "session_id": "..."}
  → Mounts read-only in a fresh mount namespace. Returns mount point path inside namespace.
- {"cmd": "unmount", "session_id": "..."}
  → Unmounts all partitions for session and destroys namespace.
- {"cmd": "eject", "sysfs_path": "..."}
  → Requests USB power-off via sysfs authorized attribute.
- {"cmd": "ping"}
  → Returns {"ok": true} for health check.

## Path Validation Rules
- Broker NEVER accepts raw /dev/sd* or /dev/disk/* paths from callers.
- Caller passes sysfs identifier (e.g. /sys/bus/usb/devices/1-1) or partition UUID.
- Broker resolves to block device internally; caller cannot influence resolution.
- Mount namespace is per-session (session_id from orchestrator). Destroyed on unmount.

## Mount Options (applied by broker, not caller)
FAT32/exFAT: ro,noexec,nosuid,nodev,uid=0,gid=<usbscan-read-gid>,dmask=0027,fmask=0137
NTFS (ntfs3): ro,noexec,nosuid,nodev,uid=0,gid=<usbscan-read-gid>,dmask=0027,fmask=0137
  → Validate kernel ntfs3 driver version before deployment; check CVE history.
  → Alternative: ntfs-3g with same options. Document which driver is used.
ext2/3/4: ro,noexec,nosuid,nodev
ISO 9660: ro,noexec,nosuid,nodev

## Mount Namespace Access for Scanners
ClamAV and YARA worker get ReadOnlyPaths=/run/usb-scan/mounts/<session_id>/ in their
systemd unit via a per-scan transient drop-in, not a persistent systemd unit change.
This avoids exposing previous sessions' mounts to current scanner processes.

## Orchestrator Side (src/orchestrator/broker_client.py)
broker_client = BrokerClient("/run/usb-scan/broker.sock", hmac_key=...)
partitions = await broker_client.enumerate(sysfs_path)
mount_result = await broker_client.mount(partition_uuid, session_id)
await broker_client.unmount(session_id)
await broker_client.eject(sysfs_path)
```

---

## .claude/skills/clamav-integration.md

```markdown
---
name: clamav-integration
description: ClamAV clamd socket protocol, scan result parsing, error handling,
  and freshclam integration. Use when working on scan pipeline or health checks.
---

# ClamAV Integration

## Communication
Use clamd Unix socket at /var/run/clamav/clamd.ctl (not TCP).
Send INSTREAM command for file scanning via socket streaming.
Send VERSION command for daemon + signature version.

## Python Pattern
Use asyncio StreamReader/StreamWriter. Do NOT use blocking socket calls.
Chunk size for INSTREAM: 4096 bytes. Terminate with zero-length chunk (4-byte big-endian 0).

## Result Parsing
OK response:     `stream: OK`
Threat found:    `stream: Eicar-Test-Signature FOUND`
Parse: `name, status = line.rsplit(' ', 1)`
status == 'OK' → clean; status == 'FOUND' → threat; anything else → error

## Error Handling
clamd unavailable → verdict = ERROR, clamav_complete = False, log clamd_unreachable=True
File too large for clamd → files_skipped++ with reason 'too_large_for_engine'
Timeout → files_failed++ with reason 'timeout', clamav_complete = False

## Coverage Tracking
Track per-file: scanned | detected | skipped | failed | timeout | encrypted | unsupported
Aggregate into ScanResult.coverage metrics. clamav_complete=True only if zero failed/timeout.

## Health Check
On startup: send PING → expect PONG. Check VERSION for signature age.
Signature age > config.clamav.max_signature_age_hours → station NOT_READY.
```

---

## .claude/skills/pyqt6-statemachine.md

```markdown
---
name: pyqt6-statemachine
description: PySide6 state machine pattern for the kiosk GUI. Use when working on
  GUI states, transitions, animations, the IPC event loop, or PIN overlay.
  Note: spec uses PySide6 (preferred), not PyQt6. API is nearly identical.
---

# PySide6 GUI State Machine

## States (11 total — src/gui/state_machine.py)
STARTING | NOT_READY | IDLE | VALIDATING | MOUNTING | SCANNING | EVALUATING |
OPERATOR_HOLD | EJECTING | RESULT | EJECT_FAILED | REJECTED | ERROR
Defined as QState objects; transitions driven by ScanEvent objects from IPC socket.

## Rules
- NEVER call scan logic, broker RPC, or mount operations from GUI code.
- All state transitions driven by ScanEvent objects received on the IPC state socket.
- Use QPropertyAnimation for transitions — no blocking calls on the UI thread.
- IPC socket reader runs in a QThread — emits Qt signals to the main thread only.

## PIN Overlay (widgets/pin_overlay.py)
- Digit positions MUST be randomized on every show() call: random.shuffle(digit_list)
- Render digits as QLabel with text '●' — never display the actual digit
- Long-press detection: QTimer(3000ms) started on touchDown in the IDLE reserved region
- Lockout state persisted to events DB; check via IPC before allowing entry attempt
- Operator functions only: last scan summary, health status, language, operator_hold ack

## operator_hold (OPERATOR_HOLD state)
- Only available after CLEAN or SUSPICIOUS verdict (never THREAT)
- Entered when config.operator_hold.enabled=true and scan completes
- Display: PIN entry required + countdown timer showing remaining hold seconds
- On timeout: auto-transition to EJECTING (no operator action)
- On PIN accepted: operator may view result summary and acknowledge → EJECTING
- Log entry on OPERATOR_HOLD enter and exit (reason: acknowledged | timeout | removed)

## Touchscreen
Minimum tap target: 48×48px. Use QTouchEvent, not mouse events.
```

---

## Phase 1 — Shared Foundation

**Goal:** Config loader, data models (7 verdicts + full coverage metrics), IPC protocol, PIN auth, and logging. Everything else depends on this.

**Duration estimate:** 3–5 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and docs/USB-Scan-Station-Spec-v1.5.md sections 3.3 and 3.4.
Implement src/shared/ completely:

config.py:
  Load and validate /etc/usb-scan/scan_station.yaml using PyYAML and dataclasses.
  Raise ConfigError with a clear message on invalid or missing required fields.
  Apply validation rules from spec §6.2:
    - virustotal.role=mandatory requires on_quota_or_network_failure in {incomplete,error}
    - yara.role=mandatory requires a signed compiled ruleset path
    - operator_hold.enabled requires max_duration_seconds (15–300) and allowed_verdicts set
  Config contains NO secrets — credential fields are file references (str paths).
  Env var overrides: USB_SCAN_VT_KEY, USB_SCAN_SMTP_PASS, USB_SCAN_HMAC_KEY.

models.py:
  Verdict enum: CLEAN, THREAT, SUSPICIOUS, INCOMPLETE, ERROR, REJECTED, NOT_READY
  ScanStage enum: AUTHORIZING, ENUMERATING, MOUNTING, SCANNING, EVALUATING, EJECTING
  GUIState enum: STARTING, NOT_READY, IDLE, VALIDATING, MOUNTING, SCANNING,
                 EVALUATING, OPERATOR_HOLD, EJECTING, RESULT, EJECT_FAILED, REJECTED, ERROR
  DeviceLifecycle enum: PRESENT, MOUNTED, UNMOUNTED, POWER_OFF_REQUESTED,
                        SAFE_TO_REMOVE, REMOVED, EJECT_FAILED
  CoverageMetrics dataclass: partitions_discovered, partitions_scanned, partitions_excluded,
    files_discovered, files_scanned, files_skipped, files_failed, files_uninspectable,
    bytes_enumerated, bytes_read, clamav_complete (bool), yara_complete (bool|None),
    vt_complete (bool|None)
  SkipReason enum: TOO_LARGE, ENCRYPTED, UNREADABLE, UNSUPPORTED, RECURSION_LIMIT,
                   SCAN_LIMIT, TIMEOUT, POLICY_EXCLUSION, TOO_LARGE_FOR_ENGINE
  ThreatEntry dataclass: file_path (str), engine (str), signature_name (str), sha256 (str)
  ScanMetadata dataclass: scan_id, station_id, device_sysfs_id, session_start_utc,
                          session_end_utc (optional), firmware_version (str|None)
  ScanResult dataclass: metadata, verdict, threats (list[ThreatEntry]), coverage,
                        policy_violations (list[str]), engine_errors (list[str]),
                        schema_version='1.5'
  ScanEvent dataclass: event_type (str), scan_id (str), timestamp_utc, payload (dict)
  All dataclasses must be JSON-serialisable via a to_dict() method.

ipc.py:
  Async Unix socket server (orchestrator side) and client (GUI side).
  Protocol: one JSON-serialised ScanEvent per line, newline-delimited.
  Client: exponential backoff reconnect (0.5s → 30s max). Emit reconnect events.
  Server: authenticate clients by socket credential (SO_PEERCRED uid check).

auth.py:
  hash_pin(pin: str) → str  (bcrypt cost 12; validate len <= 72 bytes first)
  verify_pin(pin: str, hashed: str) → bool
  validate_pin_format(pin: str) → None | str (returns error message if invalid)
    Rules: exactly 6 digits, not all-repeated (111111), not sequential (123456, 654321)
    Reject pins on configured deny_list.
  AuthManager class:
    verify(pin, level) → bool  (checks hash + records attempt + checks lockout)
    is_locked_out(level, interface) → bool
    record_attempt(level, interface, success)  (persists to SQLite, not in-memory only)
    clear_lockout(level, interface)  (admin action only)
  Lockout state persists across process restarts (stored in events DB, not RAM).
  Default: 5 failures → 15 min lockout. Rate-limit independently of hash computation.

logging_setup.py:
  Structured JSON logging to file + optional RFC 5424 syslog forward.
  scan_id as a ContextVar injected into every log record when set.
  Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL.
  Never log PIN values at any level.

Write unit tests in tests/unit/shared/ for all of the above.
No hardware dependencies in shared/ — must run on a dev laptop.
```

**Acceptance:** `pytest tests/unit/shared/` passes. All tests green, no warnings.

---

## Phase 2 — Device Broker

**Goal:** Standalone privileged broker service — the only component that mounts filesystems.

**Duration estimate:** 4–6 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and .claude/skills/device-broker.md and spec §2.1, §5.4, §8.2.

Implement src/broker/ — the privileged device broker. This service replaces udisks2
entirely. It runs as root. It is the ONLY component allowed to call mount(8).

broker_server.py:
  Async Unix socket server at /run/usb-scan/broker.sock (mode 0600, owner root:root).
  Authenticate each client connection by SO_PEERCRED — only accept connections from
  uid matching the usbscan service user.
  Parse newline-delimited JSON commands. Validate command against strict allowlist.
  All unknown or malformed commands return {"error": "unknown_command"} — never raise.

commands/:
  enumerate.py: given a sysfs_path, walk sysfs to find block partitions.
    Return list of {uuid, fs_type, size_bytes, partition_index}.
    Validate sysfs_path starts with /sys/bus/usb/devices/ — reject anything else.
    Use blkid (subprocess, no shell=True) to detect filesystem type per partition.
    Never return /dev/sd* paths in the response — use UUIDs only.

  mount.py: given partition_uuid and session_id:
    Resolve partition UUID to block device via /dev/disk/by-uuid/ (read symlink, validate).
    Create a new mount namespace (unshare CLONE_NEWNS via ctypes/libc).
    Mount read-only in the new namespace at /run/usb-scan/mounts/<session_id>/<uuid>/.
    Apply mount options per filesystem type (from skill file).
    Write a transient systemd drop-in for clamav-daemon.service and usb-scan-yara.service
    that adds ReadOnlyPaths=/run/usb-scan/mounts/<session_id>/ for this session.
    Return {"mount_path": "/run/usb-scan/mounts/<session_id>/<uuid>/", "session_id": ...}

  unmount.py: given session_id:
    Unmount all mounts under /run/usb-scan/mounts/<session_id>/.
    Remove the transient drop-in files for the scanner services.
    Destroy the mount namespace.
    Return {"ok": true} or {"error": "unmount_failed", "detail": "..."}

  eject.py: given sysfs_path:
    Write "0" to /sys/bus/usb/devices/<dev>/authorized to request power-off.
    Validate sysfs_path strictly before writing.
    Return {"ok": true} or {"error": "eject_failed"}

  ping.py: return {"ok": true}

record all privileged actions to /var/log/usb-scan/broker-audit.log (append-only, JSON lines).

__main__.py: entry point. Drop capabilities after binding socket (keep only CAP_SYS_ADMIN
for mount namespace, CAP_DAC_READ_SEARCH for blkid). Install SIGTERM handler.

Write tests/unit/broker/ mocking subprocess calls and sysfs paths.
Write a broker integration test that mounts a loopback ext4 image read-only and
verifies mount flags with `findmnt --json`.
```

**Acceptance:**
- `pytest tests/unit/broker/` passes.
- Integration test mounts a loopback image read-only and confirms `ro,noexec,nosuid,nodev`.
- Broker rejects a command with a raw `/dev/sda1` path argument.

---

## Phase 3 — Scan Orchestrator (Core)

**Goal:** Working scan pipeline — USB detection → broker RPC → ClamAV → coverage → verdict → eject → log.

**Duration estimate:** 6–10 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md, .claude/skills/clamav-integration.md, .claude/skills/device-broker.md.
Read spec §3.1–§3.5, §3.8.

Implement src/orchestrator/:

usb_monitor.py:
  Use pyudev to watch for USB block device add/remove events.
  Filter: SUBSYSTEM=block, DEVTYPE=disk, ID_USB_DRIVER=usb-storage.
  Extract sysfs_path from udev event (not /dev/ path).
  Ignore internal devices: check that sysfs path is under /sys/bus/usb/ and not in
  the configured internal_device_sysfs_prefixes list.
  On remove event: emit DeviceRemovedEvent regardless of scan state.
  Single active device constraint: second insertion → emit REJECTED event, do not scan.

broker_client.py:
  Async client for /run/usb-scan/broker.sock.
  Implement: enumerate(sysfs_path), mount(partition_uuid, session_id),
  unmount(session_id), eject(sysfs_path), ping().
  All methods raise BrokerError on {"error":...} response.
  Connection retry on socket unavailable: exponential backoff, max 3 attempts.

scanner_clamav.py:
  Async clamd socket client per .claude/skills/clamav-integration.md.
  scan_file(path) → ClamResult (status: ok|found|error, signature_name, duration_ms)
  scan_directory(mount_path, config) → AsyncIterator[ScanProgress]
  Enforce: max_file_size_bytes, archive depth/count limits, per-file timeout.
  Track CoverageMetrics during scan: increment counters per outcome.
  clamav_complete=False if any file_failed or timeout, or if clamd disconnects.

inventory.py:
  Traverse mount_path, enumerate all regular files and symlinks.
  Reject symlinks that escape the mount root (os.path.realpath check).
  Apply traversal limits from config: max_files, max_depth, max_bytes_total.
  Return FileInventory: list of FileEntry (path, size, is_symlink, excluded, exclude_reason).
  Record files_discovered, files_uninspectable (unreadable metadata).

verdict_engine.py:
  Evaluate ScanResult → Verdict.
  Rules (in priority order):
    1. Any ThreatEntry with severity=HIGH → THREAT
    2. clamav_complete=False and clamav.role=mandatory → INCOMPLETE
    3. yara_complete=False and yara.role=mandatory → INCOMPLETE
    4. vt_complete=False and virustotal.role=mandatory → INCOMPLETE
    5. Any partition uninspected and config.require_full_coverage=true → INCOMPLETE
    6. Any ThreatEntry with severity=MEDIUM or YARA match → SUSPICIOUS
    7. All required engines complete, no detections → CLEAN
  INCOMPLETE takes precedence over CLEAN always.
  Policy violations (blocked extensions) produce SUSPICIOUS or THREAT per config severity.

orchestrator.py:
  Main async event loop. State machine: NOT_READY → IDLE → VALIDATING → MOUNTING →
  SCANNING → EVALUATING → [OPERATOR_HOLD] → EJECTING → RESULT.
  At VALIDATING: check USBGuard status (read /sys/bus/usb/devices/<dev>/authorized).
    If unauthorized: emit REJECTED, do not call broker.
  At MOUNTING: call broker.enumerate then broker.mount per partition.
  At SCANNING: call scanner_clamav.scan_directory; forward ScanProgress to GUI via IPC.
  At EVALUATING: call verdict_engine.evaluate; commit ScanResult to events service.
  operator_hold: if config.operator_hold.enabled and verdict in allowed_verdicts,
    transition to OPERATOR_HOLD; wait for operator_ack IPC message or timeout.
  At EJECTING: call broker.unmount then broker.eject.
  On DeviceRemovedEvent at any stage: abort, call broker.unmount(session_id), emit ERROR.
  Publish ScanEvent objects to GUI socket and events socket after each transition.

health.py:
  Check all mandatory health gates from spec §3.8:
  broker ping, clamd ping, signature age, ruleset presence (if yara.role=mandatory),
  disk space on data partition, events DB writable, system clock validity.
  Return HealthReport: passed (bool), failures (list[str]).
  NOT_READY if any mandatory gate fails.

__main__.py: entry point. Run health check on startup. Transition NOT_READY → IDLE when healthy.

Write tests/unit/orchestrator/ mocking broker_client, clamd, pyudev.
Write tests/integration/test_scan_pipeline.py using a loopback ext4 image.
```

**Acceptance:**
- `pytest tests/unit/orchestrator/` passes.
- Integration test: loopback image containing EICAR → THREAT verdict with correct coverage metrics.
- Integration test: loopback image with clean files → CLEAN with `clamav_complete=True`.
- Integration test: loopback image with one unreadable file → INCOMPLETE.

---

## Phase 4 — YARA Worker

**Goal:** Isolated YARA scan service with its own process, socket, and resource budget.

**Duration estimate:** 3–4 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and spec §3.2 step 6, §5.4.

Implement src/yara_worker/ — the isolated YARA scan process.
This is a separate service (user: yarascan), not a library imported by the orchestrator.

yara_server.py:
  Async Unix socket server at /run/usb-scan/yara.sock (mode 0660, usbscan:yarascan).
  Accept scan_directory requests from the orchestrator.
  Request format: {"session_id": "...", "mount_path": "...", "scan_id": "..."}
  Response: stream of {"file": "...", "matches": [...], "skipped": bool, "reason": "..."} lines,
            terminated by {"done": true, "yara_complete": bool}

rules.py:
  Load rules from config.yara.rules_path using yara.compile(filepaths={...}).
  Validate all rule files before activating (yara.compile catches syntax errors).
  Keep last known-good compiled ruleset in memory; fall back if new ruleset fails compile.
  Expose rules_version (hash of active ruleset files) for health reporting.

scanner.py:
  scan_file(path, timeout_seconds) → YaraScanResult
  Use yara.Rules.match(filepath=path, timeout=timeout_seconds).
  timeout parameter uses YARA's native timeout — raises yara.TimeoutError on expiry.
  Catch yara.TimeoutError → return YaraScanResult(timed_out=True).
  Catch any other yara exception → return YaraScanResult(error=str(e)).
  yara_complete=False if any file timed out or errored.

__main__.py:
  Load config. Compile rules (fail to NOT_READY if yara.role=mandatory and compile fails).
  Start server. Install SIGTERM handler for graceful shutdown.
  Enforce total session memory budget via resource.setrlimit(RLIMIT_AS, ...).

Wire into orchestrator via a YaraClient in src/orchestrator/scanner_yara_client.py:
  If yara service unavailable and yara.role=mandatory → INCOMPLETE verdict.
  If unavailable and yara.role=advisory → log warning, continue without YARA.
  Orchestrator watchdog: if YARA session exceeds config.yara.global_budget_seconds,
  send SIGKILL to yara worker process and record INCOMPLETE.

Write tests/unit/yara_worker/ mocking yara module (for non-Pi dev environments).
```

**Acceptance:**
- `pytest tests/unit/yara_worker/` passes.
- YARA worker correctly reports `yara_complete=False` on a timeout.
- Orchestrator marks INCOMPLETE when `yara.role=mandatory` and worker is unavailable.

---

## Phase 5 — PySide6 GUI

**Goal:** Fullscreen kiosk implementing all 13 GUI states, responsive to IPC events, randomized PIN pad.

**Duration estimate:** 8–12 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and .claude/skills/pyqt6-statemachine.md.
Read spec §4.1–§4.4, §3.5 (operator_hold), §10.1 (PIN keypad requirement).

Implement src/gui/:

app.py:
  PySide6 QApplication setup. Fullscreen window. Wayland/labwc kiosk flags.
  Set WM_CLASS and title to 'usb-scan-kiosk'. No window decorations.

state_machine.py:
  QStateMachine with all 13 states from spec §4.2. Each state is a QState with
  entry/exit signal connections to show/hide the appropriate screen widget.

ipc_worker.py:
  QThread connecting to /run/usb-scan/state.sock.
  Parses incoming ScanEvent JSON lines and emits typed Qt signals to main thread.
  Reconnects with exponential backoff. Emits ipc_disconnected signal on persistent failure.

screens/:
  One QWidget subclass per state: starting.py, not_ready.py, idle.py, validating.py,
  mounting.py, scanning.py, evaluating.py, operator_hold.py, ejecting.py, result.py,
  eject_failed.py, rejected.py, error.py
  scanning.py: updates file counter and current file path at ≤500ms intervals (throttled).
  result.py: shows verdict, coverage summary (files scanned/skipped/failed), engine completion,
    and safe-removal instruction. Redacts full file paths by default (show only filename).
  operator_hold.py: countdown timer (QTimer, updates every second), PIN entry widget,
    result summary. Auto-transitions to EJECTING on timeout via IPC message to orchestrator.

widgets/pin_overlay.py:
  Fullscreen overlay PIN entry. MANDATORY: randomize digit positions on every show():
    digits = list('0123456789'); random.shuffle(digits)
    Render as 3×4 grid (10 digits + backspace + confirm).
  Display entered digits as '●' — never show actual digit.
  Send PIN to orchestrator via IPC (not local verification — orchestrator/auth service verifies).
  Long-press detection: IDLE screen reserved region, QTimer(3000ms) on touchPress.
  Show lockout state if orchestrator reports is_locked_out=True.

widgets/led_bridge.py:
  Fire-and-forget UDP-like sends to /run/usb-scan/led.sock.
  Never block the GUI thread. Use QThread for socket send.

ambient_mode.py:
  QTimer after config.idle_timeout_seconds in IDLE state.
  Show: appliance station_id, date/time, health status indicator. No scan data.
  Wake on USB insertion (IPC event) without requiring touch.

assets/:
  SVG icons for each verdict and each state. Use QPainter to render inline.

Write tests/unit/gui/ using pytest-qt:
  - All 13 state transitions driven by mock IPC events
  - PIN keypad randomization: 100 renders, no two consecutive layouts identical
  - Long-press detection activates PIN overlay at 3s
  - operator_hold countdown fires EJECTING on timeout
  - result screen redacts paths correctly
```

**Acceptance:**
- `pytest tests/unit/gui/` passes.
- `python -m src.gui` launches fullscreen, cycles through all states with mock events.
- PIN keypad shows randomized layout on every display (manual verification).

---

## Phase 6 — LED Controller

**Goal:** GPIO LED service responding to scan state commands via socket.

**Duration estimate:** 2–3 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md. Read spec §3.3 (LED column in verdict table), §5.1 (GPIO pins).

Implement src/led/:

led_controller.py:
  Use lgpio (via rpi-lgpio) to drive RGB LED on GPIO pins 17 (R), 27 (G), 22 (B) BCM.
  Pins configurable in scan_station.yaml.
  LED patterns per spec §3.3 verdict table:
    NOT_READY:   white solid
    IDLE:        blue slow pulse (1Hz)
    SCANNING:    amber solid
    CLEAN:       green solid
    THREAT:      red pulse (4Hz)
    SUSPICIOUS:  amber pulse (2Hz)
    INCOMPLETE:  white/amber alternate (1Hz each)
    ERROR:       white blink (2Hz)
    REJECTED:    white/amber blink
    EJECTING:    white solid
  Use software PWM for pulse effects. Run pulse loop in a threading.Thread.

led_server.py:
  Unix socket server at /run/usb-scan/led.sock (mode 0660, usbscan:gpio).
  Accept {"state": "THREAT"} JSON messages from GUI (fire-and-forget).
  Update led_controller state on each received message.

__main__.py:
  SIGTERM handler: turn LED off, close socket, exit cleanly.

Stub lgpio import when not available: create src/led/lgpio_stub.py that logs calls.
Auto-detect Pi hardware; use stub on non-Pi (enables unit tests on dev machines).

Write tests/unit/led/ mocking lgpio using lgpio_stub.
```

**Acceptance:**
- `pytest tests/unit/led/` passes.
- LED patterns cycle correctly on Pi with `python -m src.led`.

---

## Phase 7 — Optional Scan Modules (VirusTotal, Quarantine, Alerting)

**Goal:** Three independently toggled optional modules. Each degrades gracefully when disabled.

**Duration estimate:** 5–8 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and spec §3.2 steps 7 and 9, §3.7.

Implement three optional modules in src/orchestrator/:

virustotal.py:
  Hash-only lookup using VirusTotal API v3 GET /files/{sha256} via httpx.
  Config key: virustotal.large_file_hash_budget_mb controls max CPU budget for SHA-256
  hashing of large files — this is NOT a size restriction on uploads (no files are uploaded).
  Local SQLite cache (hash → result, expires after config.virustotal.cache_ttl_days).
  VTResult dataclass: sha256, positives, total_engines, permalink, cached (bool).
  Rate-limit: 4 req/min (free tier default; configurable).
  on_quota_or_network_failure: if role=mandatory → INCOMPLETE; if advisory → log, continue.
  Credential loaded from USB_SCAN_VT_KEY env var — never from YAML.
  All HTTP calls via httpx with TLS verification. No verify=False.

quarantine.py:
  Copy flagged files to LUKS2-encrypted mount at /var/lib/usb-scan/quarantine/.
  Store as: {scan_id}/{opaque_id}/{opaque_filename} — no original filename in path.
  Write sidecar JSON: {original_path, sha256, verdict, timestamp, device_uuid, scan_id}.
  Original filename stored in sidecar metadata ONLY, never in the filesystem path.
  Enforce retention_days: delete old entries on each scan in a background thread.
  If quarantine not mounted or full: log error, skip quarantine, DO NOT fail scan verdict.
  Release back to source USB device is architecturally prohibited — do not implement any
  path that writes to USB block device or mount.

alerting.py:
  Dispatch ScanResult to configured channels: webhook (httpx POST), email (smtplib/STARTTLS),
  CEF syslog (TCP socket), RFC 5424 syslog.
  Each channel is independent — one failure does not affect others.
  All dispatches are async (asyncio.gather with return_exceptions=True).
  Webhook: retry once after 5s on failure. Log on second failure, do not block.
  Credentials (SMTP password, webhook token) loaded from env vars — never from YAML.

Wire all three into orchestrator.py behind config flag checks.
Write unit tests for each module with all external calls mocked.
```

**Acceptance:**
- `pytest tests/unit/orchestrator/test_vt.py test_quarantine.py test_alerting.py` passes.
- End-to-end: EICAR scan with webhook configured → webhook POSTed with THREAT verdict.

---

## Phase 8 — Events Service

**Goal:** Durable event/logging service — SQLite WAL, event hash chain, SIEM forwarding queue.

**Duration estimate:** 3–5 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and spec §3.7, §5.4.

Implement src/events/ — the durable event and logging service (user: usbscan-events).

event_store.py:
  SQLite WAL database at /var/lib/usb-scan/db/events.db.
  Schema:
    events(id INTEGER PRIMARY KEY, event_type TEXT, scan_id TEXT, station_id TEXT,
           sequence INTEGER, timestamp_utc TEXT, payload TEXT,
           hash TEXT, prev_hash TEXT)
    auth_events(id, interface TEXT, level TEXT, success INTEGER, timestamp_utc TEXT,
                lockout_triggered INTEGER)
    delivery_queue(id, event_id, channel TEXT, status TEXT, attempts INTEGER,
                   last_attempt_utc TEXT, ack_received INTEGER)
  sequence: monotonically increasing per station_id. Gap detection on read.
  hash: SHA-256(prev_hash + event_type + scan_id + sequence + payload).
  prev_hash: hash of previous event (chain anchor). Genesis block uses hash of station_id.
  WAL mode: PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL.
  Disk full handling: pre-check free space before write; emit NOT_READY if below threshold.
  Integrity check: run PRAGMA integrity_check on startup. Alert and halt if fails.

events_server.py:
  Async Unix socket server at /run/usb-scan/events.sock (0660 usbscan:usbscan-events).
  Accept ScanEvent JSON from orchestrator and auth_event JSON from auth.py.
  Write to event_store with hash chaining.
  Expose query interface: get_last_scan(), get_health(), get_lockout_state(level, interface).
  The orchestrator and auth module query lockout state here (not in-memory).

forwarder.py:
  Background task: read delivery_queue, forward undelivered events to configured SIEM.
  Supports RFC 5424 syslog (TCP+TLS) and JSON webhook.
  Mark delivered on ACK. Increment attempts on failure. Retry with backoff.
  Max retries configurable (default 10). Dead-letter to local log after max retries.
  Preserve event ordering: forward in sequence order per station_id.
  Deduplicate: track forwarded sequence numbers; skip already-forwarded on retry.

checkpoint.py:
  Periodically (config.audit.checkpoint_interval_hours) compute a signed checkpoint:
    checkpoint = HMAC-SHA256(hmac_key, concatenation of last N event hashes)
  Write checkpoint to events DB and forward off-device via forwarder.
  Gaps between checkpoints are detectable by the central SIEM.

Write tests/unit/events/:
  - Hash chain integrity: verify chain breaks are detected
  - Gap detection: insert events with non-consecutive sequence, verify detection
  - Delivery queue retry: simulate network failure, verify retry backoff
  - Lockout state persistence: write auth_event, read back lockout state
```

**Acceptance:**
- `pytest tests/unit/events/` passes.
- Chain integrity check detects a manually tampered event.
- Lockout state survives process restart (read from DB, not RAM).

---

## Phase 9 — Admin Web UI

**Goal:** Flask + HTMX admin dashboard. OIDC/SSO + MFA for remote admin. No shared admin PIN.

**Duration estimate:** 8–12 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and spec §9.1, §10.2.

Implement src/web/ — Flask + HTMX admin web UI.

Structure:
- app.py: Flask app factory. WSGI-compatible (Gunicorn). Blueprints: auth, dashboard,
  history, config_view, stats, update, audit.
- auth/:
  OIDC authentication using authlib (Flask-OIDC or direct authlib OAuth2Session).
  Session: Flask-Session with SQLite backend. Cookie: HttpOnly, SameSite=Strict, Secure.
  MFA enforcement: require_mfa=true is mandatory for OIDC per spec §6.2.
  Local named-account fallback: only if config.auth.web.oidc_enabled=false AND
    config.auth.web.local_fallback_allowed=true (for isolated networks only).
    Local accounts use bcrypt cost 12. NO shared PIN for remote admin.
  RBAC: roles defined in config (viewer, operator, admin). Map from OIDC claims or local.
  Session IP binding: reject if remote_addr changes mid-session.
  Generic error message on all auth failures — never reveal account existence.
  All POST routes: CSRF token (Flask-WTF or manual double-submit cookie).

dashboard/:
  Live status via HTMX polling every 5s. Show: last scan result, CPU temp
  (read /sys/class/thermal/thermal_zone0/temp in Celsius), disk usage (shutil.disk_usage),
  signature age (query events service), service health from health.py, station version.

history/:
  Paginated scan log from events DB (query via events service socket).
  Filters: date range, verdict, device UUID. Drill-down per scan with full coverage metrics.
  Export as CSV and JSON (streamed response). Filenames include station_id and date range.

config_view/:
  Read-only for all roles. No in-browser config editing (avoid injection risk).
  Show: active config (secrets redacted), YARA ruleset version, ClamAV version/signature date.
  Admin: trigger config reload (signals orchestrator to re-read config on safe restart).

stats/:
  Charts using Chart.js (CDN, pinned version). Scans/day, threats/day, top threat names.
  Data served as JSON endpoints under /api/stats/. Client-side rendering only.

update/:
  Admin only. Trigger manual signature update (runs freshclam via systemd transient unit).
  Stream update log output via Server-Sent Events. Show last update timestamp and result.

audit/:
  Admin only. View audit log from events DB (auth events, config changes, admin actions).
  Read-only; no delete via UI.

Security:
- All routes check session validity and RBAC role via a decorator.
- Bind to config.admin_web.bind_host:bind_port (default: 127.0.0.1, management interface).
- TLS terminates at reverse proxy (nginx/caddy), not in Flask directly.
- Flask debug mode MUST be off in production. Add a startup check that raises if DEBUG=True
  and not in a test environment.
- Log every authenticated request with user identity, role, action, and timestamp to
  events service (audit events).

Write tests/unit/web/ using Flask test client:
  - All routes return 302 (redirect to login) when unauthenticated.
  - OIDC callback handled correctly with mock token.
  - RBAC: viewer cannot access audit log (403).
  - CSRF: POST without token returns 400.
  - IP binding: mock remote_addr change → 401.
```

**Acceptance:**
- `pytest tests/unit/web/` passes.
- Web UI accessible on configured bind address; OIDC login flow completes.
- Viewer cannot access audit log.

---

## Phase 10 — Systemd Integration & First-Boot Script

**Goal:** All services wired into systemd; appliance boots to IDLE unattended; USBGuard configured.

**Duration estimate:** 4–6 hours

**Claude Code prompt to start:**

```
Read CLAUDE.md and spec §5.4, §8.2, §10.1.

Create all systemd service unit files in systemd/ and the first-boot setup script.

Service unit files:
  usb-scan-device-broker.service:
    User=root, Group=root (minimal caps post-bind — see broker phase)
    ExecStart=/opt/usb-scan/.venv/bin/python -m src.broker
    Restart=always, RestartSec=3, WatchdogSec=30
    After=network.target
    AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH
    NoNewPrivileges=false  (needs caps — document this exception explicitly)

  usb-scan-orchestrator.service:
    User=usbscan, SupplementaryGroups=clamav
    Restart=always, RestartSec=5, WatchdogSec=30, NotifyAccess=main
    After=usb-scan-device-broker.service clamav-daemon.service
    ProtectSystem=strict, PrivateTmp=true, NoNewPrivileges=true
    ReadWritePaths=/var/lib/usb-scan/ /run/usb-scan/

  usb-scan-yara.service:
    User=yarascan
    Restart=always, RestartSec=5, WatchdogSec=60
    After=usb-scan-orchestrator.service
    ProtectSystem=strict, NoNewPrivileges=true
    ReadOnlyPaths=/var/lib/usb-scan/rules/ (ruleset)
    (mount namespace access added transiently by broker per session)

  usb-scan-gui.service:
    User=usbscan-gui
    Environment=WAYLAND_DISPLAY=wayland-1 XDG_RUNTIME_DIR=/run/user/<uid>
    Restart=always, After=usb-scan-orchestrator.service
    NoNewPrivileges=true

  usb-scan-led.service:
    User=usbscan-led, SupplementaryGroups=gpio
    Restart=always, After=usb-scan-orchestrator.service
    NoNewPrivileges=true

  usb-scan-events.service:
    User=usbscan-events
    Restart=always, After=network-online.target
    ProtectSystem=strict, ReadWritePaths=/var/lib/usb-scan/db/ /var/log/usb-scan/
    NoNewPrivileges=true

  usb-scan-admin.service:
    User=usbscan-web
    Restart=on-failure  (not always — OIDC misconfiguration should surface, not hide)
    After=usb-scan-events.service
    ProtectSystem=strict, NoNewPrivileges=true

  usb-scan-update.service + usb-scan-update.timer:
    Weekly, Sunday 03:00 local time.
    ExecStart=/opt/usb-scan/scripts/run-update.sh

USBGuard policy:
  scripts/setup-usbguard.sh: install usbguard, generate initial policy allowing:
    - Internal USB controllers (by ID)
    - External scan port restricted to bInterfaceClass=08 (Mass Storage)
    Composite devices with bInterfaceClass=03 (HID) → default deny
  Write /etc/usbguard/rules.conf. Enable usbguard.service.

udev rule (/etc/udev/rules.d/99-usb-scan.rules):
  ACTION=="add", SUBSYSTEM=="block", ENV{ID_USB_DRIVER}=="usb-storage",
  TAG+="systemd", ENV{SYSTEMD_WANTS}+="usb-scan-orchestrator.service"

scripts/first-boot-setup.sh:
  Create system users: usbscan, usbscan-gui, usbscan-web, usbscan-events, usbscan-led, yarascan
  Create gpio group if not present; add usbscan-led to gpio group
  Create /var/lib/usb-scan/{db,queue,cache,rules,quarantine}/
  Create /var/log/usb-scan/ and /run/usb-scan/ with correct ownership
  Copy scan_station.yaml template to /etc/usb-scan/ if not present
  Generate TLS cert for reverse proxy (self-signed; document production cert replacement)
  Run usb-scan-set-pin.py to set operator PIN interactively (6-digit, bcrypt cost 12)
  Set up USBGuard policy
  Enable and start all services
  Fail if operator PIN not set — appliance must not start without a PIN

scripts/usb-scan-set-pin.py:
  Accepts --level operator. (Admin auth is OIDC — no admin PIN to set here.)
  Prompt for new PIN twice. Validate: exactly 6 digits, not sequential, not all-repeated.
  Hash with bcrypt cost 12. Write hash to protected file (not scan_station.yaml).
  Report success/failure clearly.

scripts/run-update.sh:
  apt update && apt upgrade (in OverlayFS maintenance window: disable overlay, reboot writable,
  upgrade, re-enable overlay).
  freshclam (signature update — does NOT require maintenance window; runs on persistent partition).
  YARA rule sync with signature verification.
  Log result to events service. Alert on failure if configured.
  Document: run only on UPS-backed power due to reflash risk on interrupted update.
```

**Acceptance:**
- `sudo bash scripts/first-boot-setup.sh` completes on Pi without errors.
- All services show `active (running)` in systemctl.
- USBGuard rejects a USB keyboard (HID class 03).
- Pi boots to IDLE GUI within 30 seconds.

---

## Phase 11 — Hardening & Read-Only Root

**Goal:** Production-hardened OS. Appliance survives power loss. OverlayFS configured.

**Duration estimate:** 4–6 hours  
**This phase is mostly bash and config — work interactively on the Pi.**

**Claude Code prompt:**

```
Read CLAUDE.md and spec §8.1, §8.2.

Create scripts/harden.sh — runs once after first-boot-setup.sh. Each step is idempotent.

- OverlayFS: configure /etc/overlayroot.conf for read-only root.
  /var/lib/usb-scan, /etc/usb-scan, /var/log/usb-scan remain on persistent data partition.
  tmpfs for /tmp and runtime state.

- Disable unnecessary services:
  bluetooth, cups, avahi-daemon, triggerhappy, hciuart, ModemManager, wpa_supplicant
  (if Wi-Fi disabled), systemd-rfkill.

- nftables: generate /etc/nftables.conf:
  Default-deny inbound. Allow: established/related, management port (LAN only, configurable IP range),
  SSH if enabled. Allow outbound: HTTPS (443), HTTP (80 for apt), DNS (53), NTP (123),
  clamd signature update. Apply and enable nftables.service.

- Kernel filesystem module blacklist:
  /etc/modprobe.d/usb-scan-fs.conf: blacklist cramfs, hfs, hfsplus, jffs2, udf, freevxfs

- NTFS/exFAT driver validation: document which driver is active and how to verify:
  cat /proc/filesystems | grep -E 'ntfs|exfat'
  Confirm ntfs3 or ntfs-3g is in use; document the chosen option and its security notes.

- User lockdown: lock pi user (usermod --expiredate 1 pi || true).
  SSH: PasswordAuthentication no, PermitRootLogin no, MaxAuthTries 3.
  AllowUsers: only named admin user (configurable).

- Swap: dphys-swapfile swapoff; systemctl disable dphys-swapfile (if present).

- sysctl /etc/sysctl.d/99-usb-scan.conf:
  net.ipv4.ip_forward=0, net.ipv4.conf.all.send_redirects=0,
  net.ipv4.conf.all.accept_redirects=0, kernel.dmesg_restrict=1,
  kernel.kptr_restrict=2, fs.suid_dumpable=0, kernel.unprivileged_bpf_disabled=1

- AppArmor:
  Generate enforce-mode profiles for: clamav-daemon, usb-scan-device-broker,
  usb-scan-orchestrator. Complain-mode profiles for remaining services as a starting point.

- HMAC key setup: generate /etc/usb-scan/secrets/hmac.key (32 random bytes).
  Mode 0400, owner root. Reference from config.

Also produce docs/hardening-checklist.md with every §8 item and status:
  scripted | manual | validated | n/a — with reference to implementing file.
```

**Acceptance:**
- `sudo bash scripts/harden.sh` completes without errors.
- After reboot: `mount | grep ' / '` shows `ro`.
- Full scan completes end-to-end with read-only root active.
- `cat /proc/filesystems | grep -E 'ntfs|exfat'` matches documented driver choice.

---

## Phase 12 — Acceptance Testing

**Goal:** All AC-F, AC-S, AC-R criteria from spec §14 verified. Test fixtures documented.

**Duration estimate:** 4–6 hours on Pi

**Claude Code prompt:**

```
Read CLAUDE.md. Read spec §14 (all acceptance criteria).
Create tests/acceptance/run_acceptance.py and tests/acceptance/MANUAL_TEST_CHECKLIST.md.

Automated tests (no physical USB manipulation required):

AC-R01: Start orchestrator without clamav-daemon running. Verify station transitions
  to NOT_READY and emits a health_gate_failed event with reason 'clamav_unavailable'.
  Restart clamav-daemon; verify station recovers to IDLE.

AC-R03: Kill orchestrator PID. Verify systemd watchdog restarts it within 30 seconds.
  Verify station transitions correctly (NOT_READY or IDLE, not stuck).
  (AC-R04 in spec)

AC-F07: Submit 10 clean scans via the integration test loopback image.
  Verify each scan event record contains all required coverage fields from spec §3.4.
  (AC-F07 in spec)

AC-S01: After harden.sh and reboot: assert mount point '/' has 'ro' flag.
  Assert /var/lib/usb-scan is writable. Assert /tmp is tmpfs.

AC-S05: Trigger PIN lockout (5 failures via IPC). Kill GUI process and restart it.
  Verify 6th attempt is still rejected. (Lockout state must survive GUI restart.)

AC-S06: Trigger PIN overlay display 100 times via IPC mock. Collect digit layouts.
  Verify no two consecutive layouts are identical. Verify all 10 digits appear.

AC-F04: Issue a REJECTED device event via broker mock (capacity exceeded).
  Verify verdict=REJECTED in scan record and explicit reason code present.

Negative tests:
  Try to call broker.mount with a raw /dev/sda1 path → verify broker returns error.
  Try to connect to broker socket as non-usbscan user → verify connection refused.

Manual checklist must cover:
  AC-F01: Clean USB → CLEAN verdict with coverage metrics. Document expected metrics.
  AC-F02: USB with EICAR → THREAT with engine evidence and non-safe-use warning.
  AC-F03: Multi-partition USB → all partitions in coverage report.
  AC-S02: USB HID keyboard → rejected at USBGuard layer, event logged, GUI shows REJECTED.
  AC-S03: Verify noexec mount: attempt to execute a file from mounted USB → fails.
  AC-R02: 100 consecutive insert/scan/remove cycles without leaked mounts.
  AC-R03: Power loss during scan → verify no invalid safe-remove after reboot.
  Synthetic fixture test (AC-F05): run maintenance synthetic scan, verify event log entry.
```

**Acceptance:** All automated tests pass. Manual checklist completed with evidence and sign-off.

---

## Phase 13 — Documentation & Packaging

**Goal:** Installation docs, operator guide, admin guide, ADRs, and deployable image preparation.

**Duration estimate:** 4–6 hours

**Claude Code prompt:**

```
Read CLAUDE.md and the spec.
Generate the following in docs/:

docs/installation.md:
  Step-by-step from blank Pi OS Trixie to running hardened appliance.
  Cover: OS flash, SSH enable, repo clone, pip install, first-boot-setup.sh, harden.sh,
  USBGuard setup, OIDC provider configuration, first test scan.

docs/operator-guide.md:
  One-page end-user guide. How to scan (insert → wait → remove when instructed).
  What each verdict means. What to do on ERROR or REJECTED.
  Written for non-technical factory/office staff. No jargon.

docs/admin-guide.md:
  IT admin guide. Web UI walkthrough. OIDC/SSO setup. Operator PIN management.
  Log export. SIEM setup. Update procedure. OverlayFS maintenance window procedure.
  Quarantine configuration. Troubleshooting common faults.
  Emphasise: OS updates require planned maintenance window on UPS-backed power.

docs/architecture-decisions.md (ADR format):
  ADR-001: Custom device broker vs udisks2/dasbus — rationale: eliminate D-Bus attack surface.
  ADR-002: PySide6 vs PyQt6 — rationale: LGPL distribution flexibility.
  ADR-003: lgpio vs RPi.GPIO — rationale: Pi 5 GPIO chip change; RPi.GPIO unsupported.
  ADR-004: SQLite vs PostgreSQL — rationale: offline-first, embedded, WAL durability.
  ADR-005: OverlayFS vs A/B update — rationale: A/B was over-engineered; OverlayFS simpler.
  ADR-006: OIDC vs shared admin PIN — rationale: named accounts, auditability, MFA.
  ADR-007: Unix socket IPC vs D-Bus — rationale: simpler, auditable, no D-Bus daemon dep.
  ADR-008: YARA as isolated service vs library import — rationale: resource budget enforcement,
    process isolation against hostile rules/input.

scripts/build-image.sh:
  Wrapper for fleet imaging.
  Documents the full unattended setup sequence for a production image.
  Stub the actual dd/rpi-imager call with a comment block and parameter list.
```

---

## .claude/settings.json — Hooks

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "grep -rn 'RPi\\.GPIO\\|import RPi' src/ 2>/dev/null && echo '{\"block\": true, \"message\": \"RPi.GPIO is not supported on Pi 5 / Trixie. Use lgpio / rpi-lgpio with --system-site-packages venv.\"}' >&2 || true"
        }]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "grep -rn 'import dasbus\\|from dasbus\\|udisks2\\|UDisks2' src/ 2>/dev/null && echo '{\"block\": true, \"message\": \"udisks2/dasbus is replaced by the custom device broker in src/broker/. No D-Bus mount calls allowed.\"}' >&2 || true"
        }]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "grep -rn 'plaintext\\|plain_text\\|str(pin\\|print(pin\\|log.*pin' src/shared/auth.py 2>/dev/null && echo '{\"block\": true, \"message\": \"Never log or store a PIN in plaintext. bcrypt hash at cost 12.\"}' >&2 || true"
        }]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "grep -rn 'verify=False\\|ssl_verify=False' src/ 2>/dev/null && echo '{\"block\": true, \"message\": \"TLS verification must never be disabled. All external HTTP calls use verified TLS.\"}' >&2 || true"
        }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [{
          "type": "command",
          "command": "cd $(git rev-parse --show-toplevel 2>/dev/null || echo .) && python -m pytest tests/unit/ -q --tb=no 2>/dev/null | tail -1 || true"
        }]
      }
    ]
  }
}
```

---

## Development Workflow Tips for Claude Code

### Session Strategy

| Phase | Claude Code Mode | Tip |
|---|---|---|
| Starting a phase | **Plan Mode** (`Shift+Tab`) | Let Claude map the work before writing code. Verify against CLAUDE.md. |
| Implementing | **Auto Mode** | Correct immediately if it drifts to udisks2 or shared admin PIN |
| Debugging | **Ask Mode** | Diagnose before fixing. Use a subagent for deep investigation. |
| Between phases | `/clear` | Fresh context per phase prevents architecture drift |

### Effective Prompts for This Project

**When Claude drifts to udisks2:**
```
Stop. Read CLAUDE.md. There is no udisks2 in this project. All mount operations
go through src/broker/ via the authenticated Unix socket RPC. Never call mount(8) or
D-Bus directly from the orchestrator.
```

**When Claude puts scan logic in the GUI:**
```
Stop. The GUI is a pure display client. Move that logic to src/orchestrator/.
The GUI only receives ScanEvent objects via the IPC socket. It emits user input
events to the orchestrator and does nothing else.
```

**Investigation sub-task (keep main context clean):**
```
Use a subagent to investigate whether Python's asyncio can reliably detect
a Unix socket peer disconnect mid-stream on Linux. Report back: does read() return 0,
raise ConnectionResetError, or something else? What is the recommended detection pattern?
```

**Starting each phase:**
```
Read CLAUDE.md. Read docs/USB-Scan-Station-Spec-v1.5.md section [N].
Before writing any code, list the files you will create, the key design decisions,
and any questions about the spec.
```

---

## Risk Register (Implementation)

| Risk | Mitigation |
|---|---|
| pyudev race on fast insert/remove | Debounce USB events with 500ms delay before calling broker |
| clamd not ready at scan start | Orchestrator waits for clamd ping with 10s timeout, retries 3× before NOT_READY |
| GUI floods IPC channel on large scans | Throttle ScanProgress dispatch to 2Hz in orchestrator; batch file-count updates |
| LUKS quarantine not mounted on boot | Check in health.py; report in web dashboard; quarantine failure never blocks scan |
| lgpio unavailable on dev machine | Auto-detect: fall back to lgpio_stub.py when not on Pi hardware |
| Update interrupted by power loss | Document UPS requirement; scripted recovery checklist in admin-guide.md |
| OIDC provider unavailable | Local named-account fallback (explicitly configured only); document config change procedure |
| YARA rule with hostile timeout | YARA-native timeout per file; orchestrator watchdog kills worker on global budget |
| Context window overflow in long sessions | Use subagents for investigation; `/clear` between phases |

---

## Phase Completion Checklist

| Phase | Done | Tests Pass | Committed |
|---|---|---|---|
| 0 — Scaffold & CLAUDE.md | ☐ | n/a | ☐ |
| 1 — Shared Foundation | ☐ | ☐ | ☐ |
| 2 — Device Broker | ☐ | ☐ | ☐ |
| 3 — Scan Orchestrator Core | ☐ | ☐ | ☐ |
| 4 — YARA Worker | ☐ | ☐ | ☐ |
| 5 — PySide6 GUI | ☐ | ☐ | ☐ |
| 6 — LED Controller | ☐ | ☐ | ☐ |
| 7 — Optional Modules (VT, Quarantine, Alerting) | ☐ | ☐ | ☐ |
| 8 — Events Service | ☐ | ☐ | ☐ |
| 9 — Admin Web UI | ☐ | ☐ | ☐ |
| 10 — Systemd & First Boot | ☐ | ☐ | ☐ |
| 11 — Hardening & Read-Only Root | ☐ | ☐ | ☐ |
| 12 — Acceptance Testing | ☐ | ☐ | ☐ |
| 13 — Docs & Packaging | ☐ | n/a | ☐ |

---

*USB Scan Station — Implementation Plan v1.5 · Internal / Confidential · © SilverDay Media*
