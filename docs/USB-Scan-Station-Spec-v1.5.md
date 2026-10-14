# USB Scan Station — Software Specification

**Version:** 1.5.9 DRAFT  
**Date:** 14 October 2026  
**Baseline:** v1.5 DRAFT (13 October 2026)  
**Target hardware:** Raspberry Pi 5 (8 GB RAM), High-Endurance/Industrial microSD, Pi 5 Active Cooler  
**Target OS:** Raspberry Pi OS Lite 64-bit (Debian 13 / Trixie), OverlayFS read-only root  
**Classification:** Internal / Confidential  
**Status:** Architecture proposal; platform integration and performance benchmarks require validation on reference hardware before implementation-ready gate is passed.

> **Security assurance statement:** A CLEAN result indicates that all content *required by the configured scan policy* was inspected without reportable detections, subject to the inherent limitations of signature- and rule-based detection. CLEAN is **not** a certification that the USB device is safe. Any uninspected content, mandatory engine failure, or unresolved scan limit must prevent CLEAN.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [Functional Requirements](#3-functional-requirements)
4. [GUI Specification](#4-gui-specification)
5. [Technical Architecture](#5-technical-architecture)
6. [Configuration Reference](#6-configuration-reference)
7. [OS Updates & Maintenance Strategy](#7-os-updates--maintenance-strategy)
8. [Security Hardening](#8-security-hardening)
9. [Admin Web UI](#9-admin-web-ui)
10. [Authentication & Authorization](#10-authentication--authorization)
11. [Non-Functional Requirements](#11-non-functional-requirements)
12. [Future Extensions](#12-future-extensions)
13. [Risks & Mitigations](#13-risks--mitigations)
14. [Acceptance Criteria](#14-acceptance-criteria)
15. [Revision History & Open Decisions](#15-revision-history--open-decisions)

---

## 1. Introduction

### 1.1 Purpose

This document specifies an autonomous Raspberry Pi 5-based appliance for examining USB mass-storage media for malicious or policy-prohibited content. The device automatically detects insertion, checks hardware and filesystem eligibility, scans permitted volumes, displays a verdict and scan-completeness information on a 5-inch touchscreen, safely powers off storage when supported, and records and optionally forwards results.

### 1.2 Objectives

- **Zero-interaction scanning:** ordinary users insert media, wait for the result, and remove media when explicitly instructed.
- **Trustworthy results:** distinguish no detections from incomplete inspection; fail closed when mandatory controls are unavailable.
- **Safe processing of hostile input:** minimize exposure to untrusted USB interfaces, filesystems, archives, filenames, and metadata.
- **Self-maintaining with recovery:** maintain signatures independently of image updates; recover from failed appliance updates.
- **Operational accountability:** preserve security-relevant events, expose health and version status, and support a central SIEM.
- **Clearly scoped administration:** local Operator PIN is strictly for constrained operational functions; remote administrative changes require stronger named-user authentication.

### 1.3 In Scope

USB storage detection; class/interface authorization; multi-partition discovery; read-only mounting; ClamAV and optional YARA; optional VirusTotal hash reputation; verdict/coverage engine; policy rules; Qt touchscreen and LED; safe eject/power-off; local SQLite storage; SIEM and alerts; health checks; management UI; setup script; optional quarantine; local and central administration; acceptance tests.

### 1.4 Out of Scope

Content Disarm and Reconstruction (CDR); device disinfection, modification or wiping; releasing quarantined files back to the source USB device (see §3.6 for the architectural prohibition); assurance against firmware-level compromise of the USB device; detection of every novel malware family; scanning network shares or email attachments; using the appliance as a transparent USB bridge or certified data-diode.

### 1.5 Threat Model and Assumptions

Treat USB descriptors, interface combinations, partition tables, filesystem metadata, file content, archive structure, filenames, and device identifiers as **untrusted**. Attackers may supply malicious hardware, crafted filesystem images, enormous files, archive bombs, composite HID/storage devices, or drives disconnected/reinserted during a scan. The physical enclosure is in a semi-public location; administrative network access is restricted to a management segment. The Pi kernel and boot chain remain trusted components unless separately hardened with additional assurance controls.

**Important limitation:** Device-class filtering and read-only mounting mitigate some threats but cannot guarantee immunity to kernel USB/parser bugs or malicious USB firmware. Stronger hardware isolation is an optional high-assurance deployment variant and must be assessed per environment.

---

## 2. System Overview

### 2.1 Components and Trust Boundaries

| Component | Responsibility and authority |
|---|---|
| USB authorization layer | Detect interfaces and enforce USBGuard or equivalent device policy before permitting storage access; reject unauthorized composite interfaces. |
| Device broker | Minimal privileged custom service to validate device identity, enumerate partitions, mount approved filesystems read-only, unmount and power off; exposes allowlisted operations over an authenticated local socket. |
| Scan orchestrator (`usbscand`) | Unprivileged coordinator for scanning, coverage, verdicts, cancellation, resource limits and state transitions; cannot arbitrarily mount filesystems or execute shell commands. |
| ClamAV daemon | Mandatory local antivirus engine with explicitly configured file access, size/decompression limits and timeouts. |
| YARA worker | Optional rule-based engine with isolated process and resource budgets; rules must be validated before activation. |
| VirusTotal client | Optional **hash-only** reputation lookup; no file uploads in v1.x; rate, privacy and failure behavior configured. |
| Verdict engine | Separates detection severity, policy violations, mandatory-engine completion and scan coverage. |
| GUI / LED controller | Restricted output clients subscribing to sanitized state events; cannot authorize privileged operations directly. |
| Durable event/logging service | SQLite operational records, event sequence and export/forwarding queue; log integrity anchored remotely where possible. |
| Admin API / UI | HTTPS administration through a separate restricted principal; authorization enforced server-side per endpoint. |
| Setup and Update subsystem | OverlayFS maintenance script separating frequent signature/rule updates from OS-level writable maintenance windows. |
| Central dashboard (optional) | Receives authenticated, replay-resistant events from individually enrolled stations; no implicit administrative trust. |

### 2.2 Trust Flow

`USB insertion → USB policy authorization → device broker/partition enumeration → isolated read-only mount → orchestrator → required engines → completeness + policy evaluation → local durable verdict → safe eject/power-off → result displayed until physical removal`. Alerts and SIEM forwarding proceed asynchronously from durable events and must never silently change the verdict.

### 2.3 Deployment Topology

Single-site and fleet installations work offline for *local* scanning. If a configured enterprise policy makes network reputation a mandatory check, lack of connectivity produces INCOMPLETE, not CLEAN. Each unit can forward events through an outbound authenticated channel to a central dashboard. There is no direct inbound scan-control requirement from the central dashboard.

### 2.4 Physical Design

Raspberry Pi 5, standard office enclosure, 5-inch touchscreen, one externally accessible current-limited USB-A storage port extended from the host board, visible discrete RGB status indicator, optional buzzer and enclosure-tamper input, protected Ethernet management connection, optional approved Wi-Fi (see §5.1 for Wi-Fi policy scope). Other Pi ports must be inaccessible or disabled.

---

## 3. Functional Requirements

### 3.1 Device Detection, Authorization and Enumeration

- FR-USB-01: Detect a newly inserted candidate storage device within a **target of 2 seconds**, subject to validated hardware and OS behavior.
- FR-USB-02: Do not accept HID devices or automatically trust USB hubs. Composite devices with unapproved interfaces SHALL be rejected or placed into an explicit restricted policy state; ignoring input in the GUI alone is insufficient.
- FR-USB-03: Evaluate USB class/subclass/protocol and topology with an auditable authorization policy (USBGuard or equivalent); maintain separate handling for storage descriptors and USB interface changes.
- FR-USB-04: Inspect **every exposed block device and partition**; either scan supported readable partitions or record each excluded/unsupported partition and mark coverage incomplete unless an explicit, authorized deployment policy declares it outside scope. The only such policy is `device.excludable_partition_types` (GPT type GUIDs / MBR type IDs, default empty): it applies solely to partitions with **no** filesystem or other signature and no larger than `device.excludable_partition_max_mb`; such partitions are counted as `partitions_out_of_scope` and named in the scan record, never silently dropped.
- FR-USB-05: Supported read-only filesystem targets: FAT32, exFAT, NTFS, ext2/3/4 and ISO 9660. Unsupported, encrypted, damaged or unreadable volumes are classified as uninspected, never implicitly clean. Mount support depends on validated kernel/userspace implementations. For NTFS and exFAT specifically: validate which kernel driver is active (kernel `ntfs3` vs `ntfs-3g` for NTFS; kernel `exfat` module vs `exfat-fuse` for exFAT) on the target Trixie kernel and confirm safe read-only mount flags for each. The kernel `ntfs3` driver has a security maintenance record that must be reviewed before deployment.
- FR-USB-06: Limit to one active physical device scan. A second insertion is **rejected by default** and clearly signaled; any queueing feature must bind queued work to stable kernel device identity and handle removal safely.
- FR-USB-07: Handle removal, interface changes, device renumbering and reinsertion at every stage without confusing files from different devices or resuming a stale session.
- FR-USB-08: Block system/boot disks and internally attached storage from scan discovery, even if their device names change.
- FR-USB-09: Define `max_device_capacity_gb` independently of engine scan limits. Capacity excess produces REJECTED/INCOMPLETE with explicit reason, not CLEAN.

### 3.2 Scan Pipeline

1. **Authorize device** against USB class/interface policy; detect and reject prohibited composite capabilities.
2. **Identify physical device and partitions** with stable session-scoped UUIDs and metadata, avoiding raw `/dev/` paths.
3. **Mount each eligible partition** through the privileged device broker in read-only mode (`ro,nodev,nosuid,noexec,nosymfollow` plus filesystem-specific safe options; `noload` for ext3/4). The block device is set read-only (`BLKROSET`) before probing or mounting, because a read-only mount alone does not stop ext3/4 journal replay. Disable any system automount path. Mounts are made in the host mount namespace under `/run/usb-scan/mounts/<session_id>/<partition_id>`, in `0750 root:<scanner read group>` directories; non-scanner services receive `InaccessiblePaths=/run/usb-scan/mounts`. (A broker-private namespace is not used: systemd does not propagate mounts from a unit's namespace to the host, and `ReadOnlyPaths=` changes only take effect on unit restart — systemd.exec(5).) Each mount is verified against the kernel mount table (device number and flags) and removed deterministically on unmount; stale session mounts are removed when the broker starts. Content hidden from the unprivileged scanner by on-media permissions (e.g. ext4 `lost+found`) is opened by the broker read-only via `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)` relative to the mount root and handed to the scanner as a file descriptor.
4. **Discover inventory** (files/dirs, symbolic links, byte totals, metadata failures). Bound traversal, reject escapes from the mount root and record reasons for exclusion. Do not follow symlinks outside the scan root.
5. **Perform mandatory ClamAV inspection** over all in-scope discoverable files within specified resource limits, passing each opened file to clamd as a file descriptor (`FILDES`) so that clamd itself needs no access to USB mounts; clamd must report limit hits and encrypted content (`AlertExceedsMax`, `AlertEncrypted`), which count as uninspected; collect per-file outcomes including `scanned`, `detected`, `skipped`, `failed`, `timeout`, `encrypted` and `unsupported`.
6. **Run YARA** if enabled and required by site policy. Compile and validate the activated ruleset in advance; apply resource/time limits and record the result per file. The YARA worker has no access to USB mounts: the orchestrator passes each already-opened, read-only file descriptor (including broker-confined opens) over the worker socket; the worker never receives paths. Each scan session runs in a disposable child process with memory, CPU and file-descriptor limits; files above `yara.max_file_size_mb` are not YARA-scanned and are reported. Per-file timeouts use YARA's native timeout API. The worker's supervisor kills the child (`SIGKILL`) when the session exceeds `yara.global_budget_seconds` (the orchestrator runs as a different user and cannot signal it); the orchestrator enforces the same budget on its side and records YARA as incomplete — INCOMPLETE when YARA is mandatory. Rule meta `severity = "high"` marks THREAT-level rules; other matches are SUSPICIOUS.
7. **Perform VirusTotal SHA-256 reputation queries** if enabled, respecting cache age, quota, privacy and policy. No file-content upload. Hash-only lookups must not be restricted by arbitrary file-upload-size thresholds; hashing large files can have a separately configured CPU/IO budget (config key: `virustotal.large_file_hash_budget_mb`).
8. **Evaluate detections and completeness** across every partition, file and **required** engine. Policy blocks can produce THREAT or SUSPICIOUS but cannot transform missing inspection into CLEAN. If the orchestrator's global timeout is reached before individual engine timeouts, the system must gracefully terminate engine processes and record an INCOMPLETE verdict.
9. **Optionally retain evidence** to isolated quarantine using a controlled copy path if triggered by a THREAT or configured policy violation, provided storage and policy allow it; quarantine failure is recorded independently of the detection verdict.
10. **Commit verdict and event record durably** before beginning ejection. Persist enough state for crash recovery and retrospective reconciliation.
11. **Safely unmount and attempt logical power-off** through the broker; verify operation result, then display whether the device can be removed. A logical eject or power-off attempt is not equivalent to actual physical removal.
12. **Forward logs/alerts asynchronously** using a durable delivery queue with retries and acknowledgments. Preserve ordering and deduplicate events.

### 3.3 Verdict and Completeness Semantics

| Verdict | Meaning | User instruction | LED |
|---|---|---|---|
| CLEAN | All content **required under the active policy** was inspected by all mandatory engines, without detection/policy violation. | No known threats detected; this does not guarantee safety. Remove only after safe-eject confirmation. | Green solid |
| THREAT | Malware detection or a policy rule designated high-severity violation. | Do not use the device; contact IT. | Red pulse |
| SUSPICIOUS | Indicator requiring caution, such as a non-critical YARA match or low-confidence reputation result. | Contact IT before use. | Amber pulse |
| INCOMPLETE | At least one required file, partition or scan stage could not be inspected or an explicit limit was hit. No confirmed threat takes precedence. | Device was not fully assessed; contact IT. | White/amber alternate |
| ERROR | Appliance/device fault prevented reliable processing or safe completion. No confirmed threat takes precedence. | Contact IT; obey physical removal instructions. | White blink |
| REJECTED | Unauthorized or out-of-policy device/interface or device-capacity policy rejection before scan. | Device not accepted; contact IT. | White/amber blink |
| NOT_READY | Appliance fails a mandatory health gate before insertion. | Scanning unavailable; contact IT. | White solid |

### 3.4 Coverage Accounting and File Policies

- Required metrics: `partitions_discovered`, `partitions_scanned`, `partitions_excluded`, `files_discovered`, `files_scanned`, `files_skipped`, `files_failed`, `files_uninspectable`, `bytes_enumerated`, `bytes_read`, and completion by engine.
- Each skip has an enumerated reason (`too_large`, `encrypted`, `unreadable`, `unsupported`, `recursion_limit`, `scan_limit`, `timeout`, `policy_exclusion`, etc.).
- Block extensions are **policy violations**, not automatically validated malware detections; configurable severity with a non-CLEAN verdict.
- Extension matching is case-insensitive with explicit behavior for double extensions, extensionless files and Unicode normalization.
- Separate orchestrator traversal limits from engine-specific parsing limits.
- For archives: apply decompression limits, total decompressed byte budgets, recursion depth, file count and time budgets.
- Scan content without executing macros, scripts, installers or binaries from the device.

### 3.5 Safe Ejection, User Presence and Operator Hold

Device processing SHALL maintain two independent dimensions: scan verdict and physical lifecycle (`present`, `mounted`, `unmounted`, `power_off_requested`, `safe_to_remove`, `removed`, `eject_failed`). After evaluating results, unmount and request drive power-off where supported. Only display **Safe to remove** after successful unmount. Retain the final result on screen while the device remains inserted.

`operator_hold` is an optional post-result state that delays the ejection command to allow a physically present operator to view the result before the device is powered off. It is **not** a substitute for access control or physical custody. Specifics:

- **Scope:** Available only after CLEAN or SUSPICIOUS verdicts, not after THREAT (device must not leave unchecked). Configurable per site.
- **Authorization:** Requires operator PIN entry within the hold window.
- **Actions permitted:** View last scan summary; acknowledge result; release device for ejection.
- **Timeout:** Maximum hold duration is configurable (default: 60 seconds). Automatic ejection proceeds if no operator interaction occurs within the hold window.
- **Logging:** Entry into OPERATOR_HOLD and exit (by operator acknowledgment, timeout, or removal) are recorded as distinct events in the scan record.

### 3.6 Quarantine (Optional, Default Disabled)

Quarantine is not needed for ordinary scan operation. When enabled via `quarantine_on_threat`, only authorized selected evidence is copied to an encrypted, non-executable partition (`nodev,nosuid,noexec`); store files under randomized opaque IDs and keep original names/paths in protected metadata only. Release of files directly back to the scanned source USB device is **architecturally prohibited in all versions** to maintain the strict read-only boundary enforced by the device broker. Secure exports are disabled by default; if enabled, they require administrator step-up authentication, visible malware warnings, explicit secure network export destination, audit logging, and a controlled transfer flow.

### 3.7 Alerts and Logging

- Persist scan-start, engine-stage, detection, completeness, verdict, ejection, alert-delivery, authentication, config, update and tamper events in structured JSON with schema version, `station_id`, `scan_id`, monotonic event sequence and UTC timestamps.
- Use SQLite for local operational events and queue (WAL with bounded storage, checkpoint and integrity checks).
- Support remote RFC 5424 or structured SIEM forwarding over an authenticated transport where possible.
- Write audit entries with a forward sequence/hash chain or periodically signed checkpoints and forward checkpoints off-device.
- Hash/omit filenames and device identifiers according to a privacy policy. Prefer keyed pseudonymization for correlation when appropriate.
- Default alerts: THREAT, SUSPICIOUS, INCOMPLETE, ERROR, REJECTED (policy-configurable), NOT_READY, tamper, signature staleness, auth abuse and update failure.

### 3.8 Health and Readiness

Before reporting ready, verify: USB policy controller, broker, mandatory scanner engine, required signature age threshold, ruleset when mandatory, sufficient filesystem space, writable event DB/queue, clock validity, and operational GUI/status channel. Mandatory failure leads to NOT_READY. A periodic end-to-end synthetic scan using a safe test fixture (e.g. EICAR string in a temporary file) SHALL be supported for maintenance validation; the synthetic scan must produce a deterministic result that is verifiable in the scan event log.

---

## 4. GUI Specification

### 4.1 Design Principles

Fullscreen Qt touchscreen kiosk; no access to host shell or desktop; portrait/landscape support; minimum 48×48-pixel touch targets; high contrast; accessible color-plus-icon state indications; translations (`.ts`/`.qm`); no full sensitive filenames on the public screen by default.

### 4.2 State Machine

| UI state | Trigger / content | Exit condition |
|---|---|---|
| STARTING | Boot, dependency initialization, health progress | All mandatory checks pass → IDLE; else NOT_READY |
| NOT_READY | Mandatory dependency failed; support code displayed | Health gate recovers after authorized verification |
| IDLE | Insert USB prompt; optional minimal stats | Candidate insertion |
| VALIDATING | Authorize USB interfaces; enumerate physical device/partitions | Authorized → MOUNTING; else REJECTED |
| MOUNTING | Preparing constrained read-only volumes | Ready → SCANNING; else ERROR/INCOMPLETE |
| SCANNING | Stage, elapsed time, files scanned, qualified progress estimate | Scan evaluation reached |
| EVALUATING | Scan completeness and detection aggregation | Verdict persisted |
| OPERATOR_HOLD | If configured and verdict is CLEAN or SUSPICIOUS: restricted operator acknowledgment workflow (see §3.5) | Authorized operator acknowledgment or timeout → EJECTING |
| EJECTING | Unmount/power-off attempt; never announce safe removal prematurely | Successful unmount → RESULT; failure → EJECT_FAILED |
| RESULT | Final verdict; coverage, scan limitations; safe-removal status | Physical removal → IDLE |
| EJECT_FAILED | Retain verdict but warn that media cannot be safely removed | Authorized retry, intervention or removal |
| REJECTED | Reason code and removal instruction | Physical removal → IDLE |
| ERROR | Failure reason code and safety instruction | Recovery and physical removal |

### 4.3 Local Operator Overlay

A 3-second long-press in a reserved IDLE region reveals the PIN pad. The PIN pad **must randomize the position of all digits on each presentation** to mitigate shoulder-surfing attacks in public-facing locations. Operator functions: last scan summary, health, language and bounded operational hold acknowledgment if allowed. High-risk actions require the remote named-admin interface or separately authorized maintenance CLI. A local operator PIN is strictly for constrained UI functions and is **not** an administrative credential.

### 4.4 Screen Privacy and Ambient Mode

After 5 minutes idle, show minimal appliance ID/status/date, not identifiable user or file details. Scanning resumes on insertion without requiring touch. Public RESULT screens redact source paths and identifiers by default.

---

## 5. Technical Architecture

### 5.1 Hardware Bill of Materials

| Component | Baseline | Design note |
|---|---|---|
| SBC | Raspberry Pi 5 / 8 GB RAM | Validate power, thermal and USB load. |
| Storage | High-Endurance/Industrial microSD | SLC/pSLC required for SQLite WAL durability. Standard consumer SD cards are strictly prohibited. |
| Display | 5-inch capacitive touchscreen, approx. 800×480 | Verify selected display, driver, Wayland and power use. |
| Scan port | Replaceable panel-mount USB extension | Connects to internal USB 3.0 port to prevent physical wear on the host SBC. |
| LED | Discrete common-cathode RGB LED | Configured on GPIO 17, 27, 22 (BCM). Eliminates need for root-level PWM timing required by NeoPixels. |
| Buzzer (optional) | GPIO 18 via suitable driver | Verify output driver and current. |
| Tamper sensor | GPIO 24 with debounce, enclosure protection | Physical switch is advisory, not a secure tamper-proof element. |
| Power | Raspberry Pi 27W (5A) USB-C PSU | Mandatory to guarantee 1.2A downstream for high-draw USB media. |
| Cooling | Raspberry Pi 5 Active Cooler | Mandatory. CPU throttling above 80°C must trigger an ERROR or DEGRADED state and alert. |
| Network | Ethernet management primary | Outbound-only telemetry preferred; optional managed Wi-Fi (WPA3-Enterprise preferred; confined to management VLAN; subject to site security policy approval before deployment). |

### 5.2 OS Layout and Persistence

**Preferred production design:** OverlayFS scripted architecture. The primary root filesystem is mounted strictly read-only using the Pi's native OverlayFS utility to prevent corruption during power loss. Standard OS-level writes are redirected to a volatile `tmpfs` in RAM. A dynamically provisioned `ext4` persistent data partition resides at the end of the SD card.

Persistent paths mapped to the data partition include: `/var/lib/usb-scan/` (database, queue, cache, rules), `/etc/usb-scan/` (configuration overlay), and `/var/log/usb-scan/` (logs).

### 5.3 Software Stack and Version Policy

| Component | Baseline selection | Validation requirement |
|---|---|---|
| Python | Distribution-supported Python 3.x (Trixie target: 3.13) | Pin/test runtime with selected GPIO, Qt and dependency wheels. |
| ClamAV | Supported security-maintained release available from validated repository | Validate binary + DB format + socket access + resource limits on Pi 5. |
| Qt | **PySide6 preferred** for distribution flexibility | API compatibility and LGPL obligations must be reviewed; not presumed a drop-in PyQt6 replacement. |
| YARA | yara-python, supported release | Validate compile and hostile-input timeouts. |
| Web | Flask + HTMX behind production WSGI server and reverse proxy | Validate TLS, auth sessions and security headers. |
| SQLite | OS-supported release | WAL, backups, migrations, corruption and disk-full handling. |
| Device control | Custom device broker | Verify strict allowlist, mount constraints and sysfs path handling. |
| GPIO | lgpio/rpi-lgpio compatible stack | Validate GPIO chip mapping and packaging. lgpio is a system package on Trixie; the Python venv must be created with `--system-site-packages`. Do not `pip install lgpio`. |
| Encryption | cryptsetup LUKS2 | Document unlock and key recovery for optional quarantine. |
| HTTP | Supported httpx release | Connection pooling, CA trust, egress proxy and retries. |
| Password hashing | **bcrypt** (cost 12) for all PIN and local named-account credential storage. Argon2id may be substituted for named-account passphrases when explicitly configured, but must not be mixed with bcrypt in the same credential store without schema versioning. The 72-byte input limit of bcrypt is not a concern for 6-digit numeric PINs; implementation must validate input length regardless. |

### 5.4 Services, IPC and Privileges

| Service | User/privileges | Interface |
|---|---|---|
| `usb-scan-device-broker.service` | Restricted privileged custom service (root; only `CAP_SYS_ADMIN` and `CAP_CHOWN` retained after start, `no_new_privs`). Bypasses `udisks2` entirely to eliminate D-Bus attack surface. Must not use namespace-creating sandboxing options. | `0660 root:usbscan` Unix socket; peer uid check plus per-message HMAC with replay protection; strict allowlisted JSON/RPC commands. |
| `usb-scan-orchestrator.service` | `usbscan`, unprivileged, no shell execution | Broker RPC; events; clamd socket |
| `clamav-daemon.service` | `clamav` user. Enforces `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices=yes`, and `NoNewPrivileges=true`; `InaccessiblePaths=/run/usb-scan/mounts`. | Clamd Unix socket; files are received as descriptors (`FILDES`), no mount access needed. |
| `usb-scan-yara.service` (optional) | Isolated `yarascan` user; no access to USB mounts (`InaccessiblePaths=`), no network | `0660 yarascan:usbscan` socket, peer uid check; files received as descriptors; per-session child with rlimits and native YARA timeout; supervisor kills the child on budget expiry. |
| `usb-scan-gui.service` | `usbscan-gui`, no device rights | Read-only state/event socket; restricted operator RPC |
| `usb-scan-led.service` | Restricted GPIO identity | State events; GPIO only |
| `usb-scan-admin.service` | `usbscan-web`, no direct device/mount/secret reads | Authenticated management API |
| `usb-scan-events.service` | `usbscan-events` | Durable local queue; remote outbound delivery |

**IPC requirement:** Authenticate clients, version message schema, validate all commands, prevent arbitrary path arguments or host filesystem traversal, and record privileged actions. The orchestrator must not pass raw device paths (e.g., `/dev/sda1`) to the broker; it must pass validated kernel `sysfs` identifiers or partition UUIDs.

---

## 6. Configuration Reference

### 6.1 Principles

`/etc/usb-scan/scan_station.yaml` contains **no plaintext secrets or credential hashes**. Secret fields are references to root-controlled files, systemd credentials or a protected key store. Environment-variable secrets are permitted only in development mode (`USB_SCAN_DEV=1`), because environment variables are readable by same-user processes. Config must pass a typed schema with defaults, enum validation, size/time bounds and cross-field rules before activation.

### 6.2 Validation Rules

- VirusTotal is advisory-only (§15.2 #4, 1.5.9): `virustotal.enabled=true` requires a credential reference; there is no mandatory role.
- `yara.role=mandatory` requires a valid signed, compiled ruleset, otherwise station is NOT_READY.
- `auth.web.require_mfa=true` is mandatory for OIDC.
- Non-empty `allow_extensions` constitutes a restricted policy scope and requires prominent report/UI disclosure; files outside it make the result INCOMPLETE (§15.2 #6, 1.5.9).
- Quarantine is enabled only if the encrypted mount has been verified, has sufficient capacity, and export rules are explicitly set.
- `operator_hold.enabled=true` requires `operator_hold.max_duration_seconds` to be set (range: 15–300 seconds) and `operator_hold.allowed_verdicts` to enumerate CLEAN and/or SUSPICIOUS explicitly.

### 6.3 Key Configuration Field Notes

- `virustotal.large_file_hash_budget_mb`: CPU/IO budget for computing SHA-256 hashes of large files prior to VT lookup. This is a processing budget, not a size restriction on VT upload (no file content is uploaded in v1.x).
- `pin.hash_algorithm`: must be `bcrypt`; cost factor must be 12 or higher.

---

## 7. OS Updates & Maintenance Strategy

### 7.1 OS Updates and Maintenance Mode

A provisioning script configures the OverlayFS read-only root and persistent data partition at setup. System and application updates are applied by invoking a maintenance toggle script that disables OverlayFS and reboots the system into a writable state. Administrators apply standard package updates (`apt upgrade`) before executing the script to re-enable the read-only overlay.

If an OS update fails or a power loss occurs during the writable maintenance window, the SD card requires manual reflashing; automatic fallback/rollback is not supported in this architecture. Updates must be applied on UPS-backed or otherwise reliable power. A reflash image and documented recovery procedure must be maintained and accessible to field maintenance personnel (see §13 for the associated risk entry).

### 7.2 AV Signature Updates

Freshclam operates independently of image updates on a maintained schedule (target hourly, adjusted for upstream guidance/availability). Use writable signature storage on the persistent partition, validate successful update and reload, and expose signature age and engine readiness. Mark mandatory scanner NOT_READY if signatures exceed the configured freshness threshold.

### 7.3 YARA Rules

Fetch signed versioned manifests and bundles over TLS; validate trust anchor/signature, hash, compatible rule compiler, rule syntax and resource limits; stage and compile separately; activate atomically; retain last known-good ruleset. Format (owner decision): `manifest.json` (`format`, monotonically increasing `version`, SHA-256 per rule file) signed with **minisign** against `yara.trust_anchor_path`. The worker verifies the exact manifest bytes it parses, compiles only listed files from the exact bytes it hashed, disables `include` directives, refuses versions older than the last accepted one, and keeps the previous ruleset if any step fails. A signed bundle is required whenever YARA is enabled, whatever its role.

---

## 8. Security Hardening

### 8.1 Host Hardening

- Minimal OS image; remove unused services/accounts; restrict USB peripherals.
- Default-deny inbound firewall. Bind management service only to trusted interface/reverse proxy, with allowlisted management networks.
- SSH off by default; if enabled, named administrator keys and separate management VLAN, no password login.
- AppArmor and systemd sandboxing (`NoNewPrivileges`, capability bounding, `ProtectSystem`, `ProtectHome`, device allowlists, memory/CPU quotas), validated against required hardware interfaces.
- Trixie note: passwordless sudo is disabled by default since the April 2026 Trixie release; do not re-enable it.

### 8.2 USB and Filesystem Isolation

- **USBGuard Policy:** Default-deny policy explicitly authorizes internal controllers and restricts the external scan port strictly to the Mass Storage class (`08`).
- **Composite Block:** Devices presenting a composite interface that includes the Human Interface Device (HID) class (`03`) are immediately rejected at the USB authorization layer before any scan state is entered. Rejection at the GUI layer alone is insufficient.
- **Broker Constraints:** Dedicated privileged broker utilizes kernel `sysfs` identifiers/UUIDs rather than raw `/dev/` paths to prevent traversal.
- **Mount Hardening:** Read-only, `noexec,nodev,nosuid` mounts with safe filesystem-specific options. Non-POSIX mounts enforce `gid=<usbscan-read-gid>,dmask=0027,fmask=0137` to guarantee files are exclusively readable by the scanner processes.
- **Automount Prevention:** Host automount features (`gvfs`, `pcmanfm`) are permanently masked or uninstalled to prevent race conditions.
- **Kernel Surface Reduction:** Legacy filesystem modules (`cramfs`, `hfs`, `jffs2`, etc.) are explicitly blacklisted via `/etc/modprobe.d/` configuration.
- Constrain scanner access to the mounted media with strict namespaces/path validation; never follow path traversal or links outside allowed mount roots.

### 8.3 Secrets, Authentication and Audit

Store signing keys, PIN hashes, local fallback credential hashes, SMTP/VT credentials and quarantine keys outside general YAML. Minimize filesystem-readable scope using file ownership and systemd credentials. Support rotation, revocation, protected backup and disaster recovery.

---

## 9. Admin Web UI

### 9.1 Exposure and Transport

Optional Flask + HTMX UI, disabled by default in the sample config until HTTPS and authentication are configured. Use supported WSGI server behind TLS reverse proxy; no direct Internet exposure. Management-network restriction and per-user authorization mandatory. Endpoints are authenticated and CSRF-protected.

### 9.2 Central Dashboard

Each station is individually enrolled using a unique mTLS certificate issued during factory provisioning. The secure bootstrap mechanism for delivering certificates to appliances before deployment requires explicit design and owner approval (see §15.2 item 2). Once enrolled, the station uses mTLS for event delivery to the central collector. Include event ID, station ID, monotonic sequence and UTC timestamp; deduplicate and reject replays, detect gaps, and queue when disconnected.

---

## 10. Authentication & Authorization

### 10.1 Local Operator PIN

A minimum six-digit numeric PIN (no factory default) unlocks the restricted touchscreen operator overlay. Reject repeated/sequential PINs and PINs on configured deny lists. The on-screen keypad **must randomize digit positions on each presentation** to mitigate shoulder-surfing in public-facing locations. Store the hash using bcrypt at cost factor 12 or higher in a protected secrets store outside the general config YAML. Rate-limit independently of hash computation cost. Retain lockout state robustly across GUI restarts (lockout state is persisted in the orchestrator's own SQLite database, not held in process memory; every attempt is also recorded in the audit event chain — see revision 1.5.4). Default: five failed attempts followed by 15-minute lockout. Within one boot, lockout expiry is measured on the monotonic boot clock, so wall-clock changes neither shorten nor extend it; if after a reboot the wall clock is behind the lockout record, the lockout is re-armed once (fail closed, extended by at most one lockout period).

### 10.2 Named Remote Administrator Authentication

Remote administration SHALL use individual named accounts with OIDC/SSO and MFA. A local named-account fallback with passphrases (bcrypt cost 12 or Argon2id, see §5.3) is allowed only when explicitly configured for an isolated management network where OIDC is unavailable. Shared PINs or shared passwords for remote administrative access are not permitted.

---

## 11. Non-Functional Requirements

| NFR | Proposed target / validation |
|---|---|
| Detection latency | Candidate insertion visible within 2 seconds on qualified reference hardware. |
| Scan startup | 3 seconds from authorized insertion to first scan work on reference media. |
| Boot/readiness | Target 30 seconds from cold boot to actual health-gated IDLE. |
| GUI | No blocking IO on UI thread; stage/status updates at least twice per second. |
| Data durability | SQLite WAL with backup/restore tests, bounded queue, disk-full and corruption recovery. |
| Thermal | CPU throttling above 80°C must trigger an alert, log the event, and halt active scans. Threshold in Celsius. |
| Offline operation | Core ClamAV scanning works with valid local signatures; required external checks yield INCOMPLETE when unavailable. |
| Service recovery | A crashed or hung service must be recovered within 30 seconds. Broker and events service units use `WatchdogSec=30`; the orchestrator uses `WatchdogSec=15` with `TimeoutAbortSec=5` and `RestartSec=2` so that hang detection plus restart also fits within 30 seconds (1.5.8). Persistent crashes (3 restarts in 5 minutes) must alert and transition the station to NOT_READY. |
| Availability | Unplanned downtime caused by a recoverable service fault must not exceed the watchdog-recovery window. Planned maintenance windows for OS updates require documented pre/post-check procedures. |

---

## 12. Future Extensions

- CDR with sanitized-output delivery path and separate assurance claims.
- Isolated hardware USB gateway or specialized USB attack-resistant controller for high-assurance OT deployments.
- Badge/RFID or enterprise identity for scan attribution.
- QR receipt displaying a short-lived, access-controlled report token.
- Fleet provisioning bootstraps, inventory and remote health dashboard with per-device certificates.

---

## 13. Risks & Mitigations

| Risk | Indicative likelihood / impact | Mitigation and residual concern |
|---|---|---|
| Hostile USB firmware/interface | Medium / High | USB class policy, composite rejection at authorization layer, isolated broker, physical protection; kernel/firmware exposure remains. |
| Crafted filesystem / archive parser | Medium / High | Read-only restricted mounts, minimal parser surface, worker isolation, fuzz/test corpus; kernel vulnerabilities remain possible. |
| Archive/resource exhaustion | High / Medium | Per-worker budgets, decompression caps, scan timeouts, load testing and safe failure. |
| Quarantine exposes malware | Medium / High | Disabled default, encryption, non-executable mount, opaque names, controlled audited exports. |
| Audit deletion or rollback | Medium / High | Remote forwarding, hash chain/checkpoints, off-device sequence/gap monitoring. |
| Update-window power loss | Medium / High | OS update requires reflash of SD card with no automatic rollback. Mitigation: apply updates on UPS-backed power; maintain a current reflash image and documented recovery procedure accessible to field staff. Residual: field recovery time depends on image availability and staff access. |

---

## 14. Acceptance Criteria

### 14.1 Functional and Scan Correctness

| ID | Criterion |
|---|---|
| AC-F01 | Clean reference USB medium, all content in scope and all mandatory stages complete, results in CLEAN with actual coverage metrics and no false exclusions. |
| AC-F02 | EICAR reference test artifact is detected as THREAT with accurate engine evidence and clear non-safe-use warning. |
| AC-F03 | All supported partitions are inventoried and scanned; an unsupported or uninspected partition prevents CLEAN under default policy. |
| AC-F04 | A device exceeding `max_device_capacity_gb` produces REJECTED with an explicit reason code; CLEAN is never returned. |
| AC-F05 | The synthetic scan fixture (§3.8) produces a deterministic, known result visible in the scan event log within a maintenance test run. |
| AC-F06 | Mandatory ClamAV failure or timeout yields ERROR/INCOMPLETE; advisory YARA/VT failure follows configured policy (VT: always advisory) and is visible in report. |
| AC-F07 | All required coverage metrics (`partitions_discovered`, `files_scanned`, `files_skipped`, skip reasons, bytes, and engine completion flags) are present in the emitted scan event record for every completed scan. |

### 14.2 Security and Isolation

| ID | Criterion |
|---|---|
| AC-S01 | Root image is read-only; persistent writable paths are explicitly bounded and verified after reboot. |
| AC-S02 | A USB device presenting composite HID+Storage interfaces is rejected at the USBGuard authorization layer before any scan state is entered; the rejection is recorded in the event log. Bypassing the rejection by GUI-only filtering does not satisfy this criterion. |
| AC-S03 | All user partitions are mounted read-only, noexec/nosuid/nodev with appropriate filesystem options; writes from broker/scanner are strictly denied across all operations. |
| AC-S04 | Orchestrator/web/GUI cannot execute arbitrary broker commands, choose unapproved host paths or mount internal system disks. |
| AC-S05 | Operator PIN lockout state persists across GUI process restarts; a restarted GUI cannot be used to reset the lockout counter. |
| AC-S06 | Operator PIN pad presents digits in a randomized layout on each display. |

### 14.3 Reliability, Operations and Recovery

| ID | Criterion |
|---|---|
| AC-R01 | Station transitions to NOT_READY when a mandatory health gate fails (ClamAV unavailable, signatures exceeded freshness threshold, insufficient disk space); transitions back to IDLE after the gate recovers. |
| AC-R02 | 100 consecutive media insert/scan/remove cycles run without leaked mounts, device-identity confusion or service restart. |
| AC-R03 | Power loss during scan leaves recoverable DB/config with scan marked interrupted; no invalid safe-remove indication after reboot. |
| AC-R04 | A crashed or hung orchestrator service is recovered by systemd (restart policy, watchdog) within 30 seconds and the station transitions correctly to NOT_READY or IDLE after restart. |

---

## 15. Revision History & Open Decisions

### 15.1 Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | Prior release | Initial appliance concept. |
| 1.1 DRAFT | July 2026 | Baseline analyzed for inconsistencies. |
| 1.2 DRAFT | October 2026 | Reworked scan semantics/coverage, USB trust boundary, privileged device broker, state machine/ejection, admin authentication. |
| 1.3 DRAFT | 13 October 2026 (superseded same day) | Addressed architectural contradictions regarding quarantine release workflows; unified terminology around local Operator constraints vs. remote Admins. Superseded by v1.4 before distribution. |
| 1.4 DRAFT | 13 October 2026 | Resolved Hardware BOM (office configuration, 27W PSU, Active cooler); standardized on High-Endurance microSD with OverlayFS script architecture (A/B updates abandoned); locked USBGuard class enforcement and hardened scanner namespace access. |
| 1.5 DRAFT | 13 October 2026 | Final review findings applied: stripped review annotations; resolved §9.2/§15.2 mTLS contradiction; added missing acceptance criteria (NOT_READY, USBGuard policy-layer rejection, coverage metrics, REJECTED, PIN lockout persistence, synthetic fixture); added randomized PIN keypad requirement; specified YARA file delivery and kill-on-timeout behavior; defined `operator_hold` semantics; added update-window power-loss risk; added MTTR/watchdog NFR; clarified bcrypt vs Argon2id scope; added NTFS/exFAT driver validation note; clarified mount namespace model; added Wi-Fi policy scope note; disambiguated v1.3/v1.4 same-day revision. |
| 1.5.1 DRAFT | 13 October 2026 | Implementation-driven owner decisions: host-namespace mount model with BLKROSET, verified mounts and broker-confined `openat2` opens (replaces per-session namespace + `ReadOnlyPaths` drop-in, §3.2/§5.4); ClamAV via `FILDES` with mandatory limit/encryption alerts; explicit partition-type exclusion policy (FR-USB-04); `network_outage_policy_ref` for mandatory VirusTotal; environment secrets development-only; lockout clock-jump handling (§10.1); blocked-extension default severity SUSPICIOUS (§15.2 #6). |
| 1.5.2 DRAFT | 13 October 2026 | YARA worker (owner decisions): descriptor delivery instead of mount access, per-session child with supervisor-side budget kill, minisign-signed manifest with rollback guard (§7.3), `yara.max_file_size_mb` default 256 (§3.2 step 6, §5.4). |
| 1.5.3 DRAFT | 13 October 2026 | Optional modules (owner decisions): VirusTotal reputation thresholds — ≥ `suspicious_min_malicious` (default 1) engines "malicious" → SUSPICIOUS, ≥ `threat_min_malicious` (default 5) → THREAT (§3.2 step 7); quarantine retains THREAT-level (high-severity) detections only, on a verified LUKS2 mount, and quarantine export stays disabled until the step-up/audited flow exists (§3.2 step 9, §3.6); alert channels webhook (https), e-mail (STARTTLS/TLS) and syslog over TLS (RFC 5424 JSON or CEF) with interim best-effort delivery until the events-service queue (§3.7). |
| 1.5.4 DRAFT | 13 October 2026 | Events service (owner decisions): authoritative PIN lockout state remains in the orchestrator's own SQLite database (auth attempts are additionally recorded in the audit chain) (§10.1); alert delivery moves to `usb-scan-events` together with SIEM forwarding, through per-channel durable queues with backoff and dead-lettering (§3.2 step 12, §3.7, §5.4); audit database uses `synchronous=FULL`; hash chain over canonical JSON records with HMAC checkpoints of the chain head; a failed chain verification records a tamper event and keeps the station NOT_READY until an administrator acknowledges it (§3.7, §3.8). |
| 1.5.5 DRAFT | 13 October 2026 | Admin web UI (owner decisions): read-only interface — no configuration reload or signature-update triggers from the web process (§9.1); front-end libraries vendored and integrity-verified, strict CSP without CDN; OIDC MFA proven by ID-token `amr`/`acr` claims; per-role data minimisation (file paths and device serials for administrators only); every data access audited, failing closed when the audit log is unavailable (§3.7, §10.2). |
| 1.5.6 DRAFT | 13 October 2026 | Deployment (owner decisions): optional quarantine on a separate LUKS2 medium unlocked at boot by a root-only keyfile, with an escrowed recovery passphrase (§3.6, §8.3); YARA rulesets installable offline and optionally pulled over HTTPS, activated only after signature/hash/compile/rollback checks with an atomic switch (§7.3); service crash loops (3 restarts in 5 minutes) enforced by systemd start limits (§11); USBGuard rejects any HID-bearing device and authorises only all-mass-storage devices (§8.2). |
| 1.5.7 DRAFT | 13 October 2026 | Host hardening (owner decisions): AppArmor profiles for all station services shipped in complain mode and promoted to enforce after on-device tuning (§8.1); outbound traffic restricted to a per-service allowlist in addition to default-deny inbound (§8.1); read-only root via `overlayroot=tmpfs:recurse=0` so the persistent data partition is not overlaid, with ClamAV signatures on the persistent partition and scanning disabled during the writable maintenance window (§5.3). |
| 1.5.8 DRAFT | 14 October 2026 | Acceptance (owner decisions): orchestrator hang recovery within 30 s (`WatchdogSec=15`, `TimeoutAbortSec=5`, `RestartSec=2`; §11, AC-R04 covers crash and hang); USBGuard HID rule uses `block` instead of `reject` so the rejection is recorded deterministically in the audit chain (§8.2, AC-S02); VirusTotal hash sharing approved as per-site opt-in, disabled by default (§15.2 #3); GUI ships English and German. |
| **1.5.9 DRAFT** | **14 October 2026** | Open decisions §15.2 #2–#6 resolved by the owner: on-device key + CSR enrolment for the station mTLS identity, provider-neutral OIDC with roles admin/operator/viewer (#2); keyed HMAC pseudonyms off-device, retention 180 d audit / 30 d quarantine adjustable per site, quarantine optional and off by default (#3); VirusTotal advisory-only, mandatory role removed (#4, §6.2); escrow of history-protecting secrets and regeneration of the rest (#5); allow-list-scoped scans never CLEAN when files were excluded (#6, §6.2). |

### 15.2 Implementation Decisions Still Requiring Prototype or Owner Approval

1. **Throughput and readiness thresholds:** prototype benchmark must establish realistic mandatory limits and service-level objectives.
2. **Fleet identity and mTLS bootstrap:** *Resolved (1.5.9):*
   - **Key generation:** each station generates its EC P-256 key on the device. It never
     leaves the station; the Pi 5 has no TPM, so it is a root-owned file, 0640
     root:usbscan-events.
   - **Signing:** a CSR (CN = station id, EKU clientAuth) is exported over SSH or the serial
     console and signed by the organisation's CA. The public-key fingerprint is compared out
     of band.
   - **Installation:** the certificate is installed after key, CN, expiry, EKU and chain
     checks, and rotated without downtime (`scripts/station-cert.sh`).
   - **Automated enrolment** (EST/ACME) is out of scope for v1.x.
   - **OIDC:** provider-neutral; the organisation's IdP is chosen at deployment. RBAC roles
     are `admin`, `operator` and `viewer`, mapped from IdP group claims
     (`auth.web.oidc.role_map`). MFA is proven by `amr`/`acr`.
3. **Privacy and retention:** *Resolved:*
   - **VT hash sharing (1.5.8):** approved as a per-site opt-in. VirusTotal stays disabled
     by default; a site may enable hash-only lookups (no uploads) after its own privacy
     approval.
   - **Off-device data (1.5.9):** file paths and device serials leave the station only as
     keyed HMAC pseudonyms (`logging.filename_privacy: hash`). The key is generated per
     station and escrowed; a fleet-wide key is optional for cross-station correlation.
     Full detail stays in the on-device audit database, and the admin web shows it to the
     `admin` role only.
   - **Retention (1.5.9):** audit database 180 days, quarantine 30 days; the SIEM is the
     long-term record. Sites adjust both to their regional obligations as a deployment step.
   - **Quarantine (1.5.9):** optional and off by default. A site enables it with a separate
     LUKS2 medium. It keeps THREAT-level evidence only, and export stays disabled until an
     audited step-up flow exists.
4. **Cloud mandatory mode:** *Resolved (1.5.9):* VirusTotal is advisory-only.
   - It never changes a verdict through missing coverage and never gates readiness.
   - Offline, out of quota or without a key, the result is unchanged and the reason codes
     record the failure (`virustotal_unavailable:*`); a missing client is a health warning.
   - The settings `virustotal.role`, `on_quota_or_network_failure` and
     `network_outage_policy_ref` were removed. The configuration loader rejects them.
5. **Secret recovery:** *Resolved (1.5.9):*
   - **Escrowed:** secrets that protect history go to the organisation's vault: the event
     checkpoint key, the pseudonymisation key and the quarantine recovery passphrase.
   - **Regenerated on rebuild:** the broker key, the quarantine keyfile (re-keyed with the
     recovery passphrase), the mTLS key (new CSR, old certificate revoked) and the operator
     PIN.
   - The procedure is in `docs/secret-recovery.md`.
6. **Threat/policy definitions:** *Resolved:*
   - Prohibited extensions are policy violations with default severity SUSPICIOUS
     (`scan.blocked_extension_severity`, configurable to THREAT).
   - Extension-scoped scans (1.5.9) fail closed. Any file outside `scan.allow_extensions` is
     not inspected and makes the result INCOMPLETE (`restricted_extension_scope`). CLEAN
     under an allow-list is possible only when every file was in scope, and it is still
     disclosed.

### 15.3 Release Gate

**Do not mark implementation-ready** until:
- Core failure behavior is validated on real Pi 5 hardware with the intended microSD model.
- Negative/security acceptance tests AC-S02 through AC-S06 have owners and reproducible test fixtures.
- Open decisions in §15.2 items 2–6 are either resolved or explicitly deferred with a documented fallback behavior for the initial implementation phase.

---

*End of specification.*
