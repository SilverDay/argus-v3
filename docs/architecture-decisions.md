# Architecture decision records

Format: context → decision → consequences. "Spec x.y.z" names the specification revision
that recorded the decision. Deviations from the implementation plan are noted where they
apply.

---

## ADR-001 — Custom device broker instead of udisks2/dasbus

**Status:** accepted (spec 1.5; mount model refined in 1.5.1)

**Context.** Mounting hostile USB media needs root. udisks2 brings D-Bus, polkit and a large
automount-oriented code base. Every one of them is attack surface reachable by local
services, and its policy is hard to restrict to exactly what a scanner needs.

**Decision.** `src/broker/` is a small root service with an allowlisted JSON RPC on a Unix
socket:
- SO_PEERCRED restricts callers to one uid; HMAC protects every request;
- requests carry sysfs identifiers only, never `/dev` paths;
- the block device is set read-only (BLKROSET) before mounting;
- mounts are `ro,noexec,nosuid,nodev,nosymfollow`, and each mount is verified in mountinfo;
- files are opened for the orchestrator with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`;
- the broker keeps only CAP_SYS_ADMIN and CAP_CHOWN.

**Consequences.**
- No D-Bus in the scan path; udisks2 is masked.
- The broker is security-critical code we maintain. It is covered by unit and loopback
  integration tests (docs/broker-design-notes.md).

---

## ADR-002 — PySide6 instead of PyQt6

**Status:** accepted

**Context.** The kiosk needs Qt.

**Decision.** PySide6 (Qt for Python), the official Qt binding.
- PySide6 is available under LGPLv3. PyQt6 is GPLv3 or commercial.
- The LGPL allows distributing the appliance without putting the whole station software
  under the GPL, provided the LGPL obligations are met: dynamic linking, a replaceable
  library, license texts.

**Consequences.**
- License texts and a relinking/replacement notice must ship with images.
- GUI strings use `QCoreApplication.translate("usbscan", …)` so `pyside6-lupdate` extracts
  them.

---

## ADR-003 — lgpio instead of RPi.GPIO

**Status:** accepted (refined)

**Context.** The Raspberry Pi 5 drives its GPIO header through the RP1 I/O controller.
RPi.GPIO programs the older SoC GPIO registers directly and does not support the Pi 5.

**Decision.**
- Use the native `lgpio` module from the distribution package `python3-lgpio`, made visible
  through a `--system-site-packages` venv.
- **Deviation from the plan:** the `rpi-lgpio` compatibility shim is *not* used. It installs
  a package named `RPi.GPIO` and would blur the "no RPi.GPIO" rule.

**Consequences.**
- The LED service runs with group `gpio` and nothing else.
- Development machines use the stub driver; production uses `led.driver: lgpio`, which fails
  visibly when the chip cannot be opened.

---

## ADR-004 — SQLite instead of PostgreSQL

**Status:** accepted (events service design in spec 1.5.4)

**Context.** The station must work offline and survive power loss. It has no administrator
on site.

**Decision.** Embedded SQLite in WAL mode with `synchronous=FULL`:
- **audit/event store:** hash chain over canonical JSON, HMAC checkpoints, durable delivery
  queues;
- also used for the PIN lockout database, the web sessions and the VirusTotal cache.

The orchestrator writes events through the events service. An fsync'd spool covers
outages of that service.

**Consequences.**
- No database server to patch or expose.
- Single-writer design, so throughput is bounded by one station's needs.
- Off-device durability comes from SIEM forwarding.

---

## ADR-005 — OverlayFS read-only root instead of A/B partitions

**Status:** accepted (spec 1.5.7)

**Context.** SD cards wear out and power can fail. A/B image updates would need a second
root partition, a boot-selection mechanism and an update agent. That is more moving parts
than one station justifies.

**Decision.**
- **Root:** `overlayroot=tmpfs:recurse=0`, a read-only root with a RAM overlay.
  `recurse=0` keeps the separate data partition (`LABEL=USBSCAN-DATA`) out of the overlay.
  `/var/lib/usb-scan`, `/etc/usb-scan`, `/var/log/usb-scan` and `/var/lib/clamav` are bind
  mounts from that partition.
- **OS and application updates** happen in an explicit maintenance window
  (`scripts/maintenance-mode.sh`). The orchestrator does not run during the window.

**Consequences.**
- Runtime changes to the root vanish at reboot.
- Signatures and rules update without a window.
- A power loss during the window can leave the card unbootable. Mitigations: UPS, a reflash
  image, escrowed keys (spec §5.3, docs/secret-recovery.md).

---

## ADR-006 — Named accounts with MFA instead of a shared admin PIN

**Status:** accepted (spec §10.2, 1.5.5; provider-neutral in 1.5.9; local accounts as a regular
method in 1.5.10)

**Context.** A shared PIN cannot say *who* did something and cannot be revoked per person.

**Decision.**
- Remote administration uses OIDC: authorization code with PKCE, nonce and JWKS rotation.
- MFA is proven by the `amr`/`acr` claims.
- Roles `admin`/`operator`/`viewer` are mapped from IdP groups.
- Local named accounts are a second method, alone or alongside OIDC (1.5.10):
  - bcrypt passphrase plus TOTP (RFC 6238) by default;
  - managed with a root-only, audited CLI on the station;
  - sessions re-checked on every request.
  Sites that run without an IdP still get named, individually revocable accounts with a
  second factor.
- The operator PIN is limited to the local touchscreen overlay.

**Consequences.**
- Every data access is attributable and audited (fail closed).
- The station depends on the IdP for remote access, but not for scanning.

---

## ADR-007 — Unix socket IPC instead of D-Bus

**Status:** accepted

**Context.** Local services (broker, orchestrator, GUI, LED, YARA worker, events, web) must
talk to each other with strict, auditable access rules.

**Decision.**
- One Unix socket per service boundary under `/run/usb-scan/`.
- Filesystem permissions (dedicated groups) control who can connect. SO_PEERCRED maps the
  caller's uid to a role.
- Newline-delimited JSON with size limits.
- HMAC on the privileged broker channel; file descriptors are passed where content must
  cross boundaries (FILDES).

**Consequences.**
- No bus daemon and no policy files spread across services.
- Each protocol is small and fully tested.
- Access is enforced twice: by file mode and by peer uid. The acceptance suite verifies it
  as the real service accounts (AC-S04).

---

## ADR-008 — YARA as an isolated service instead of a library import

**Status:** accepted (spec 1.5.2)

**Context.**
- YARA rules are code-like input; a hostile or buggy rule, or hostile file content, can
  consume unbounded CPU and memory.
- Importing yara-python into the orchestrator would put that risk into the process that
  holds the broker key.

**Decision.**
- **Separate account and service.** `usb-scan-yara` runs as `yarascan` with no mount access;
  it receives read-only file descriptors from the orchestrator.
- **Supervision.** A supervisor starts one rlimited child per scan session and SIGKILLs it
  when the budget expires.
- **Rule sets.** Only minisign-signed, hash-checked bundles with a rollback guard.

**Consequences.**
- A YARA failure costs coverage (INCOMPLETE when YARA is mandatory), never the orchestrator.
- Rule updates are atomic and verifiable.

---

## ADR-009 — ClamAV through FILDES

**Status:** accepted (spec 1.5.1)

**Decision.**
- The orchestrator opens each file, without following symlinks, and passes the descriptor
  to clamd.
- clamd needs no access to USB mounts and is sandboxed away from them.
- `AlertExceedsMax`/`AlertEncrypted` turn silent limit hits into INCOMPLETE.
- The clamd socket is 0660 group `clamav`, also under socket activation.

**Consequences.** No path-based TOCTOU, and no `StreamMaxLength` limit as with INSTREAM.

---

## ADR-010 — Read-only admin web

**Status:** accepted (spec 1.5.5)

**Decision.**
- The web process has no privileged actions: no configuration reload, no signature
  trigger, no lockout reset.
- Front-end libraries are vendored and integrity-checked under a strict CSP.

**Consequences.**
- A compromised web process can read audited data but cannot change the station.
- Changes need SSH and, for OS-level settings, a maintenance window.

---

## ADR-011 — USBGuard `block` for HID-bearing devices

**Status:** accepted (spec 1.5.8)

**Decision.**
- Authorise only devices whose interfaces are all mass storage.
- Any HID interface is caught by a `block` rule. `reject` would remove the device before
  the orchestrator can record why.

**Consequences.**
- No driver binds to a blocked device.
- The rejection is always in the audit chain (`usb_policy_blocked`, AC-S02).

---

## ADR-012 — VirusTotal advisory-only, hash lookups only

**Status:** accepted (spec 1.5.8 / 1.5.9)

**Decision.**
- VirusTotal is a per-site opt-in after privacy approval, sending SHA-256 lookups only and
  never file content.
- It never gates a verdict through missing coverage and never gates readiness. Its
  reputation results can still raise SUSPICIOUS/THREAT.

**Consequences.** Station availability is independent of the internet and of VT quotas.

---

## ADR-013 — Fail closed on scope and coverage

**Status:** accepted (spec §3.3; extension scope 1.5.9)

**Decision.** Anything required but not inspected makes the result INCOMPLETE, never CLEAN:
- unreadable, encrypted or limit-exceeding files;
- an unsupported partition;
- a mandatory engine gap;
- a file outside an extension allow-list.

A periodic synthetic EICAR scan proves the detection path end to end (spec §3.8).

**Consequences.** Operators see more INCOMPLETE results. That is intended: a false CLEAN is
the failure this appliance exists to prevent.
