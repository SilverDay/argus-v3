# Scan Orchestrator — Design Notes and Open Items (Phase 3)

## Decisions implemented

1. **ClamAV via FILDES.** The orchestrator opens files and passes descriptors to clamd
   (clamd(8) FILDES). clamd needs no access to USB mounts, so the spec's per-session
   `ReadOnlyPaths=` for clamd (§3.2 step 3, §5.4) is unnecessary.
2. **Limit and encryption signals are mandatory.** clamd must run with
   `AlertExceedsMax yes` and `AlertEncrypted yes` (config/clamd.conf.recommended);
   verified with clamd 1.5.4 that MaxFiles, MaxFileSize and MaxRecursion hits and
   encrypted ZIPs are reported and mapped to INCOMPLETE.
3. **Signature age.** No official database date in `VERSION` → NOT_READY
   (`signatures_unknown`), never "unknown but OK".
4. **Removal mid-scan → INCOMPLETE** (plan said ERROR). Spec §3.3 defines INCOMPLETE as
   "at least one required file … could not be inspected"; ERROR is reserved for
   appliance faults. A threat found before removal stays THREAT.
5. **Verdict precedence:** THREAT > ERROR > INCOMPLETE > SUSPICIOUS > CLEAN.
6. **No file names on the public channel.** Progress events carry counters only; the
   GUI verdict payload has signatures and counts but no paths. Paths and SHA-256 are in
   the committed record only; the events service pseudonymises them before forwarding.
7. **Durable sink.** `EventClient` (events service, synchronous=FULL, with an fsync'ed local
   spool when the service is unreachable — see events-design-notes.md). `JsonlEventSink`
   remains for development and tests. The verdict is durable before ejection starts.
8. **Crash recovery.** An `active_scan.json` marker turns a crash/power loss into a
   `scan_interrupted` event with `safe_to_remove=false` and a broker `release` on restart.

## Owner decisions (13 Oct 2026, spec 1.5.1)

### A. ext media / permission-hidden content — RESOLVED: broker-confined opens
The orchestrator first opens files itself; on `EACCES` it asks the broker (`open`
command, see broker-design-notes §7). Verified end to end on a real ext4 loop mount:
`lost+found`, a 0700 directory and mode-000 files are scanned by the `nobody` scanner;
EICAR inside them is detected. If the broker cannot open them, the verdict stays
INCOMPLETE (fail-closed).

### B. Physical removal after logical eject — default 300 s kept
The result stays until the next insertion or `orchestrator.result_display_seconds`
(default 300 s). Still validate on the Pi whether port status can detect the unplug.

### C. Partitions without a filesystem — RESOLVED: explicit allow-list
`device.excludable_partition_types` (default empty) + `device.excludable_partition_max_mb`
(default 128). Applies only to partitions with no signature at all (blkid finds nothing)
of a listed type and within the size cap; counted as `partitions_out_of_scope` and named
in `reason_codes` (`partition_out_of_scope:<type>`). Encrypted/unsupported/ambivalent
partitions are never excluded. Partition type comes from libblkid `PART_ENTRY_TYPE`
(GPT GUID or MBR `0x%x`, per util-linux source).

### Other decisions recorded
- Blocked extensions: default severity SUSPICIOUS (configurable to THREAT).
- VirusTotal mandatory: requires `virustotal.network_outage_policy_ref`.
- Environment-variable secrets: only with `USB_SCAN_DEV=1` (logged warning).
- PIN lockout clock jumps: boot-clock based within a boot; after a reboot with the wall
  clock behind the record, re-armed once (≤ one extra lockout period).

## Optional modules (Phase 7, spec 1.5.3)

### VirusTotal (`src/orchestrator/virustotal.py`)
- Hash-only `GET https://www.virustotal.com/api/v3/files/{sha256}` with the `X-Apikey`
  header (verified against the official vt-py client source). No uploads.
- 200 → `data.attributes.last_analysis_stats`; 404 with error code `NotFoundError` →
  hash unknown (no finding). Every other answer (429 quota, 401/403, 5xx, redirects,
  unexpected bodies, transport errors) is a lookup failure. The exact VT quota error code
  was not verifiable offline, so classification does not depend on it: any failure opens a
  per-session circuit breaker (remaining hashes are answered from the cache only).
- Owner decision: ≥ `suspicious_min_malicious` (1) "malicious" engines → SUSPICIOUS
  (medium), ≥ `threat_min_malicious` (5) → THREAT (high). Only the `malicious` count is used.
- Every in-scope file is hashed from the descriptor that was scanned (no re-open), including
  files too large for ClamAV (hash lookups have no size threshold). `large_file_hash_budget_mb`
  is a per-scan hashing budget; files beyond it are reported (`virustotal_hash_budget=N`).
- `vt_complete` is true only if every in-scope file was hashed and answered, no failure
  occurred and lookups finished within `finish_wait_seconds` after the local scan.
  Advisory role: never changes the verdict (reason codes only). Mandatory role: incomplete
  coverage → INCOMPLETE; with `on_quota_or_network_failure: error` a lookup failure or a
  missing client → ERROR. A mandatory VT whose API key cannot be resolved fails the health
  gate (`virustotal_unavailable` → NOT_READY); advisory gives a warning.
- Cache: SQLite (0600), known hashes `cache_ttl_days`, unknown hashes at most 1 day,
  entries with timestamps in the future (clock jump) are ignored; TTL 0 disables it.
- Rate limit: sliding 60 s window shared by all sessions; two lookup workers per scan.
- `httpx` request logging is raised to WARNING so hashes are not logged per request.

### Quarantine (`src/orchestrator/quarantine.py`)
- Owner decision: only high-severity detections with a known SHA-256 (ClamAV signature,
  high YARA rule, VT ≥ threat threshold). Never policy violations or medium/low findings.
- Runs after the verdict is committed and before ejection (mounts still present); the file
  is re-opened (direct or broker-confined), copied while hashing, and kept only if the
  SHA-256 equals the detected hash. Failures produce a `quarantine_result` event and never
  change the verdict.
- Store verified before every use: `quarantine.path` is the topmost mount point, mounted
  `rw,nodev,nosuid,noexec`, its device is a dm mapping whose `dm/uuid` starts with
  `CRYPT-LUKS2-` (cryptsetup dm UUID format, verified in cryptsetup `lib/libdevmapper.c`),
  directory owned by the service user with mode 0700, not a symlink. LUKS2 must be the
  device directly under the filesystem (LVM on LUKS is rejected).
- Layout `<path>/<scan_id>/<random 128-bit hex>.bin|.json`, files 0600; original path,
  device IDs and signature only in the sidecar. All writes are `dir_fd`-relative with
  `O_NOFOLLOW|O_EXCL`. Config validation rejects a quarantine path overlapping
  `broker.mounts_dir`. Retention cleanup (fd-based `shutil.rmtree`) touches only
  UUID-named scan directories.
- `quarantine.export_enabled: true` is rejected by config validation (spec §3.6 needs
  admin step-up, warnings, a secure destination and an audited flow — not built yet).
- The quarantine LUKS2 volume, its key handling and unlock at boot are Phase 10 work.

### Alerting (moved to `src/events/alerting.py` in Phase 8 — see events-design-notes.md)
- Verdict alerts after commit (`alerts.verdicts`, default THREAT/SUSPICIOUS/INCOMPLETE/
  ERROR/REJECTED); `alerts.not_ready` alerts when a health gate starts failing.
- Channels are independent queues; each outcome is an `alert_delivery` event with an error
  class only (no exception text, URLs or secrets).
- Webhook: https only, no redirects, optional bearer token from a secret ref. E-mail: STARTTLS is mandatory in `starttls` mode
  (`SMTPNotSupportedError` if not offered) or implicit TLS; header values cannot contain
  CR/LF (validated + `EmailMessage` refuses them). Syslog: TLS only, RFC 5425 octet-counting
  framing, RFC 5424 header (facility local0) with a JSON or CEF body.
- TLS verification checked against a local self-signed server: rejected with the system
  trust store, delivered only when the CA is configured via `ca_file`.
- Privacy: paths and device serials follow `logging.filename_privacy`; `hash` uses
  HMAC-SHA256 with `pseudonymization_key_ref` and omits the value if no key is available.
- Since Phase 8 alerts are derived from committed events by the events service and sent
  through its durable queues; the one-retry webhook behaviour was replaced by queue backoff.

### Synthetic scan (spec §3.8, AC-F05; added in Phase 12)
- `src/orchestrator/synthetic.py` writes the EICAR test string and a harmless control file
  to `<state_dir>/synthetic/` (0600, `O_EXCL|O_NOFOLLOW`), opens them with the production
  `open_for_scan`, unlinks them and passes the descriptors to clamd (FILDES) and, when
  enabled, to the YARA worker. The production verdict engine evaluates the result.
- The result is deterministic: `passed` means
  - ClamAV reported EICAR as FOUND;
  - the control file was clean;
  - the verdict was THREAT.
  YARA results are recorded but not asserted, since the deployed rules need not contain an
  EICAR rule. VirusTotal is never queried.
- Recorded as a `synthetic_scan` event in the audit chain. It is not a `verdict`, so scan
  statistics are unaffected. The admin audit view lists it.
- When it runs:
  - at start-up;
  - every `health.synthetic_scan_interval_hours` (default 24; 0 = start-up and on demand);
  - on demand with `systemctl kill -s SIGUSR1 --kill-whom=main usb-scan-orchestrator`.
- It only runs while no device is handled and no other health gate fails; otherwise it
  retries after 30 s. The orchestrator lock is held for the run, so an insertion waits for it.
- A failed run adds the mandatory health failure `synthetic_scan_failed` (NOT_READY, and the
  `not_ready` alert). A failure is retried every 5 minutes. Only a passing run clears it.
- Not covered by the synthetic scan: USBGuard, the broker and the mount path. Those are
  covered by the reference-medium acceptance tests (AC-F01/F02).

## Still to validate on the Pi
- vfat/exfat/ntfs3 mounts (this CI kernel only supports ext4).
- `PART_ENTRY_TYPE` on real partition devices (CI cannot create loop partitions).
- pyudev event timing for insertion/removal (FR-USB-01 2 s target).
- FILDES throughput and `clamav.concurrency` on Pi 5 (spec §15.2 #1).
- Quarantine on a real LUKS2 volume (`dm/uuid`, mount options, unlock at boot).
- VirusTotal lookups against the live API (quota answers, latency) once network policy allows.
