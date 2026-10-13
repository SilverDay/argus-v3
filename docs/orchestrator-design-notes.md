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
   the committed record only (privacy handling: Phase 8).
7. **Interim durable sink.** `JsonlEventSink` (fsync per event) until the events service
   exists (Phase 8). The verdict is on disk before ejection starts.
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

## Still to validate on the Pi
- vfat/exfat/ntfs3 mounts (this CI kernel only supports ext4).
- `PART_ENTRY_TYPE` on real partition devices (CI cannot create loop partitions).
- pyudev event timing for insertion/removal (FR-USB-01 2 s target).
- FILDES throughput and `clamav.concurrency` on Pi 5 (spec §15.2 #1).
