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

## Needs owner decision

### A. ext2/3/4 media always INCOMPLETE (fail-closed)
Every ext filesystem has `lost+found` (0700 root). The unprivileged scanner cannot list
it, so ext media can never be CLEAN; any private directory or file on the media has the
same effect. FAT/exFAT/NTFS are unaffected (the broker forces group-readable modes).
Options:
- (a) accept: ext media are INCOMPLETE by policy (current behaviour);
- (b) grant the orchestrator `CAP_DAC_READ_SEARCH` — read any file on the host too;
  must be paired with `InaccessiblePaths=` for secrets/keys in its unit;
- (c) the broker opens files/directories on the orchestrator's behalf and passes fds
  (`openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`) — strongest isolation, more
  broker surface and per-file RPC overhead.

### B. Physical removal after logical eject is not observable
After the broker writes `remove`, the kernel forgets the device; pulling it out
produces no event. The result stays until the next insertion or
`orchestrator.result_display_seconds` (default 300 s). Validate on the Pi whether the
port status (e.g. `usbN-portM` attributes) can detect the physical unplug.

### C. Partitions without a filesystem (e.g. GPT Microsoft Reserved Partition)
Reported as `unrecognized` → partition excluded → INCOMPLETE under
`require_full_coverage`. External HDDs formatted by Windows (GPT) usually carry an MSR,
so they will be INCOMPLETE until a deployment policy explicitly scopes such partition
types out (FR-USB-04 allows this only "by an explicit, authorized deployment policy").

## Still to validate on the Pi
- vfat/exfat/ntfs3 mounts (this CI kernel only supports ext4).
- pyudev event timing for insertion/removal (FR-USB-01 2 s target).
- FILDES throughput and `clamav.concurrency` on Pi 5 (spec §15.2 #1).
