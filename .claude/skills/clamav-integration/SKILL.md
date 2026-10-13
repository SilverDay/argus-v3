---
name: clamav-integration
description: >-
  ClamAV clamd socket protocol, scan result parsing, error handling,
  and freshclam integration. Use when working on scan pipeline or health checks.
---

# ClamAV Integration (as implemented in src/orchestrator/scanner_clamav.py)

## Transport: FILDES, not paths, not INSTREAM
- Unix socket (clamav.socket_path, default /var/run/clamav/clamd.ctl).
- The orchestrator opens each file (O_RDONLY|O_NOFOLLOW|O_NONBLOCK, regular files only)
  and sends `nFILDES\n` + one byte carrying the fd in SCM_RIGHTS ancillary data.
- clamd needs NO path access to USB mounts; no StreamMaxLength limit.
- One connection per file; concurrency = clamav.concurrency.

## Replies (verified against clamd 1.5.4)
- `fd[N]: OK` → clean
- `fd[N]: <Sig> FOUND` → threat (severity high); `Heuristics.*` → medium (SUSPICIOUS)
- `Heuristics.Limits.Exceeded.{MaxFiles,MaxFileSize,MaxScanSize,MaxRecursion}` → skip
  (scan_limit / too_large_for_engine / recursion_limit) → INCOMPLETE
- `Heuristics.Encrypted.*` → uninspectable (encrypted) → INCOMPLETE
- `... ERROR`, garbage, timeout → files_failed → INCOMPLETE
- clamd unreachable mid-scan → appliance fault → ERROR
- Custom databases append `.UNOFFICIAL` to signature names.

## Required clamd.conf settings (see config/clamd.conf.recommended)
AlertExceedsMax yes, AlertEncrypted yes, HeuristicScanPrecedence no,
MaxFileSize = clamav.max_file_size_mb (≤ 2047M: ClamAV cannot scan files > 2 GB).
Without AlertExceedsMax, limit hits are silent and could yield a false CLEAN.

## VERSION / signature age
`ClamAV <engine>/<db version>/<ctime>` (clamd/session.c print_ver). With only
unofficial databases the reply is `ClamAV <engine>` → `signatures_unknown` → NOT_READY.
ctime is clamd's local time; the appliance runs in UTC.

## Health gates (src/orchestrator/health.py)
PING→PONG; signature age ≤ clamav.max_signature_age_hours, else NOT_READY.
