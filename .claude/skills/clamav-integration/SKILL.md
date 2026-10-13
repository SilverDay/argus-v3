---
name: clamav-integration
description: >-
  ClamAV clamd socket protocol, scan result parsing, error handling,
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
