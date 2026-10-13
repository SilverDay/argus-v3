# Events service — design notes and deviations (Phase 8, spec 1.5.4)

`src/events/` runs as `usbscan-events`. It owns the audit database and every outbound
delivery (SIEM forwarding and alerts). It has no USB, mount or quarantine access.

## Owner decisions (13 Oct 2026)

- **PIN lockout stays with the orchestrator.** The plan wanted the events service to own the
  lockout table, queried over IPC on every PIN attempt. Instead, the authoritative lockout
  state is `<orchestrator.state_dir>/auth.db` (user `usbscan`). It is persisted, survives
  restarts, and has the boot_id/clock-jump handling from spec 1.5.1. PIN authentication
  therefore keeps working when the events service is down. Every attempt is also recorded
  as an `auth_result` event in the audit chain. There is no `auth_events` table and no
  lockout query in the events service.
- **Alerts moved from the orchestrator to the events service** (spec §5.4: "remote outbound
  delivery"). The orchestrator no longer holds SMTP/webhook credentials and has no
  outbound network use except VirusTotal. Alerts are derived from committed events:
  - VERDICT for `alerts.verdicts`,
  - HEALTH_GATE_FAILED when `alerts.not_ready` is set,
  - TAMPER_DETECTED always.

## Data path

```
orchestrator ──append (SO_PEERCRED writer)──▶ events.sock ──▶ SQLite (WAL, synchronous=FULL)
      │  service down / disk full                                │ delivery rows per queue
      ▼                                                          ▼
 <state_dir>/event_spool.jsonl (fsync, 0600)          forwarder: siem, alert:webhook,
      replayed in order on reconnect                  alert:email, alert:syslog
```

- **Durability.**
  - `commit_result` returns only once the verdict is acknowledged after a FULL-synchronous
    commit, or fsync'ed to the spool.
  - Ejection happens after that (spec §3.2 step 10).
  - The plan proposed `synchronous=NORMAL`, which can lose the last transactions on power
    loss, so it is not used.
- **Ordering.** One writer task in the orchestrator. While the spool is not empty, new events
  are spooled behind it. Replay is idempotent: `event_id` is UNIQUE and duplicates are
  acknowledged without a second insert.
- **Readiness.**
  - An unreachable service → `event_store_unavailable`.
  - Free space below `events.min_free_mb` → `event_store_unwritable`.
  - A spool that could not be replayed → `event_spool_pending`.
  - A tamper flag → `audit_chain_broken`.
  - Each of these is a health failure → NOT_READY (spec §3.8 "writable event DB/queue").
  - The spool (bounded, default 64 MB) only has to cover the scan in progress. If it is full,
    the commit fails; the job ends in ERROR, the device is still released, and the verdict is
    shown.
- **Roles.**
  - `events.writer_users` (orchestrator) may append and query.
  - `events.web_audit_users` (admin web, Phase 9) may query and append only its own
    `web_auth`/`web_access` audit events, and nobody else may append those.
  - `events.reader_users` may only query.
  - All other uids are disconnected unread.
  - Clients cannot submit service-generated types (checkpoint, tamper) or local IPC types.
- **Socket.** `/run/usb-scan/events.sock`, mode 0660, owned by `usbscan-events`, group
  `events.socket_group`.
  - Since Phase 9 the default group is `usbscan-audit`, a dedicated group. Joining it does
    not also open `broker.sock` or `yara.sock`, which use group `usbscan`.
  - This corrects the earlier note in CLAUDE.md, which listed `usbscan:usbscan-events`: the
    server creates the socket, so its user owns it.

## Hash chain

- **Record hash.** `hash = SHA-256(canonical JSON [prev_hash, seq, event_id, event_type,
  scan_id, station_id, timestamp_utc, received_utc, payload])`.
  - The plan's plain string concatenation is ambiguous at field boundaries; a JSON array
    is not.
  - The first link is `SHA-256("usb-scan-events-genesis\0" + station_id)`.
- **`verify()`** walks from the anchor and reports:
  - `gap`: missing seq;
  - `broken_link`: prev_hash mismatch;
  - `modified`: recomputed hash differs;
  - `truncated`: the head is behind `meta.last_seq`.
- **Checkpoints.**
  - Every `checkpoint_interval_hours`, and at start-up if none is due yet, the service
    appends an `audit_checkpoint` event.
  - Its MAC is HMAC-SHA256(`events.hmac_key_ref`, ["usb-scan-checkpoint-v1", station, seq,
    head_hash, created]).
  - The plan wanted a MAC over the "last N hashes". Because the head hash already commits to
    the entire chain, authenticating the head is equivalent and simpler.
  - `verify_checkpoints()` detects a chain rewritten by someone without the key (tested).
  - The key is at least 32 bytes and separate from the broker HMAC key.
- **What this does not protect against.** Root on the device holds the checkpoint key, can
  rewrite everything and can roll the database back. That threat is covered only by
  off-device forwarding: the collector sees `seq`, `hash`, `prev_hash` and the checkpoints
  and can detect gaps, rollbacks and forks (spec §13).
- **Start-up.**
  1. `PRAGMA integrity_check`. On failure the service exits and systemd restarts it.
  2. Chain and checkpoint verification. On failure the service records a
     `tamper_detected` event (alerted and forwarded) and sets a persistent tamper flag; the
     station stays NOT_READY.
  3. The same verification is repeated every hour.
  4. After investigation, an administrator runs `python -m src.events --acknowledge-tamper
     "<note>"`. This re-anchors verification at the current head and records
     `tamper_acknowledged` with the acting user. The damaged rows are kept for forensics.
  5. `python -m src.events --verify` checks the database and chain offline and exits 0 or 1.
- **Retention.** Hourly pruning removes events older than `events.retention_days`, from the
  start of the chain only, and never at or after the first pending delivery. The anchor
  (seq + hash of the last removed event) moves forward.

## Delivery queues (`forwarder.py`)

- **Per-queue processing.** Each queue has its own task and strict seq order: the head
  blocks later entries.
- **Retries.** Exponential backoff (`backoff_initial_seconds` doubling up to
  `backoff_max_seconds`). After `max_attempts` the entry is dead-lettered: status `dead` in
  the database plus a `DEAD LETTER` error log line, and the queue moves on.
- **Outcome events.** Alert outcomes are recorded as `alert_delivery` events, which are
  forwarded to the SIEM queue only. SIEM delivery is never recorded as an event, because
  that would feed itself.
- **Acknowledgement per channel.**
  - Webhook: HTTP 2xx.
  - E-mail: SMTP accepted the message.
  - Syslog: written and flushed on the TLS connection. RFC 5425 has no application-level ack
    (RELP is not implemented), so a record lost by the collector after the TCP flush is not
    detected locally. The collector's gap detection on `seq` covers it.
- **Deduplication.** Every forwarded event carries `station_id`, `seq`, `event_id`, `hash` and
  `prev_hash`; alerts carry `event_seq` and `event_id`. Receivers deduplicate on these.
  A retry after an unacknowledged success can produce a duplicate.
- **Privacy.**
  - Before leaving the device, `file_path`, `original_path`, `file` and `serial` fields and
    the paths inside `policy_violations` follow `logging.filename_privacy` (HMAC
    pseudonyms, or omitted).
  - The local database keeps plain values (protected: 0600, `usbscan-events` only).
  - A forwarded payload therefore cannot be re-hashed by the collector, which tracks the
    chain through the transmitted hashes.
- **SIEM transports.**
  - RFC 5424 over TLS: JSON body, persistent connection, reconnect on error.
  - HTTPS webhook: JSON envelope, optional bearer token.
  - Both support an mTLS client identity (`client_cert_file` + `client_key_ref`, file: or
    credential: only; the key file must not be world-accessible).
  - Certificate enrolment and bootstrap remain open (spec §15.2 #2).
- **Alert channels without a resolvable secret.** They are reported in `status`
  (`channels_unavailable`). Their queue keeps the alerts and retries with backoff until fixed
  or dead-lettered.

## Fixed along the way

- **Oversized GUI verdict (commit `bfdd031`).** A VERDICT with ~1000+ detections exceeded the
  64 KiB state-socket frame and aborted the commit. The GUI payload is now bounded
  (20 distinct detections + `threat_count`).
- **Shutdown hang.** Python ≥ 3.12 `Server.wait_closed()` waits for open connections, and the
  orchestrator keeps one open. The events server now calls `close_clients()` first; without
  that, SIGTERM hung until systemd's kill timeout (found by the integration test).

## Still to validate on the Pi

- `usb-scan-events.service`:
  - `MemoryDenyWriteExecute=yes` with CPython;
  - SupplementaryGroups and socket group ownership;
  - `/run/usb-scan` creation via tmpfiles.d (Phase 10).
- SQLite FULL-sync latency on the industrial microSD (per-event fsync).
- A real SIEM collector over TLS/mTLS.
