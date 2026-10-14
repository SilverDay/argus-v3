# Administrator guide

For IT staff who operate USB Scan Stations. Installation: docs/installation.md. Reference
material: docs/deployment.md (provisioning), docs/hardening-checklist.md,
docs/secret-recovery.md.

> **OS and application updates need a planned maintenance window on UPS-backed power.**
> While the root filesystem is writable, a power loss can make the SD card unbootable, and
> there is no automatic rollback (spec §5.3). Keep a current reflash image and the escrowed
> keys at hand.

## 1. How the station is administered

| Task | Where | Persistent? |
|---|---|---|
| Watch status, history, statistics, audit | admin web (read-only) | – |
| Change `scan_station.yaml` (scan policy, alerts, retention, …) | SSH, `/etc/usb-scan/` (data partition) | yes, at once |
| Change anything rendered into the OS (firewall egress, SSH, radios, AppArmor mode) or units | SSH, **maintenance window** + `harden.sh` | only in the window |
| ClamAV signatures | automatic (`clamav-freshclam`) | data partition |
| YARA rules | signed bundles (§6.2) | data partition |
| OS packages, application code | **maintenance window** (§6.3) | only in the window |

The web UI never changes anything (owner decision). There is no remote "reload" and no
remote lockout reset.

The firewall opens outbound ports from the configuration. Re-run `harden.sh` in a
maintenance window after you change any of these:
- VirusTotal;
- SIEM or alert endpoints;
- the OIDC issuer;
- `yara.update_url`;
- `host.*`.

## 2. Admin web

Open `admin_web.public_url` and sign in with your organisation account (OIDC with MFA). Your
IdP groups decide your role (`auth.web.oidc.roles`). The highest matching role wins; no
match means no access.

| Page | Role | Content |
|---|---|---|
| Dashboard | viewer | station state, health gates, signature age, engine versions, last result (refreshes every 5 s) |
| Statistics | viewer | verdicts per day, top signatures |
| Configuration | viewer | effective configuration; secret fields show references only, never values |
| History | operator | scans with filters (verdict, period; device serial for admin), detail per scan |
| Export | operator | CSV or JSON of the filtered history (formula-safe CSV) |
| Audit | admin | sign-ins, data access, PIN attempts, tamper/acknowledge events, alert delivery, synthetic scans |

- **Data minimisation:** file paths and device serials are shown to the `admin` role only.
- **Every access is audited.** Every page view and export is written to the audit chain
  *before* the response is sent. If the audit log is unavailable, the page is refused (fail
  closed).
- **Sessions:**
  - idle timeout 15 minutes, maximum 8 hours;
  - bound to the client address;
  - signing out ends the session on the server.

**Local accounts** (isolated networks only, `local_fallback_allowed: true` with OIDC
disabled):
- Each account is a line `username:role:bcrypt-hash` (cost ≥ 12) in a secret-referenced
  file.
- Never create shared accounts.

## 3. Operator PIN

- **Set or change:**
  ```
  sudo /opt/usb-scan/.venv/bin/python -m src.shared.pin_admin --config /etc/usb-scan/scan_station.yaml
  sudo systemctl restart usb-scan-orchestrator
  ```
  - The PIN is typed twice without echo. It is never an argument and never printed.
  - Policy (`pin.*`): 6–12 digits, no single repeated digit, no sequential run, optional
    deny list.
- **Lockout:**
  - After `pin.max_failed_attempts` (default 5) wrong PINs, the overlay is locked for
    `pin.lockout_minutes` (default 15).
  - The lockout survives GUI and orchestrator restarts (orchestrator database), and every
    attempt is in the audit chain.
  - There is no remote unlock: wait for the expiry.
- **Scope:** the PIN only unlocks the local operator overlay. It cannot authorise scans,
  configuration or remote access.

## 4. Logs and evidence

| Source | Access |
|---|---|
| Scan history and audit events | admin web, export (CSV/JSON) |
| Audit database (hash chain + HMAC checkpoints) | `/var/lib/usb-scan/events/events.db`. Verify: `sudo -u usbscan-events /opt/usb-scan/.venv/bin/python -m src.events --verify` (from `/opt/usb-scan`) |
| Service logs | `journalctl -u 'usb-scan-*'`; JSON log file `/var/log/usb-scan/usb-scan.jsonl` |
| Broker audit (mount/eject/refusals) | broker audit log (`broker.audit_log`) |
| USB authorisation decisions | `journalctl -u usbguard` |
| Firewall drops | `journalctl -k \| grep usbscan-drop` |

- **Tamper alarm (`audit_chain_broken`):** the station stays NOT_READY.
  1. Investigate: `--verify` output, compare with the SIEM copy.
  2. Re-anchor:
     ```
     sudo -u usbscan-events /opt/usb-scan/.venv/bin/python -m src.events --acknowledge-tamper "<ticket and finding>"
     ```
  The damaged history is kept for forensics.
- **Retention:** `events.retention_days` (default 180) and `quarantine.retention_days`
  (default 30). Set them to your regional obligations. The SIEM is the long-term record.

## 5. SIEM forwarding and alerts

Both are delivered by the events service from durable queues, with retries, backoff and
dead-lettering. Every delivery outcome is recorded as an `alert_delivery` event (error class
only, never secrets).

**Forwarding:**
- Settings: `events.forwarding`.
  - **Syslog:** RFC 5424 over TLS (RFC 5425), JSON body, port 6514.
  - **Webhook:** HTTPS POST, JSON body.
- TLS verification is always on. Put your collector CA in `/etc/usb-scan/pki/` and set
  `ca_file`.
- Station identity (mTLS):
  1. `sudo /opt/usb-scan/scripts/station-cert.sh csr` → have the CA sign the CSR (CN =
     station id, EKU clientAuth).
  2. `sudo /opt/usb-scan/scripts/station-cert.sh install CERT --ca /etc/usb-scan/pki/<ca>.pem`
  3. Set `client_cert_file` and `client_key_ref` as printed, then
     `systemctl restart usb-scan-events`.
  - Renew before expiry with `csr --rotate` + `install`. `status` warns 30 days ahead.
- **Privacy:** paths and serials leave the station only as keyed HMAC pseudonyms
  (`logging.filename_privacy: hash`).

**Alerts:**
- Settings: `alerts`.
- **Triggers:** verdicts (default THREAT, SUSPICIOUS, INCOMPLETE, ERROR, REJECTED; never
  CLEAN), NOT_READY (`alerts.not_ready`), and tamper detection (always).
- **Channels:**
  - webhook: https only, optional bearer token via `credential:`;
  - e-mail: STARTTLS or implicit TLS, password via `credential:`;
  - syslog: TLS; RFC 5424 with a JSON or CEF body.

## 6. Updates

### 6.1 ClamAV signatures

These are automatic (`clamav-freshclam.service`) and stored on the data partition. No
maintenance window is needed. If signatures are older than
`clamav.max_signature_age_hours` (default 24), the station goes NOT_READY
(`signatures_stale`). Check egress and freshclam:

```
journalctl -u clamav-freshclam -n 50
```

### 6.2 YARA rules

Rules come only as minisign-signed bundles:
- **offline:** `python -m src.yara_worker.install BUNDLE`;
- **online:** set `yara.update_url`; the weekly timer then pulls the bundle.

Older or tampered bundles are refused, and the switch is atomic. Details: deployment.md §4.

### 6.3 OS packages and application (maintenance window)

1. Plan the window. Confirm UPS power and a current reflash image. Put up a notice that the
   station is unavailable.
2. Enter maintenance mode:
   ```
   sudo /opt/usb-scan/scripts/maintenance-mode.sh enter
   ```
   This reboots with a writable root. The orchestrator does not start, and the screen shows
   "Scanning unavailable".
3. Update:
   ```
   sudo apt update && sudo apt full-upgrade
   # git checkout:
   cd /opt/usb-scan && sudo git fetch && sudo git checkout <reviewed release tag>
   # or a release payload from scripts/build-image.sh (verify its .sha256 first):
   #   sudo mv /opt/usb-scan /opt/usb-scan.old && sudo tar -C /opt -xf usb-scan-<tag>.tar
   #   sudo mv /opt/usb-scan.old/.venv /opt/usb-scan/ && sudo rm -r /opt/usb-scan.old
   cd /opt/usb-scan
   sudo scripts/first-boot-setup.sh --skip-packages
   sudo scripts/harden.sh
   ```
   - `first-boot-setup.sh --skip-packages` updates the Python packages and units. Keys,
     configuration and the PIN stay untouched.
   - `harden.sh` re-renders the firewall/SSH policy and AppArmor.
4. Leave maintenance mode:
   ```
   sudo /opt/usb-scan/scripts/maintenance-mode.sh exit
   ```
   This reboots read-only.
5. After the reboot:
   - `maintenance-mode.sh status`;
   - the acceptance checks `run_acceptance run --only PRE,AC-F05,AC-S01`;
   - a test scan with the EICAR stick.

Never interrupt power while maintenance mode is active.

## 7. Evidence quarantine (optional)

- **Off by default** (owner decision).
- **What is kept:** THREAT-level detections only, on a separate LUKS2 medium.
- **Setup:**
  - `scripts/setup-quarantine.sh /dev/sdX --yes-erase-all-data`, then escrow the printed
    recovery passphrase.
  - Add the medium's USB port to `device.internal_device_sysfs_prefixes` so it is not
    scanned. The setup script prints the path.
  - Set `quarantine.quarantine_on_threat: true` and restart the orchestrator.
- **Medium unavailable:** a warning (`quarantine_unavailable`); scanning continues.
- **No export:** quarantined files cannot be exported from the station (disabled until an
  audited step-up flow exists).

## 8. Troubleshooting

The screen shows "Scanning unavailable" while a health gate fails. The failing codes are on
the dashboard, in `health_gate_failed` events and in the orchestrator journal.

| Code | Meaning | Action |
|---|---|---|
| `broker_unavailable` | device broker not running | `systemctl status usb-scan-device-broker`; journal |
| `clamav_unavailable` | clamd not reachable | `systemctl status clamav-daemon clamav-daemon.socket`; first start after install takes minutes |
| `signatures_unknown` / `signatures_stale` | no or outdated signatures | freshclam journal, egress rules (§6.1) |
| `yara_unavailable` | mandatory YARA without a verified ruleset or worker | install a signed bundle; `systemctl status usb-scan-yara` |
| `disk_space_low` | data partition below `health.min_free_disk_mb` | check `/data` usage, retention |
| `clock_invalid` | clock earlier than `health.min_valid_year` | NTP reachability (`timedatectl`) |
| `thermal_limit` | CPU above `health.max_cpu_temp_c` | cooler, ventilation |
| `event_store_unavailable` / `event_store_unwritable` | events service down / database not writable | `systemctl status usb-scan-events`; disk |
| `event_spool_pending` | orchestrator holds unsent events | resolves when the events service is back; check its journal |
| `audit_chain_broken` | audit verification failed (tamper alarm) | §4 |
| `synthetic_scan_failed` | the EICAR self-test failed | clamd configuration and signatures; re-test with `systemctl kill -s SIGUSR1 --kill-whom=main usb-scan-orchestrator` |

Warnings do not block scanning: `pin_not_configured`, `thermal_unknown`,
`virustotal_unavailable`, `quarantine_unavailable`.

| Symptom | Cause / action |
|---|---|
| A unit stays "failed" after restarts | crash loop: 3 restarts in 5 min stop it (spec §11). Read the journal, fix the cause, `systemctl reset-failed <unit>` and start it |
| Sticks are always REJECTED `usb_policy_blocked` | USBGuard policy; `usbguard list-devices` shows the decision. Only pure mass-storage devices are allowed |
| Result "Device not safely ejected" | unmount failed; the broker keeps the device read-only. Check the broker audit log; remove the device only after IT checked it |
| Many INCOMPLETE results | look at the reason codes in History: encrypted archives, ClamAV limits (`MaxFileSize`, `MaxScanSize`), unsupported partitions, files outside an extension allow-list |
| Admin web "Sign-in failed." | IdP groups/role mapping, MFA claim (`mfa_amr_values`/`mfa_acr_values`), clock skew; details in the `web_auth` audit events |
| Admin web refuses pages | the events service is down (fail closed) |
| Operator overlay "Locked" | PIN lockout; wait `pin.lockout_minutes` |

An SD card failure or rebuild is covered in docs/secret-recovery.md.
