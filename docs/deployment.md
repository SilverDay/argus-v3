# Deployment and operations (Phase 10)

Target: Raspberry Pi 5, Raspberry Pi OS Lite 64-bit (Debian 13 trixie). The checkout lives
at `/opt/usb-scan`; configuration at `/etc/usb-scan/scan_station.yaml`.

## 1. First boot

```
sudo git clone <repo> /opt/usb-scan        # or copy a release tree
sudo /opt/usb-scan/scripts/first-boot-setup.sh
```

The script is idempotent. Existing configuration, keys, the PIN and YARA rules are never
overwritten. Steps:

| Step | What happens |
|---|---|
| Packages | python3-venv, python3-lgpio, clamav-daemon/-freshclam, usbguard, minisign, cryptsetup-bin, cage, Qt runtime libraries |
| venv | `/opt/usb-scan/.venv` with `--system-site-packages` (lgpio comes from apt) |
| Users | `config/system/sysusers.d/usb-scan.conf` → `systemd-sysusers` (table below) |
| Directories | `config/system/tmpfiles.d/usb-scan.conf` → `systemd-tmpfiles` |
| Config | template copied once to `/etc/usb-scan/scan_station.yaml` and validated |
| Secrets | `/etc/usb-scan/secrets` (0711): `broker-hmac.key` (0640 root:usbscan) and `events-checkpoint.key` (0640 root:usbscan-events), 256-bit random each |
| ClamAV | keys of `config/clamd.conf.recommended` merged into `/etc/clamav/clamd.conf` (original kept as `.usb-scan.orig`), TCP socket disabled, sandbox drop-in |
| Kernel | `modprobe.d/usb-scan-blacklist.conf`; `udisks2` and `usbguard-dbus` masked |
| Units | `systemd/*.service`, `*.timer` → `/etc/systemd/system` |
| PIN | **mandatory**: without an operator PIN the script stops before enabling services (spec §10.1, no factory default) |
| Services | events, broker, orchestrator, GUI; plus YARA, LED and admin web when enabled in config; YARA update timer when `yara.update_url` is set |
| USBGuard | applied **last**, after confirmation: from then on USB keyboards, mice and hubs are rejected or blocked. Administer over SSH (if enabled) or the serial console. |

## 2. Identities

| User | Service | Groups (besides its own) | Can reach |
|---|---|---|---|
| root | usb-scan-device-broker | — | block devices, mount; caps reduced to CAP_SYS_ADMIN+CAP_CHOWN in-process |
| usbscan | usb-scan-orchestrator | usbscan-read, usbscan-audit, clamav | broker.sock, clamd socket, yara.sock, events.sock, state.sock (owner) |
| yarascan | usb-scan-yara | — | its own yara.sock; rules read-only |
| usbscan-events | usb-scan-events | usbscan-audit | events DB, outbound SIEM/alerts |
| usbscan-web | usb-scan-admin | usbscan-audit | events.sock (web role) |
| usbscan-gui | usb-scan-gui | video, render, input | state.sock (GUI), display/touch |
| usbscan-led | usb-scan-led | usbscan-gui, gpio | state.sock (read-only), GPIO |
| usbscan-update | usb-scan-yara-update | — | `/var/lib/usb-scan/rules` (write), outbound HTTPS to `yara.update_url` |

Two groups are deliberately separate:
- `usbscan` (`broker.sock`, `yara.sock`);
- `usbscan-audit` (`events.sock` only).

The admin web is never in `usbscan`.

## 3. Operator PIN

```
sudo /opt/usb-scan/.venv/bin/python -m src.shared.pin_admin --config /etc/usb-scan/scan_station.yaml
sudo systemctl restart usb-scan-orchestrator
```

- **Entry:** the PIN is entered twice without echo. It is never accepted as an argument and
  never printed.
- **Policy:** `pin.*`, with at least 6 digits, no repeated or sequential runs, and the deny
  list.
- **Storage:** bcrypt cost ≥ 12, written atomically to the `file:` target of `pin.hash_ref`
  (0640 root:usbscan).
- **Lockout state** is in the orchestrator's `auth.db`, unaffected by a PIN change.

## 4. Signatures and YARA rules

- **ClamAV signatures:** `clamav-freshclam.service`, the distribution daemon. The orchestrator
  reports `signatures_stale` (NOT_READY) beyond `clamav.max_signature_age_hours`.
- **YARA rules.** Bundles are tar(.gz) archives with `manifest.json`, `manifest.json.minisig`
  and `*.yar` files, signed with the minisign key whose public part is `yara.trust_anchor_path`.
  - Offline install:
    ```
    sudo -u usbscan-update /opt/usb-scan/.venv/bin/python -m src.yara_worker.install \
        --config /etc/usb-scan/scan_station.yaml /path/to/bundle.tar.gz
    ```
  - Online: set `yara.update_url` (https). The weekly timer `usb-scan-yara-update.timer`
    (Sunday 03:00 ± 1 h) pulls and installs.
  - Both paths:
    - read the archive without letting tarfile write anything;
    - accept only regular files with plain names, within size limits;
    - verify the signature, per-file SHA-256 and compile in a staging directory;
    - refuse versions that are not newer;
    - switch `rules/active -> versions/<n>` atomically.
  - The worker notices the new link within 30 s (or `systemctl reload usb-scan-yara`) and
    re-verifies with its own persisted rollback guard.

## 5. Optional evidence quarantine (LUKS2)

```
sudo /opt/usb-scan/scripts/setup-quarantine.sh /dev/sdX --yes-erase-all-data
```

- **Medium:** use a separate medium (e.g. a USB SSD), not the boot SD card. The script refuses
  the boot disk.
- **Owner decision (keyfile unlock):** the unlock keyfile (`/etc/usb-scan/secrets/quarantine.key`,
  0400 root) is on the root filesystem. Encryption protects evidence at rest only when the
  medium is stored or disposed of separately. The Pi 5 has no TPM.
- **Recovery:** a random recovery passphrase (second LUKS slot) is printed once. Escrow it
  offline.
- **crypttab/fstab** use `nofail`: a missing medium never blocks boot. The orchestrator then
  reports `quarantine_unavailable` (warning) and keeps scanning.
- **Enable:** set `quarantine.quarantine_on_threat: true` afterwards.
- **A USB quarantine disk is itself a mass-storage device.** It passes the USBGuard policy, and
  the orchestrator would treat it as a stick to scan.
  - Attach it to a fixed port.
  - Add that port's sysfs path (printed by the setup script, e.g.
    `/sys/devices/…/usbN/N-M`; the exact path depends on the port) to
    `device.internal_device_sysfs_prefixes`. The orchestrator then ignores it.
  - Keep that port out of reach.

## 6. Admin web (optional)

- **Behind a proxy:** run it behind a TLS reverse proxy (nginx or caddy) with a certificate from
  your PKI.
- **Settings:** `admin_web.enabled: true`, `admin_web.public_url`, OIDC settings (see
  docs/web-design-notes.md).
- **Process:** the unit listens on 127.0.0.1:8080 only.
- **Self-signed certificates** are acceptable for an isolated lab only. Production uses the
  organisation's CA. Configuring the proxy is site-specific and not automated here.

## 7. Recovery and maintenance

| Situation | Action |
|---|---|
| Audit chain verification failed (`audit_chain_broken`) | investigate with `python -m src.events --verify`, compare with the SIEM copy, then `python -m src.events --acknowledge-tamper "<note>"` (as usbscan-events) |
| A service crash-loops (3 restarts / 5 min) | it stays failed (spec §11); `journalctl -u <unit>`; GUI/LED show not ready |
| Lost operator PIN | set a new one (section 3) |
| Lost quarantine keyfile | `cryptsetup open /dev/sdX usbscan-quarantine` with the recovery passphrase, then `cryptsetup luksAddKey` a new keyfile |
| USB keyboard needed on site | there is none by design; use SSH or the serial console, or stop `usbguard` deliberately and audit it |

## 7a. Hardening and read-only root (Phase 11)

1. **Prepare the persistent data partition when imaging the card.**
   - Do this on a Linux workstation after writing the image and before the first boot.
   - Create an ext4 partition in the free space after the root partition and label it
     `USBSCAN-DATA` (or `host.data_partition_label`), e.g.
     `sudo parted /dev/sdX -- mkpart primary ext4 -16GiB 100%` and
     `sudo mkfs.ext4 -L USBSCAN-DATA /dev/sdX3`.
   - `harden.sh` never repartitions.
   - *Pi validation:* how the trixie first-boot root expansion treats a partition placed
     after root was not verifiable offline. Check that the partition is intact after the
     first boot.
2. **Set `host.*`** in `scan_station.yaml`: management networks, SSH users (SSH stays off
   unless `host.ssh_enabled`), radios.
3. **Run `sudo /opt/usb-scan/scripts/harden.sh`, then reboot.** It applies:
   - firewall: default deny in and out, per-service egress;
   - sysctl, SSH policy, disabled services and radios, swap off;
   - AppArmor profiles in complain mode;
   - data bind mounts;
   - `overlayroot=tmpfs:recurse=0` and a read-only `/boot/firmware`.
4. **OS updates go through `scripts/maintenance-mode.sh enter` → update → `exit`, on UPS power
   only.** The orchestrator does not run while the root is writable.
5. **After tuning on the Pi** (`aa-logprof` during the acceptance tests), promote the profiles
   with `harden.sh --apparmor-enforce`.

The item-by-item status is in docs/hardening-checklist.md.

## 8. Plan items handled differently

| Plan Phase 10 | Implemented | Reason |
|---|---|---|
| udev rule `SYSTEMD_WANTS=usb-scan-orchestrator.service` | not used | the orchestrator always runs and follows udev itself (pyudev); per-insertion activation would add a start-up race |
| broker `AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH`, `NoNewPrivileges=false` | broker as root with bounding set CAP_SYS_ADMIN CAP_CHOWN CAP_SETPCAP, in-process drop, `NoNewPrivileges=yes` | spec §5.4 (1.5.1) and docs/broker-design-notes.md |
| YARA "mount namespace access added per session" | none | the worker receives descriptors and has no mount access |
| set-pin "exactly 6 digits" | `pin.min_length`..`max_length` (default 6–12) | spec §10.1 says *minimum* six digits |
| run-update.sh with apt upgrade + OverlayFS window | freshclam daemon + YARA timer now; OS updates with the read-only root in Phase 11 | the OverlayFS maintenance window belongs to Phase 11 |
| self-signed TLS cert generation | documented, not automated | the reverse proxy and its PKI are deployment-specific |
| `usb-scan-admin.service` | same name (the Phase 9 draft was `usb-scan-web.service`) | spec §5.4 naming |

## 9. Still to validate on the Pi

- **Packages:** `cage`, `usbguard` (1.1.x rule syntax `with-interface equals/one-of`) and
  `python3-lgpio` on trixie. Here they were verified only against Ubuntu 24.04's archive and
  USBGuard's upstream documentation and parser.
- **Kiosk:** cage under `PAMName=login` on tty1 (logind seat access to DRM/input).
- **Mount propagation:** broker mounts must stay visible to the sandboxed orchestrator and
  invisible to units with `InaccessiblePaths=/run/usb-scan/mounts`.
- **Sockets under ProtectSystem=strict:** connecting to a Unix socket on a read-only `/run`
  must work for GUI/LED/web.
- **Quarantine:** a real run of `setup-quarantine.sh` (no device-mapper in the build container).
- **Acceptance:** the full procedure (automated + manual, with sign-off) is
  tests/acceptance/MANUAL_TEST_CHECKLIST.md; tooling notes in docs/acceptance-notes.md.
