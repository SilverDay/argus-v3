# Installation: from a blank SD card to a hardened station

This is the linear walkthrough. Each step links to the reference section in
docs/deployment.md, which explains *why* and lists every option.

**Time:** about 1–2 hours, most of it package and signature downloads.
**You need:**
- Raspberry Pi 5 (8 GB), active cooler, the 5" touchscreen and the RGB status LED;
- a high-endurance microSD card (≥ 64 GB);
- a Linux workstation with a card reader;
- network access during installation (packages, ClamAV signatures);
- an SSH key pair.

## 1. Flash the operating system

1. Use Raspberry Pi Imager and choose **Raspberry Pi OS Lite (64-bit)**, based on Debian 13
   "trixie".
2. In the Imager settings:
   - set the hostname (e.g. the station id);
   - create a named administrator account; do not reuse `pi`;
   - **enable SSH with public-key authentication only** and paste your public key;
   - set the time zone to UTC (the station logs in UTC).
3. Write the card. **Do not boot it yet.**

## 2. Create the persistent data partition (workstation)

The root filesystem becomes read-only later. Data that must survive reboots lives on a
separate ext4 partition labelled `USBSCAN-DATA`. Use a size that suits you; 16 GB is plenty:

```
sudo parted /dev/sdX -- mkpart primary ext4 -16GiB 100%
sudo mkfs.ext4 -L USBSCAN-DATA /dev/sdX3
```

Replace `/dev/sdX` with the card device and check it twice with `lsblk`.
**Pi validation:** after the first boot, check that this partition is still intact
(`lsblk -f`). The trixie first-boot root expansion could not be tested offline
(deployment.md §7a).

## 3. First boot and base update

Boot the Pi with network, then over SSH:

```
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y git
sudo reboot
```

## 4. Install the application

```
sudo git clone https://github.com/SilverDay/argus-v3.git /opt/usb-scan
cd /opt/usb-scan && sudo git log -1 --format='%H %s'      # record the deployed commit
```

- **Production:** check out a reviewed release tag or commit, not a moving branch.
- **Private repository:** clone with a read-only deploy key, or copy a reviewed release tree
  to `/opt/usb-scan`.
- **The path must be `/opt/usb-scan`.** The units and scripts depend on it.

## 5. Prepare the configuration

The setup script installs the template only when no configuration exists. Prepare it first:

```
sudo install -d -m 0755 /etc/usb-scan
sudo install -m 0644 /opt/usb-scan/config/scan_station.yaml /etc/usb-scan/scan_station.yaml
sudo nano /etc/usb-scan/scan_station.yaml
```

Set at least:

| Key | Value |
|---|---|
| `station.station_id` | unique name, e.g. `hq-lobby-01` (also the certificate CN later) |
| `host.management_networks` | CIDRs allowed to reach SSH / the admin web, e.g. `[10.20.0.0/24]` |
| `host.ssh_enabled`, `host.ssh_allow_users` | `true` and your admin account, if you need SSH after hardening |
| `events.retention_days`, `quarantine.retention_days` | your regional retention obligations (defaults 180 / 30) |
| `gui.language` | `en` or `de` |
| `led.driver` | `lgpio` on the station (`stub` only without an LED) |

Optional modules (YARA, VirusTotal, admin web, SIEM forwarding, alerts, quarantine) stay
disabled for now. Enable them in step 8.

## 6. Run first-boot setup

```
sudo /opt/usb-scan/scripts/first-boot-setup.sh
```

The script:
- installs the packages;
- creates the Python venv (`--system-site-packages`) and `pip install`s
  `requirements.txt`;
- creates the service users and directories;
- generates the station keys;
- configures ClamAV;
- installs the units.

Then:
- **It asks for the operator PIN.** Enter it twice: at least 6 digits, no repeated or
  sequential digits. Without a PIN no service is enabled (spec §10.1).
- **It asks before applying USBGuard.** From then on USB keyboards and mice are blocked.
  Confirm only when SSH (or the serial console) works.

The first ClamAV signature download can take several minutes. Until it finishes, the screen
shows "Scanning unavailable" (`signatures_unknown`/`clamav_unavailable`).

## 7. Check the station

```
systemctl --no-pager status usb-scan-events usb-scan-device-broker usb-scan-orchestrator usb-scan-gui
journalctl -u usb-scan-orchestrator -n 30 --no-pager
```

The touchscreen should show **"Insert a USB device"**.

## 8. Optional modules (each: edit the config, then restart the named service)

| Module | Guide |
|---|---|
| YARA rules | deployment.md §4: install the minisign public key, then a signed bundle (`python -m src.yara_worker.install`), set `yara.enabled: true`, `systemctl enable --now usb-scan-yara` |
| Evidence quarantine (LUKS2 USB SSD) | deployment.md §5: `scripts/setup-quarantine.sh`, escrow the recovery passphrase |
| Admin web: OIDC and/or local accounts | below, and admin-guide.md §2 |
| SIEM forwarding with mTLS | admin-guide.md §5, `scripts/station-cert.sh` |
| Alerts | admin-guide.md §5 |
| VirusTotal | deployment.md §6a: per-site opt-in after privacy approval |

### Admin web sign-in

The admin web supports single sign-on (OIDC), local accounts (username + passphrase +
authenticator code), or both (spec §10.2, 1.5.10). Common steps:

1. Set `admin_web.enabled: true` and `admin_web.public_url`.
2. Put a TLS reverse proxy (nginx/caddy) with a certificate from your PKI in front of
   `127.0.0.1:8080`.
3. Run `systemctl enable --now usb-scan-admin`.

**Local accounts only** (no IdP):

```yaml
auth:
  web:
    oidc_enabled: false
    local_enabled: true
```

```
cd /opt/usb-scan
sudo .venv/bin/python -m src.web.accounts_admin add j.doe --role admin
```

The tool asks for the passphrase twice. It then shows the authenticator key (URI and text)
and asks for a code from the app. Details: admin-guide.md §2.2.

### OIDC provider (generic)

Register a client at the organisation's IdP with these values. They work for any compliant
provider.

| Setting at the IdP | Value |
|---|---|
| Client type | confidential (client secret) or public with PKCE (no secret) |
| Redirect URI | `<admin_web.public_url>/auth/oidc/callback`, e.g. `https://usbscan-hq.example.org/auth/oidc/callback` |
| Grant | authorization code (PKCE S256 is always used) |
| Scopes | `openid profile email` |
| Token signing | RS256, PS256 or ES256 |
| Groups claim | a claim with the user's groups in the ID token (default claim name `groups`) |
| MFA | require MFA for this client; the ID token must carry `amr` containing `mfa` (or set `mfa_acr_values` to what your IdP emits) |

Station configuration:

```yaml
admin_web:
  enabled: true
  public_url: https://usbscan-hq.example.org
auth:
  web:
    oidc_enabled: true
    require_mfa: true
    oidc:
      issuer: https://idp.example.org/realms/corp      # exact issuer string from discovery
      client_id: usb-scan-hq
      client_secret_ref: credential:web_oidc_client_secret   # "" for a public client
      role_claim: groups
      roles:
        admin: [usbscan-admins]
        operator: [usbscan-operators]
        viewer: [usbscan-viewers]
```

1. **Store the client secret as a root-only file.** systemd hands it to the service as a
   credential, so the web account never reads the file itself:
   ```
   (umask 077; cat > /etc/usb-scan/secrets/web_oidc_client_secret)        # paste, Ctrl-D
   sudo systemctl edit usb-scan-admin
   #   [Service]
   #   LoadCredential=web_oidc_client_secret:/etc/usb-scan/secrets/web_oidc_client_secret
   ```
   Do this **before** step 9. Afterwards, unit drop-ins under `/etc/systemd` would only land
   in the RAM overlay; use the maintenance window then (admin-guide.md §6).
2. **Put a TLS reverse proxy** (nginx/caddy) with a certificate from your PKI in front of
   `127.0.0.1:8080`.
3. **Start the service:** `systemctl enable --now usb-scan-admin`.
4. **Test each role.** Sign in once with each role and check that MFA is enforced.

## 9. Harden and switch to the read-only root

```
sudo /opt/usb-scan/scripts/harden.sh
sudo reboot
```

This sets up:
- the firewall (default deny both ways, per-service egress);
- sysctl and the SSH policy;
- AppArmor (complain mode);
- the data bind mounts;
- the read-only root with a RAM overlay.

After the reboot:

```
sudo /opt/usb-scan/scripts/maintenance-mode.sh status     # overlay active now: yes
findmnt /data /var/lib/usb-scan /etc/usb-scan /var/log/usb-scan /var/lib/clamav
```

## 10. First test scan and acceptance

1. Prepare a stick with the EICAR test file from eicar.org. Insert it: the screen must show
   **"Threat detected"**.
2. Insert a clean stick: **"No known threats detected"**. Remove it when told.
3. Run the automated checks:
   ```
   cd /opt/usb-scan && sudo .venv/bin/python -m tests.acceptance.run_acceptance baseline
   sudo .venv/bin/python -m tests.acceptance.run_acceptance run
   ```
4. Complete tests/acceptance/MANUAL_TEST_CHECKLIST.md and sign it off.
5. Tune and enforce AppArmor (`aa-logprof`, then `harden.sh --apparmor-enforce`).
6. **Escrow the history keys** (docs/secret-recovery.md).

Print docs/operator-guide.md (or `operator-guide.de.md`) and place it next to the station.
