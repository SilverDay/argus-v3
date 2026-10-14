# Secret backup and recovery (spec §15.2 #5)

**Owner decision (spec 1.5.9).**
- **Escrow:** only the secrets that protect *history* go into the organisation's secret
  vault.
- **Regenerate:** everything else is created anew when a station is rebuilt. A rebuilt
  station never needs a secret that only existed on the failed SD card.

The Pi 5 has no TPM, so every station secret is a root-owned file on the persistent data
partition (`/etc/usb-scan/secrets`, bind-mounted from `/data`). Escrow and restore happen
over SSH from a management network or on the serial console. Secrets are never printed into
logs, tickets or chat.

## Inventory

| Secret | File (default) | Owner / mode | Protects | After a rebuild |
|---|---|---|---|---|
| Event checkpoint HMAC key | `events-checkpoint.key` | root:usbscan-events 0640 | authenticity of the audit chain checkpoints (history) | **restore from escrow** |
| Pseudonymisation key | `pseudonymization.key` | root:usbscan-events 0640 | linking pseudonyms in SIEM/alerts across time | **restore from escrow** |
| Quarantine recovery passphrase | not stored on the station (printed once by `setup-quarantine.sh`) | – | access to quarantined evidence | **escrowed at setup**; used to re-key the volume |
| Broker HMAC key | `broker-hmac.key` | root:usbscan 0640 | broker RPC between local services | regenerate (`first-boot-setup.sh`) |
| Quarantine keyfile | `quarantine.key` | root 0400 | unattended unlock of the LUKS2 medium | regenerate, then `cryptsetup luksAddKey` with the recovery passphrase |
| Station mTLS key | `station-mtls.key` | root:usbscan-events 0640 | station identity towards the collector | regenerate: `scripts/station-cert.sh csr`; revoke the old certificate at the CA |
| Operator PIN hash | `operator_pin.hash` | root:usbscan 0640 | touchscreen operator overlay | set a new PIN (`src.shared.pin_admin`) |
| Local admin web accounts (optional) | `web-accounts` | root:usbscan-web 0640 | admin web sign-in (bcrypt hashes, TOTP seeds) | re-create with `src.web.accounts_admin add` (new passphrase, re-enrol the authenticator) |
| OIDC client secret (optional) | `web_oidc_client_secret` or `credential:` | per unit | admin web ↔ IdP | issue a new secret at the IdP |
| VirusTotal API key (optional) | `credential:` / file | per unit | VT lookups | re-provision from the vault (it is an external account credential) |
| Alert/forwarding tokens (optional) | `credential:` | per unit | webhook/SIEM authentication | re-provision from the vault |

Not secrets, but needed for a complete rebuild. Keep them in configuration management:
- `scan_station.yaml`;
- the YARA minisign public key (`yara.trust_anchor_path`);
- the collector CA bundle (`/etc/usb-scan/pki/`);
- the station id.

## Escrow (once, after provisioning, and after any rotation)

```
# on the station, as root, in an SSH session that is not recorded
sha256sum /etc/usb-scan/secrets/events-checkpoint.key /etc/usb-scan/secrets/pseudonymization.key
cat /etc/usb-scan/secrets/events-checkpoint.key; echo
cat /etc/usb-scan/secrets/pseudonymization.key; echo
```

- Store both values in the vault entry `usb-scan/<station_id>`, with the two SHA-256 values
  for verification. Then `clear` the terminal.
- **One pseudonymisation key per fleet?** Correlating the same file or stick across stations
  in the SIEM requires one shared key on all stations. Generate it once in the vault and
  install it on every station instead of the generated one. The trade-off: a compromised
  station then exposes the key of the whole fleet.
- **Quarantine recovery passphrase:** store it in the same vault entry when
  `setup-quarantine.sh` prints it.

## Restore after an SD card failure

1. **Flash and image.** Flash the image and create the data partition (docs/deployment.md
   §7a).
2. **Restore the escrowed keys** *before* `first-boot-setup.sh`. The script never overwrites
   an existing key.
   ```
   install -d -m 0711 /etc/usb-scan/secrets
   (umask 077; cat > /etc/usb-scan/secrets/events-checkpoint.key)   # paste, Ctrl-D
   (umask 077; cat > /etc/usb-scan/secrets/pseudonymization.key)    # paste, Ctrl-D
   sha256sum /etc/usb-scan/secrets/*.key                            # compare with the vault
   ```
   Owners and modes are set by `first-boot-setup.sh`.
3. **Run `first-boot-setup.sh`.** It generates the broker key and asks for a new operator PIN.
4. **Restore the audit history, if wanted.** Restore the events database from its backup and
   run `python -m src.events --verify` as usbscan-events. Checkpoints made with the escrowed
   key verify again. Without the old database, the SIEM copy is the record of the past.
5. **Re-key the quarantine.** Generate a new keyfile and add it with the recovery passphrase
   (docs/deployment.md §7, "Lost quarantine keyfile").
6. **Re-establish the station identity.**
   - Run `scripts/station-cert.sh csr` and have the CA sign the CSR.
   - Run `scripts/station-cert.sh install CERT --ca ...`.
   - Revoke the old station certificate.
7. **Re-provision optional credentials** (OIDC client secret, VT key, alert tokens) from the
   vault or the issuing systems.
8. **Run `scripts/harden.sh` and reboot.** Then run the acceptance PRE and AC-F05 checks
   (tests/acceptance).

## Losing an escrowed secret

- **Checkpoint key lost:**
  - The retained HMAC checkpoints can no longer be verified. `src.events --verify` checks
    every retained checkpoint's MAC, even after `--acknowledge-tamper`, so an old database
    cannot stay in service under a new key.
  - Record the loss, stop `usb-scan-events`, and archive the old database read-only for
    forensics (`events.db` with its `-wal`/`-shm` files). Its hash chain can still be
    recomputed offline; no key is involved in the chain itself.
  - Generate a new key (`first-boot-setup.sh` does this when the file is missing) and start
    with an empty database.
  - The SIEM copy remains the authoritative record of the earlier period.
- **Pseudonymisation key lost:** new pseudonyms differ from old ones. Historic SIEM data
  stays pseudonymous but cannot be linked to new events.
