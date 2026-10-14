# Hardening checklist (spec §8, plan Phase 11)

Status legend:
- **scripted** — done by a script or unit in this repository and checked here as far as
  possible without the Pi;
- **validated** — verified by an automated test or tool run;
- **manual** — an operator step;
- **Pi** — must still be verified on the reference hardware;
- **n/a**.

Owner decisions (Phase 11):
- AppArmor profiles ship in **complain** mode and are promoted after tuning.
- Outbound traffic is a **per-service allowlist**.

## §8.1 Host hardening

| Requirement | Status | Implementation |
|---|---|---|
| Minimal OS image | manual | Raspberry Pi OS **Lite**; `harden.sh` disables bluetooth, hciuart, avahi, cups, triggerhappy, ModemManager, systemd-rfkill |
| Remove unused services/accounts | scripted / Pi | services above; the default `pi` account is locked if present (`usermod --lock --expiredate 1`); review other human accounts manually |
| Restrict USB peripherals | scripted, validated | USBGuard policy `config/system/usbguard/rules.conf` (parser-validated); applied by `first-boot-setup.sh` |
| Default-deny inbound firewall | scripted, validated | `src/host/render.py` → `/etc/nftables.conf`; `nft -c` in unit tests; input/forward policy drop |
| Management service only on a trusted interface / reverse proxy, allowlisted networks | scripted | gunicorn on 127.0.0.1; firewall opens `host.admin_proxy_port` only from `host.management_networks`; config validation requires networks when the admin web is enabled |
| Outbound restriction (owner decision, beyond spec) | scripted, validated / Pi | per-uid egress (`meta skuid`) with ports derived from config; everything else dropped and rate-limited logged; **validate on the Pi** that freshclam, apt, NTP and DNS work |
| SSH off by default | scripted | `host.ssh_enabled: false` → ssh.service/ssh.socket disabled |
| SSH: named keys, management VLAN, no passwords | scripted | `/etc/ssh/sshd_config.d/usb-scan.conf`: publickey only, `AllowUsers` from config, no root login, MaxAuthTries 3, no forwarding; firewall restricts port 22 to management networks; `sshd -t` before reload |
| AppArmor | scripted (complain) / Pi | `config/system/apparmor.d/usb-scan-*` (parser-validated), attached by `AppArmorProfile=` drop-ins after a successful load; promotion via `harden.sh --apparmor-enforce` after `aa-logprof` tuning |
| systemd sandboxing (NoNewPrivileges, capability bounding, ProtectSystem/Home, device allowlists, quotas) | scripted, validated | all units in `systemd/` (`systemd-analyze verify` clean); broker keeps CAP_SYS_ADMIN+CAP_CHOWN only (spec §5.4); MemoryMax/TasksMax per unit |
| Validated against required hardware interfaces | Pi | GPIO (LED), DRM/input (cage), block devices (broker) under the sandbox and AppArmor |
| Trixie: no passwordless sudo | manual | nothing in this repository enables it; check `/etc/sudoers.d` on the image |
| Kernel parameters | scripted | `/etc/sysctl.d/99-usb-scan.conf`: no forwarding/redirects/source routing, rp_filter, kptr/dmesg restrict, unprivileged BPF off, BPF JIT hardening, Yama ptrace 2, suid_dumpable 0, protected links/fifos |
| Radios | scripted | `dtoverlay=disable-wifi` / `disable-bt` unless enabled in `host.*` (overlays verified in the Raspberry Pi overlays README) |
| Swap | scripted / Pi | `swapoff -a`; dphys-swapfile and any swap units disabled and masked; overlayroot drops swap entries. The trixie swap mechanism was not verifiable offline. |

## §8.2 USB and filesystem isolation

| Requirement | Status | Implementation |
|---|---|---|
| USBGuard default deny, mass storage only | scripted, validated | `allow with-interface equals { 08:*:* }`, `ImplicitPolicyTarget=block`, IPC root only, `usbguard-dbus` masked |
| Composite with HID rejected at the authorization layer | scripted, validated / Pi | `block with-interface one-of { 03:*:* }` before the allow rule (owner decision 1.5.8: `block` keeps the device enumerated but unauthorised, so the orchestrator records `usb_policy_blocked` deterministically; `reject` would remove it first); **acceptance on the Pi** with a keyboard and a stick + HID composite |
| Broker uses sysfs identifiers, not /dev paths | validated | `src/broker` (Phase 2 tests) |
| Read-only, noexec,nodev,nosuid mounts; gid/dmask/fmask for non-POSIX | validated | `src/broker/mounts.py`, mountinfo verification (Phase 2) |
| Automount prevention | scripted | `udisks2` masked (warning if installed), no gvfs on Lite |
| clamd socket restricted | scripted | `clamav-daemon.socket.d/usb-scan.conf`: `SocketMode=0660`, group `clamav`. Under socket activation systemd creates the node, so systemd's default `SocketMode=0666` would otherwise apply instead of `LocalSocketMode` in clamd.conf. `clamd.conf` also disables SHUTDOWN/RELOAD/STATS. **Pi:** `stat -c '%a %U:%G' /run/clamav/clamd.ctl` → `660 clamav:clamav` |
| Legacy filesystem modules blacklisted | scripted | `config/system/modprobe.d/usb-scan-blacklist.conf` (cramfs, freevxfs, jffs2, hfs, hfsplus, udf, squashfs, romfs, minix, erofs; dccp, sctp, rds, tipc) |
| Scanner access confined to mount roots, no traversal | validated | inventory without symlink following, `openat2` RESOLVE_BENEATH (Phase 2/3) |
| NTFS/exFAT driver choice | Pi | default `broker.ntfs_driver: ntfs3` (kernel driver; avoids a FUSE daemon). Verify on the image with `grep -E 'ntfs|exfat' /proc/filesystems`: expect `ntfs3` and `exfat` (or `fuseblk` only if ntfs-3g is chosen). Security notes: ntfs3 runs in the kernel (a parser bug is a kernel bug, mitigated by `ro` + BLKROSET); ntfs-3g runs in user space as root through FUSE (a parser bug is a root process bug). Choose and record per deployment (FR-USB-05). |

## §8.3 Secrets, authentication and audit

| Requirement | Status | Implementation |
|---|---|---|
| Secrets outside general YAML | validated | secret references (`file:`/`credential:`) only; config loader rejects hash-like values |
| Minimal filesystem-readable scope | scripted | `/etc/usb-scan/secrets` 0711; `broker-hmac.key` 0640 root:usbscan (orchestrator must read it, so not 0400 as the plan proposed), `events-checkpoint.key` 0640 root:usbscan-events, PIN hash 0640 root:usbscan, `quarantine.key` 0400 root |
| Rotation / revocation | manual | replace a key file and restart its services; PIN via `pin_admin` |
| Protected backup and disaster recovery | manual | back up `/data` (persistent partition) to protected storage; quarantine recovery passphrase escrowed offline; reflash image maintained (spec §13) |
| Audit integrity | validated | hash chain + HMAC checkpoints, tamper → NOT_READY (Phase 8) |

## Read-only root and persistence (spec §5.3)

| Requirement | Status | Implementation |
|---|---|---|
| Read-only root with RAM overlay | scripted / Pi | `overlayroot=tmpfs:recurse=0` on the kernel command line; `recurse=0` verified in the overlayroot init script; with the default `recurse=1` the data partition would also be overlaid and lost at reboot |
| Persistent data partition | scripted (needs prepared partition) | ext4 labelled `USBSCAN-DATA` at the end of the SD card (created at imaging time; the script never repartitions), mounted `nodev,nosuid,noexec`; bind mounts for `/var/lib/usb-scan`, `/etc/usb-scan`, `/var/log/usb-scan`, `/var/lib/clamav` |
| Boot partition read-only | scripted | `/boot/firmware` `defaults,ro` in fstab (same edit as raspi-config) |
| Maintenance window for OS updates | scripted | `scripts/maintenance-mode.sh enter|exit|status`; UPS confirmation; the orchestrator only starts with the overlay (`ConditionKernelCommandLine=overlayroot`) |
| Signatures/rules updated outside the window | scripted | freshclam and YARA bundles write to the persistent partition |

## Still to validate on the Pi

1. Boot with the overlay: `findmnt /` shows overlay; the data mounts and all four bind mounts are present.
2. A full scan works end to end with the read-only root, the firewall and AppArmor (complain) active.
3. `journalctl -k | grep usbscan-drop-out` shows no drops for freshclam, apt (maintenance window), NTP or DNS.
4. `aa-status`: all `usb-scan-*` profiles are in complain mode. Run `aa-logprof` after the acceptance tests, then `--apparmor-enforce`.
5. The overlayroot package on trixie behaves like the 0.49 version reviewed here.
6. The NTFS/exFAT drivers match the documented choice.
