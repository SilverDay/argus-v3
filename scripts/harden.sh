#!/usr/bin/env bash
# USB Scan Station host hardening (spec §8.1/§8.2, plan Phase 11). Run once after
# first-boot-setup.sh, as root, from /opt/usb-scan; idempotent. Reboot afterwards.
#
#   sudo /opt/usb-scan/scripts/harden.sh                  # full hardening
#   sudo /opt/usb-scan/scripts/harden.sh --apparmor-enforce   # promote tuned profiles
#
# Owner decisions: AppArmor profiles ship in complain mode; outbound firewall is a per-service
# allowlist. Read-only root: overlayroot=tmpfs:recurse=0 (recurse=0 is REQUIRED — the default
# recurse=1 would also put the persistent data partition behind a RAM overlay and every scan
# record, audit event, key and the PIN would be lost at reboot).
set -euo pipefail
umask 022

APP=/opt/usb-scan
CFG=/etc/usb-scan/scan_station.yaml
PY=$APP/.venv/bin/python
OVERLAY_PARAM="overlayroot=tmpfs:recurse=0"

log()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'harden: %s\n' "$*" >&2; exit 1; }
confirm() {  # confirm "question" -> returns 0 on yes; non-interactive runs answer yes
    [[ -t 0 ]] || return 0
    local a; read -r -p "$1 [y/N] " a; [[ $a == [yY] ]]
}

[[ $EUID -eq 0 ]] || die "must run as root"
cd "$APP"
[[ -x $PY ]] || die "run scripts/first-boot-setup.sh first"
cfgval() { "$PY" -c "from src.shared.config import load_config; c = load_config('$CFG'); print($1)"; }
cfgval "c.station.station_id" >/dev/null || die "$CFG is invalid"

BOOT=/boot/firmware; [[ -d $BOOT ]] || BOOT=/boot
CMDLINE=$BOOT/cmdline.txt
CONFIGTXT=$BOOT/config.txt
grep -q "overlayroot=" /proc/cmdline && die "the read-only overlay is active; run scripts/maintenance-mode.sh enter first"

boot_rw() { findmnt -n -o OPTIONS "$BOOT" | grep -qE '(^|,)ro(,|$)' && mount -o remount,rw "$BOOT" || true; }

# --- promotion only ----------------------------------------------------------------------------
if [[ ${1:-} == "--apparmor-enforce" ]]; then
    log "Promoting USB Scan Station AppArmor profiles to enforce mode"
    for p in /etc/apparmor.d/usb-scan-*; do
        sed -i 's/ flags=(complain) {/ {/' "$p"
        apparmor_parser -r -W "$p"
    done
    echo "Enforced. Run the acceptance tests again; revert with: harden.sh (re-installs complain profiles)."
    exit 0
fi

WORK=$(mktemp -d /run/usb-scan-harden.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# --- 1. render and validate ----------------------------------------------------------------------
log "Rendering firewall, sysctl and SSH policy from $CFG"
"$PY" -m src.host.render --config "$CFG" --out "$WORK" >/dev/null
command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables
nft -c -f "$WORK/nftables.conf" || die "generated nftables ruleset failed validation"

# --- 2. persistent data partition (spec §5.3) --------------------------------------------------------
LABEL=$(cfgval "c.host.data_partition_label")
DATA=$(cfgval "c.host.data_mountpoint")
log "Persistent data partition (LABEL=$LABEL -> $DATA)"
DEV=$(blkid -L "$LABEL" || true)
[[ -n $DEV ]] || die "no partition labelled $LABEL. Create an ext4 partition in free space at the end of the
SD card before running this script (see docs/deployment.md); this script never repartitions."
[[ $(blkid -s TYPE -o value "$DEV") == ext4 ]] || die "$DEV ($LABEL) must be ext4"
install -d -m 0755 "$DATA"
if ! grep -qE "^LABEL=${LABEL}[[:space:]]" /etc/fstab; then
    echo "LABEL=$LABEL $DATA ext4 defaults,nodev,nosuid,noexec,noatime 0 2" >> /etc/fstab
fi
findmnt -n "$DATA" >/dev/null || mount "$DATA"

# directories that must survive reboots under the read-only root -> bind mounts from $DATA
declare -A PERSIST=(
    [/var/lib/usb-scan]=var-lib-usb-scan
    [/etc/usb-scan]=etc-usb-scan
    [/var/log/usb-scan]=var-log-usb-scan
    [/var/lib/clamav]=var-lib-clamav        # signatures stay fresh across reboots (spec §5.3)
)
STOPPED=0
for target in "${!PERSIST[@]}"; do
    src="$DATA/${PERSIST[$target]}"
    if findmnt -n "$target" >/dev/null && [[ $(findmnt -n -o SOURCE "$target") == *"${PERSIST[$target]}"* ]]; then
        continue
    fi
    if [[ $STOPPED -eq 0 ]]; then
        systemctl stop 'usb-scan-*.service' clamav-daemon.service clamav-freshclam.service 2>/dev/null || true
        STOPPED=1
    fi
    if [[ ! -d $src ]]; then
        install -d "$src"
        [[ -d $target ]] && cp -a "$target/." "$src/"     # migrate existing content with owners/modes
        chown --reference="$target" "$src" 2>/dev/null || true
        chmod --reference="$target" "$src" 2>/dev/null || true
    fi
    # Per-mount flags are set explicitly on the bind (mount(8) applies them with a remount).
    grep -qE "^${src}[[:space:]]+${target}[[:space:]]" /etc/fstab ||
        echo "$src $target none bind,nodev,nosuid,noexec,x-systemd.requires-mounts-for=$DATA 0 0" >> /etc/fstab
    install -d "$target"
    mount "$target"
done
systemctl daemon-reload

# --- 3. radios and unneeded services ----------------------------------------------------------------
log "Disabling unneeded services and radios"
for unit in bluetooth.service hciuart.service avahi-daemon.service avahi-daemon.socket cups.service \
            cups-browsed.service triggerhappy.service triggerhappy.socket ModemManager.service \
            systemd-rfkill.service systemd-rfkill.socket; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
boot_rw
if [[ $(cfgval "int(c.host.wifi_enabled)") == 0 ]]; then
    systemctl disable --now wpa_supplicant.service >/dev/null 2>&1 || true
    grep -q '^dtoverlay=disable-wifi' "$CONFIGTXT" || printf '[all]\ndtoverlay=disable-wifi\n' >> "$CONFIGTXT"
fi
if [[ $(cfgval "int(c.host.bluetooth_enabled)") == 0 ]]; then
    grep -q '^dtoverlay=disable-bt' "$CONFIGTXT" || printf '[all]\ndtoverlay=disable-bt\n' >> "$CONFIGTXT"
fi

# --- 4. swap (the overlay additionally drops swap entries from fstab) ---------------------------------------
log "Swap off"
swapoff -a || true
for unit in dphys-swapfile.service $(systemctl list-units --type=swap --all --plain --no-legend 2>/dev/null | awk '{print $1}'); do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done

# --- 5. sysctl --------------------------------------------------------------------------------------------------
log "Kernel parameters"
install -m 0644 "$WORK/99-usb-scan.conf" /etc/sysctl.d/99-usb-scan.conf
sysctl --system >/dev/null || warn "some sysctl keys are not supported by this kernel (see 'sysctl --system')"

# --- 6. accounts and SSH ----------------------------------------------------------------------------------------------
log "Accounts and SSH (spec §8.1: off by default)"
ALLOW=$(cfgval "' '.join(c.host.ssh_allow_users)")
if id pi >/dev/null 2>&1 && [[ " $ALLOW " != *" pi "* ]]; then
    usermod --lock --expiredate 1 pi && echo "  locked default account 'pi'"
fi
if [[ $(cfgval "int(c.host.ssh_enabled)") == 1 ]]; then
    install -d -m 0755 /etc/ssh/sshd_config.d
    install -m 0644 "$WORK/sshd-usb-scan.conf" /etc/ssh/sshd_config.d/usb-scan.conf
    sshd -t || die "sshd configuration invalid"
    for u in $ALLOW; do
        id "$u" >/dev/null 2>&1 || warn "ssh_allow_users: account $u does not exist"
        [[ -s $(getent passwd "$u" | cut -d: -f6)/.ssh/authorized_keys ]] || warn "$u has no authorized_keys"
    done
    systemctl enable ssh.service && systemctl reload-or-restart ssh.service
else
    systemctl disable --now ssh.service ssh.socket >/dev/null 2>&1 || true
fi

# --- 7. firewall ---------------------------------------------------------------------------------------------------------
log "Firewall (default deny in/out; per-service egress)"
grep -E '^\s*(# [a-z_-]+:|meta skuid|ip6? saddr)' "$WORK/nftables.conf" | sed 's/^/    /'
if confirm "Apply this firewall now? Connections from outside host.management_networks will be cut."; then
    install -m 0644 "$WORK/nftables.conf" /etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable nftables.service
else
    warn "firewall NOT applied"
fi

# --- 8. AppArmor (complain mode) ---------------------------------------------------------------------------------------------
log "AppArmor profiles (complain mode)"
install -m 0644 "$APP"/config/system/apparmor.d/usb-scan-* /etc/apparmor.d/
if [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]]; then
    for p in /etc/apparmor.d/usb-scan-*; do
        name=$(basename "$p")
        apparmor_parser -r -W "$p"
        install -d "/etc/systemd/system/$name.service.d"
        printf '[Service]\nAppArmorProfile=%s\n' "$name" > "/etc/systemd/system/$name.service.d/apparmor.conf"
    done
    systemctl daemon-reload
else
    warn "AppArmor is not enabled in this kernel; adding 'apparmor=1 security=apparmor' to $CMDLINE"
    warn "re-run harden.sh after the reboot to load the profiles and attach them to the units"
    boot_rw
    grep -q 'security=apparmor' "$CMDLINE" || sed -i '1 s/$/ apparmor=1 security=apparmor/' "$CMDLINE"
fi

# --- 9. read-only root ---------------------------------------------------------------------------------------------------------
log "Read-only root (overlayroot, $OVERLAY_PARAM)"
dpkg-query -W -f='${Status}' overlayroot 2>/dev/null | grep -q installed ||
    DEBIAN_FRONTEND=noninteractive apt-get install -y overlayroot
boot_rw
sed -i -E '1 s/(^| )overlayroot=[^ ]*//g; 1 s/^ +//' "$CMDLINE"
sed -i "1 s/^/$OVERLAY_PARAM /" "$CMDLINE"
# Scanning only on the read-only root: during maintenance (overlay off) the orchestrator stays
# down and the station reports not ready (fail closed).
install -d /etc/systemd/system/usb-scan-orchestrator.service.d
printf '[Unit]\nConditionKernelCommandLine=overlayroot\n' \
    > /etc/systemd/system/usb-scan-orchestrator.service.d/readonly-root.conf
systemctl daemon-reload
# boot partition read-only as well (same edit as raspi-config enable_bootro)
sed -i -E "s#^(\S+\s+$BOOT\s+vfat\s+)defaults(,ro)?#\1defaults,ro#" /etc/fstab

[[ $STOPPED -eq 1 ]] && systemctl start 'usb-scan-*.service' clamav-daemon.service clamav-freshclam.service 2>/dev/null || true
cat <<EOF

Hardening applied. REBOOT to activate the read-only root:  sudo reboot
After the reboot verify:
  findmnt /            -> overlay (root changes go to RAM)
  findmnt $DATA /var/lib/usb-scan /etc/usb-scan /var/log/usb-scan /var/lib/clamav
  nft list ruleset | head;  aa-status | grep usb-scan
For OS updates use scripts/maintenance-mode.sh (UPS-backed power only).
EOF
