#!/usr/bin/env bash
# Create the optional encrypted evidence quarantine (spec §3.6; owner decision Phase 10:
# keyfile unlock at boot + recovery passphrase). DESTROYS ALL DATA on the given device.
#
#   sudo scripts/setup-quarantine.sh /dev/sdX --yes-erase-all-data
#
# Use a SEPARATE medium (e.g. a USB SSD on an internal/fixed port), not a partition of the
# boot SD card: the unlock keyfile lives on the root filesystem, so encryption only protects
# evidence at rest when the quarantine medium is stored, moved or disposed of on its own.
#
# Result:
#   LUKS2 volume, slot 0 = random 512-bit keyfile /etc/usb-scan/secrets/quarantine.key (0400 root)
#                 slot 1 = random recovery passphrase, printed ONCE for offline escrow
#   /etc/crypttab  usbscan-quarantine UUID=... keyfile luks,nofail,headless=true
#   /etc/fstab     /dev/mapper/usbscan-quarantine /var/lib/usb-scan/quarantine ext4
#                  rw,nodev,nosuid,noexec,nofail
#   mount point owned by the orchestrator user (usbscan), mode 0700
# The orchestrator verifies all of this (mount point, options, dm uuid CRYPT-LUKS2-*) before
# every use. Afterwards set quarantine.quarantine_on_threat: true in scan_station.yaml.
set -euo pipefail
umask 077

NAME=usbscan-quarantine
KEYFILE=/etc/usb-scan/secrets/quarantine.key
MOUNTPOINT=/var/lib/usb-scan/quarantine
OWNER=usbscan

die() { echo "setup-quarantine: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"
[[ $# -eq 2 && $2 == "--yes-erase-all-data" ]] || die "usage: $0 /dev/<disk> --yes-erase-all-data"
DEV=$1
[[ -b $DEV ]] || die "$DEV is not a block device"
for tool in cryptsetup mkfs.ext4 blkid lsblk findmnt; do
    command -v "$tool" >/dev/null || die "$tool is required (apt install cryptsetup-bin e2fsprogs util-linux)"
done
id "$OWNER" >/dev/null 2>&1 || die "user $OWNER does not exist (run first-boot-setup.sh first)"

# Never touch the disk that holds the root filesystem, or anything mounted / in use.
root_src=$(findmnt -n -o SOURCE /)
root_disk=$(lsblk -n -o PKNAME "$root_src" 2>/dev/null | head -n1 || true)
dev_disk=$(lsblk -n -d -o NAME "$DEV")
dev_parent=$(lsblk -n -o PKNAME "$DEV" | head -n1 || true)
for d in "$dev_disk" "$dev_parent"; do
    [[ -n $d && $d == "$root_disk" ]] && die "$DEV is on the boot disk ($root_disk); use a separate medium"
done
if lsblk -n -o MOUNTPOINTS "$DEV" | grep -q '[^[:space:]]'; then
    die "$DEV (or a partition on it) is mounted"
fi
[[ -e /dev/mapper/$NAME ]] && die "/dev/mapper/$NAME already exists"
grep -qE "^[[:space:]]*${NAME}[[:space:]]" /etc/crypttab 2>/dev/null && die "$NAME already in /etc/crypttab"

echo "About to ERASE $DEV ($(lsblk -n -d -o SIZE,MODEL "$DEV" | xargs))."
read -r -p "Type the device path again to confirm: " confirm
[[ $confirm == "$DEV" ]] || die "confirmation did not match"

install -d -m 0711 -o root -g root /etc/usb-scan/secrets
[[ -e $KEYFILE ]] && die "$KEYFILE exists; refusing to overwrite an existing key"
head -c 64 /dev/urandom > "$KEYFILE"
chmod 0400 "$KEYFILE"

work=$(mktemp -d /run/usbscan-quarantine.XXXXXX)
trap 'rm -rf "$work"' EXIT
# Recovery passphrase: 8 groups of 5 base32 characters (~200 bits), no trailing newline so
# that typing it at an interactive prompt later produces the same key.
recovery=$(head -c 25 /dev/urandom | base32 | tr -d '=\n' | fold -w5 | head -n8 | paste -sd-)
printf '%s' "$recovery" > "$work/recovery"

cryptsetup luksFormat --type luks2 --batch-mode --key-file "$KEYFILE" "$DEV"
cryptsetup luksAddKey --key-file "$KEYFILE" --new-keyfile "$work/recovery" "$DEV"
rm -f "$work/recovery"
cryptsetup open --type luks2 --key-file "$KEYFILE" "$DEV" "$NAME"
mkfs.ext4 -q -L usbscan-q "/dev/mapper/$NAME"

uuid=$(blkid -s UUID -o value "$DEV")
[[ -n $uuid ]] || die "could not read the LUKS UUID"
echo "$NAME UUID=$uuid $KEYFILE luks,nofail,headless=true" >> /etc/crypttab
echo "/dev/mapper/$NAME $MOUNTPOINT ext4 rw,nodev,nosuid,noexec,nofail,x-systemd.device-timeout=10s 0 2" >> /etc/fstab

install -d -m 0700 -o "$OWNER" -g "$OWNER" "$MOUNTPOINT"
systemctl daemon-reload
mount "$MOUNTPOINT"
chown "$OWNER:$OWNER" "$MOUNTPOINT"
chmod 0700 "$MOUNTPOINT"
findmnt -n -o OPTIONS "$MOUNTPOINT" | grep -q noexec || die "mounted without noexec — check /etc/fstab"

cat <<EOF

Quarantine volume ready: $DEV (LUKS2 UUID $uuid) mounted at $MOUNTPOINT.

RECOVERY PASSPHRASE (shown once — store it offline, e.g. sealed envelope / password vault):

    $recovery

Unlock without the keyfile:  cryptsetup open $DEV $NAME   (enter the recovery passphrase)
If this disk is attached over USB, add its port to device.internal_device_sysfs_prefixes
so the orchestrator never treats it as a stick to scan. Device path:
    /sys$(udevadm info -q path -n "$DEV" 2>/dev/null || echo "<udevadm info -q path -n $DEV>")
Next: set quarantine.quarantine_on_threat: true in /etc/usb-scan/scan_station.yaml and
restart usb-scan-orchestrator. The dashboard health warnings show "quarantine_unavailable"
if the volume is missing or not verified.
EOF
