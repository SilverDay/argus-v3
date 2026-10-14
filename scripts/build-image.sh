#!/usr/bin/env bash
# Fleet imaging wrapper (plan Phase 13). Runs on a Linux imaging WORKSTATION, never on a station.
#
#   scripts/build-image.sh --image raspios-trixie-arm64-lite.img.xz --sha256 <hash> \
#       --release v1.0.0 --config site/scan_station.yaml --device /dev/sdX --station-id hq-lobby-01
#
# What it does today:
#   1. checks parameters and refuses the workstation's own disks;
#   2. verifies the OS image against the SHA-256 published by Raspberry Pi;
#   3. builds a reproducible application payload from a reviewed git tag
#      (git archive, plus a SHA-256 manifest), and validates the site configuration;
#   4. prints the remaining device steps.
# The destructive device steps (write the image, create the data partition, copy the
# payload) are STUBS below. They are listed as exact commands for the imaging operator and
# are not executed, because a wrong /dev path destroys the workstation.
#
# Unattended vs. commissioning:
# A production image intentionally does NOT contain:
#   - an operator PIN: spec §10.1 forbids factory defaults;
#   - station keys: generated on the device;
#   - the mTLS key: generated on the device, docs/secret-recovery.md.
# So every station needs a short commissioning session (SSH or serial console):
#   first-boot-setup.sh (asks for the PIN) -> station-cert.sh csr/install -> harden.sh ->
#   reboot -> acceptance checks.
# See docs/installation.md (steps 6-10).
set -euo pipefail

usage() {
    cat <<'EOF'
usage: build-image.sh --image FILE --sha256 HEX --release TAG --config FILE --device /dev/sdX
                      --station-id ID [--data-size 16GiB] [--out DIR]
EOF
    exit 2
}
die() { printf 'build-image: %s\n' "$*" >&2; exit 1; }

IMAGE="" SHA="" RELEASE="" CONFIG="" DEVICE="" STATION="" DATA_SIZE=16GiB OUT=./image-build
while [[ $# -gt 0 ]]; do
    case $1 in
        --image) IMAGE=$2; shift 2 ;;
        --sha256) SHA=${2,,}; shift 2 ;;
        --release) RELEASE=$2; shift 2 ;;
        --config) CONFIG=$2; shift 2 ;;
        --device) DEVICE=$2; shift 2 ;;
        --station-id) STATION=$2; shift 2 ;;
        --data-size) DATA_SIZE=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n $IMAGE && -n $SHA && -n $RELEASE && -n $CONFIG && -n $DEVICE && -n $STATION ]] || usage
[[ -f $IMAGE ]] || die "image $IMAGE not found"
[[ $SHA =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 hex digits"
[[ -f $CONFIG ]] || die "config $CONFIG not found"
[[ $STATION =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "invalid station id"
[[ $DATA_SIZE =~ ^[0-9]+GiB$ ]] || die "--data-size like 16GiB"
[[ -b $DEVICE ]] || die "$DEVICE is not a block device"
TYPE=$(lsblk -dno TYPE "$DEVICE")
[[ $TYPE == disk || ($TYPE == loop && ${BUILD_IMAGE_ALLOW_LOOP:-0} == 1) ]] || die "$DEVICE is not a whole disk"
# Refuse any disk that holds a mounted filesystem (the workstation's own disks).
if lsblk -nro MOUNTPOINT "$DEVICE" | grep -q .; then
    die "$DEVICE has mounted filesystems; refusing"
fi
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

echo "==> 1. verify OS image"
actual=$(sha256sum "$IMAGE" | awk '{print $1}')
[[ $actual == "$SHA" ]] || die "SHA-256 mismatch: expected $SHA, got $actual"
echo "    OK $actual"

echo "==> 2. application payload from $RELEASE"
git -C "$REPO" rev-parse --verify --quiet "$RELEASE^{commit}" >/dev/null || die "unknown release $RELEASE"
if git -C "$REPO" cat-file -t "$RELEASE" 2>/dev/null | grep -q tag; then
    git -C "$REPO" tag -v "$RELEASE" >/dev/null 2>&1 \
        || echo "    WARNING: tag $RELEASE has no valid signature (git tag -v); verify the commit by other means"
fi
COMMIT=$(git -C "$REPO" rev-parse "$RELEASE^{commit}")
mkdir -p "$OUT"
PAYLOAD=$OUT/usb-scan-$RELEASE.tar
git -C "$REPO" archive --format=tar --prefix=usb-scan/ "$COMMIT" > "$PAYLOAD"
sha256sum "$PAYLOAD" > "$PAYLOAD.sha256"
echo "    $PAYLOAD (commit $COMMIT)"

echo "==> 3. site configuration"
SITE_CFG=$OUT/scan_station.$STATION.yaml
sed -E "s/^([[:space:]]*station_id:).*/\1 $STATION/" "$CONFIG" > "$SITE_CFG"
(cd "$REPO" && python3 -c "import sys; from src.shared.config import load_config; c = load_config(sys.argv[1]); \
assert c.station.station_id == sys.argv[2], 'station_id not set'; print('    valid, station_id', c.station.station_id)" \
    "$SITE_CFG" "$STATION") || die "site configuration invalid"
# shellcheck disable=SC2016  # literal $ in the bcrypt pattern
if grep -nE '(BEGIN [A-Z ]*PRIVATE KEY|\$2[aby]\$[0-9]{2}\$)' "$SITE_CFG"; then
    die "the configuration contains key material or a bcrypt hash; use secret references"
fi

PART=$DEVICE; [[ $DEVICE =~ [0-9]$ ]] && PART=${DEVICE}p      # /dev/mmcblk0 -> /dev/mmcblk0p3
cat <<EOF
==> 4. device steps (STUB: run them yourself after checking $DEVICE twice with lsblk)

  # 4a. write the image (or use rpi-imager with the customisation: hostname $STATION,
  #     named admin user, SSH public-key only, time zone UTC)
  xzcat "$IMAGE" | sudo dd of=$DEVICE bs=4M conv=fsync status=progress

  # 4b. persistent data partition at the end of the card (docs/deployment.md §7a)
  sudo parted $DEVICE -- mkpart primary ext4 -$DATA_SIZE 100%
  sudo mkfs.ext4 -L USBSCAN-DATA ${PART}3

  # 4c. application and configuration onto the root partition
  sudo mount ${PART}2 /mnt
  sudo tar -C /mnt/opt -xf "$PAYLOAD"                # creates /mnt/opt/usb-scan
  sudo install -d -m 0755 /mnt/etc/usb-scan
  sudo install -m 0644 "$SITE_CFG" /mnt/etc/usb-scan/scan_station.yaml
  sudo umount /mnt

  # 4d. record: station $STATION, image $actual, release $RELEASE ($COMMIT)

Commissioning on the station (SSH/serial): docs/installation.md steps 6-10.
EOF
