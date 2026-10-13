#!/usr/bin/env bash
# OS maintenance window for the read-only root (spec §5.3, §13 "update-window power loss").
#
#   sudo scripts/maintenance-mode.sh status
#   sudo scripts/maintenance-mode.sh enter    # disable the overlay, reboot writable
#        ... apt update && apt full-upgrade ... (re-run first-boot-setup.sh/harden.sh if needed)
#   sudo scripts/maintenance-mode.sh exit     # re-enable the overlay, reboot read-only
#
# WARNING (spec §5.3): a power loss while the root is writable can leave the SD card
# unbootable; there is no automatic rollback. Use UPS-backed power and keep a current reflash
# image. Signature (freshclam) and YARA updates do NOT need this window: they live on the
# persistent data partition.
# The orchestrator only starts when the kernel command line carries overlayroot= (drop-in
# installed by harden.sh), so no scanning happens on the writable root; the station shows
# "not ready" until the overlay is back. Unit changes made while the overlay is active would
# be lost (they land in RAM), which is why this script only edits cmdline.txt on /boot.
set -euo pipefail

OVERLAY_PARAM="overlayroot=tmpfs:recurse=0"
BOOT=/boot/firmware; [[ -d $BOOT ]] || BOOT=/boot
CMDLINE=$BOOT/cmdline.txt

die() { printf 'maintenance-mode: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "must run as root"
[[ -f $CMDLINE ]] || die "$CMDLINE not found"

active_now() { grep -q "overlayroot=" /proc/cmdline; }
configured() { grep -q "overlayroot=" "$CMDLINE"; }
boot_rw() {
    if findmnt -n -o OPTIONS "$BOOT" | grep -qE '(^|,)ro(,|$)'; then
        mount -o remount,rw "$BOOT"
        trap 'mount -o remount,ro "$BOOT" 2>/dev/null || true' EXIT
    fi
}
journal() { logger -t usb-scan-maintenance -p auth.notice "$*"; }

case ${1:-status} in
    status)
        echo "overlay active now:        $(active_now && echo yes || echo no)"
        echo "overlay configured (boot): $(configured && echo yes || echo no)"
        findmnt -n -o SOURCE,FSTYPE,OPTIONS / ;;
    enter)
        active_now || die "the overlay is not active (already in maintenance mode?)"
        cat <<'EOF'
Entering MAINTENANCE MODE: after the reboot the root filesystem is writable and the
orchestrator does not start (no scanning; the station shows not ready). Power loss during
this window may require reflashing the SD card.
EOF
        if [[ -t 0 ]]; then
            read -r -p "Is the station on UPS-backed / reliable power? Type 'yes': " answer
            [[ $answer == yes ]] || die "aborted"
        fi
        boot_rw
        sed -i -E '1 s/(^| )overlayroot=[^ ]*//g; 1 s/^ +//' "$CMDLINE"
        journal "maintenance mode entered by ${SUDO_USER:-root}"
        echo "Rebooting into maintenance mode..."
        systemctl reboot ;;
    exit)
        active_now && die "the overlay is already active"
        boot_rw
        sed -i -E '1 s/(^| )overlayroot=[^ ]*//g; 1 s/^ +//' "$CMDLINE"
        sed -i "1 s/^/$OVERLAY_PARAM /" "$CMDLINE"
        journal "maintenance mode left by ${SUDO_USER:-root}"
        echo "Rebooting with the read-only root..."
        systemctl reboot ;;
    *)
        die "usage: $0 status|enter|exit" ;;
esac
