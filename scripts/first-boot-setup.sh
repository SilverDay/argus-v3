#!/usr/bin/env bash
# USB Scan Station first-boot / provisioning (plan Phase 10). Idempotent; run as root on the
# Raspberry Pi 5 (Raspberry Pi OS Lite / Debian 13 trixie) from the deployed checkout:
#
#   sudo /opt/usb-scan/scripts/first-boot-setup.sh [--skip-packages]
#
# Steps: packages -> venv -> users/groups -> directories -> config -> secrets -> clamd ->
# kernel/automount hardening -> systemd units -> YARA layout -> operator PIN (mandatory) ->
# enable services -> USBGuard (last: it rejects USB keyboards from then on).
# Nothing that already exists (config, keys, PIN, rules) is overwritten.
set -euo pipefail
umask 022

APP=/opt/usb-scan
ETC=/etc/usb-scan
CFG=$ETC/scan_station.yaml
SECRETS=$ETC/secrets
VENV=$APP/.venv
PY=$VENV/bin/python
SKIP_PACKAGES=0
[[ ${1:-} == "--skip-packages" ]] && SKIP_PACKAGES=1

log()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'first-boot-setup: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ $SRC == "$APP" ]] || die "expected the checkout at $APP (found $SRC)"
cd "$APP"                         # python -m src.* and cfgval import from the checkout
# shellcheck source=/dev/null
. /etc/os-release
[[ ${VERSION_CODENAME:-} == trixie ]] || warn "tested target is Debian 13 trixie; found ${PRETTY_NAME:-unknown}"

# Read one value from the validated config (the loader rejects invalid files).
cfgval() { "$PY" -c "import sys; from src.shared.config import load_config; c = load_config('$CFG'); print($1)"; }

# --- 1. packages ---------------------------------------------------------------------------------
if [[ $SKIP_PACKAGES -eq 0 ]]; then
    log "Installing system packages"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-venv python3-lgpio \
        clamav-daemon clamav-freshclam usbguard minisign \
        cryptsetup-bin e2fsprogs util-linux \
        cage libegl1 libgl1 libxkbcommon0 libfontconfig1
fi

# --- 2. virtual environment ------------------------------------------------------------------------
log "Python environment ($VENV)"
# --system-site-packages: python3-lgpio comes from the distribution (never pip install lgpio).
[[ -x $PY ]] || python3 -m venv --system-site-packages "$VENV"
"$VENV/bin/pip" install --disable-pip-version-check -q -r "$APP/requirements.txt"

# --- 3. users, groups, directories ------------------------------------------------------------------
log "Service users and directories"
install -m 0644 "$APP/config/system/sysusers.d/usb-scan.conf" /etc/sysusers.d/usb-scan.conf
systemd-sysusers /etc/sysusers.d/usb-scan.conf
install -m 0644 "$APP/config/system/tmpfiles.d/usb-scan.conf" /etc/tmpfiles.d/usb-scan.conf
systemd-tmpfiles --create /etc/tmpfiles.d/usb-scan.conf

# --- 4. configuration ---------------------------------------------------------------------------------
if [[ ! -e $CFG ]]; then
    log "Installing configuration template to $CFG"
    install -m 0644 -o root -g root "$APP/config/scan_station.yaml" "$CFG"
else
    log "Keeping existing $CFG"
fi
cfgval "c.station.station_id" >/dev/null || die "$CFG is invalid (see the message above)"

# --- 5. secrets (never overwritten) -------------------------------------------------------------------
log "Secrets in $SECRETS"
install -d -m 0711 -o root -g root "$SECRETS"
new_key() {  # path group
    if [[ ! -e $1 ]]; then
        (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$1")
        echo "  created $1"
    fi
    chown "root:$2" "$1"
    chmod 0640 "$1"
}
new_key "$SECRETS/broker-hmac.key" usbscan                  # broker (root) + orchestrator
new_key "$SECRETS/events-checkpoint.key" usbscan-events     # events service only
# Off-device pseudonyms (spec §15.2 #3). Escrow this and the checkpoint key (docs/secret-recovery.md).
new_key "$SECRETS/pseudonymization.key" usbscan-events

# --- 6. ClamAV ----------------------------------------------------------------------------------------
log "ClamAV settings (config/clamd.conf.recommended)"
CLAMD=/etc/clamav/clamd.conf
[[ -f $CLAMD ]] || die "$CLAMD missing (clamav-daemon not installed?)"
cp -n "$CLAMD" "$CLAMD.usb-scan.orig"
grep -E '^[A-Za-z]' "$APP/config/clamd.conf.recommended" | while read -r key value; do
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$CLAMD"; then
        sed -i -E "s|^#?[[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$CLAMD"
    else
        printf '%s %s\n' "$key" "$value" >> "$CLAMD"
    fi
done
sed -i -E 's|^[[:space:]]*TCPSocket[[:space:]]|#TCPSocket |' "$CLAMD"
install -d -m 0755 /etc/systemd/system/clamav-daemon.service.d
install -m 0644 "$APP/systemd/clamav-daemon.service.d/usb-scan.conf" /etc/systemd/system/clamav-daemon.service.d/
# Socket activation: without this the socket node is created 0666 (systemd default).
install -d -m 0755 /etc/systemd/system/clamav-daemon.socket.d
install -m 0644 "$APP/systemd/clamav-daemon.socket.d/usb-scan.conf" /etc/systemd/system/clamav-daemon.socket.d/

# --- 7. kernel surface, automount ---------------------------------------------------------------------
log "Kernel module blacklist and automount masking"
install -m 0644 "$APP/config/system/modprobe.d/usb-scan-blacklist.conf" /etc/modprobe.d/
for unit in udisks2.service usbguard-dbus.service; do
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
if dpkg-query -W -f='${Status}' udisks2 2>/dev/null | grep -q installed; then
    warn "udisks2 is installed (masked now); remove it: apt purge udisks2"
fi

# --- 8. systemd units ----------------------------------------------------------------------------------
log "systemd units"
install -m 0644 "$APP"/systemd/*.service "$APP"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

# --- 9. YARA ruleset layout ------------------------------------------------------------------------------
YARA_ENABLED=$(cfgval "int(c.yara.enabled)")
if [[ $YARA_ENABLED == 1 ]]; then
    log "YARA ruleset layout"
    anchor=$(cfgval "c.yara.trust_anchor_path")
    [[ -f $anchor ]] || warn "YARA trust anchor $anchor missing: install the minisign public key"
    rules=$(cfgval "c.yara.rules_path")
    if [[ -d $rules && ! -L $rules ]]; then
        die "$rules is a directory; the installer manages it as a symlink (see docs/deployment.md)"
    fi
    [[ -L $rules ]] || warn "no YARA ruleset installed yet: python -m src.yara_worker.install BUNDLE"
fi

# --- 10. operator PIN (mandatory, spec §10.1: no factory default) -------------------------------------------
PIN_FILE=$(cfgval "c.pin.hash_ref.partition(':')[2] if c.pin.hash_ref.startswith('file:') else ''")
[[ -n $PIN_FILE ]] || die "pin.hash_ref must be a file: reference"
if [[ ! -s $PIN_FILE ]]; then
    log "Set the operator PIN"
    [[ -t 0 ]] || die "no operator PIN set and no terminal to ask for one; run: $PY -m src.shared.pin_admin"
    "$PY" -m src.shared.pin_admin --config "$CFG" || die "operator PIN not set; services NOT enabled"
fi
[[ -s $PIN_FILE ]] || die "operator PIN missing ($PIN_FILE); services NOT enabled"

# --- 11. enable services ---------------------------------------------------------------------------------------
log "Enabling services"
systemctl enable --now clamav-freshclam.service
systemctl stop clamav-daemon.service
if systemctl cat clamav-daemon.socket >/dev/null 2>&1; then
    systemctl restart clamav-daemon.socket      # recreate the node with SocketMode=0660
fi
systemctl start clamav-daemon.service
SERVICES=(usb-scan-events usb-scan-device-broker usb-scan-orchestrator usb-scan-gui)
[[ $YARA_ENABLED == 1 ]] && SERVICES+=(usb-scan-yara)
[[ $(cfgval "c.led.driver.value") != stub ]] && SERVICES+=(usb-scan-led)
[[ $(cfgval "int(c.admin_web.enabled)") == 1 ]] && SERVICES+=(usb-scan-admin)
systemctl enable "${SERVICES[@]/%/.service}"
if [[ -n $(cfgval "c.yara.update_url") ]]; then
    systemctl enable --now usb-scan-yara-update.timer
fi
systemctl disable getty@tty1.service >/dev/null 2>&1 || true   # tty1 belongs to the kiosk

# --- 12. USBGuard (last) -----------------------------------------------------------------------------------------------
log "USBGuard policy (mass storage only; HID blocked)"
cat <<'EOF'
From now on USB keyboards, mice and hubs are REJECTED/BLOCKED on this station.
Continue administration over SSH (if enabled) or the serial console.
EOF
if [[ -t 0 ]]; then
    read -r -p "Apply the USBGuard policy now? [y/N] " answer
    [[ $answer == [yY] ]] || die "USBGuard not applied; re-run when ready (services are enabled but not started)"
fi
install -m 0600 -o root -g root "$APP/config/system/usbguard/rules.conf" /etc/usbguard/rules.conf
UGCONF=/etc/usbguard/usbguard-daemon.conf
declare -A UG=(
    [RuleFile]=/etc/usbguard/rules.conf
    [ImplicitPolicyTarget]=block
    [PresentDevicePolicy]=apply-policy
    [PresentControllerPolicy]=keep
    [InsertedDevicePolicy]=apply-policy
    [AuthorizedDefault]=none
    [RestoreControllerDeviceState]=false
    [IPCAllowedUsers]=root
    [IPCAllowedGroups]=""
)
for key in "${!UG[@]}"; do
    if grep -qE "^#?${key}=" "$UGCONF"; then
        sed -i -E "s|^#?${key}=.*|${key}=${UG[$key]}|" "$UGCONF"
    else
        printf '%s=%s\n' "$key" "${UG[$key]}" >> "$UGCONF"
    fi
done
chmod 0600 "$UGCONF"
systemctl enable --now usbguard.service
systemctl restart usbguard.service

log "Starting services"
systemctl start "${SERVICES[@]/%/.service}"
systemctl --no-pager --lines=0 status "${SERVICES[@]/%/.service}" usbguard.service clamav-daemon.service || true
cat <<EOF

Provisioning complete.
- Optional quarantine:   scripts/setup-quarantine.sh /dev/<separate disk> --yes-erase-all-data
- YARA rules (offline):  $PY -m src.yara_worker.install --config $CFG BUNDLE.tar.gz
- Change operator PIN:   $PY -m src.shared.pin_admin --config $CFG
See docs/deployment.md.
EOF
