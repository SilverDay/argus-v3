#!/usr/bin/env bash
# Station mTLS identity for event forwarding (spec §9.2; owner decision §15.2 #2, 1.5.9:
# key generated ON the station, CSR signed by the organisation's CA, certificate installed here).
#
#   sudo scripts/station-cert.sh csr [--rotate]      # print a CSR (new key with --rotate)
#   sudo scripts/station-cert.sh install CERT [--ca CA_BUNDLE]
#   sudo scripts/station-cert.sh status
#
# The private key never leaves the station: only the CSR (public) is copied out, over SSH or
# the serial console. Compare the public-key fingerprint printed here with the one the CA
# operator sees before signing. The Pi 5 has no TPM, so the key is a root-owned file readable
# by the events service (0640 root:usbscan-events); it is regenerated, not escrowed, after a
# rebuild (docs/secret-recovery.md).
# --rotate writes the new key next to the current one; `install` switches to it only when the
# new certificate matches, so forwarding keeps working until then.
set -euo pipefail

ETC=${USB_SCAN_ETC:-/etc/usb-scan}
CFG=${USB_SCAN_CFG:-$ETC/scan_station.yaml}
PY=${USB_SCAN_PY:-/opt/usb-scan/.venv/bin/python}
APP=${USB_SCAN_APP:-/opt/usb-scan}
KEY=$ETC/secrets/station-mtls.key
NEXT=$KEY.next
CSR=$ETC/station-mtls.csr
CRT=$ETC/station-mtls.crt
GROUP=${USB_SCAN_KEY_GROUP:-usbscan-events}

die() { printf 'station-cert: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "must run as root"
command -v openssl >/dev/null || die "openssl not installed"

station_id() {
    (cd "$APP" && "$PY" -c "from src.shared.config import load_config; print(load_config('$CFG').station.station_id)")
}
pub_fp() {  # SHA-256 over the DER public key
    openssl pkey -in "$1" -pubout -outform DER | openssl dgst -sha256 | awk '{print $NF}'
}
cert_pub_fp() {
    openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $NF}'
}
new_key() {
    local tmp="$1.tmp"
    rm -f "$tmp"
    (umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp" 2>/dev/null)
    chown "root:$GROUP" "$tmp"
    chmod 0640 "$tmp"
    mv "$tmp" "$1"
}

cmd_csr() {
    local id key=$KEY
    id=$(station_id) || die "configuration invalid"
    [[ $id =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "station_id '$id' is not usable as a certificate CN"
    install -d -m 0711 "$ETC/secrets"
    if [[ ${1:-} == --rotate ]]; then
        key=$NEXT
        new_key "$key"
        echo "new key: $key (activated by 'install' once the matching certificate is installed)" >&2
    elif [[ ! -e $KEY ]]; then
        new_key "$KEY"
        echo "new key: $KEY" >&2
    fi
    openssl req -new -sha256 -key "$key" -subj "/CN=$id" \
        -addext "keyUsage = critical, digitalSignature" \
        -addext "extendedKeyUsage = clientAuth" -out "$CSR.tmp"
    chmod 0644 "$CSR.tmp"
    mv "$CSR.tmp" "$CSR"
    echo "CSR for CN=$id written to $CSR" >&2
    echo "public key SHA-256: $(pub_fp "$key")" >&2
    echo "Have the CA sign it as a TLS client certificate (EKU clientAuth), then run: $0 install CERT" >&2
    cat "$CSR"
}

cmd_install() {
    local cert=${1:-} ca="" id subject_cn fp key=""
    [[ -n $cert && -f $cert ]] || die "usage: $0 install CERT [--ca CA_BUNDLE]"
    if [[ ${2:-} == --ca ]]; then ca=${3:-}; [[ -f $ca ]] || die "CA bundle not found"; fi
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 || die "$cert is not a PEM certificate"
    fp=$(cert_pub_fp "$cert")
    if [[ -e $NEXT && $(pub_fp "$NEXT") == "$fp" ]]; then key=$NEXT
    elif [[ -e $KEY && $(pub_fp "$KEY") == "$fp" ]]; then key=$KEY
    else die "certificate does not match the station key (fingerprint $fp)"; fi
    id=$(station_id) || die "configuration invalid"
    subject_cn=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 | sed -n 's/^subject=.*CN=\([^,]*\).*$/\1/p')
    [[ $subject_cn == "$id" ]] || die "certificate CN '$subject_cn' is not the station id '$id'"
    openssl x509 -in "$cert" -noout -checkend 0 >/dev/null || die "certificate has expired"
    openssl x509 -in "$cert" -noout -ext extendedKeyUsage 2>/dev/null | grep -q "TLS Web Client Authentication" \
        || die "certificate lacks extendedKeyUsage clientAuth"
    if [[ -n $ca ]]; then
        openssl verify -CAfile "$ca" -purpose sslclient "$cert" >/dev/null || die "certificate does not verify against $ca"
    else
        echo "warning: chain not verified (no --ca given)" >&2
    fi
    install -m 0644 -o root -g root "$cert" "$CRT.tmp"
    mv "$CRT.tmp" "$CRT"
    if [[ $key == "$NEXT" ]]; then
        mv "$NEXT" "$KEY"
        echo "rotated: new key active" >&2
    fi
    logger -t usb-scan-station-cert -p auth.notice "station certificate installed (key SHA-256 $fp)" 2>/dev/null || true
    cat >&2 <<EOF
installed $CRT ($(openssl x509 -in "$CRT" -noout -enddate))
Configuration (scan_station.yaml), if not set yet:
  events.forwarding.client_cert_file: $CRT
  events.forwarding.client_key_ref: file:$KEY
then: systemctl restart usb-scan-events
EOF
}

cmd_status() {
    [[ -e $KEY ]] && echo "key:  $KEY (SHA-256 $(pub_fp "$KEY"))" || echo "key:  none"
    [[ -e $NEXT ]] && echo "next: $NEXT (SHA-256 $(pub_fp "$NEXT"), awaiting certificate)"
    if [[ -e $CRT ]]; then
        openssl x509 -in "$CRT" -noout -subject -issuer -enddate
        if [[ -e $KEY && $(pub_fp "$KEY") == "$(cert_pub_fp "$CRT")" ]]; then echo "certificate matches key"
        else echo "WARNING: certificate does not match the active key"; fi
        openssl x509 -in "$CRT" -noout -checkend $((30 * 86400)) >/dev/null || echo "WARNING: expires within 30 days"
    else
        echo "certificate: none"
    fi
}

case ${1:-} in
    csr) shift; cmd_csr "$@" ;;
    install) shift; cmd_install "$@" ;;
    status) cmd_status ;;
    *) die "usage: $0 csr [--rotate] | install CERT [--ca CA_BUNDLE] | status" ;;
esac
