"""Render host hardening files from scan_station.yaml (spec §8.1; owner decisions Phase 11).

    python -m src.host.render --config /etc/usb-scan/scan_station.yaml --out DIR

Writes ``nftables.conf``, ``99-usb-scan.conf`` (sysctl) and ``sshd-usb-scan.conf``. scripts/harden.sh
validates (``nft -c``) and installs them.

Firewall model:
* inbound default deny: loopback, established/related, DHCP replies, essential ICMPv6 (neighbour
  discovery / router advertisements), SSH and the admin reverse proxy from
  ``host.management_networks`` only (when enabled);
* outbound default deny (owner decision): new connections only for the service accounts that
  need them, matched by socket owner uid (``meta skuid``), each limited to the destination ports
  derived from its configuration, plus DNS for those accounts;
* forwarding: drop. Rate-limited log lines for drops help tuning on the device.
The broker, YARA worker, GUI and LED have no network at all (also IPAddressDeny / address
family restrictions in their units).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import pwd
import sys
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from src.shared.config import Config, ConfigError, ForwardTransport, load_config

DNS = 53


@dataclass
class Egress:
    user: str
    purpose: str
    tcp: set[int] = field(default_factory=set)
    udp: set[int] = field(default_factory=set)
    dns: bool = True


def _url_port(url: str) -> int:
    parts = urllib.parse.urlsplit(url)
    return parts.port or (443 if parts.scheme == "https" else 80)


def egress_policy(cfg: Config) -> list[Egress]:
    """Which local account may open which outbound ports, derived from the configuration."""
    rules = [
        Egress("root", "DHCP, NTP (when run as root)", udp={67, 547, 123}),
        Egress("systemd-timesync", "NTP (systemd-timesyncd)", udp={123}),
        Egress("systemd-resolve", "DNS resolver (systemd-resolved)", tcp={DNS}, udp={DNS}, dns=False),
        Egress("_apt", "Debian/Raspberry Pi package mirrors (maintenance window)", tcp={80, 443}),
        Egress("clamav", "freshclam signature updates", tcp={80, 443}),
    ]
    if cfg.virustotal.enabled:
        rules.append(Egress("usbscan", "VirusTotal hash lookups", tcp={443}))
    ev = Egress("usbscan-events", "SIEM forwarding and alerts")
    f = cfg.events.forwarding
    if f.enabled:
        ev.tcp.add(f.port if f.transport is ForwardTransport.SYSLOG else _url_port(f.url))
    a = cfg.alerts
    if a.webhook.enabled:
        ev.tcp.add(_url_port(a.webhook.url))
    if a.email.enabled:
        ev.tcp.add(a.email.smtp_port)
    if a.syslog.enabled:
        ev.tcp.add(a.syslog.port)
    if ev.tcp:
        rules.append(ev)
    if cfg.admin_web.enabled and cfg.auth.web.oidc_enabled and cfg.auth.web.oidc.issuer:
        rules.append(Egress("usbscan-web", "OIDC provider", tcp={_url_port(cfg.auth.web.oidc.issuer)}))
    if cfg.yara.update_url:
        rules.append(Egress("usbscan-update", "YARA ruleset pull", tcp={_url_port(cfg.yara.update_url)}))
    return rules


def _ports(ports: Iterable[int]) -> str:
    p = sorted(set(ports))
    return str(p[0]) if len(p) == 1 else "{ " + ", ".join(map(str, p)) + " }"


def _networks(cfg: Config) -> tuple[list[str], list[str]]:
    nets = [ipaddress.ip_network(n) for n in cfg.host.management_networks]
    return ([str(n) for n in nets if n.version == 4], [str(n) for n in nets if n.version == 6])


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def render_nftables(cfg: Config, user_exists: Callable[[str], bool] = _user_exists) -> str:
    v4, v6 = _networks(cfg)
    log = cfg.host.log_dropped_packets
    inbound: list[str] = []

    def mgmt(port: int, what: str) -> None:
        inbound.append(f"# {what}: management networks only")
        if v4:
            inbound.append(f"ip saddr {{ {', '.join(v4)} }} tcp dport {port} ct state new accept")
        if v6:
            inbound.append(f"ip6 saddr {{ {', '.join(v6)} }} tcp dport {port} ct state new accept")

    if cfg.host.ssh_enabled:
        mgmt(22, "SSH")
    if cfg.admin_web.enabled:
        mgmt(cfg.host.admin_proxy_port, "admin web reverse proxy (TLS)")

    outbound: list[str] = []
    skipped: list[str] = []
    for rule in egress_policy(cfg):
        if not user_exists(rule.user):
            skipped.append(rule.user)
            continue
        outbound.append(f"# {rule.user}: {rule.purpose}")
        tcp, udp = set(rule.tcp), set(rule.udp)
        if rule.dns:
            tcp.add(DNS)
            udp.add(DNS)
        if tcp:
            outbound.append(f'meta skuid "{rule.user}" tcp dport {_ports(tcp)} ct state new accept')
        if udp:
            outbound.append(f'meta skuid "{rule.user}" udp dport {_ports(udp)} ct state new accept')
    if skipped:
        outbound.append("# accounts not present on this system (no rule): " + ", ".join(skipped))

    def drop(prefix: str) -> str:
        return f'limit rate 10/minute log prefix "{prefix} " level info' if log else "# drop logging disabled"

    def block(lines: list[str]) -> str:
        return "\n".join("        " + line for line in lines)

    return f"""#!/usr/sbin/nft -f
# Generated by src/host/render.py from {cfg.station.station_id}'s scan_station.yaml - do not edit;
# change the configuration and re-run scripts/harden.sh.
flush ruleset

table inet usb_scan {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        # DHCP / DHCPv6 replies
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept
        # IPv6 neighbour discovery / router advertisements: on-link only (RFC 4861 hop limit 255)
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} ip6 hoplimit 255 accept
        icmpv6 type mld-listener-query ip6 saddr fe80::/10 accept
        icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} accept
        icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
{block(inbound)}
        {drop("usbscan-drop-in")}
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}

    chain output {{
        type filter hook output priority filter; policy drop;
        oif "lo" accept
        ct state established,related accept
        ct state invalid drop
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld2-listener-report }} accept
{block(outbound)}
        {drop("usbscan-drop-out")}
    }}
}}
"""


SYSCTL = """# Generated by src/host/render.py (spec section 8.1 host hardening)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
"""


def render_sshd(cfg: Config) -> str:
    users = " ".join(cfg.host.ssh_allow_users) or "nobody-allowed"
    return f"""# Generated by src/host/render.py (spec section 8.1). Installed as /etc/ssh/sshd_config.d/usb-scan.conf;
# Debian's sshd_config includes sshd_config.d first, and for sshd the first value wins.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers {users}
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-host-render")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    parser.add_argument("--out", required=True)
    opts = parser.parse_args(argv)
    try:
        cfg = load_config(opts.config)
    except ConfigError as exc:
        print(f"usb-scan-host-render: {exc}", file=sys.stderr)
        return 2
    os.makedirs(opts.out, exist_ok=True)
    files = {"nftables.conf": render_nftables(cfg), "99-usb-scan.conf": SYSCTL, "sshd-usb-scan.conf": render_sshd(cfg)}
    for name, text in files.items():
        with open(os.path.join(opts.out, name), "w", encoding="ascii") as fh:
            fh.write(text)
    print("\n".join(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
