import os
import shutil
import subprocess

import pytest

from src.host.render import SYSCTL, egress_policy, main, render_nftables, render_sshd
from src.shared.config import load_config_from_dict

ALL_USERS = {"root", "_apt", "clamav", "systemd-timesync", "systemd-resolve", "usbscan", "usbscan-events",
             "usbscan-web", "usbscan-update"}


def cfg(**sections):
    return load_config_from_dict(sections)


def rendered(c, users=ALL_USERS):
    return render_nftables(c, user_exists=lambda u: u in users)


def lines_for(text, user):
    return [line.strip() for line in text.splitlines() if f'meta skuid "{user}"' in line]


def test_default_deny_everywhere_and_no_inbound_services():
    text = rendered(cfg())
    assert text.count("policy drop;") == 3
    assert "dport 22" not in text and "dport 443 ct state new accept" not in text.split("chain output")[0]
    # scanner-side services get no outbound rule unless configured
    for user in ("usbscan", "usbscan-events", "usbscan-web", "usbscan-update"):
        assert lines_for(text, user) == []
    assert lines_for(text, "clamav") == ['meta skuid "clamav" tcp dport { 53, 80, 443 } ct state new accept',
                                          'meta skuid "clamav" udp dport 53 ct state new accept']


def test_ports_follow_configuration():
    c = cfg(virustotal={"enabled": True, "api_key_ref": "credential:vt"},
            events={"forwarding": {"enabled": True, "host": "siem.example.org", "port": 6515}},
            alerts={"webhook": {"enabled": True, "url": "https://hooks.example.org:8443/x"},
                    "email": {"enabled": True, "smtp_host": "smtp.example.org", "smtp_port": 465, "security": "tls",
                              "from_addr": "a@example.org", "to_addrs": ["b@example.org"]}},
            yara={"update_url": "https://rules.example.org/b.tar.gz"},
            admin_web={"enabled": True, "public_url": "https://st.example.org"},
            auth={"web": {"oidc": {"issuer": "https://idp.example.org:9443/realms/x", "client_id": "c",
                                   "roles": {"admin": ["a"]}}}},
            host={"management_networks": ["10.0.0.0/8"]})
    text = rendered(c)
    assert lines_for(text, "usbscan")[0].startswith('meta skuid "usbscan" tcp dport { 53, 443 }')
    assert "tcp dport { 53, 465, 6515, 8443 }" in lines_for(text, "usbscan-events")[0]
    assert "tcp dport { 53, 9443 }" in lines_for(text, "usbscan-web")[0]
    assert "tcp dport { 53, 443 }" in lines_for(text, "usbscan-update")[0]
    assert "ip saddr { 10.0.0.0/8 } tcp dport 443 ct state new accept" in text


def test_ssh_only_from_management_networks():
    c = cfg(host={"ssh_enabled": True, "ssh_allow_users": ["alice", "bob"],
                  "management_networks": ["192.0.2.0/24", "2001:db8::/48"]})
    text = rendered(c)
    assert "ip saddr { 192.0.2.0/24 } tcp dport 22 ct state new accept" in text
    assert "ip6 saddr { 2001:db8::/48 } tcp dport 22 ct state new accept" in text
    sshd = render_sshd(c)
    assert "AllowUsers alice bob" in sshd and "PasswordAuthentication no" in sshd and "PermitRootLogin no" in sshd


def test_missing_accounts_are_skipped_not_invented():
    text = rendered(cfg(virustotal={"enabled": True, "api_key_ref": "credential:vt"}), users={"root"})
    assert lines_for(text, "usbscan") == [] and "no rule): " in text and "usbscan" in text.split("no rule): ")[1]


def test_broker_and_sandboxed_services_never_get_egress():
    names = {e.user for e in egress_policy(cfg(virustotal={"enabled": True, "api_key_ref": "credential:vt"}))}
    assert not names & {"yarascan", "usbscan-gui", "usbscan-led"}


def test_sysctl_has_required_keys():
    for key in ("net.ipv4.ip_forward = 0", "kernel.kptr_restrict = 2", "fs.suid_dumpable = 0",
                "kernel.unprivileged_bpf_disabled = 1", "kernel.dmesg_restrict = 1"):
        assert key in SYSCTL


def test_cli_writes_files(tmp_path):
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text("station: {station_id: st-1}\n")
    assert main(["--config", str(cfgfile), "--out", str(tmp_path / "out")]) == 0
    assert sorted(os.listdir(tmp_path / "out")) == ["99-usb-scan.conf", "nftables.conf", "sshd-usb-scan.conf"]


@pytest.mark.skipif(shutil.which("nft") is None, reason="nft not installed")
def test_ruleset_passes_nft_check(tmp_path):
    c = cfg(host={"ssh_enabled": True, "ssh_allow_users": ["alice"],
                  "management_networks": ["10.10.0.0/16", "fd00:10::/64"]},
            virustotal={"enabled": True, "api_key_ref": "credential:vt"})
    path = tmp_path / "r.nft"
    path.write_text(rendered(c, users={"root"}))           # only accounts that exist here
    res = subprocess.run(["nft", "-c", "-f", str(path)], capture_output=True, text=True)
    if res.returncode != 0 and "Operation not permitted" in res.stderr:
        pytest.skip("nft check needs CAP_NET_ADMIN")
    assert res.returncode == 0, res.stderr


def test_outputs_are_ascii():
    c = cfg(host={"ssh_enabled": True, "ssh_allow_users": ["alice"], "management_networks": ["10.0.0.0/8"]})
    for text in (rendered(c), SYSCTL, render_sshd(c)):
        text.encode("ascii")
