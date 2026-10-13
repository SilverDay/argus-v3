import json
import os
import subprocess
import sys

import pytest

from src.broker import mounts, probe, sysfs
from src.broker.audit import AuditLog, verify_chain
from src.broker.sysenv import SysEnv
from src.shared.broker_protocol import ProtocolError

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# --- probe -------------------------------------------------------------------

def test_parse_export_sanitises_and_unescapes():
    fields = probe.parse_export("TYPE=vfat\nLABEL=MY\\ STICK\x07\nUUID=AB-12\nbad line\n")
    assert fields == {"TYPE": "vfat", "LABEL": "MY STICK?", "UUID": "AB-12"}


@pytest.mark.parametrize("fields,status", [
    ({"TYPE": "exfat"}, probe.VolumeStatus.SUPPORTED),
    ({"TYPE": "BitLocker"}, probe.VolumeStatus.ENCRYPTED),
    ({"TYPE": "udf"}, probe.VolumeStatus.UNSUPPORTED),
    ({"PTTYPE": "dos"}, probe.VolumeStatus.UNRECOGNIZED),
])
def test_classify(fields, status):
    assert probe.classify(fields).status is status


# --- mounts ------------------------------------------------------------------

def test_parse_mountinfo_with_escapes():
    text = "36 35 8:1 / /run/usb-scan/mounts/s/part\\0401 ro,nosuid shared:1 - vfat /dev/sda1 ro,fmask=0137\n"
    (m,) = mounts.parse_mountinfo(text)
    assert (m.major, m.minor, m.mountpoint, m.fs_type) == (8, 1, "/run/usb-scan/mounts/s/part 1", "vfat")
    assert "ro" in m.super_options


@pytest.mark.parametrize("fs", ["ext2", "ext3", "ext4", "vfat", "exfat", "ntfs3", "ntfs-3g", "iso9660"])
def test_mount_options_always_hardened(fs):
    opts = set(mounts.mount_options(fs, 1234).split(","))
    assert {"ro", "noexec", "nosuid", "nodev", "nosymfollow"} <= opts
    assert not any(o in opts for o in ("rw", "exec", "suid", "dev"))


def test_mount_options_reject_other_types():
    with pytest.raises(ProtocolError):
        mounts.mount_options("hfsplus", 1)


def test_ensure_private_dir_refuses_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "mounts"
    link.symlink_to(target)
    with pytest.raises(ProtocolError):
        mounts.ensure_private_dir(str(link), os.getgid())


@pytest.mark.parametrize("value,ok", [
    ("0f8fad5b-d9cb-469f-a165-70867728950e", True), ("0F8FAD5B-D9CB-469F-A165-70867728950E", False),
    ("../x", False), ("", False), (None, False),
])
def test_session_id_validation(value, ok):
    assert mounts.valid_session_id(value) is ok


# --- sysfs device nodes -----------------------------------------------------

def test_verify_device_node_rejects_non_block(tmp_path):
    os.makedirs(tmp_path / "dev")
    (tmp_path / "dev" / "sda1").write_text("")
    env = SysEnv(dev_root=str(tmp_path / "dev"))
    with pytest.raises(ProtocolError):
        sysfs.verify_device_node(env, sysfs.BlockInfo("sda1", 8, 1, 0, 1, "sda"))


def test_verify_device_node_rejects_wrong_numbers():
    loops = [n for n in os.listdir("/dev") if n.startswith("loop") and n[4:].isdigit()]
    if not loops:
        pytest.skip("no block device node available")
    st = os.stat(f"/dev/{loops[0]}")
    env = SysEnv()
    good = sysfs.BlockInfo(loops[0], os.major(st.st_rdev), os.minor(st.st_rdev), 0, 0, loops[0])
    assert sysfs.verify_device_node(env, good) == f"/dev/{loops[0]}"
    bad = sysfs.BlockInfo(loops[0], os.major(st.st_rdev), os.minor(st.st_rdev) + 99, 0, 0, loops[0])
    with pytest.raises(ProtocolError):
        sysfs.verify_device_node(env, bad)


# --- audit -------------------------------------------------------------------

def test_audit_chain_detects_tampering_and_continues_after_restart(tmp_path):
    path = str(tmp_path / "audit.log")
    log = AuditLog(path)
    log.write("a", x=1)
    log.write("b", x=2)
    log.close()
    log = AuditLog(path)  # restart continues the chain
    log.write("c", x=3)
    log.close()
    with open(path) as fh:
        lines = fh.read().splitlines()
    assert verify_chain(lines) is None and [json.loads(l)["seq"] for l in lines] == [1, 2, 3]
    tampered = list(lines)
    rec = json.loads(tampered[1])
    rec["x"] = 99
    tampered[1] = json.dumps(rec)
    assert verify_chain(tampered) == 1
    assert verify_chain([lines[0], lines[2]]) == 1  # deleted record
    assert os.stat(path).st_mode & 0o777 == 0o640


def test_audit_restart_marker_after_corrupt_tail(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text('{"seq": 1, "hash": "forged"}\n')
    log = AuditLog(str(path))
    log.close()
    assert json.loads(path.read_text().splitlines()[-1])["action"] == "chain_restart"


# --- capabilities ------------------------------------------------------------

@pytest.mark.skipif(os.geteuid() != 0, reason="needs root with CAP_SETPCAP")
def test_drop_capabilities_in_child_process():
    code = (
        "import json, subprocess;"
        "from src.broker import caps;"
        "caps.drop_capabilities();"
        "child = subprocess.run(['grep', '-E', '^Cap(Eff|Bnd)', '/proc/self/status'],"
        " capture_output=True, text=True).stdout;"
        "print(json.dumps({'eff': caps.effective_caps(), 'child': child}))"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    data = json.loads(out.stdout)
    expected = (1 << 21) | (1 << 0)
    assert data["eff"] == expected
    child = dict(line.split(":\t") for line in data["child"].strip().splitlines())
    assert int(child["CapBnd"], 16) == expected
    assert int(child["CapEff"], 16) & ~expected == 0
