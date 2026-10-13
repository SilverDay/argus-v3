import hashlib
import json
import os
import time
import uuid

import pytest

from src.orchestrator.quarantine import Evidence, Quarantine, QuarantineUnavailable, verify_store
from src.shared.config import load_config_from_dict

SCAN = str(uuid.uuid4())
MALWARE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$ fake sample " * 10


def make_store(tmp_path, options="rw,nosuid,nodev,noexec,relatime", dm_uuid="CRYPT-LUKS2-0123abcd-qstore",
               mounted=True):
    store = tmp_path / "quarantine"
    store.mkdir(mode=0o700, exist_ok=True)
    os.chmod(store, 0o700)
    lines = ["22 1 0:21 / / rw,relatime - ext4 /dev/root rw"]
    if mounted:
        escaped = str(store).replace(" ", "\\040")
        lines.append(f"99 22 253:3 / {escaped} {options} - ext4 /dev/mapper/qstore rw")
    mi = tmp_path / "mountinfo"
    mi.write_text("\n".join(lines) + "\n")
    dm = tmp_path / "sys" / "dev" / "block" / "253:3" / "dm"
    dm.mkdir(parents=True, exist_ok=True)
    (dm / "uuid").write_text(dm_uuid + "\n")
    return store, str(mi), str(tmp_path / "sys")


def quarantine(tmp_path, **cfg):
    store, mi, sysfs = make_store(tmp_path)
    qcfg = load_config_from_dict({"quarantine": {"quarantine_on_threat": True, "path": str(store), **cfg}}).quarantine
    return Quarantine(qcfg, "station-001", mountinfo_path=mi, sysfs_root=sysfs), store


def evidence(tmp_path, data=MALWARE, name="evil payload.exe", sha=None):
    src = tmp_path / "usb" / name
    src.parent.mkdir(exist_ok=True)
    src.write_bytes(data)
    return Evidence(sha or hashlib.sha256(data).hexdigest(), f"part1/{name}", "clamav", "Win.Test.Evil",
                    lambda: os.open(src, os.O_RDONLY), {"vendor_id": "0781", "serial": "S123"})


# --- store verification --------------------------------------------------------

def test_verified_store(tmp_path):
    store, mi, sysfs = make_store(tmp_path)
    verify_store(str(store), mountinfo_path=mi, sysfs_root=sysfs)


@pytest.mark.parametrize("kw,reason", [
    ({"mounted": False}, "not_a_mount_point"),
    ({"options": "rw,nosuid,nodev,relatime"}, "mount_options:noexec"),
    ({"options": "ro,nosuid,nodev,noexec"}, "mount_options:rw"),
    ({"dm_uuid": "CRYPT-PLAIN-qstore"}, "not_luks2"),
    ({"dm_uuid": "LVM-abc"}, "not_luks2"),
])
def test_store_rejected(tmp_path, kw, reason):
    store, mi, sysfs = make_store(tmp_path, **kw)
    with pytest.raises(QuarantineUnavailable) as exc:
        verify_store(str(store), mountinfo_path=mi, sysfs_root=sysfs)
    assert exc.value.reason == reason


def test_store_requires_dm_device(tmp_path):
    store, mi, _ = make_store(tmp_path)
    with pytest.raises(QuarantineUnavailable, match="not_dm_crypt"):
        verify_store(str(store), mountinfo_path=mi, sysfs_root=str(tmp_path / "nosys"))


def test_store_permissions_and_symlink(tmp_path):
    store, mi, sysfs = make_store(tmp_path)
    os.chmod(store, 0o750)
    with pytest.raises(QuarantineUnavailable, match="path_permissions"):
        verify_store(str(store), mountinfo_path=mi, sysfs_root=sysfs)
    os.chmod(store, 0o700)
    link = tmp_path / "qlink"
    link.symlink_to(store)
    with pytest.raises(QuarantineUnavailable, match="path_not_plain_directory"):
        verify_store(str(link), mountinfo_path=mi, sysfs_root=sysfs)
    with pytest.raises(QuarantineUnavailable, match="path_missing"):
        verify_store(str(tmp_path / "missing"), mountinfo_path=mi, sysfs_root=sysfs)


def test_topmost_mount_wins(tmp_path):
    store, mi, sysfs = make_store(tmp_path)
    with open(mi, "a") as fh:      # something mounted over the encrypted store later
        fh.write(f"120 99 0:50 / {store} rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
    with pytest.raises(QuarantineUnavailable, match="not_dm_crypt"):
        verify_store(str(store), mountinfo_path=mi, sysfs_root=sysfs)


# --- copy -------------------------------------------------------------------------

def test_store_copies_with_opaque_names_and_sidecar(tmp_path):
    q, store = quarantine(tmp_path)
    ev = evidence(tmp_path)
    (out,) = q.store(SCAN, "THREAT", [ev])
    assert out.status == "stored" and len(out.item_id) == 32
    scan_dir = store / SCAN
    names = sorted(os.listdir(scan_dir))
    assert names == [f"{out.item_id}.bin", f"{out.item_id}.json"]
    assert "evil" not in "".join(names)                       # original name only in the sidecar
    assert (scan_dir / f"{out.item_id}.bin").read_bytes() == MALWARE
    for name in names:
        assert (scan_dir / name).stat().st_mode & 0o777 == 0o600
    assert scan_dir.stat().st_mode & 0o777 == 0o700
    meta = json.loads((scan_dir / f"{out.item_id}.json").read_text())
    assert meta["original_path"] == "part1/evil payload.exe" and meta["sha256"] == ev.sha256
    assert meta["verdict"] == "THREAT" and meta["scan_id"] == SCAN and meta["device"]["serial"] == "S123"


def test_hash_mismatch_discarded(tmp_path):
    q, store = quarantine(tmp_path)
    (out,) = q.store(SCAN, "THREAT", [evidence(tmp_path, sha="0" * 64)])
    assert out.status == "hash_mismatch" and os.listdir(store / SCAN) == []


def test_duplicates_limits_and_space(tmp_path):
    q, store = quarantine(tmp_path, max_files_per_scan=1)
    a = evidence(tmp_path, b"A" * 100, "a")
    b = evidence(tmp_path, b"B" * 100, "b")
    outs = q.store(SCAN, "THREAT", [a, a, b])
    assert [o.status for o in outs] == ["stored", "duplicate", "limit_reached"]

    q2, _ = quarantine(tmp_path, max_file_size_mb=1)
    big = evidence(tmp_path, b"Z" * (1024 * 1024 + 1), "big")
    assert q2.store(str(uuid.uuid4()), "THREAT", [big])[0].status == "too_large"

    q3, _ = quarantine(tmp_path, min_free_mb=1_000_000)
    assert q3.store(str(uuid.uuid4()), "THREAT", [b])[0].status == "insufficient_space"

    gone = Evidence("1" * 64, "part1/x", "clamav", "sig", lambda: None)
    assert q.store(str(uuid.uuid4()), "THREAT", [gone])[0].status == "unreadable"


def test_store_refuses_unverified_or_bad_scan_id(tmp_path):
    q, store = quarantine(tmp_path)
    with pytest.raises(ValueError):
        q.store("../escape", "THREAT", [])
    os.chmod(store, 0o755)
    with pytest.raises(QuarantineUnavailable):
        q.store(SCAN, "THREAT", [evidence(tmp_path)])


def test_retention_cleanup(tmp_path):
    q, store = quarantine(tmp_path, retention_days=30)
    old, new = str(uuid.uuid4()), str(uuid.uuid4())
    q.store(old, "THREAT", [evidence(tmp_path)])
    q.store(new, "THREAT", [evidence(tmp_path)])
    (store / "not-a-scan").mkdir()
    past = time.time() - 31 * 86_400
    for path in (store / old, store / "not-a-scan"):
        os.utime(path, (past, past))
    assert q.cleanup() == 1
    assert sorted(os.listdir(store)) == sorted([new, "not-a-scan"])   # unknown entries are never touched
