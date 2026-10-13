"""End-to-end scan pipeline against a real clamd and a real read-only loop mount.

* clamd 1.x with a private signature database (the official databases are not
  downloadable in CI): EICAR is detected through a test hash signature.
* The volume is mounted by the broker's mount layer (BLKROSET, ro,noexec,...).
* The scan itself runs in a subprocess as ``nobody`` (gid ``nogroup`` = read group),
  mirroring the unprivileged orchestrator; files are passed to clamd via FILDES.

Plan Phase 3 acceptance: EICAR -> THREAT with coverage; clean -> CLEAN with
clamav_complete=True; one unreadable file -> INCOMPLETE.
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

import pytest

from src.broker import mounts, sysfs
from src.broker.sysenv import SysEnv

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NOBODY, NOGROUP = 65534, 65534
# Assembled at runtime so the repository itself never contains the test string.
with open("/proc/filesystems") as _fh:
    KERNEL_FS = {line.split()[-1] for line in _fh if line.strip()}
# Most USB sticks are FAT; use it when the kernel supports it, otherwise ext4 (CI sandbox).
DEFAULT_FS = "vfat" if "vfat" in KERNEL_FS else "ext4"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(t) for t in ("clamd", "losetup", "mkfs.ext4")),
    reason="requires root, clamd, losetup and mkfs.ext4",
)

SCAN_SCRIPT = r"""
import asyncio, json, sys
from src.orchestrator.scan_session import ScanSession
from src.orchestrator.scanner_clamav import ClamdClient
from src.shared.config import load_config_from_dict
from tests.unit.orchestrator.fakes import FakeBroker

mount_path, clamd_sock = sys.argv[1], sys.argv[2]
cfg = load_config_from_dict({"clamav": {"socket_path": clamd_sock}})

async def main():
    async def publish(ev):
        pass
    s = ScanSession(cfg, FakeBroker({"part1": mount_path}), ClamdClient(clamd_sock), publish,
                    scan_id="s", session_id="0f8fad5b-d9cb-469f-a165-70867728950e",
                    sysfs_path="/sys/bus/usb/devices/1-1")
    await s.validate()
    await s.mount_all()
    await s.scan()
    print(json.dumps(s.finalize().to_dict()))

asyncio.run(main())
"""


@pytest.fixture(scope="module")
def clamd():
    from pathlib import Path
    base = Path(tempfile.mkdtemp(prefix="usbscan-clamd-", dir="/tmp"))   # reachable by nobody
    os.chmod(base, 0o755)
    db = base / "db"
    db.mkdir()
    (db / "test.hdb").write_text(f"{hashlib.md5(EICAR).hexdigest()}:{len(EICAR)}:Test.EICAR\n")
    sock = base / "clamd.sock"
    conf = base / "clamd.conf"
    conf.write_text("\n".join([
        f"LocalSocket {sock}", "LocalSocketMode 666", f"DatabaseDirectory {db}", "Foreground yes",
        "User root", "AlertExceedsMax yes", "AlertEncrypted yes", "MaxFiles 50", "MaxRecursion 5",
    ]) + "\n")
    proc = subprocess.Popen(["clamd", "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(150):
        if sock.exists():
            break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.skip("clamd did not start")
    yield str(sock)
    proc.terminate()
    proc.wait(10)
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def volume(tmp_path):
    """Build a vfat or ext4 image from a file spec, mount it read-only, yield the mount path."""
    created = []

    def build(files: dict[str, bytes], modes: dict[str, int] | None = None, fs: str = DEFAULT_FS,
              keep_lost_found: bool = False) -> str:
        src = tmp_path / "content"
        src.mkdir()
        for name, data in files.items():
            p = src / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            p.chmod((modes or {}).get(name, 0o644))
        # Typical removable media: world-readable directories (pytest tmp dirs are 0700).
        for d in [src, *(p for p in src.rglob("*") if p.is_dir())]:
            d.chmod(0o755)
        img = tmp_path / "usb.img"
        subprocess.run(["truncate", "-s", "32M", str(img)], check=True)
        if fs == "vfat":
            subprocess.run(["mkfs.vfat", str(img)], check=True, capture_output=True)
            entries = [str(p) for p in src.iterdir()]
            if entries:
                subprocess.run(["mcopy", "-s", "-i", str(img), *entries, "::/"], check=True)
        else:
            subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(src), str(img)], check=True)
            if not keep_lost_found:
                # lost+found is 0700 root and unlistable by the scanner (see limitation test).
                subprocess.run(["debugfs", "-w", "-R", "rmdir lost+found", str(img)],
                               check=True, capture_output=True)
        dev = subprocess.run(["losetup", "-f", "--show", str(img)], check=True,
                             capture_output=True, text=True).stdout.strip()
        # pytest's tmp root is 0700; mount below a 0755 base like /run/usb-scan/mounts.
        base = tempfile.mkdtemp(prefix="usbscan-it-", dir="/tmp")
        os.chmod(base, 0o755)
        target = os.path.join(base, "mnt")
        env = SysEnv()
        created.append((env, target, dev, base))     # register before mounting: always cleaned up
        st = os.stat(dev)
        mounts.ensure_private_dir(target, NOGROUP)

        async def do_mount():
            await mounts.set_readonly(env, dev)
            await mounts.mount_readonly(env, dev, os.major(st.st_rdev), os.minor(st.st_rdev), fs, target, NOGROUP)

        asyncio.run(do_mount())
        return target

    yield build
    for env, target, dev, base in created:
        asyncio.run(mounts.unmount(env, target))
        subprocess.run(["losetup", "-d", dev], check=False)
        shutil.rmtree(base, ignore_errors=True)


def scan_as_nobody(mount_path: str, clamd_sock: str) -> dict:
    out = subprocess.run([sys.executable, "-c", SCAN_SCRIPT, mount_path, clamd_sock], cwd=ROOT,
                         user=NOBODY, group=NOGROUP, extra_groups=[], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_clean_volume(clamd, volume):
    path = volume({"docs/report.txt": b"quarterly numbers\n", "hello.txt": b"hello\n"})
    r = scan_as_nobody(path, clamd)
    assert r["verdict"] == "CLEAN", json.dumps({k: r[k] for k in ("coverage", "engine_errors", "reason_codes")})
    cov = r["coverage"]
    assert cov["clamav_complete"] is True
    assert (cov["files_discovered"], cov["files_scanned"], cov["partitions_scanned"]) == (2, 2, 1)
    assert cov["bytes_read"] == cov["bytes_enumerated"] == len(b"quarterly numbers\n") + len(b"hello\n")


def test_eicar_is_threat(clamd, volume):
    path = volume({"clean.txt": b"fine\n", "sub/eicar.com": EICAR})
    r = scan_as_nobody(path, clamd)
    assert r["verdict"] == "THREAT", r
    (t,) = r["threats"]
    assert t["engine"] == "clamav" and t["signature_name"] == "Test.EICAR.UNOFFICIAL"
    assert t["file_path"] == "part1/sub/eicar.com" and t["sha256"] == hashlib.sha256(EICAR).hexdigest()
    assert r["coverage"]["files_scanned"] == 2 and r["coverage"]["clamav_complete"] is True


def test_unreadable_file_is_incomplete(clamd, volume):
    path = volume({"ok.txt": b"ok\n", "secret.txt": b"locked\n"}, modes={"secret.txt": 0o000}, fs="ext4")
    r = scan_as_nobody(path, clamd)
    assert r["verdict"] == "INCOMPLETE", r
    assert r["coverage"]["files_scanned"] == 1
    assert r["coverage"]["files_uninspectable"] == 1
    assert r["coverage"]["skip_reasons"] == {"unreadable": 1}
    assert r["coverage"]["clamav_complete"] is False


def test_ext4_lost_and_found_limitation(clamd, volume):
    """Known limitation (pending decision): an unprivileged scanner cannot list ext4's
    0700 root-owned lost+found, so every ext4 volume is INCOMPLETE (fail-closed)."""
    path = volume({"hello.txt": b"hello\n"}, fs="ext4", keep_lost_found=True)
    r = scan_as_nobody(path, clamd)
    assert r["verdict"] == "INCOMPLETE"
    assert r["coverage"]["files_scanned"] == 1 and r["coverage"]["skip_reasons"] == {"unreadable": 1}


def test_encrypted_archive_is_incomplete(clamd, volume, tmp_path):
    enc = tmp_path / "enc.zip"
    subprocess.run(["zip", "-q", "-P", "pw", str(enc), "/etc/hostname"], check=True)
    path = volume({"enc.zip": enc.read_bytes()})
    r = scan_as_nobody(path, clamd)
    assert r["verdict"] == "INCOMPLETE" and r["coverage"]["skip_reasons"] == {"encrypted": 1}, r


def test_archive_limit_is_incomplete(clamd, volume, tmp_path):
    many = tmp_path / "many.zip"
    with zipfile.ZipFile(many, "w") as z:
        for i in range(100):
            z.writestr(f"f{i}.txt", f"{i}")
    path = volume({"many.zip": many.read_bytes()})
    r = scan_as_nobody(path, clamd)
    assert r["verdict"] == "INCOMPLETE" and r["coverage"]["skip_reasons"] == {"scan_limit": 1}, r
