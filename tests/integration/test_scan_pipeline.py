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
from src.orchestrator.broker_client import BrokerClient
from src.orchestrator.scanner_yara_client import YaraClient
from tests.unit.orchestrator.fakes import FakeBroker

mount_path, clamd_sock, broker_sock, key_hex, yara_sock = sys.argv[1:6]
raw = {"clamav": {"socket_path": clamd_sock}}
if yara_sock:
    raw["yara"] = {"enabled": True, "role": "mandatory", "socket_path": yara_sock}
cfg = load_config_from_dict(raw)


class HybridBroker(FakeBroker):
    # enumerate/mount are simulated (no USB sysfs in CI); confined opens go to the real broker.
    def __init__(self):
        super().__init__({"part1": mount_path})
        self.real = BrokerClient(broker_sock, bytes.fromhex(key_hex))

    def open_path(self, session_id, partition_id, rel):
        return self.real.open_path(session_id, partition_id, rel)

async def main():
    async def publish(ev):
        pass
    s = ScanSession(cfg, HybridBroker(), ClamdClient(clamd_sock), publish,
                    scan_id="s", session_id="0f8fad5b-d9cb-469f-a165-70867728950e",
                    sysfs_path="/sys/bus/usb/devices/1-1",
                    yara=YaraClient(yara_sock) if yara_sock else None)
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


class BrokerHarness:
    """Real BrokerServer in a background thread, serving one injected session to uid nobody."""

    SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"

    def __init__(self):
        self.key = os.urandom(32)
        self.socket_path = None
        self._thread = None
        self._loop = None

    def start(self, target, major, minor, base):
        import threading
        from src.broker.audit import AuditLog
        from src.broker.broker_server import BrokerServer
        from src.broker.context import BrokerContext
        from src.broker.session import Session
        from src.broker.sysfs import UsbDevice

        self.socket_path = os.path.join(base, "broker.sock")
        self.audit = AuditLog(os.path.join(base, "audit.log"))
        ctx = BrokerContext(env=SysEnv(), audit=self.audit, mounts_dir=base, read_gid=NOGROUP)
        session = Session(self.SESSION, UsbDevice("1-1", "/x", 1, 1, "", "", ""))
        session.root_fds["part1"] = mounts.open_mount_root(target, major, minor)
        ctx.sessions.open(session)
        self.session = session
        self._loop = asyncio.new_event_loop()
        server = BrokerServer(ctx, socket_path=self.socket_path, hmac_key=self.key,
                              client_uid=NOBODY, socket_gid=NOGROUP)
        self._loop.run_until_complete(server.start())
        self.server = server
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.server.close(), self._loop).result(10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self._loop.close()
        self.session.close_root_fds()   # must precede unmount
        self.audit.close()
        self._loop = None


@pytest.fixture
def broker_harness():
    h = BrokerHarness()
    yield h
    h.stop()


@pytest.fixture
def volume(tmp_path, broker_harness):
    """Build a vfat or ext4 image from a file spec, mount it read-only, yield the mount path."""
    created = []

    def build(files: dict[str, bytes], modes: dict[str, int] | None = None, fs: str = DEFAULT_FS,
              dir_modes: dict[str, int] | None = None) -> str:
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
        for name, mode in (dir_modes or {}).items():
            (src / name).chmod(mode)
        img = tmp_path / "usb.img"
        subprocess.run(["truncate", "-s", "32M", str(img)], check=True)
        if fs == "vfat":
            subprocess.run(["mkfs.vfat", str(img)], check=True, capture_output=True)
            entries = [str(p) for p in src.iterdir()]
            if entries:
                subprocess.run(["mcopy", "-s", "-i", str(img), *entries, "::/"], check=True)
        else:
            subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(src), str(img)], check=True)
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
        broker_harness.start(target, os.major(st.st_rdev), os.minor(st.st_rdev), base)
        return target

    yield build
    broker_harness.stop()
    for env, target, dev, base in created:
        asyncio.run(mounts.unmount(env, target))
        subprocess.run(["losetup", "-d", dev], check=False)
        shutil.rmtree(base, ignore_errors=True)


def scan_as_nobody(mount_path: str, clamd_sock: str, broker: "BrokerHarness", broker_up: bool = True,
                   yara_sock: str = "") -> dict:
    sock = broker.socket_path if broker_up else "/nonexistent/broker.sock"
    out = subprocess.run([sys.executable, "-c", SCAN_SCRIPT, mount_path, clamd_sock, sock, broker.key.hex(),
                          yara_sock],
                         cwd=ROOT,
                         user=NOBODY, group=NOGROUP, extra_groups=[], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_clean_volume(clamd, volume, broker_harness):
    path = volume({"docs/report.txt": b"quarterly numbers\n", "hello.txt": b"hello\n"})
    r = scan_as_nobody(path, clamd, broker_harness)
    assert r["verdict"] == "CLEAN", json.dumps({k: r[k] for k in ("coverage", "engine_errors", "reason_codes")})
    cov = r["coverage"]
    assert cov["clamav_complete"] is True
    assert (cov["files_discovered"], cov["files_scanned"], cov["partitions_scanned"]) == (2, 2, 1)
    assert cov["bytes_read"] == cov["bytes_enumerated"] == len(b"quarterly numbers\n") + len(b"hello\n")


def test_eicar_is_threat(clamd, volume, broker_harness):
    path = volume({"clean.txt": b"fine\n", "sub/eicar.com": EICAR})
    r = scan_as_nobody(path, clamd, broker_harness)
    assert r["verdict"] == "THREAT", r
    (t,) = r["threats"]
    assert t["engine"] == "clamav" and t["signature_name"] == "Test.EICAR.UNOFFICIAL"
    assert t["file_path"] == "part1/sub/eicar.com" and t["sha256"] == hashlib.sha256(EICAR).hexdigest()
    assert r["coverage"]["files_scanned"] == 2 and r["coverage"]["clamav_complete"] is True


def test_ext4_restricted_content_scanned_via_broker(clamd, volume, broker_harness):
    """Content hidden by on-media permissions (0700 root dir, 0600 files, lost+found) is
    opened by the broker's confined openat2 and still scanned by the unprivileged scanner."""
    path = volume({"top.txt": b"top\n", "private/eicar.com": EICAR, "private/notes.txt": b"n\n"},
                  modes={"private/eicar.com": 0o600, "private/notes.txt": 0o000},
                  dir_modes={"private": 0o700}, fs="ext4")
    r = scan_as_nobody(path, clamd, broker_harness)
    assert r["verdict"] == "THREAT", r
    cov = r["coverage"]
    assert cov["files_scanned"] == 3 and cov["files_uninspectable"] == 0 and cov["skip_reasons"] == {}
    (t,) = r["threats"]
    assert t["file_path"] == "part1/private/eicar.com" and t["sha256"] == hashlib.sha256(EICAR).hexdigest()
    assert any(n.startswith("part1:privileged_opens=") for n in r["reason_codes"])


def test_ext4_with_lost_and_found_can_be_clean(clamd, volume, broker_harness):
    path = volume({"hello.txt": b"hello\n"}, fs="ext4")
    r = scan_as_nobody(path, clamd, broker_harness)
    assert r["verdict"] == "CLEAN", r
    assert r["coverage"]["clamav_complete"] is True


def test_unreadable_when_broker_unavailable_is_incomplete(clamd, volume, broker_harness):
    """Fail-closed: if hidden content cannot be opened at all, the verdict is INCOMPLETE."""
    path = volume({"ok.txt": b"ok\n", "secret.txt": b"locked\n"}, modes={"secret.txt": 0o000}, fs="ext4")
    r = scan_as_nobody(path, clamd, broker_harness, broker_up=False)
    assert r["verdict"] == "INCOMPLETE", r
    assert r["coverage"]["files_scanned"] == 1
    # secret.txt plus ext4's lost+found (0700 root) cannot be inspected without the broker.
    assert r["coverage"]["skip_reasons"] == {"unreadable": 2}
    assert r["coverage"]["clamav_complete"] is False


def test_encrypted_archive_is_incomplete(clamd, volume, tmp_path, broker_harness):
    enc = tmp_path / "enc.zip"
    subprocess.run(["zip", "-q", "-P", "pw", str(enc), "/etc/hostname"], check=True)
    path = volume({"enc.zip": enc.read_bytes()})
    r = scan_as_nobody(path, clamd, broker_harness)
    assert r["verdict"] == "INCOMPLETE" and r["coverage"]["skip_reasons"] == {"encrypted": 1}, r


def test_archive_limit_is_incomplete(clamd, volume, tmp_path, broker_harness):
    many = tmp_path / "many.zip"
    with zipfile.ZipFile(many, "w") as z:
        for i in range(100):
            z.writestr(f"f{i}.txt", f"{i}")
    path = volume({"many.zip": many.read_bytes()})
    r = scan_as_nobody(path, clamd, broker_harness)
    assert r["verdict"] == "INCOMPLETE" and r["coverage"]["skip_reasons"] == {"scan_limit": 1}, r


# --- YARA worker end to end (Phase 4) -------------------------------------------

YARA_RULES = {
    "malware.yar": 'rule usbscan_test_high { meta: severity = "high" strings: $a = "USBSCAN-YARA-TEST-HIGH" condition: $a }',
}


@pytest.fixture
def yara_worker():
    """Real supervisor + child processes with a minisign-signed bundle, serving uid nobody."""
    import threading
    from src.yara_worker.rules import RuleStore
    from src.yara_worker.yara_server import YaraServer
    from tests.unit.yara_worker.bundle import MINISIGN, make_bundle, make_keypair, yara_cfg
    if MINISIGN is None:
        pytest.skip("minisign not installed")
    base = tempfile.mkdtemp(prefix="usbscan-yara-", dir="/tmp")
    os.chmod(base, 0o755)
    pub, sec = make_keypair(base)
    rules = make_bundle(os.path.join(base, "rules"), sec, YARA_RULES, version=1)
    cfg = yara_cfg(rules, pub, os.path.join(base, "state"), socket_path=os.path.join(base, "yara.sock"))
    store = RuleStore(cfg)
    assert store.reload(), store.last_error
    loop = asyncio.new_event_loop()
    server = YaraServer(cfg, store, client_uid=NOBODY, socket_gid=NOGROUP)
    loop.run_until_complete(server.start())
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield cfg.socket_path
    asyncio.run_coroutine_threadsafe(server.close(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(10)
    loop.close()
    shutil.rmtree(base, ignore_errors=True)


def test_yara_and_clamav_on_hidden_content(clamd, volume, broker_harness, yara_worker):
    """Mandatory YARA + ClamAV, scanner as nobody, content in a 0700 dir opened via the broker:
    the YARA worker gets the same broker-confined descriptors and never touches a path."""
    path = volume({"ok.txt": b"fine\n", "private/marker.bin": b"xx USBSCAN-YARA-TEST-HIGH xx",
                   "private/eicar.com": EICAR},
                  modes={"private/marker.bin": 0o600, "private/eicar.com": 0o600},
                  dir_modes={"private": 0o700}, fs="ext4")
    r = scan_as_nobody(path, clamd, broker_harness, yara_sock=yara_worker)
    assert r["verdict"] == "THREAT", r
    cov = r["coverage"]
    assert cov["clamav_complete"] is True and cov["yara_complete"] is True, cov
    engines = sorted((t["engine"], t["signature_name"], t["file_path"]) for t in r["threats"])
    assert engines == [("clamav", "Test.EICAR.UNOFFICIAL", "part1/private/eicar.com"),
                       ("yara", "malware.usbscan_test_high", "part1/private/marker.bin")]
    assert any(rc.startswith("yara_rules=1:") for rc in r["reason_codes"])


def test_yara_clean_volume_complete(clamd, volume, broker_harness, yara_worker):
    path = volume({"hello.txt": b"hello\n"}, fs="ext4")
    r = scan_as_nobody(path, clamd, broker_harness, yara_sock=yara_worker)
    assert r["verdict"] == "CLEAN" and r["coverage"]["yara_complete"] is True, r
