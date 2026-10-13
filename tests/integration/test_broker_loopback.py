"""Broker mount layer against a real loopback ext4 image (needs root + loop devices).

Verifies with findmnt --json that the mount is ro,noexec,nosuid,nodev, that the
block device was set read-only, and that writes and execution are refused.
"""
import asyncio
import json
import os
import shutil
import subprocess

import pytest

from src.broker import mounts, sysfs
from src.broker.sysenv import SysEnv
from src.shared.broker_protocol import ProtocolError

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not shutil.which("losetup") or not shutil.which("mkfs.ext4"),
    reason="requires root, losetup and mkfs.ext4",
)


@pytest.fixture
def loop_image(tmp_path):
    content = tmp_path / "content"
    content.mkdir()
    (content / "hello.txt").write_text("hello\n")
    script = content / "run.sh"
    script.write_text("#!/bin/sh\necho executed\n")
    script.chmod(0o755)
    img = tmp_path / "usb.img"
    subprocess.run(["truncate", "-s", "16M", str(img)], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(content), str(img)], check=True)
    dev = subprocess.run(["losetup", "-f", "--show", str(img)], check=True,
                         capture_output=True, text=True).stdout.strip()
    yield dev
    subprocess.run(["umount", "-q", str(tmp_path / "mnt")], check=False)
    subprocess.run(["losetup", "-d", dev], check=False)


def _block(dev):
    st = os.stat(dev)
    name = os.path.basename(dev)
    return sysfs.BlockInfo(name, os.major(st.st_rdev), os.minor(st.st_rdev), 0, 0, name)


def test_readonly_mount_flags(loop_image, tmp_path):
    env = SysEnv()
    block = _block(loop_image)
    node = sysfs.verify_device_node(env, block)
    target = tmp_path / "mnt"
    mounts.ensure_private_dir(str(target), os.getgid())

    async def scenario():
        await mounts.set_readonly(env, node)
        return await mounts.mount_readonly(env, node, block.major, block.minor, "ext4",
                                           str(target), os.getgid())

    entry = asyncio.run(scenario())
    try:
        assert subprocess.run(["blockdev", "--getro", node], capture_output=True, text=True).stdout.strip() == "1"
        info = json.loads(subprocess.run(["findmnt", "--json", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", str(target)],
                                         check=True, capture_output=True, text=True).stdout)
        (fs,) = info["filesystems"]
        opts = set(fs["options"].split(","))
        assert {"ro", "noexec", "nosuid", "nodev", "nosymfollow"} <= opts
        assert "norecovery" in opts  # noload
        assert fs["source"] == node and entry.fs_type == "ext4"

        assert (target / "hello.txt").read_text() == "hello\n"
        with pytest.raises(OSError):
            (target / "new.txt").write_text("x")
        with pytest.raises(PermissionError):
            subprocess.run([str(target / "run.sh")], check=True)
    finally:
        asyncio.run(mounts.unmount(env, str(target)))
    assert not mounts.mounts_under(env, str(target))


def test_post_mount_check_rejects_wrong_device_number(loop_image, tmp_path):
    env = SysEnv()
    block = _block(loop_image)
    target = tmp_path / "mnt"
    mounts.ensure_private_dir(str(target), os.getgid())
    with pytest.raises(ProtocolError, match="does not match"):
        asyncio.run(mounts.mount_readonly(env, loop_image, block.major, block.minor + 1000, "ext4",
                                          str(target), os.getgid()))
    assert not mounts.mounts_under(env, str(target))  # rolled back
