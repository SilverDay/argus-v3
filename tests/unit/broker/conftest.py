"""Fake host for broker unit tests: sysfs tree, /proc files, and a runner that
simulates blkid/blockdev/mount/umount by editing a fake mountinfo."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import pytest

from src.broker import sysfs
from src.broker.audit import AuditLog
from src.broker.context import BrokerContext
from src.broker.sysenv import CommandResult, SysEnv

USB_REL = "devices/platform/axi/xhci-hcd.0/usb1/1-1"
SCSI_REL = "1-1:1.0/host0/target0:0:0/0:0:0:0"


def _w(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(value + "\n")


@dataclass
class FakeHost:
    root: str
    blkid: dict[str, tuple[int, str]] = field(default_factory=dict)   # devnode -> (rc, stdout)
    calls: list[list[str]] = field(default_factory=list)
    mount_rc: int = 0
    mount_majmin: str | None = None      # override device number reported after mount
    mount_flags: str = "ro,nosuid,nodev,noexec,relatime,nosymfollow"
    umount_busy: bool = False
    base_mountinfo: str = "22 1 179:2 / / rw,relatime shared:1 - ext4 /dev/mmcblk0p2 rw\n"
    _next_id: int = 100

    @property
    def sys(self):
        return os.path.join(self.root, "sys")

    @property
    def usb_dir(self):
        return os.path.join(self.sys, USB_REL)

    @property
    def mountinfo(self):
        return os.path.join(self.root, "proc", "self", "mountinfo")

    def env(self) -> SysEnv:
        return SysEnv(sysfs_root=self.sys, dev_root=os.path.join(self.root, "dev"),
                      proc_root=os.path.join(self.root, "proc"), runner=self.run)

    def build(self, *, partitions=((1, "8:1"),), iface_classes=("08",), authorized="1", diskseq="7"):
        u = self.usb_dir
        for name, value in [("authorized", authorized), ("busnum", "1"), ("devnum", "5"),
                            ("idVendor", "0781"), ("idProduct", "5583"), ("serial", "ABC\x01123"),
                            ("bDeviceClass", "00")]:
            _w(os.path.join(u, name), value)
        _w(os.path.join(u, "remove"), "")
        for i, cls in enumerate(iface_classes):
            _w(os.path.join(u, f"1-1:1.{i}", "bInterfaceClass"), cls)
        disk = os.path.join(u, SCSI_REL, "block", "sda")
        _w(os.path.join(disk, "dev"), "8:0")
        _w(os.path.join(disk, "size"), "2048")
        _w(os.path.join(disk, "diskseq"), diskseq)
        _w(os.path.join(u, SCSI_REL, "delete"), "")
        os.makedirs(os.path.join(disk, "holders"), exist_ok=True)
        os.symlink(os.path.join(u, SCSI_REL), os.path.join(disk, "device"))
        for idx, majmin in partitions:
            p = os.path.join(disk, f"sda{idx}")
            _w(os.path.join(p, "dev"), majmin)
            _w(os.path.join(p, "size"), "1024")
            _w(os.path.join(p, "partition"), str(idx))
            os.makedirs(os.path.join(p, "holders"), exist_ok=True)
        os.makedirs(os.path.join(self.sys, "bus", "usb", "devices"), exist_ok=True)
        os.symlink(u, os.path.join(self.sys, "bus", "usb", "devices", "1-1"))
        cb = os.path.join(self.sys, "class", "block")
        os.makedirs(cb, exist_ok=True)
        os.symlink(disk, os.path.join(cb, "sda"))
        for idx, _ in partitions:
            os.symlink(os.path.join(disk, f"sda{idx}"), os.path.join(cb, f"sda{idx}"))
        _w(self.mountinfo, self.base_mountinfo.rstrip("\n"))
        _w(os.path.join(self.root, "proc", "swaps"), "Filename Type Size Used Priority")
        os.makedirs(os.path.join(self.root, "dev"), exist_ok=True)
        return self

    async def run(self, argv, timeout):
        argv = list(argv)
        self.calls.append(argv)
        prog = argv[0]
        if prog == "blkid":
            rc, out = self.blkid.get(argv[-1], (2, ""))
            return CommandResult(rc, out, "")
        if prog == "blockdev":
            return CommandResult(0, "", "")
        if prog == "mount":
            if self.mount_rc:
                return CommandResult(self.mount_rc, "", "mount failed")
            dev, target, fstype = argv[-2], argv[-1], argv[argv.index("-t") + 1]
            majmin = self.mount_majmin or {"sda": "8:0"}.get(os.path.basename(dev), "8:%s" % dev[-1])
            self._next_id += 1
            with open(self.mountinfo, "a") as fh:
                fh.write(f"{self._next_id} 22 {majmin} / {target} {self.mount_flags} - {fstype} {dev} ro\n")
            return CommandResult(0, "", "")
        if prog == "umount":
            if self.umount_busy:
                return CommandResult(32, "", "target is busy")
            target = argv[-1]
            with open(self.mountinfo) as fh:
                lines = [l for l in fh if l.split()[4] != target]
            with open(self.mountinfo, "w") as fh:
                fh.writelines(lines)
            return CommandResult(0, "", "")
        return CommandResult(127, "", "unexpected command")


@pytest.fixture
def host(tmp_path):
    return FakeHost(str(tmp_path / "host"))


@pytest.fixture
def ctx(host, tmp_path, monkeypatch):
    # Device nodes cannot be created without CAP_MKNOD; node validation is tested separately.
    monkeypatch.setattr(sysfs, "verify_device_node", lambda env, block: f"/dev/{block.name}")
    audit = AuditLog(str(tmp_path / "audit.log"))
    c = BrokerContext(env=host.env(), audit=audit, mounts_dir=str(tmp_path / "mounts"),
                      read_gid=os.getgid())
    yield c
    audit.close()

