"""USB device validation and block-device discovery through sysfs (spec §3.1, §8.2).

Callers identify a device only as ``/sys/bus/usb/devices/<port path>``. The broker
resolves it itself, checks that it is an authorized USB *device* (not an interface
or hub) whose interfaces are all Mass Storage (class 08), and walks the resolved
sysfs subtree (without following symlinks) for disks and partitions.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field

from src.shared.broker_protocol import (
    E_DEVICE_CHANGED, E_DEVICE_IN_USE, E_INVALID_ARGUMENT, E_NOT_FOUND, ProtocolError,
)

from .sysenv import SysEnv

USB_SYSFS_PREFIX = "/sys/bus/usb/devices/"
_USB_PORT = re.compile(r"^[1-9][0-9]{0,2}-[1-9][0-9]{0,2}(?:\.[1-9][0-9]{0,2}){0,6}$")
_BLOCK_NAME = re.compile(r"^[a-z][a-z0-9]{0,31}$")
_MAJMIN = re.compile(r"^([0-9]{1,9}):([0-9]{1,9})$")
MASS_STORAGE_CLASS = "08"
MAX_WALK_DEPTH = 12
SECTOR = 512


@dataclass(frozen=True)
class BlockInfo:
    name: str
    major: int
    minor: int
    size_bytes: int
    partition_index: int        # 0 = whole disk
    disk: str                   # owning disk name (== name for whole disks)


@dataclass
class UsbDevice:
    port: str                   # e.g. "1-1.2"
    realpath: str               # resolved sysfs directory
    busnum: int
    devnum: int
    vendor_id: str
    product_id: str
    serial: str
    disks: list[BlockInfo] = field(default_factory=list)
    partitions: dict[str, list[BlockInfo]] = field(default_factory=dict)  # disk name -> partitions
    diskseq: dict[str, str] = field(default_factory=dict)                 # disk name -> diskseq


def _read(path: str, limit: int = 4096) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return os.read(fd, limit).decode("ascii", "replace").strip()
    finally:
        os.close(fd)


def _read_opt(path: str) -> str | None:
    try:
        return _read(path)
    except OSError:
        return None


def sanitize(value: str | None, limit: int = 64) -> str:
    """Untrusted device strings: printable ASCII only, bounded length."""
    if not value:
        return ""
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in value)[:limit]


def parse_port(sysfs_path: object) -> str:
    if not isinstance(sysfs_path, str) or not sysfs_path.startswith(USB_SYSFS_PREFIX):
        raise ProtocolError(E_INVALID_ARGUMENT, "sysfs_path must be /sys/bus/usb/devices/<port>")
    port = sysfs_path[len(USB_SYSFS_PREFIX):].rstrip("/")
    if not _USB_PORT.match(port):
        raise ProtocolError(E_INVALID_ARGUMENT, "sysfs_path is not a USB device port path")
    return port


def _majmin(text: str | None) -> tuple[int, int]:
    m = _MAJMIN.match(text or "")
    if not m:
        raise ProtocolError(E_DEVICE_CHANGED, "unreadable block device number")
    return int(m.group(1)), int(m.group(2))


def resolve_usb_device(env: SysEnv, sysfs_path: object, internal_prefixes: tuple[str, ...] = ()) -> UsbDevice:
    port = parse_port(sysfs_path)
    link = env.sys("bus", "usb", "devices", port)
    if not os.path.lexists(link):
        raise ProtocolError(E_NOT_FOUND, "USB device not present")
    real = os.path.realpath(link)
    devices_root = os.path.realpath(env.sys("devices")) + os.sep
    if not real.startswith(devices_root) or not os.path.isdir(real):
        raise ProtocolError(E_INVALID_ARGUMENT, "USB device resolves outside /sys/devices")
    shown = "/sys" + real[len(os.path.realpath(env.sysfs_root)):]
    for prefix in internal_prefixes:
        if prefix and (shown.startswith(prefix) or real.startswith(prefix)):
            raise ProtocolError(E_DEVICE_IN_USE, "device is configured as internal")

    if _read_opt(os.path.join(real, "authorized")) != "1":
        raise ProtocolError(E_INVALID_ARGUMENT, "USB device is not authorized")
    if _read_opt(os.path.join(real, "bDeviceClass")) == "09":
        raise ProtocolError(E_INVALID_ARGUMENT, "USB hubs are not accepted")

    interfaces = [e for e in os.listdir(real) if e.startswith(port + ":")]
    if not interfaces:
        raise ProtocolError(E_INVALID_ARGUMENT, "USB device exposes no interfaces")
    for iface in interfaces:
        cls = _read_opt(os.path.join(real, iface, "bInterfaceClass"))
        if cls != MASS_STORAGE_CLASS:
            # Composite devices (e.g. HID + storage) are refused here as well as by USBGuard.
            raise ProtocolError(E_INVALID_ARGUMENT, "USB device exposes a non-storage interface")

    try:
        busnum = int(_read(os.path.join(real, "busnum")))
        devnum = int(_read(os.path.join(real, "devnum")))
    except (OSError, ValueError):
        raise ProtocolError(E_DEVICE_CHANGED, "USB device identity unreadable") from None

    dev = UsbDevice(
        port=port, realpath=real, busnum=busnum, devnum=devnum,
        vendor_id=sanitize(_read_opt(os.path.join(real, "idVendor")), 4),
        product_id=sanitize(_read_opt(os.path.join(real, "idProduct")), 4),
        serial=sanitize(_read_opt(os.path.join(real, "serial")), 128),
    )
    _discover_blocks(dev)
    return dev


def _block_info(path: str, name: str, disk: str, index: int) -> BlockInfo:
    major, minor = _majmin(_read_opt(os.path.join(path, "dev")))
    try:
        size = int(_read(os.path.join(path, "size"))) * SECTOR
    except (OSError, ValueError):
        size = -1
    return BlockInfo(name, major, minor, size, index, disk)


def _discover_blocks(dev: UsbDevice) -> None:
    base_depth = dev.realpath.rstrip(os.sep).count(os.sep)
    for root, dirs, _files in os.walk(dev.realpath, followlinks=False):
        if root.count(os.sep) - base_depth >= MAX_WALK_DEPTH:
            dirs[:] = []
            continue
        if os.path.basename(root) != "block":
            continue
        for disk in sorted(dirs):
            if not _BLOCK_NAME.match(disk):
                continue
            disk_path = os.path.join(root, disk)
            dev.disks.append(_block_info(disk_path, disk, disk, 0))
            seq = _read_opt(os.path.join(disk_path, "diskseq"))
            dev.diskseq[disk] = seq or ""
            parts: list[BlockInfo] = []
            for entry in sorted(os.listdir(disk_path)):
                p = os.path.join(disk_path, entry)
                if not _BLOCK_NAME.match(entry) or os.path.islink(p):
                    continue
                idx = _read_opt(os.path.join(p, "partition"))
                if idx and idx.isdigit():
                    parts.append(_block_info(p, entry, disk, int(idx)))
            dev.partitions[disk] = sorted(parts, key=lambda b: b.partition_index)
        dirs[:] = []  # never descend below a block/ directory


def holders(env: SysEnv, name: str) -> list[str]:
    try:
        return os.listdir(env.sys("class", "block", name, "holders"))
    except OSError:
        return []


def verify_device_node(env: SysEnv, block: BlockInfo) -> str:
    """Return /dev/<name> after checking it is the expected block device node."""
    if not _BLOCK_NAME.match(block.name):
        raise ProtocolError(E_DEVICE_CHANGED, "invalid block device name")
    node = env.dev(block.name)
    try:
        st = os.lstat(node)
    except OSError:
        raise ProtocolError(E_DEVICE_CHANGED, "block device node missing") from None
    if not stat.S_ISBLK(st.st_mode) or st.st_rdev != os.makedev(block.major, block.minor):
        raise ProtocolError(E_DEVICE_CHANGED, "block device node does not match sysfs")
    return node


def check_same_device(env: SysEnv, dev: UsbDevice) -> None:
    """Fail if the port now holds a different device (removal/re-insertion, FR-USB-07)."""
    link = env.sys("bus", "usb", "devices", dev.port)
    if not os.path.lexists(link) or os.path.realpath(link) != dev.realpath:
        raise ProtocolError(E_DEVICE_CHANGED, "USB device no longer present")
    try:
        busnum = int(_read(os.path.join(dev.realpath, "busnum")))
        devnum = int(_read(os.path.join(dev.realpath, "devnum")))
    except (OSError, ValueError):
        raise ProtocolError(E_DEVICE_CHANGED, "USB device no longer present") from None
    if (busnum, devnum) != (dev.busnum, dev.devnum):
        raise ProtocolError(E_DEVICE_CHANGED, "USB device was re-enumerated")
    for disk in dev.disks:
        seq = _read_opt(env.sys("class", "block", disk.name, "diskseq")) or ""
        if seq != dev.diskseq.get(disk.name, ""):
            raise ProtocolError(E_DEVICE_CHANGED, "disk media changed")
