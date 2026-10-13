"""Unprivileged, read-only sysfs pre-checks for a newly inserted USB device.

They give precise REJECTED reason codes (AC-S02: USBGuard-blocked devices must show
REJECTED and be logged) before the broker is involved. The broker repeats its own
checks; these are not a security boundary.
"""
from __future__ import annotations

import os
import re

_PORT = re.compile(r"^[1-9][0-9]{0,2}-[1-9][0-9]{0,2}(?:\.[1-9][0-9]{0,2}){0,6}$")


def is_usb_port(name: str) -> bool:
    return bool(_PORT.match(name))


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            return fh.read(64).strip()
    except OSError:
        return None


def precheck(sysfs_root: str, port: str) -> str | None:
    """Return a rejection reason code, or None if the device may proceed to the broker."""
    base = os.path.join(sysfs_root, "bus", "usb", "devices", port)
    if not os.path.isdir(base):
        return "device_gone"
    if _read(os.path.join(base, "authorized")) != "1":
        return "usb_policy_blocked"           # USBGuard (or kernel default) refused it
    if _read(os.path.join(base, "bDeviceClass")) == "09":
        return "hub_not_allowed"
    classes = [_read(os.path.join(base, e, "bInterfaceClass"))
               for e in os.listdir(base) if e.startswith(port + ":")]
    if not classes:
        return "no_interfaces"
    if "03" in classes:
        return "hid_interface"
    if any(c != "08" for c in classes):
        return "non_storage_interface"
    return None


def has_block_device(sysfs_root: str, port: str, max_depth: int = 8) -> bool:
    base = os.path.realpath(os.path.join(sysfs_root, "bus", "usb", "devices", port))
    depth0 = base.count(os.sep)
    for root, dirs, _ in os.walk(base, followlinks=False):
        if os.path.basename(root) == "block" and dirs:
            return True
        if root.count(os.sep) - depth0 >= max_depth:
            dirs[:] = []
    return False
