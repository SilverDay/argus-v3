"""Test doubles for the orchestrator (importable as tests.unit.orchestrator.fakes)."""
from __future__ import annotations

import os
import time

from src.orchestrator.broker_client import BrokerError
from src.orchestrator.scanner_clamav import ClamdUnavailable, ClamResult, ClamStatus, ClamVersion
from src.shared.models import Severity


class FakeBroker:
    def __init__(self, mounts: dict[str, str], volumes=None, capacity=10**9):
        self.mounts = mounts
        self.volumes = volumes or [{"partition_id": p, "status": "supported", "fs_type": "vfat"} for p in mounts]
        self.capacity = capacity
        self.calls: list[tuple] = []
        self.fail: dict[str, str] = {}     # command -> error code
        self.alive = True

    def _maybe_fail(self, cmd):
        self.calls.append((cmd,))
        if cmd in self.fail:
            raise BrokerError(self.fail[cmd])

    async def ping(self):
        if not self.alive:
            raise BrokerError("broker_unavailable")
        return True

    async def enumerate(self, sysfs_path, session_id):
        self._maybe_fail("enumerate")
        return {"device": {"vendor_id": "0781", "product_id": "5583", "serial": "S", "capacity_bytes": self.capacity},
                "volumes": self.volumes}

    async def mount(self, session_id, partition_id):
        self._maybe_fail("mount")
        return {"mount_path": self.mounts[partition_id], "fs_type": "vfat"}

    async def unmount(self, session_id):
        self._maybe_fail("unmount")

    async def eject(self, session_id):
        self._maybe_fail("eject")
        return {"ejected": True, "method": "remove"}

    async def release(self, session_id):
        self._maybe_fail("release")


class FakeClamd:
    """Decides by file content: EVIL -> high, HEUR -> medium, LIMIT/ENC/ERR/SLOW markers."""

    def __init__(self):
        self.alive = True
        self.db_time = time.time()
        self.scanned = 0
        self.gate = None          # optional asyncio.Event to pause scanning

    async def ping(self):
        if not self.alive:
            raise ClamdUnavailable("down")
        return True

    async def version(self):
        return ClamVersion("1.5.4", 27800, self.db_time)

    async def scan_fd(self, fd, timeout):
        if not self.alive:
            raise ClamdUnavailable("down")
        if self.gate is not None:
            await self.gate.wait()
        data = os.pread(fd, 4096, 0)
        self.scanned += 1
        if b"EVIL" in data:
            return ClamResult(ClamStatus.FOUND, "Win.Test.Evil", Severity.HIGH)
        if b"HEUR" in data:
            return ClamResult(ClamStatus.FOUND, "Heuristics.Test", Severity.MEDIUM)
        if b"LIMIT" in data:
            return ClamResult(ClamStatus.LIMIT, "Heuristics.Limits.Exceeded.MaxFiles")
        if b"ENC" in data:
            return ClamResult(ClamStatus.ENCRYPTED, "Heuristics.Encrypted.Zip")
        if b"ERR" in data:
            return ClamResult(ClamStatus.ERROR, "read error")
        return ClamResult(ClamStatus.CLEAN)


def make_sysfs(root, port="1-1", authorized="1", classes=("08",), block=True):
    base = os.path.join(root, "devices", "usb1", port)
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, "authorized"), "w") as fh:
        fh.write(authorized)
    for i, c in enumerate(classes):
        d = os.path.join(base, f"{port}:1.{i}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "bInterfaceClass"), "w") as fh:
            fh.write(c)
    if block:
        os.makedirs(os.path.join(base, f"{port}:1.0", "host0", "block", "sda"), exist_ok=True)
    links = os.path.join(root, "bus", "usb", "devices")
    os.makedirs(links, exist_ok=True)
    if not os.path.lexists(os.path.join(links, port)):
        os.symlink(base, os.path.join(links, port))
