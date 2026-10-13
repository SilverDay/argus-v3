"""Reduce the broker's Linux capabilities after the socket is bound.

Kept: CAP_SYS_ADMIN (mount/umount, BLKROSET) and CAP_CHOWN (group of mount dirs).
Not needed: CAP_DAC_READ_SEARCH — the broker runs as uid 0, which owns the block
device nodes and sysfs attributes it touches, so ordinary DAC already permits it.

Steps: drop every other capability from the bounding set (needs CAP_SETPCAP, so
this happens first), clear ambient caps, set permitted/effective/inheritable to the
kept set, then set no_new_privs. Children (mount, blkid, blockdev) therefore run
with at most the kept capabilities.
"""
from __future__ import annotations

import ctypes
import os
import threading

CAP_CHOWN = 0
CAP_SETPCAP = 8
CAP_SYS_ADMIN = 21
KEEP = (CAP_SYS_ADMIN, CAP_CHOWN)

PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


class CapabilityError(OSError):
    pass


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _check(ret: int, what: str) -> None:
    if ret != 0:
        err = ctypes.get_errno()
        raise CapabilityError(err, f"{what}: {os.strerror(err)}")


def last_cap(proc_root: str = "/proc") -> int:
    with open(os.path.join(proc_root, "sys/kernel/cap_last_cap")) as fh:
        return int(fh.read().strip())


def drop_capabilities(keep: tuple[int, ...] = KEEP) -> None:
    # Capability sets are per thread: other threads would keep full privileges.
    if threading.active_count() != 1:
        raise CapabilityError(0, "drop_capabilities must run before any other thread starts")
    libc = _libc()
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    for cap in range(last_cap() + 1):
        if cap not in keep:
            _check(libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0), f"drop bounding cap {cap}")
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)  # EINVAL on very old kernels: ignore

    mask = [0, 0]
    for cap in keep:
        mask[cap // 32] |= 1 << (cap % 32)
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)(*[_CapData(m, m, 0) for m in mask])
    _check(libc.capset(ctypes.byref(header), data), "capset")
    _check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no_new_privs")


def effective_caps(proc_status: str = "/proc/self/status") -> int:
    with open(proc_status) as fh:
        for line in fh:
            if line.startswith("CapEff:"):
                return int(line.split()[1], 16)
    raise CapabilityError(0, "CapEff not found")
