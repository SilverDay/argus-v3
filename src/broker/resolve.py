"""Confined open of paths inside a session mount via openat2(2).

Used so the unprivileged scanner can inspect content the on-media permissions hide
from it (e.g. ext4's 0700 root lost+found). The broker opens relative to a held
directory fd of the mount root with
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
so no lookup can leave the mount, cross into another mount, or follow any link.
Only regular files and directories are handed out (read-only fds).
Constants: linux/openat2.h; syscall 437 on x86_64 and asm-generic (arm64).
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
from dataclasses import dataclass

SYS_OPENAT2 = {"x86_64": 437, "aarch64": 437, "arm64": 437}
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RESOLVE = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
MAX_PATH_BYTES = 4096


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def openat2(dirfd: int, path: bytes, flags: int = OPEN_FLAGS, resolve: int = RESOLVE) -> int:
    nr = SYS_OPENAT2.get(platform.machine())
    if nr is None:
        raise OSError(errno.ENOSYS, "openat2 syscall number unknown for this architecture")
    how = _OpenHow(flags, 0, resolve)
    fd = _libc.syscall(ctypes.c_long(nr), ctypes.c_int(dirfd), ctypes.c_char_p(path),
                       ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return fd


def validate_relpath(path: bytes) -> bytes:
    """Reject anything but a plain relative path. ``b""`` means the mount root."""
    if not isinstance(path, bytes) or len(path) > MAX_PATH_BYTES or b"\0" in path:
        raise ValueError("invalid path")
    if path.startswith(b"/") or any(c == b".." for c in path.split(b"/")):
        raise ValueError("path must be relative and without '..'")
    return path or b"."


@dataclass(frozen=True)
class Opened:
    kind: str          # "file" | "dir" | "symlink" | "special" | "missing" | "denied"
    fd: int | None = None
    size: int = 0


def open_beneath(root_fd: int, rel: bytes) -> Opened:
    """Open ``rel`` below the mount root. Returns an fd only for regular files and dirs."""
    rel = validate_relpath(rel)
    try:
        fd = openat2(root_fd, rel)
    except OSError as exc:
        if exc.errno == errno.ELOOP:          # symlink anywhere in the path
            return Opened("symlink")
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return Opened("missing")
        if exc.errno in (errno.EACCES, errno.EPERM, errno.ENXIO, errno.ENODEV):
            return Opened("special" if exc.errno in (errno.ENXIO, errno.ENODEV) else "denied")
        if exc.errno == errno.EXDEV:
            return Opened("denied")
        raise
    st = os.fstat(fd)
    if stat.S_ISREG(st.st_mode):
        return Opened("file", fd, st.st_size)
    if stat.S_ISDIR(st.st_mode):
        return Opened("dir", fd, 0)
    os.close(fd)
    return Opened("special")
