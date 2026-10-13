"""Read-only mounting, post-mount verification and unmounting (spec §3.2 step 3, §8.2).

Defence layers for every scan mount:
  1. the block device and disk are set read-only (BLKROSET via ``blockdev --setro``)
     before mounting — ``ro`` alone does not stop ext3/4 journal replay (mount(8));
  2. mount flags ro,noexec,nosuid,nodev,nosymfollow (+ noload for ext3/4);
  3. non-POSIX filesystems: uid=0,gid=<read gid>,dmask=0027,fmask=0137;
  4. mount points live in 0750 root:<read group> directories, so only members of
     the scanner read group can traverse them, whatever the on-media permissions;
  5. after mounting, /proc/self/mountinfo is checked for the expected device
     number and flags; any mismatch unmounts and fails.

Mounts are made in the host mount namespace on purpose: systemd propagates host
mounts into service namespaces, but not the reverse (systemd.exec(5)), so a
broker-private namespace would be invisible to clamd/YARA.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass

from src.shared.broker_protocol import E_MOUNT_FAILED, E_UNMOUNT_FAILED, ProtocolError

from .sysenv import SysEnv

COMMAND_TIMEOUT = 30.0
BASE_FLAGS = ("ro", "noexec", "nosuid", "nodev", "nosymfollow")
REQUIRED_MOUNT_FLAGS = frozenset({"ro", "noexec", "nosuid", "nodev"})
_SESSION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_PARTITION_ID = re.compile(r"^part[0-9]{1,3}$")


def valid_session_id(value: object) -> bool:
    return isinstance(value, str) and bool(_SESSION_ID.match(value))


def valid_partition_id(value: object) -> bool:
    return isinstance(value, str) and bool(_PARTITION_ID.match(value))


def mount_options(fs_type: str, read_gid: int) -> str:
    opts = list(BASE_FLAGS)
    if fs_type in ("ext3", "ext4"):
        opts.append("noload")
    elif fs_type in ("vfat", "exfat", "ntfs3", "ntfs-3g"):
        opts += ["uid=0", f"gid={read_gid}", "dmask=0027", "fmask=0137"]
    elif fs_type == "iso9660":
        opts += ["uid=0", f"gid={read_gid}"]
    elif fs_type != "ext2":
        raise ProtocolError(E_MOUNT_FAILED, "filesystem type not allowed")
    return ",".join(opts)


@dataclass(frozen=True)
class MountEntry:
    mount_id: int
    major: int
    minor: int
    mountpoint: str
    mount_options: frozenset[str]
    fs_type: str
    source: str
    super_options: frozenset[str]


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def parse_mountinfo(text: str) -> list[MountEntry]:
    entries = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        lf, rf = left.split(), right.split()
        if len(lf) < 6 or len(rf) < 3:
            continue
        major, _, minor = lf[2].partition(":")
        entries.append(MountEntry(
            mount_id=int(lf[0]), major=int(major), minor=int(minor),
            mountpoint=_unescape(lf[4]), mount_options=frozenset(lf[5].split(",")),
            fs_type=rf[0], source=_unescape(rf[1]), super_options=frozenset(rf[2].split(",")),
        ))
    return entries


def read_mountinfo(env: SysEnv) -> list[MountEntry]:
    with open(env.proc("self", "mountinfo"), encoding="utf-8", errors="replace") as fh:
        return parse_mountinfo(fh.read())


def in_use_device_numbers(env: SysEnv, mounts_dir: str) -> set[tuple[int, int]]:
    """Device numbers mounted outside the broker's tree, or used as swap."""
    used = {(m.major, m.minor) for m in read_mountinfo(env)
            if not (m.mountpoint == mounts_dir or m.mountpoint.startswith(mounts_dir + "/"))}
    try:
        with open(env.proc("swaps"), encoding="utf-8") as fh:
            for line in fh.read().splitlines()[1:]:
                path = line.split()[0] if line.split() else ""
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if stat.S_ISBLK(st.st_mode):
                    used.add((os.major(st.st_rdev), os.minor(st.st_rdev)))
    except OSError:
        pass
    return used


def mounts_under(env: SysEnv, path: str) -> list[MountEntry]:
    return [m for m in read_mountinfo(env) if m.mountpoint == path or m.mountpoint.startswith(path + "/")]


# --- directories -------------------------------------------------------------

def ensure_private_dir(path: str, gid: int, mode: int = 0o750) -> None:
    """Create (or validate) a root-owned directory, refusing symlinks and foreign owners."""
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise ProtocolError(E_MOUNT_FAILED, "mount directory is not a directory")
    if st.st_uid != os.geteuid():
        raise ProtocolError(E_MOUNT_FAILED, "mount directory has unexpected owner")
    if st.st_gid != gid:
        os.chown(path, -1, gid, follow_symlinks=False)
    os.chmod(path, mode)


# --- operations --------------------------------------------------------------

async def set_readonly(env: SysEnv, devnode: str) -> None:
    result = await env.runner(["blockdev", "--setro", devnode], COMMAND_TIMEOUT)
    if result.returncode != 0:
        raise ProtocolError(E_MOUNT_FAILED, "could not set block device read-only")


async def mount_readonly(env: SysEnv, devnode: str, major: int, minor: int, fs_type: str,
                         target: str, read_gid: int) -> MountEntry:
    opts = mount_options(fs_type, read_gid)
    result = await env.runner(
        ["mount", "--options-source", "disable", "-t", fs_type, "-o", opts, devnode, target],
        COMMAND_TIMEOUT,
    )
    if result.returncode != 0:
        raise ProtocolError(E_MOUNT_FAILED, f"mount exited with status {result.returncode}")
    entries = [m for m in read_mountinfo(env) if m.mountpoint == target]
    problem = None
    if len(entries) != 1:
        problem = "unexpected mount table state"
    else:
        entry = entries[0]
        fuse = entry.fs_type.startswith("fuse")
        if not fuse and (entry.major, entry.minor) != (major, minor):
            problem = "mounted device does not match the enumerated partition"
        elif not REQUIRED_MOUNT_FLAGS <= entry.mount_options:
            problem = "mount flags missing"
        elif not fuse and "ro" not in entry.super_options:
            problem = "superblock not read-only"
    if problem:
        await unmount(env, target)
        raise ProtocolError(E_MOUNT_FAILED, problem)
    return entries[0]


def open_mount_root(target: str, major: int, minor: int, fuse: bool = False) -> int:
    """O_PATH handle on the mount root; verifies it is the expected filesystem."""
    fd = os.open(target, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    if not fuse and st.st_dev != os.makedev(major, minor):
        os.close(fd)
        raise ProtocolError(E_MOUNT_FAILED, "mount root is not on the enumerated device")
    return fd


async def unmount(env: SysEnv, target: str, attempts: int = 3) -> None:
    """Unmount everything at/under target (deepest first). Never lazy-unmounts."""
    for _ in range(attempts):
        remaining = sorted(mounts_under(env, target), key=lambda m: m.mountpoint.count("/"), reverse=True)
        if not remaining:
            return
        for entry in remaining:
            await env.runner(["umount", entry.mountpoint], COMMAND_TIMEOUT)
    if mounts_under(env, target):
        raise ProtocolError(E_UNMOUNT_FAILED, "filesystem still mounted (busy)")


def remove_tree(path: str) -> None:
    """Remove empty mount-point directories bottom-up; never deletes files."""
    if not os.path.lexists(path):
        return
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        if files:
            raise ProtocolError(E_UNMOUNT_FAILED, "unexpected files in mount directory")
        for d in dirs:
            os.rmdir(os.path.join(root, d))
    os.rmdir(path)
