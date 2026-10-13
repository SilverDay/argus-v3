"""Optional evidence quarantine (spec §3.2 step 9, §3.6, §6.2). Default disabled.

Owner decision (Phase 7): only files with a THREAT-level (high severity) detection are
retained — ClamAV signatures, high-severity YARA rules, VirusTotal above the threat
threshold. Policy violations and medium/low findings are never copied.

Store requirements, verified before every use (spec §6.2 "enabled only if the encrypted
mount has been verified"):
* ``quarantine.path`` is itself a mount point (topmost mount in /proc/self/mountinfo),
* mounted rw with nodev, nosuid and noexec,
* backed directly by a dm-crypt LUKS2 mapping: /sys/dev/block/<maj:min>/dm/uuid starts
  with ``CRYPT-LUKS2-`` (cryptsetup's dm UUID format ``CRYPT-<type>-<uuid>-<name>``),
* owned by the service user with mode 0700, not a symlink.

Layout: ``<path>/<scan_id>/<opaque>.bin`` + ``<opaque>.json`` (both 0600). Original
paths and names live only in the sidecar. Copies are made from the USB file through
a fresh descriptor, hashed while copying and discarded unless the SHA-256 equals the
detected hash. Nothing is ever written to the USB device or its mount (the config
validator also rejects a quarantine path overlapping the broker mount directory).
Quarantine failures are reported separately and never change the verdict.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.shared.config import QuarantineConfig
from src.shared.models import format_utc, utc_now
from src.shared.mountinfo import parse_mountinfo

log = logging.getLogger(__name__)
MB = 1024 ** 2
REQUIRED_OPTIONS = frozenset({"rw", "nodev", "nosuid", "noexec"})
LUKS2_DM_PREFIX = "CRYPT-LUKS2-"
_SCAN_DIR = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class QuarantineUnavailable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Evidence:
    sha256: str
    original_path: str             # printable "<partition>/<path>" (sidecar only)
    engine: str
    signature: str
    open_fd: Callable[[], int | None]
    device: dict[str, Any] = field(default_factory=dict)


@dataclass
class StoreOutcome:
    sha256: str
    status: str                    # stored | duplicate | unreadable | too_large | insufficient_space |
    item_id: str = ""              # hash_mismatch | limit_reached | io_error


def verify_store(path: str, *, mountinfo_path: str = "/proc/self/mountinfo", sysfs_root: str = "/sys",
                 uid: int | None = None) -> None:
    uid = os.geteuid() if uid is None else uid
    try:
        st = os.lstat(path)
    except OSError:
        raise QuarantineUnavailable("path_missing") from None
    if not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != os.path.normpath(path):
        raise QuarantineUnavailable("path_not_plain_directory")
    if st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o077:
        raise QuarantineUnavailable("path_permissions")
    try:
        with open(mountinfo_path, encoding="utf-8", errors="replace") as fh:
            entries = [m for m in parse_mountinfo(fh.read()) if m.mountpoint == os.path.normpath(path)]
    except OSError:
        raise QuarantineUnavailable("mountinfo_unreadable") from None
    if not entries:
        raise QuarantineUnavailable("not_a_mount_point")
    mnt = entries[-1]                         # topmost mount at that point is what we write to
    missing = REQUIRED_OPTIONS - mnt.mount_options
    if missing:
        raise QuarantineUnavailable("mount_options:" + ",".join(sorted(missing)))
    try:
        with open(os.path.join(sysfs_root, "dev", "block", f"{mnt.major}:{mnt.minor}", "dm", "uuid")) as fh:
            dm_uuid = fh.read().strip()
    except OSError:
        raise QuarantineUnavailable("not_dm_crypt") from None
    if not dm_uuid.startswith(LUKS2_DM_PREFIX):
        raise QuarantineUnavailable("not_luks2")


class Quarantine:
    def __init__(self, cfg: QuarantineConfig, station_id: str, *, mountinfo_path: str = "/proc/self/mountinfo",
                 sysfs_root: str = "/sys", clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.station_id = station_id
        self.mountinfo_path = mountinfo_path
        self.sysfs_root = sysfs_root
        self.clock = clock

    def verify(self) -> None:
        verify_store(self.cfg.path, mountinfo_path=self.mountinfo_path, sysfs_root=self.sysfs_root)

    # --- store (blocking; run in a worker thread) ------------------------------------

    def store(self, scan_id: str, verdict: str, items: list[Evidence]) -> list[StoreOutcome]:
        if not _SCAN_DIR.fullmatch(scan_id):
            raise ValueError("scan_id must be a UUID")
        self.verify()
        outcomes: list[StoreOutcome] = []
        seen: set[str] = set()
        root = os.open(self.cfg.path, _DIR_FLAGS)
        try:
            with contextlib.suppress(FileExistsError):
                os.mkdir(scan_id, 0o700, dir_fd=root)
            sdir = os.open(scan_id, _DIR_FLAGS, dir_fd=root)
            try:
                for item in items:
                    if item.sha256 in seen:
                        outcomes.append(StoreOutcome(item.sha256, "duplicate"))
                        continue
                    seen.add(item.sha256)
                    if sum(o.status == "stored" for o in outcomes) >= self.cfg.max_files_per_scan:
                        outcomes.append(StoreOutcome(item.sha256, "limit_reached"))
                        continue
                    outcomes.append(self._store_one(root, sdir, scan_id, verdict, item))
                os.fsync(sdir)
            finally:
                os.close(sdir)
        finally:
            os.close(root)
        return outcomes

    def _store_one(self, root: int, sdir: int, scan_id: str, verdict: str, item: Evidence) -> StoreOutcome:
        src = item.open_fd()
        if src is None:
            return StoreOutcome(item.sha256, "unreadable")
        opaque = secrets.token_hex(16)
        tmp = f".{opaque}.tmp"
        try:
            st = os.fstat(src)
            if not stat.S_ISREG(st.st_mode):
                return StoreOutcome(item.sha256, "unreadable")
            if st.st_size > self.cfg.max_file_size_mb * MB:
                return StoreOutcome(item.sha256, "too_large")
            vfs = os.fstatvfs(root)
            if vfs.f_bavail * vfs.f_frsize - st.st_size < self.cfg.min_free_mb * MB:
                return StoreOutcome(item.sha256, "insufficient_space")
            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                          dir_fd=sdir)
            h = hashlib.sha256()
            try:
                offset = 0
                while chunk := os.pread(src, 1024 * 1024, offset):
                    if offset + len(chunk) > st.st_size:
                        break                         # grew after fstat: hash check will fail
                    h.update(chunk)
                    os.write(out, chunk)
                    offset += len(chunk)
                os.fsync(out)
            finally:
                os.close(out)
            if h.hexdigest() != item.sha256:
                os.unlink(tmp, dir_fd=sdir)
                return StoreOutcome(item.sha256, "hash_mismatch")
            os.rename(tmp, f"{opaque}.bin", src_dir_fd=sdir, dst_dir_fd=sdir)
            meta = {
                "schema_version": 1, "item_id": opaque, "scan_id": scan_id, "station_id": self.station_id,
                "stored_utc": format_utc(utc_now()), "verdict": verdict, "sha256": item.sha256,
                "size_bytes": st.st_size, "original_path": item.original_path, "engine": item.engine,
                "signature": item.signature, "device": item.device,
            }
            fd = os.open(f"{opaque}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=sdir)
            try:
                os.write(fd, json.dumps(meta, ensure_ascii=True, sort_keys=True).encode() + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            return StoreOutcome(item.sha256, "stored", opaque)
        except OSError as exc:
            log.error("quarantine copy failed: %s", exc.strerror or type(exc).__name__)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp, dir_fd=sdir)
            return StoreOutcome(item.sha256, "io_error")
        finally:
            os.close(src)

    # --- retention ---------------------------------------------------------------------

    def cleanup(self) -> int:
        """Delete scan directories older than retention_days. Returns the number removed."""
        if not shutil.rmtree.avoids_symlink_attacks:    # fd-based rmtree required (Linux)
            raise QuarantineUnavailable("unsafe_rmtree")
        self.verify()
        cutoff = self.clock() - self.cfg.retention_days * 86_400
        removed = 0
        with os.scandir(self.cfg.path) as it:
            for entry in it:
                if not _SCAN_DIR.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                    continue
                if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    shutil.rmtree(entry.path)
                    removed += 1
        return removed

