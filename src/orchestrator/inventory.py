"""Bounded traversal of one mounted volume (spec §3.2 step 4).

* Never follows symlinks (lstat only); the broker also mounts with nosymfollow.
  Symlinks have no content of their own and are only counted.
* Special files (FIFOs, sockets, device nodes) are counted, never opened.
* Where on-media permissions hide content from the unprivileged scanner (e.g. ext4's
  0700 root lost+found), ``privileged`` is asked to open the path through the broker's
  confined openat2. Only if that also fails is the entry recorded as unreadable.
* Limits (max_files, max_depth, max_bytes_total) stop traversal and are reported;
  hitting one means the volume was not fully inventoried (INCOMPLETE).
Paths are filesystem strings (surrogateescape); ``display_path`` makes them printable.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from src.shared.models import SkipReason

# privileged(rel_path_bytes) -> (kind, fd or None, size); kind as returned by the broker.
Privileged = Callable[[bytes], tuple[str, int | None, int]]


@dataclass(frozen=True)
class FileEntry:
    path: str          # absolute path below the mount root
    rel: str           # path relative to the mount root
    size: int


@dataclass
class InventoryStats:
    files: int = 0
    bytes: int = 0
    symlinks: int = 0
    special: int = 0
    unreadable: int = 0
    privileged_opens: int = 0
    truncated: SkipReason | None = None     # SCAN_LIMIT / RECURSION_LIMIT when a limit stopped traversal
    notes: list[str] = field(default_factory=list)


def display_path(rel: str, limit: int = 512) -> str:
    raw = rel.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return "".join(c if c.isprintable() else "?" for c in raw)[:limit]


def _rel_bytes(rel: str) -> bytes:
    return b"" if rel in ("", ".") else os.fsencode(rel)


def _list_dir(directory: str, rel: str, privileged: Privileged | None, stats: InventoryStats) -> list[str] | None:
    try:
        return sorted(os.listdir(directory))
    except PermissionError:
        if privileged is None:
            return None
    except OSError:
        return None
    stats.privileged_opens += 1
    kind, fd, _ = privileged(_rel_bytes(rel))
    if fd is None:
        return None
    try:
        return sorted(os.fsdecode(n) for n in os.listdir(fd)) if kind == "dir" else None
    finally:
        os.close(fd)


def _classify(full: str, rel: str, privileged: Privileged | None, stats: InventoryStats) -> tuple[str, int]:
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        return "missing", 0
    except PermissionError:
        if privileged is None:
            return "unreadable", 0
        stats.privileged_opens += 1
        kind, fd, size = privileged(_rel_bytes(rel))
        if fd is not None:
            os.close(fd)
        return (kind if kind in ("file", "dir", "symlink", "special", "missing") else "unreadable"), size
    except OSError:
        return "unreadable", 0
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        return "symlink", 0
    if stat.S_ISDIR(mode):
        return "dir", 0
    if stat.S_ISREG(mode):
        return "file", st.st_size
    return "special", 0


def walk(root: str, *, max_files: int, max_depth: int, max_bytes: int, stats: InventoryStats,
         privileged: Privileged | None = None) -> Iterator[FileEntry]:
    """Yield regular files below ``root`` depth-first, updating ``stats``."""
    root = os.path.abspath(root)
    stack: list[tuple[str, str, int]] = [(root, ".", 0)]
    while stack:
        directory, rel_dir, depth = stack.pop()
        names = _list_dir(directory, rel_dir, privileged, stats)
        if names is None:
            stats.unreadable += 1
            continue
        subdirs = []
        for name in names:
            full = os.path.join(directory, name)
            rel = name if rel_dir == "." else os.path.join(rel_dir, name)
            kind, size = _classify(full, rel, privileged, stats)
            if kind == "symlink":
                stats.symlinks += 1
            elif kind == "dir":
                if depth + 1 > max_depth:
                    stats.truncated = stats.truncated or SkipReason.RECURSION_LIMIT
                    continue
                subdirs.append((full, rel))
            elif kind == "file":
                if stats.files >= max_files or stats.bytes + size > max_bytes:
                    stats.truncated = SkipReason.SCAN_LIMIT
                    return
                stats.files += 1
                stats.bytes += size
                yield FileEntry(full, rel, size)
            elif kind == "special":
                stats.special += 1
            elif kind == "unreadable":
                stats.unreadable += 1
        stack.extend((d, r, depth + 1) for d, r in reversed(subdirs))
