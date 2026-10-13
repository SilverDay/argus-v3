"""Bounded traversal of one mounted volume (spec §3.2 step 4).

* Never follows symlinks (os.scandir + follow_symlinks=False); the broker also mounts
  with nosymfollow. Symlinks have no content of their own and are only counted.
* Special files (FIFOs, sockets, device nodes) are counted, never opened.
* Unreadable directories and entries are recorded as uninspectable.
* Limits (max_files, max_depth, max_bytes_total) stop traversal and are reported;
  hitting one means the volume was not fully inventoried (INCOMPLETE).
Paths are kept as filesystem strings (surrogateescape) and only made printable
by ``display_path`` for reports.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field

from src.shared.models import SkipReason


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
    truncated: SkipReason | None = None     # SCAN_LIMIT / RECURSION_LIMIT when a limit stopped traversal
    notes: list[str] = field(default_factory=list)


def display_path(rel: str, limit: int = 512) -> str:
    raw = rel.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return "".join(c if c.isprintable() else "?" for c in raw)[:limit]


def walk(root: str, *, max_files: int, max_depth: int, max_bytes: int,
         stats: InventoryStats) -> Iterator[FileEntry]:
    """Yield regular files below ``root`` depth-first, updating ``stats``."""
    root = os.path.abspath(root)
    stack: list[tuple[str, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            it = os.scandir(directory)
        except OSError:
            stats.unreadable += 1
            continue
        with it:
            subdirs = []
            while True:
                try:
                    entry = next(it)
                except StopIteration:
                    break
                except OSError:
                    stats.unreadable += 1
                    break
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    stats.unreadable += 1
                    continue
                mode = st.st_mode
                if stat.S_ISLNK(mode):
                    stats.symlinks += 1
                elif stat.S_ISDIR(mode):
                    if depth + 1 > max_depth:
                        stats.truncated = stats.truncated or SkipReason.RECURSION_LIMIT
                        continue
                    subdirs.append(entry.path)
                elif stat.S_ISREG(mode):
                    if stats.files >= max_files or stats.bytes + st.st_size > max_bytes:
                        stats.truncated = SkipReason.SCAN_LIMIT
                        return
                    stats.files += 1
                    stats.bytes += st.st_size
                    yield FileEntry(entry.path, os.path.relpath(entry.path, root), st.st_size)
                else:
                    stats.special += 1
            stack.extend((d, depth + 1) for d in sorted(subdirs, reverse=True))
