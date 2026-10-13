"""/proc/<pid>/mountinfo parser (proc(5)). Shared by the broker and the quarantine check."""
from __future__ import annotations

import re
from dataclasses import dataclass


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
