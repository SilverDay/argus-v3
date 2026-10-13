"""Filesystem probing with blkid (low-level probe, no cache, no udev database).

Output values come from attacker-controlled superblocks and are sanitised before
they leave the broker. Classification decides whether a volume can be mounted;
anything else is reported so the orchestrator can mark coverage incomplete.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .sysenv import SysEnv
from .sysfs import sanitize

PROBE_TIMEOUT = 15.0
_EXPORT_LINE = re.compile(r"^([A-Z_]{1,32})=(.*)$")


class VolumeStatus(str, Enum):
    SUPPORTED = "supported"
    ENCRYPTED = "encrypted"
    UNSUPPORTED = "unsupported"
    UNRECOGNIZED = "unrecognized"
    AMBIVALENT = "ambivalent"      # several colliding signatures (possible polyglot)
    PROBE_FAILED = "probe_failed"


# blkid TYPE -> kernel filesystem type passed to mount -t (NTFS resolved at runtime).
SUPPORTED_TYPES = {
    "vfat": "vfat",
    "exfat": "exfat",
    "ntfs": "ntfs",
    "ext2": "ext2",
    "ext3": "ext3",
    "ext4": "ext4",
    "iso9660": "iso9660",
}
ENCRYPTED_TYPES = frozenset({"crypto_LUKS", "BitLocker", "VeraCrypt", "TrueCrypt"})


@dataclass(frozen=True)
class ProbeResult:
    status: VolumeStatus
    fs_type: str = ""          # blkid TYPE (sanitised)
    fs_uuid: str = ""          # informational only; attacker-controlled, never used as a key
    label: str = ""
    pt_type: str = ""
    part_type: str = ""        # PART_ENTRY_TYPE: GPT type GUID or MBR "0x.." (libblkid)


def _unescape(value: str) -> str:
    # blkid -o export escapes special characters with a backslash.
    return re.sub(r"\\(.)", r"\1", value)


def parse_export(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines()[:64]:
        m = _EXPORT_LINE.match(line)
        if m:
            out[m.group(1)] = sanitize(_unescape(m.group(2)))
    return out


def classify(fields: dict[str, str]) -> ProbeResult:
    fs_type = fields.get("TYPE", "")
    common = dict(fs_type=fs_type, fs_uuid=fields.get("UUID", ""), label=fields.get("LABEL", ""),
                  pt_type=fields.get("PTTYPE", ""), part_type=fields.get("PART_ENTRY_TYPE", "").lower())
    if fs_type in SUPPORTED_TYPES:
        return ProbeResult(VolumeStatus.SUPPORTED, **common)
    if fs_type in ENCRYPTED_TYPES:
        return ProbeResult(VolumeStatus.ENCRYPTED, **common)
    if fs_type:
        return ProbeResult(VolumeStatus.UNSUPPORTED, **common)
    return ProbeResult(VolumeStatus.UNRECOGNIZED, **common)


async def probe(env: SysEnv, devnode: str) -> ProbeResult:
    result = await env.runner(["blkid", "-p", "-c", "/dev/null", "-o", "export", devnode], PROBE_TIMEOUT)
    if result.returncode == 2:          # nothing detected / unreadable (blkid(8) EXIT STATUS)
        return ProbeResult(VolumeStatus.UNRECOGNIZED,
                           part_type=parse_export(result.stdout).get("PART_ENTRY_TYPE", "").lower())
    if result.returncode == 8:          # ambivalent low-level probe result
        return ProbeResult(VolumeStatus.AMBIVALENT)
    if result.returncode != 0:
        return ProbeResult(VolumeStatus.PROBE_FAILED)
    return classify(parse_export(result.stdout))
