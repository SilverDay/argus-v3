"""enumerate: validate a USB device, open a session and describe its volumes.

Every block device of the device is set read-only before it is probed.
Volumes that cannot be mounted are still listed (with a status) so the
orchestrator can account for them in coverage (FR-USB-04).
"""
from __future__ import annotations

from typing import Any

from src.shared.broker_protocol import (
    E_DEVICE_IN_USE, E_INVALID_ARGUMENT, E_SESSION_CONFLICT, ProtocolError,
)

from .. import mounts, probe, sysfs
from ..context import BrokerContext, require_args
from ..probe import VolumeStatus
from ..session import Partition, Session

MAX_VOLUMES = 64


async def handle(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    require_args(args, "sysfs_path", "session_id")
    if not mounts.valid_session_id(args["session_id"]):
        raise ProtocolError(E_INVALID_ARGUMENT, "session_id must be a UUID4")
    if ctx.sessions.active is not None:
        raise ProtocolError(E_SESSION_CONFLICT, "another device session is active")

    device = sysfs.resolve_usb_device(ctx.env, args["sysfs_path"], ctx.internal_prefixes)
    if not device.disks:
        raise ProtocolError(E_INVALID_ARGUMENT, "USB device exposes no block devices")

    blocks = [b for d in device.disks for b in [d, *device.partitions.get(d.name, [])]]
    if len(blocks) > MAX_VOLUMES:
        raise ProtocolError(E_INVALID_ARGUMENT, "too many block devices")

    # FR-USB-08: never touch a device that is mounted, used as swap, or held by dm/md.
    in_use = mounts.in_use_device_numbers(ctx.env, ctx.mounts_dir)
    for b in blocks:
        if (b.major, b.minor) in in_use or sysfs.holders(ctx.env, b.name):
            raise ProtocolError(E_DEVICE_IN_USE, "a block device of this USB device is in use")

    nodes = {b.name: sysfs.verify_device_node(ctx.env, b) for b in blocks}
    for b in blocks:
        await mounts.set_readonly(ctx.env, nodes[b.name])

    session = Session(args["session_id"], device)
    volumes = []
    counter = 0
    for disk in device.disks:
        parts = device.partitions.get(disk.name, [])
        disk_probe = await probe.probe(ctx.env, nodes[disk.name])
        # A whole-disk filesystem is scanned when there is no partition table, and also
        # when a filesystem signature is present alongside partitions (e.g. isohybrid).
        candidates = [(disk, disk_probe)] if (not parts or disk_probe.fs_type) else []
        for p in parts:
            candidates.append((p, await probe.probe(ctx.env, nodes[p.name])))
        for block, result in candidates:
            counter += 1
            pid = f"part{counter}"
            kernel_type = ""
            if result.status is VolumeStatus.SUPPORTED:
                kernel_type = ctx.ntfs_driver if result.fs_type == "ntfs" else probe.SUPPORTED_TYPES[result.fs_type]
            session.partitions[pid] = Partition(pid, block, result, kernel_type)
            volumes.append({
                "partition_id": pid,
                "partition_index": block.partition_index,
                "disk_index": device.disks.index(disk),
                "size_bytes": block.size_bytes,
                "fs_type": result.fs_type,
                "fs_uuid": result.fs_uuid,
                "pt_type": result.pt_type,
                "label": result.label,
                "status": result.status.value,
            })

    ctx.sessions.open(session)
    ctx.audit.write("enumerate", session_id=session.session_id, port=device.port,
                    vendor_id=device.vendor_id, product_id=device.product_id,
                    volumes=[{"id": v["partition_id"], "status": v["status"], "fs": v["fs_type"]} for v in volumes])
    return {
        "device": {
            "vendor_id": device.vendor_id,
            "product_id": device.product_id,
            "serial": device.serial,
            "capacity_bytes": sum(d.size_bytes for d in device.disks if d.size_bytes > 0),
            "disk_count": len(device.disks),
        },
        "volumes": volumes,
    }
