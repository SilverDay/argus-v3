"""mount: mount one enumerated, supported volume read-only for the session."""
from __future__ import annotations

import os
from typing import Any

from src.shared.broker_protocol import (
    E_INVALID_ARGUMENT, E_NOT_FOUND, E_SESSION_CONFLICT, E_UNSUPPORTED, ProtocolError,
)

from .. import mounts, sysfs
from ..context import BrokerContext, require_args


async def handle(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    require_args(args, "session_id", "partition_id")
    if not mounts.valid_session_id(args["session_id"]) or not mounts.valid_partition_id(args["partition_id"]):
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid session_id or partition_id")
    session = ctx.sessions.get(args["session_id"])
    part = session.partitions.get(args["partition_id"])
    if part is None:
        raise ProtocolError(E_NOT_FOUND, "unknown partition")
    if not part.kernel_fs_type:
        raise ProtocolError(E_UNSUPPORTED, f"volume status is {part.probe.status.value}")
    if part.partition_id in session.mounts:
        raise ProtocolError(E_SESSION_CONFLICT, "partition already mounted")

    # Re-validate identity immediately before mounting (removal / re-insertion, FR-USB-07).
    sysfs.check_same_device(ctx.env, session.device)
    node = sysfs.verify_device_node(ctx.env, part.block)

    session_dir = os.path.join(ctx.mounts_dir, session.session_id)
    target = os.path.join(session_dir, part.partition_id)
    mounts.ensure_private_dir(ctx.mounts_dir, ctx.read_gid)
    mounts.ensure_private_dir(session_dir, ctx.read_gid)
    mounts.ensure_private_dir(target, ctx.read_gid)
    if mounts.mounts_under(ctx.env, target):
        raise ProtocolError(E_SESSION_CONFLICT, "mount point already in use")

    try:
        await mounts.mount_readonly(ctx.env, node, part.block.major, part.block.minor,
                                    part.kernel_fs_type, target, ctx.read_gid)
        sysfs.check_same_device(ctx.env, session.device)
    except ProtocolError as exc:
        await mounts.unmount(ctx.env, target)
        ctx.audit.write("mount", session_id=session.session_id, partition_id=part.partition_id,
                        result="error", error=exc.code, detail=exc.detail)
        raise
    session.mounts[part.partition_id] = target
    ctx.audit.write("mount", session_id=session.session_id, partition_id=part.partition_id,
                    fs_type=part.kernel_fs_type, mount_path=target, result="ok")
    return {"mount_path": target, "fs_type": part.kernel_fs_type}
