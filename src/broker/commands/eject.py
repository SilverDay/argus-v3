"""eject: logically detach the session's USB device and close the session.

Sequence (mirrors what desktop "power off" implementations do):
  1. refuse while anything of the session is still mounted;
  2. confirm the port still holds the same device (busnum/devnum/diskseq);
  3. write 1 to each disk's SCSI ``device/delete`` (flushes and detaches the disk);
  4. write 1 to the USB device's ``remove`` attribute (logical disconnect);
     if absent, fall back to ``authorized`` = 0.
Whether the port actually loses VBUS depends on the hub hardware; callers must not
treat this as physical removal (spec §3.2 step 11).
"""
from __future__ import annotations

import os
from typing import Any

from src.shared.broker_protocol import (
    E_EJECT_FAILED, E_INVALID_ARGUMENT, E_SESSION_CONFLICT, ProtocolError,
)

from .. import mounts, sysfs
from ..context import BrokerContext, require_args


def _write_attr(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.write(fd, value.encode())
    finally:
        os.close(fd)


async def handle(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    require_args(args, "session_id")
    if not mounts.valid_session_id(args["session_id"]):
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid session_id")
    session = ctx.sessions.get(args["session_id"])
    if session.mounts or mounts.mounts_under(ctx.env, os.path.join(ctx.mounts_dir, session.session_id)):
        raise ProtocolError(E_SESSION_CONFLICT, "unmount before eject")

    device = session.device
    sysfs.check_same_device(ctx.env, device)
    scsi_deleted = 0
    for disk in device.disks:
        delete = ctx.env.sys("class", "block", disk.name, "device", "delete")
        # The class/block entry must still resolve inside this USB device's subtree.
        if os.path.realpath(ctx.env.sys("class", "block", disk.name)).startswith(device.realpath + os.sep) \
                and os.path.exists(delete):
            try:
                _write_attr(delete, "1")
                scsi_deleted += 1
            except OSError:
                pass

    method = None
    for attr, value in (("remove", "1"), ("authorized", "0")):
        path = os.path.join(device.realpath, attr)
        if os.path.exists(path):
            try:
                _write_attr(path, value)
                method = attr
                break
            except OSError:
                continue
    if method is None:
        ctx.audit.write("eject", session_id=session.session_id, result="error", scsi_deleted=scsi_deleted)
        raise ProtocolError(E_EJECT_FAILED, "could not detach USB device")

    ctx.sessions.close(session.session_id)
    ctx.audit.write("eject", session_id=session.session_id, result="ok", method=method, scsi_deleted=scsi_deleted)
    return {"ejected": True, "method": method, "scsi_deleted": scsi_deleted}
