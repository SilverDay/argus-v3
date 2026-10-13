"""open: confined read-only open of a path inside a mounted session volume.

Args: session_id, partition_id, path_b64 (base64 of the raw relative path bytes;
filenames on hostile media are arbitrary bytes). Result: {"type", "size"} and, for
regular files and directories, one fd passed with SCM_RIGHTS alongside the reply.
Individual opens are not audited one by one; the count is audited at unmount.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any

from src.shared.broker_protocol import E_INVALID_ARGUMENT, E_NOT_FOUND, ProtocolError

from .. import mounts
from ..context import BrokerContext, require_args
from ..resolve import open_beneath, validate_relpath

FDS_KEY = "_fds"   # handler-internal: fds to send with the reply, never serialised


async def handle(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    require_args(args, "session_id", "partition_id", "path_b64")
    if not mounts.valid_session_id(args["session_id"]) or not mounts.valid_partition_id(args["partition_id"]):
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid session_id or partition_id")
    if not isinstance(args["path_b64"], str) or len(args["path_b64"]) > 8192:
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid path")
    try:
        rel = validate_relpath(base64.b64decode(args["path_b64"], validate=True))
    except (ValueError, binascii.Error):
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid path") from None
    session = ctx.sessions.get(args["session_id"])
    root_fd = session.root_fds.get(args["partition_id"])
    if root_fd is None:
        raise ProtocolError(E_NOT_FOUND, "partition not mounted")
    try:
        opened = open_beneath(root_fd, rel)
    except OSError as exc:
        raise ProtocolError(E_INVALID_ARGUMENT, f"open failed: {exc.strerror}") from None
    session.opens += 1
    result: dict[str, Any] = {"type": opened.kind, "size": opened.size}
    if opened.fd is not None:
        result[FDS_KEY] = [opened.fd]
    return result
