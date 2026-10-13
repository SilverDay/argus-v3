"""unmount: unmount every volume of the session and remove its mount directories.

The session stays open so ``eject`` can follow; ``release`` closes it without ejecting.
"""
from __future__ import annotations

import os
from typing import Any

from src.shared.broker_protocol import E_INVALID_ARGUMENT, E_UNMOUNT_FAILED, ProtocolError

from .. import mounts
from ..context import BrokerContext, require_args


async def unmount_session(ctx: BrokerContext, session_id: str) -> None:
    session_dir = os.path.join(ctx.mounts_dir, session_id)
    try:
        await mounts.unmount(ctx.env, session_dir)
        mounts.remove_tree(session_dir)
    except OSError as exc:
        raise ProtocolError(E_UNMOUNT_FAILED, exc.strerror or "cleanup failed") from None


async def handle(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    require_args(args, "session_id")
    if not mounts.valid_session_id(args["session_id"]):
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid session_id")
    session = ctx.sessions.get(args["session_id"])
    try:
        await unmount_session(ctx, session.session_id)
    except ProtocolError as exc:
        ctx.audit.write("unmount", session_id=session.session_id, result="error", error=exc.code)
        raise
    session.mounts.clear()
    ctx.audit.write("unmount", session_id=session.session_id, result="ok")
    return {"unmounted": True}


async def handle_release(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    """Close a session without ejecting (e.g. the device was physically removed)."""
    require_args(args, "session_id")
    if not mounts.valid_session_id(args["session_id"]):
        raise ProtocolError(E_INVALID_ARGUMENT, "invalid session_id")
    session = ctx.sessions.get(args["session_id"])
    await unmount_session(ctx, session.session_id)
    ctx.sessions.close(session.session_id)
    ctx.audit.write("release", session_id=session.session_id, result="ok")
    return {"released": True}
