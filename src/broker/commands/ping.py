from __future__ import annotations

from typing import Any

from ..context import BrokerContext, require_args


async def handle(ctx: BrokerContext, args: dict[str, Any]) -> dict[str, Any]:
    require_args(args)
    return {"pong": True}
