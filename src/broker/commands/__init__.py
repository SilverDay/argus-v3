"""Strict command allowlist. Anything not listed here is ``unknown_command``."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..context import BrokerContext
from . import eject, enumerate, mount, ping, unmount

Handler = Callable[[BrokerContext, dict[str, Any]], Awaitable[dict[str, Any]]]

COMMANDS: dict[str, Handler] = {
    "ping": ping.handle,
    "enumerate": enumerate.handle,
    "mount": mount.handle,
    "unmount": unmount.handle,
    "release": unmount.handle_release,
    "eject": eject.handle,
}
