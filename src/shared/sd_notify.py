"""Minimal systemd notify protocol (READY=1, WATCHDOG=1) without extra dependencies.

All services use Type=notify and WatchdogSec=30 (spec §11 service recovery).
Outside systemd (NOTIFY_SOCKET unset) every call is a no-op.
"""
from __future__ import annotations

import asyncio
import os
import socket


def notify(message: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    elif not addr.startswith("/"):
        return False
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
        try:
            sock.sendto(message.encode(), addr)
        except OSError:
            return False
    return True


def watchdog_interval() -> float | None:
    """Half of WATCHDOG_USEC in seconds, if the watchdog is enabled for this process."""
    usec = os.environ.get("WATCHDOG_USEC")
    pid = os.environ.get("WATCHDOG_PID")
    if not usec or (pid and pid != str(os.getpid())):
        return None
    try:
        return int(usec) / 2_000_000
    except ValueError:
        return None


async def watchdog_loop(healthy=lambda: True) -> None:
    """Ping the watchdog while ``healthy()`` is true; stop pinging otherwise so systemd restarts us."""
    interval = watchdog_interval()
    if interval is None:
        return
    while True:
        if healthy():
            notify("WATCHDOG=1")
        await asyncio.sleep(interval)
