"""Entry point: python -m src.yara_worker [--config PATH]  (runs as user yarascan).

The ruleset is verified and compiled at start and on SIGHUP. Without a verified ruleset
the worker still serves the socket and answers ``ruleset_unavailable``, so the
orchestrator's health gate can report NOT_READY (mandatory) instead of systemd
restart-looping the service.
"""
from __future__ import annotations

import argparse
import asyncio
import grp
import logging
import os
import pwd
import signal
import sys

from src.shared.config import ConfigError, load_config
from src.shared.logging_setup import setup_logging
from src.shared.sd_notify import notify, watchdog_loop

from .rules import RuleStore
from .yara_server import YaraServer

log = logging.getLogger("usb-scan.yara")


async def run(cfg) -> None:
    store = RuleStore(cfg.yara)
    server = YaraServer(cfg.yara, store, client_uid=pwd.getpwnam(cfg.yara.client_user).pw_uid,
                        socket_gid=grp.getgrnam(cfg.yara.socket_group).gr_gid)
    server.reload()
    await server.start()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGHUP, server.reload)
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    watchdog = asyncio.create_task(watchdog_loop())
    watcher = asyncio.create_task(watch_active_link(server, cfg.yara.rules_path))
    notify("READY=1")
    await stop.wait()
    notify("STOPPING=1")
    watchdog.cancel()
    watcher.cancel()
    await server.close()


async def watch_active_link(server, rules_path: str, interval: float = 30.0, retries: int = 3) -> None:
    """Reload when the installer switches the ``active`` link (it runs as another user and
    cannot signal this process). A failed load is retried a few times for the same target:
    a reload racing the switch may see a mixed bundle and is rejected by the hash checks."""
    seen = os.path.realpath(rules_path)
    failures = 0
    while True:
        await asyncio.sleep(interval)
        target = os.path.realpath(rules_path)
        if target != seen:
            seen, failures = target, 0
        elif failures == 0 or failures >= retries:
            continue
        if await asyncio.to_thread(server.reload):
            failures = 0
            seen = target
        else:
            failures += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-yara")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    opts = parser.parse_args(argv)
    try:
        cfg = load_config(opts.config)
    except ConfigError as exc:
        print(f"usb-scan-yara: {exc}", file=sys.stderr)
        return 2
    if not cfg.yara.enabled:
        print("usb-scan-yara: yara.enabled is false; nothing to do", file=sys.stderr)
        return 0
    setup_logging(cfg.logging.level, station_id=cfg.station.station_id, console=True)
    asyncio.run(run(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
