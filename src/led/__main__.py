"""Entry point: python -m src.led [--config PATH]  (user usbscan-led, group gpio).

Subscribes to the orchestrator state socket directly (no GUI bridge), so the status
light keeps working if the GUI crashes. If the orchestrator is unreachable the LED
shows the NOT_READY pattern. SIGTERM turns the LED off and releases the GPIOs.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from src.shared.config import ConfigError, load_config
from src.shared.ipc import IPCClient
from src.shared.logging_setup import setup_logging
from src.shared.sd_notify import notify, watchdog_loop

from .controller import LedController
from .drivers import select_driver

log = logging.getLogger("usb-scan.led")


async def run(cfg) -> None:
    controller = LedController(select_driver(cfg.led), cfg.led)
    controller.start()
    client = IPCClient(cfg.orchestrator.state_socket, controller.on_event)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    tasks = [asyncio.create_task(client.run()), asyncio.create_task(watchdog_loop())]
    notify("READY=1")
    try:
        await stop.wait()
    finally:
        notify("STOPPING=1")
        client.stop()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        controller.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-led")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    opts = parser.parse_args(argv)
    try:
        cfg = load_config(opts.config)
    except ConfigError as exc:
        print(f"usb-scan-led: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.logging.level, station_id=cfg.station.station_id, console=True)
    asyncio.run(run(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
