"""Entry point: python -m src.led [--config PATH] [--test]  (user usbscan-led, group gpio).

``--test`` is the installer's wiring check (docs/hardware-wiring.md): with the service
stopped it lights red, green, blue and white for two seconds each, then switches off.

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
import time
from collections.abc import Callable

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


WIRING_STEPS = (("red", (1.0, 0.0, 0.0)), ("green", (0.0, 1.0, 0.0)), ("blue", (0.0, 0.0, 1.0)),
                ("white", (1.0, 1.0, 1.0)), ("off", (0.0, 0.0, 0.0)))


def wiring_test(led_cfg, seconds: float = 2.0, sleep: Callable[[float], None] = time.sleep,
                driver=None) -> int:
    driver = driver or select_driver(led_cfg)
    print(f"driver {type(driver).__name__}, gpiochip {led_cfg.gpiochip}, BCM red={led_cfg.pin_red} "
          f"green={led_cfg.pin_green} blue={led_cfg.pin_blue}, common_anode={led_cfg.common_anode}")
    if type(driver).__name__ == "StubDriver":
        print("WARNING: stub driver - nothing is driven; set led.driver: lgpio", file=sys.stderr)
    try:
        for name, color in WIRING_STEPS:
            print(f"  {name}")
            driver.set(color)
            if name != "off":
                sleep(seconds)
    finally:
        driver.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-led")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    parser.add_argument("--test", action="store_true", help="wiring check (stop usb-scan-led first)")
    opts = parser.parse_args(argv)
    try:
        cfg = load_config(opts.config)
    except ConfigError as exc:
        print(f"usb-scan-led: {exc}", file=sys.stderr)
        return 2
    if opts.test:
        return wiring_test(cfg.led)
    setup_logging(cfg.logging.level, station_id=cfg.station.station_id, console=True)
    asyncio.run(run(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
