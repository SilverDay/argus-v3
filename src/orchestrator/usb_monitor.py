"""USB device add/remove detection via udev netlink (pyudev). No D-Bus, no mounting.

Watches ``usb``/``usb_device`` events (one per physical device, whether or not USBGuard
authorised it), so USBGuard rejections also reach the orchestrator and can be shown as
REJECTED (AC-S02). Root hubs (``usbN``) and configured internal paths are ignored.
Events are handed to the asyncio loop thread-safely; the callback runs in pyudev's
observer thread and must not block.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass

from .device_check import is_usb_port

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class UsbEvent:
    action: str          # "add" | "remove"
    port: str            # e.g. "1-1"
    sys_path: str        # real sysfs path reported by udev

    @property
    def sysfs_path(self) -> str:
        return f"/sys/bus/usb/devices/{self.port}"


def to_event(action: str | None, sys_name: str, sys_path: str, device_type: str | None,
             internal_prefixes: tuple[str, ...]) -> UsbEvent | None:
    if action not in ("add", "remove") or device_type != "usb_device" or not is_usb_port(sys_name):
        return None
    if any(p and sys_path.startswith(p) for p in internal_prefixes):
        return None
    return UsbEvent(action, sys_name, sys_path)


class UsbMonitor:
    def __init__(self, loop: asyncio.AbstractEventLoop, sink: Callable[[UsbEvent], None],
                 internal_prefixes: tuple[str, ...] = ()) -> None:
        self._loop = loop
        self._sink = sink
        self._internal = internal_prefixes
        self._observer = None

    def _on_device(self, device) -> None:
        event = to_event(device.action, device.sys_name, device.sys_path, device.device_type, self._internal)
        if event is not None:
            self._loop.call_soon_threadsafe(self._sink, event)

    def start(self) -> list[UsbEvent]:
        """Start monitoring; return 'add' events for devices already present (coldplug)."""
        import pyudev

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="usb", device_type="usb_device")
        self._observer = pyudev.MonitorObserver(monitor, callback=self._on_device, name="usb-monitor", daemon=True)
        self._observer.start()
        present = []
        for dev in context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            ev = to_event("add", dev.sys_name, dev.sys_path, dev.device_type, self._internal)
            if ev is not None:
                present.append(ev)
        return present

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.send_stop()
