"""IPC worker: runs the shared asyncio IPCClient in a QThread (spec §4.2, plan Phase 5).

Incoming ScanEvents are delivered to the GUI thread only via the Qt signal
``event_received`` (queued connection). Outgoing operator messages are scheduled on the
worker's loop; nothing blocks the UI thread.
"""
from __future__ import annotations

import asyncio
import threading

from PySide6.QtCore import QThread, Signal

from src.shared.ipc import IPCClient, IPCError
from src.shared.models import ScanEvent


class IpcWorker(QThread):
    event_received = Signal(object)      # ScanEvent
    send_failed = Signal(str)

    def __init__(self, socket_path: str, parent=None, *, initial_backoff: float = 0.5,
                 max_backoff: float = 30.0) -> None:
        super().__init__(parent)
        self.socket_path = socket_path
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client: IPCClient | None = None
        self._stop_requested = threading.Event()
        self._ready = threading.Lock()

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        client = IPCClient(self.socket_path, self.event_received.emit,
                           initial_backoff=self._initial_backoff, max_backoff=self._max_backoff)
        with self._ready:
            self._loop, self._client = loop, client
            if self._stop_requested.is_set():        # stop() raced with thread start-up
                client.stop()
        try:
            loop.run_until_complete(client.run())
        finally:
            with self._ready:                       # never close while stop() schedules on it
                self._loop = None
                loop.close()

    def send(self, event: ScanEvent) -> None:
        loop, client = self._loop, self._client
        if loop is None or client is None or not client.connected:
            self.send_failed.emit(event.event_type.value)
            return

        async def _send() -> None:
            try:
                await client.send(event)
            except (IPCError, OSError):
                self.send_failed.emit(event.event_type.value)

        asyncio.run_coroutine_threadsafe(_send(), loop)

    def stop(self) -> None:
        with self._ready:
            self._stop_requested.set()
            loop, client = self._loop, self._client
            if loop is not None and client is not None and not loop.is_closed():
                loop.call_soon_threadsafe(client.stop)
        self.wait(5000)
