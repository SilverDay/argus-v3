import asyncio
import os
import threading

import pytest

from src.gui.ipc_worker import IpcWorker
from src.gui.main_window import MainWindow, current_screen_name
from src.shared.ipc import INBOUND_OPERATOR_TYPES, IPCServer
from src.shared.models import EventType, ScanEvent


class ServerThread:
    """Real IPCServer on its own asyncio loop, like the orchestrator."""

    def __init__(self, path):
        self.path = path
        self.received = []
        self.loop = asyncio.new_event_loop()

        async def on_message(event, creds):
            self.received.append((event, creds.uid))

        self.server = IPCServer(path, allowed_uids={os.getuid()}, inbound_types=INBOUND_OPERATOR_TYPES,
                                on_message=on_message,
                                on_connect=lambda creds: [ScanEvent(EventType.STATE_CHANGED, None, {"state": "IDLE"})])
        self.loop.run_until_complete(self.server.start())
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def broadcast(self, event):
        self.loop.call_soon_threadsafe(self.server.broadcast, event)

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.server.close(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


@pytest.fixture
def server(tmp_path):
    s = ServerThread(str(tmp_path / "state.sock"))
    yield s
    if s.thread.is_alive():
        s.stop()


def test_worker_drives_window_and_sends_operator_messages(qtbot, cfg, server):
    worker = IpcWorker(server.path, initial_backoff=0.05, max_backoff=0.2)
    window = MainWindow(cfg, worker.send)
    qtbot.addWidget(window)
    worker.event_received.connect(window.handle_event)
    worker.start()
    try:
        qtbot.waitUntil(lambda: current_screen_name(window) == "IDLE", timeout=5000)   # snapshot on connect
        server.broadcast(ScanEvent(EventType.STATE_CHANGED, "s1", {"state": "SCANNING"}))
        qtbot.waitUntil(lambda: current_screen_name(window) == "SCANNING", timeout=5000)

        worker.send(ScanEvent(EventType.OPERATOR_PIN_SUBMIT, None, {"pin": "482916"}))
        qtbot.waitUntil(lambda: len(server.received) == 1, timeout=5000)
        event, uid = server.received[0]
        assert event.event_type is EventType.OPERATOR_PIN_SUBMIT and uid == os.getuid()

        server.stop()                                                   # orchestrator goes away
        qtbot.waitUntil(lambda: current_screen_name(window) == "DISCONNECTED", timeout=5000)
    finally:
        worker.stop()
    assert not worker.isRunning()


def test_send_while_disconnected_reports_failure(qtbot, tmp_path):
    worker = IpcWorker(str(tmp_path / "none.sock"), initial_backoff=0.05, max_backoff=0.1)
    failures = []
    worker.send_failed.connect(failures.append)
    worker.start()
    try:
        worker.send(ScanEvent(EventType.OPERATOR_ACK, None))
        qtbot.waitUntil(lambda: failures == ["operator_ack"], timeout=2000)
    finally:
        worker.stop()
