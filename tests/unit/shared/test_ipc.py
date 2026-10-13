import asyncio
import json
import os
import stat

import pytest

from src.shared.ipc import (
    INBOUND_OPERATOR_TYPES, IPCClient, IPCError, IPCServer, MAX_LINE_BYTES, decode_event, encode_event,
)
from src.shared.models import EventType, ScanEvent


@pytest.fixture
def sock_path(tmp_path):
    return str(tmp_path / "state.sock")


async def _wait_for(pred, timeout=2.0):
    end = asyncio.get_running_loop().time() + timeout
    while not pred():
        if asyncio.get_running_loop().time() > end:
            raise AssertionError("condition not met")
        await asyncio.sleep(0.01)


def test_encode_decode_round_trip():
    e = ScanEvent(EventType.SCAN_PROGRESS, "s1", {"files_scanned": 3})
    line = encode_event(e)
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert decode_event(line) == e


@pytest.mark.parametrize("line", [b"{not json", b"[]", json.dumps({"event_type": "verdict"}).encode()])
def test_decode_rejects_garbage(line):
    with pytest.raises(IPCError):
        decode_event(line)


async def test_socket_mode_and_broadcast(sock_path):
    server = IPCServer(sock_path, allowed_uids={os.getuid()}, mode=0o660)
    await server.start()
    assert stat.S_IMODE(os.stat(sock_path).st_mode) == 0o660
    received = []
    client = IPCClient(sock_path, received.append, initial_backoff=0.05)
    task = asyncio.create_task(client.run())
    try:
        await _wait_for(lambda: server.client_count == 1)
        server.broadcast(ScanEvent(EventType.STATE_CHANGED, None, {"state": "IDLE"}))
        await _wait_for(lambda: any(e.event_type is EventType.STATE_CHANGED for e in received))
        assert received[0].event_type is EventType.IPC_CONNECTED
        assert received[-1].payload == {"state": "IDLE"}
    finally:
        client.stop()
        await server.close()
        await asyncio.wait_for(task, 2)
    assert not os.path.exists(sock_path)


async def test_unauthorized_uid_rejected(sock_path):
    server = IPCServer(sock_path, allowed_uids={os.getuid() + 12345})
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(sock_path)
        assert await asyncio.wait_for(reader.read(), 2) == b""  # closed by server
        writer.close()
        assert server.client_count == 0
    finally:
        await server.close()


async def test_inbound_allowlist_and_handler(sock_path):
    got = []

    async def on_message(event, creds):
        got.append((event, creds.uid))

    server = IPCServer(sock_path, allowed_uids={os.getuid()},
                       inbound_types=INBOUND_OPERATOR_TYPES, on_message=on_message)
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(sock_path)
        writer.write(encode_event(ScanEvent(EventType.OPERATOR_ACK, "s1")))
        await writer.drain()
        await _wait_for(lambda: len(got) == 1)
        assert got[0][1] == os.getuid()
        # A client may not inject orchestrator-only events such as a verdict.
        writer.write(encode_event(ScanEvent(EventType.VERDICT, "s1", {"verdict": "CLEAN"})))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2) == b""
        assert len(got) == 1
        writer.close()
    finally:
        await server.close()


async def test_oversized_line_disconnects(sock_path):
    server = IPCServer(sock_path, allowed_uids={os.getuid()},
                       inbound_types=INBOUND_OPERATOR_TYPES, on_message=lambda e, c: asyncio.sleep(0))
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(sock_path)
        writer.write(b"x" * (MAX_LINE_BYTES * 2))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
    finally:
        await server.close()


async def test_refuses_to_replace_regular_file(sock_path):
    open(sock_path, "w").close()
    with pytest.raises(IPCError, match="non-socket"):
        await IPCServer(sock_path, allowed_uids={os.getuid()}).start()


async def test_client_reconnects_after_server_restart(sock_path):
    received = []
    client = IPCClient(sock_path, received.append, initial_backoff=0.02, max_backoff=0.1)
    task = asyncio.create_task(client.run())
    try:
        await asyncio.sleep(0.1)  # server not up yet: client backs off
        assert not client.connected
        server = IPCServer(sock_path, allowed_uids={os.getuid()})
        await server.start()
        await _wait_for(lambda: client.connected)
        await server.close()
        await _wait_for(lambda: any(e.event_type is EventType.IPC_DISCONNECTED for e in received))
        server = IPCServer(sock_path, allowed_uids={os.getuid()})
        await server.start()
        await _wait_for(lambda: [e.event_type for e in received].count(EventType.IPC_CONNECTED) == 2)
        await server.close()
    finally:
        client.stop()
        await asyncio.wait_for(task, 2)


async def test_slow_client_dropped_without_blocking(sock_path, monkeypatch):
    monkeypatch.setattr("src.shared.ipc.CLIENT_QUEUE_SIZE", 2)
    server = IPCServer(sock_path, allowed_uids={os.getuid()})
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(sock_path)
        await _wait_for(lambda: server.client_count == 1)
        for _ in range(10):  # no await between sends: the writer task never drains
            server.broadcast(ScanEvent(EventType.SCAN_PROGRESS, "s1", {"n": 1}))
        assert server.client_count == 0
        writer.close()
    finally:
        await server.close()
