import asyncio
import json
import os
import stat

import pytest

from src.broker.broker_server import BrokerServer
from src.shared import broker_protocol as bp

KEY = os.urandom(32)


@pytest.fixture
async def server(ctx, tmp_path):
    srv = BrokerServer(ctx, socket_path=str(tmp_path / "broker.sock"), hmac_key=KEY,
                       client_uid=os.getuid())
    await srv.start()
    yield srv
    await srv.close()


async def roundtrip(path, line):
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write(line)
    await writer.drain()
    resp = await asyncio.wait_for(reader.readline(), 5)
    writer.close()
    return resp


async def request(path, cmd, args=None, key=KEY):
    line, nonce = bp.build_request(key, cmd, args)
    return bp.parse_response(KEY, await roundtrip(path, line), nonce)


async def test_socket_permissions(server):
    assert stat.S_IMODE(os.stat(server.socket_path).st_mode) == 0o660


async def test_ping(server):
    assert await request(server.socket_path, "ping") == {"pong": True}


async def test_unknown_command(server):
    with pytest.raises(bp.ProtocolError) as exc:
        await request(server.socket_path, "shell", {"cmd": "id"})
    assert exc.value.code == bp.E_UNKNOWN_COMMAND


async def test_raw_dev_path_rejected(server):
    with pytest.raises(bp.ProtocolError) as exc:
        await request(server.socket_path, "enumerate",
                      {"sysfs_path": "/dev/sda1", "session_id": "0f8fad5b-d9cb-469f-a165-70867728950e"})
    assert exc.value.code == bp.E_INVALID_ARGUMENT


async def test_bad_hmac_rejected(server):
    with pytest.raises(bp.ProtocolError) as exc:
        await request(server.socket_path, "ping", key=b"z" * 32)
    assert exc.value.code == bp.E_UNAUTHORIZED


async def test_replayed_request_rejected(server):
    line, nonce = bp.build_request(KEY, "ping")
    bp.parse_response(KEY, await roundtrip(server.socket_path, line), nonce)
    with pytest.raises(bp.ProtocolError) as exc:
        bp.parse_response(KEY, await roundtrip(server.socket_path, line), nonce)
    assert exc.value.code == bp.E_REPLAY


async def test_garbage_never_crashes_server(server):
    resp = json.loads(await roundtrip(server.socket_path, b"{garbage\n"))
    assert resp["ok"] is False and resp["error"] == bp.E_BAD_REQUEST
    assert await request(server.socket_path, "ping") == {"pong": True}


async def test_wrong_uid_refused(ctx, tmp_path):
    srv = BrokerServer(ctx, socket_path=str(tmp_path / "b.sock"), hmac_key=KEY, client_uid=os.getuid() + 4242)
    await srv.start()
    try:
        line, _ = bp.build_request(KEY, "ping")
        try:
            assert await roundtrip(srv.socket_path, line) == b""
        except ConnectionResetError:
            pass  # closed with our request unread: also a refusal
    finally:
        await srv.close()
    with open(ctx.audit.path) as fh:
        assert "refused_connection" in fh.read()


async def test_command_timeout(server, monkeypatch):
    async def slow(ctx, args):
        await asyncio.sleep(10)

    monkeypatch.setitem(__import__("src.broker.commands", fromlist=["COMMANDS"]).COMMANDS, "ping", slow)
    server._timeout = 0.1
    with pytest.raises(bp.ProtocolError) as exc:
        await request(server.socket_path, "ping")
    assert exc.value.code == bp.E_INTERNAL
