"""The AC-S04 acceptance probe's expectations, checked against the real broker server."""
import asyncio
import os

import pytest

from src.broker.broker_server import BrokerServer
from tests.acceptance.probes import broker_cases, connect

KEY = os.urandom(32)


@pytest.fixture
async def server(ctx, tmp_path):
    srv = BrokerServer(ctx, socket_path=str(tmp_path / "broker.sock"), hmac_key=KEY, client_uid=os.getuid())
    await srv.start()
    yield srv
    await srv.close()


async def test_probe_cases_all_refused_by_broker(server):
    out = await asyncio.to_thread(broker_cases, server.socket_path, KEY,
                                  "/sys/devices/platform/axi/1000fff000.mmc/mmc_host/mmc0/mmc0:0001")
    assert out["ok"], [c for c in out["cases"] if not c["ok"]]
    assert out["cases"][0]["got"] == "ok"            # the channel itself works


async def test_connect_probe_distinguishes_accept_and_refuse(server, ctx, tmp_path):
    assert (await asyncio.to_thread(connect, server.socket_path))["result"] == "accepted"
    other = BrokerServer(ctx, socket_path=str(tmp_path / "b2.sock"), hmac_key=KEY, client_uid=os.getuid() + 4242)
    await other.start()
    try:
        assert (await asyncio.to_thread(connect, other.socket_path))["result"] == "refused"
    finally:
        await other.close()
    assert (await asyncio.to_thread(connect, str(tmp_path / "none.sock")))["result"] == "missing"
