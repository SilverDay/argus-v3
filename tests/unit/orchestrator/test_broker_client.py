import os

import pytest

from src.broker.audit import AuditLog
from src.broker.broker_server import BrokerServer
from src.broker.context import BrokerContext
from src.broker.sysenv import SysEnv
from src.orchestrator.broker_client import BrokerClient, BrokerError, BrokerUnavailable

KEY = os.urandom(32)


@pytest.fixture
async def server(tmp_path):
    audit = AuditLog(str(tmp_path / "audit.log"))
    ctx = BrokerContext(env=SysEnv(sysfs_root=str(tmp_path / "sys")), audit=audit,
                        mounts_dir=str(tmp_path / "mounts"), read_gid=os.getgid())
    srv = BrokerServer(ctx, socket_path=str(tmp_path / "broker.sock"), hmac_key=KEY, client_uid=os.getuid())
    await srv.start()
    yield srv
    await srv.close()
    audit.close()


async def test_ping_and_errors(server):
    client = BrokerClient(server.socket_path, KEY)
    assert await client.ping()
    with pytest.raises(BrokerError) as exc:
        await client.enumerate("/dev/sda1", "0f8fad5b-d9cb-469f-a165-70867728950e")
    assert exc.value.code == "invalid_argument"
    with pytest.raises(BrokerError) as exc:
        await client.unmount("0f8fad5b-d9cb-469f-a165-70867728950e")
    assert exc.value.code == "not_found"


async def test_wrong_key_is_rejected(server):
    with pytest.raises(BrokerError) as exc:
        await BrokerClient(server.socket_path, b"w" * 32).ping()
    assert exc.value.code == "unauthorized"


async def test_unavailable_after_retries(tmp_path):
    client = BrokerClient(str(tmp_path / "none.sock"), KEY, attempts=2, backoff=0.01)
    with pytest.raises(BrokerUnavailable):
        await client.ping()
