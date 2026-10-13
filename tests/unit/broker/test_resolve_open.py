import asyncio
import base64
import os

import pytest

from src.broker import resolve
from src.broker.broker_server import BrokerServer
from src.broker.session import Session
from src.broker.sysfs import UsbDevice
from src.orchestrator.broker_client import BrokerClient, BrokerError

SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
KEY = os.urandom(32)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "mnt"
    (root / "private").mkdir(parents=True)
    (root / "private" / "doc.txt").write_bytes(b"secret")
    (root / "top.txt").write_bytes(b"top")
    (root / "link").symlink_to("/etc/passwd")
    (root / "dirlink").symlink_to(root / "private")
    os.mkfifo(root / "fifo")
    (root / b"bad\xffname".decode("utf-8", "surrogateescape")).write_bytes(b"x")
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
    yield root, fd
    os.close(fd)


def kind(root_fd, rel):
    opened = resolve.open_beneath(root_fd, rel)
    if opened.fd is not None:
        os.close(opened.fd)
    return opened.kind, opened.size


def test_files_dirs_and_raw_bytes(tree):
    _, fd = tree
    assert kind(fd, b"top.txt") == ("file", 3)
    assert kind(fd, b"private/doc.txt") == ("file", 6)
    assert kind(fd, b"private")[0] == "dir"
    assert kind(fd, b"")[0] == "dir"                  # mount root
    assert kind(fd, b"bad\xffname") == ("file", 1)


def test_links_and_special_never_followed(tree):
    _, fd = tree
    assert kind(fd, b"link")[0] == "symlink"
    assert kind(fd, b"dirlink/doc.txt")[0] == "symlink"   # symlink inside the path
    assert kind(fd, b"fifo")[0] == "special"              # O_NONBLOCK: does not hang
    assert kind(fd, b"nope")[0] == "missing"


@pytest.mark.parametrize("rel", [b"/etc/passwd", b"../x", b"private/../../x", b"a\0b", b"x" * 5000])
def test_escapes_rejected(tree, rel):
    _, fd = tree
    with pytest.raises(ValueError):
        resolve.open_beneath(fd, rel)


def test_beneath_enforced_by_kernel(tree):
    """Even without the lexical checks, openat2 itself refuses '..' escapes."""
    _, fd = tree
    with pytest.raises(OSError):
        resolve.openat2(fd, b"../")


# --- through the broker socket with fd passing ---------------------------------

@pytest.fixture
async def served(host, ctx, tree, tmp_path):
    host.build()          # fake /proc for unmount bookkeeping
    root, root_fd = tree
    session = Session(SESSION, UsbDevice("1-1", "/x", 1, 1, "", "", ""))
    session.root_fds["part1"] = os.dup(root_fd)
    ctx.sessions.open(session)
    srv = BrokerServer(ctx, socket_path=str(tmp_path / "broker.sock"), hmac_key=KEY, client_uid=os.getuid())
    await srv.start()
    yield srv, BrokerClient(srv.socket_path, KEY), root
    await srv.close()
    session.close_root_fds()


async def test_open_passes_readonly_fd(served):
    srv, client, root = served
    kind_, fd, size = await asyncio.to_thread(client.open_path, SESSION, "part1", b"private/doc.txt")
    try:
        assert (kind_, size) == ("file", 6)
        assert os.pread(fd, 100, 0) == b"secret"
        with pytest.raises(OSError):
            os.write(fd, b"x")                       # read-only descriptor
    finally:
        os.close(fd)
    assert await asyncio.to_thread(client.open_path, SESSION, "part1", b"link") == ("symlink", None, 0)


async def test_open_rejects_escape_and_unknown_partition(served):
    srv, client, _ = served
    with pytest.raises(BrokerError) as exc:
        await asyncio.to_thread(client.open_path, SESSION, "part1", b"../../etc/shadow")
    assert exc.value.code == "invalid_argument"
    with pytest.raises(BrokerError) as exc:
        await asyncio.to_thread(client.open_path, SESSION, "part2", b"top.txt")
    assert exc.value.code == "not_found"


async def test_open_count_audited_at_unmount(served, ctx):
    srv, client, _ = served
    for _ in range(3):
        _, fd, _ = await asyncio.to_thread(client.open_path, SESSION, "part1", b"top.txt")
        os.close(fd)
    from src.broker.commands.unmount import unmount_session
    await unmount_session(ctx, SESSION)
    with open(ctx.audit.path) as fh:
        text = fh.read()
    assert '"action":"confined_opens"' in text and '"count":3' in text


def test_bad_base64_rejected(ctx):
    from src.broker.commands.open import handle
    from src.shared.broker_protocol import ProtocolError
    with pytest.raises(ProtocolError):
        asyncio.run(handle(ctx, {"session_id": SESSION, "partition_id": "part1", "path_b64": "%%%"}))
    assert base64  # imported for clarity of the protocol encoding
