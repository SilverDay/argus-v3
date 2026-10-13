import asyncio
import os

import pytest

from src.orchestrator.scanner_yara_client import YaraClient, YaraUnavailable
from src.yara_worker.rules import RuleStore
from src.yara_worker.yara_server import YaraServer
from tests.unit.yara_worker.bundle import MINISIGN, make_bundle, make_keypair, yara_cfg

pytestmark = pytest.mark.skipif(MINISIGN is None, reason="minisign not installed")

RULES = {
    "malware.yar": 'rule evil_high { meta: severity = "high" strings: $a = "EVILMARK" condition: $a }',
    "hunting.yar": 'rule odd_medium { strings: $a = "ODDMARK" condition: $a }',
    "slow.yar": 'rule slow { strings: $a = /a.*b.*c.*d.*e.*f/ condition: $a }',
}


@pytest.fixture
def bundle(tmp_path):
    pub, sec = make_keypair(str(tmp_path))
    rules = make_bundle(str(tmp_path / "rules"), sec, RULES, version=2)
    return pub, rules


async def start_server(tmp_path, bundle, *, load=True, uid=None, **overrides):
    pub, rules = bundle
    cfg = yara_cfg(rules, pub, str(tmp_path / "state"), socket_path=str(tmp_path / "yara.sock"),
                   **{"per_file_timeout_seconds": 1, "memory_limit_mb": 1024, **overrides})
    store = RuleStore(cfg)
    if load:
        assert store.reload(), store.last_error
    server = YaraServer(cfg, store, client_uid=os.getuid() if uid is None else uid)
    await server.start()
    return server, cfg


def fd_for(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return os.open(p, os.O_RDONLY)


async def scan(session, fd):
    try:
        return await session.scan_fd(fd)
    finally:
        os.close(fd)


async def test_scan_results_via_fd(tmp_path, bundle):
    server, cfg = await start_server(tmp_path, bundle)
    try:
        session = await YaraClient(cfg.socket_path).session()
        assert session.rules_version.startswith("2:")
        r = await scan(session, fd_for(tmp_path, "a", b"xxEVILMARKxx"))
        assert r.status == "match"
        assert r.matches == [{"rule": "evil_high", "namespace": "malware", "tags": [], "severity": "high"}]
        r = await scan(session, fd_for(tmp_path, "b", b"..ODDMARK.."))
        assert r.matches[0]["severity"] == "medium"
        assert (await scan(session, fd_for(tmp_path, "c", b"harmless"))).status == "clean"
        assert (await scan(session, fd_for(tmp_path, "d", b""))).status == "clean"
        await session.bye()
    finally:
        await server.close()


async def test_native_timeout(tmp_path, bundle):
    server, cfg = await start_server(tmp_path, bundle)
    try:
        session = await YaraClient(cfg.socket_path).session()
        r = await scan(session, fd_for(tmp_path, "slow", b"a" * 3_000_000))
        assert r.status == "timeout"
        assert (await scan(session, fd_for(tmp_path, "ok", b"fine"))).status == "clean"   # session survives
        await session.bye()
    finally:
        await server.close()


async def test_too_large_and_non_regular(tmp_path, bundle):
    server, cfg = await start_server(tmp_path, bundle, max_file_size_mb=1)
    try:
        session = await YaraClient(cfg.socket_path).session()
        assert (await scan(session, fd_for(tmp_path, "big", b"x" * (1024 * 1024 + 1)))).status == "too_large"
        r_fd, w_fd = os.pipe()
        os.close(w_fd)
        r = await scan(session, r_fd)
        assert (r.status, r.reason) == ("error", "not_regular")
        await session.bye()
    finally:
        await server.close()


async def test_ruleset_unavailable_reported(tmp_path, bundle):
    server, cfg = await start_server(tmp_path, bundle, load=False)
    try:
        with pytest.raises(YaraUnavailable) as exc:
            await YaraClient(cfg.socket_path).session()
        assert exc.value.reason == "ruleset_unavailable"
    finally:
        await server.close()


async def test_wrong_uid_refused(tmp_path, bundle):
    server, cfg = await start_server(tmp_path, bundle, uid=os.getuid() + 777)
    try:
        with pytest.raises(YaraUnavailable):
            await YaraClient(cfg.socket_path).session()
    finally:
        await server.close()


async def test_supervisor_kills_child_when_budget_exhausted(tmp_path, bundle):
    server, cfg = await start_server(tmp_path, bundle)
    object.__setattr__(cfg, "global_budget_seconds", 1)
    try:
        session = await YaraClient(cfg.socket_path, reply_timeout=5).session()
        await asyncio.sleep(1.5)
        with pytest.raises(YaraUnavailable):
            await scan(session, fd_for(tmp_path, "late", b"x"))
        assert server.budget_kills == 1
    finally:
        await server.close()


async def test_child_has_no_path_to_files(tmp_path, bundle):
    """The worker only ever sees descriptors: an unlinked file is still scanned."""
    server, cfg = await start_server(tmp_path, bundle)
    try:
        session = await YaraClient(cfg.socket_path).session()
        fd = fd_for(tmp_path, "gone", b"EVILMARK")
        os.unlink(tmp_path / "gone")
        assert (await scan(session, fd)).status == "match"
        await session.bye()
    finally:
        await server.close()
