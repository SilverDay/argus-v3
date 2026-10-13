import asyncio
import os
import socket
import threading
import time

import pytest

from src.orchestrator.scanner_clamav import (
    ClamdClient, ClamdUnavailable, ClamStatus, open_for_scan, parse_reply, parse_version,
)
from src.shared.models import Severity


# Replies observed from clamd 1.5.4 with AlertExceedsMax/AlertEncrypted enabled.
@pytest.mark.parametrize("reply,status,sig,sev", [
    ("fd[10]: OK\n", ClamStatus.CLEAN, "", None),
    ("fd[10]: Eicar-Test-Signature FOUND\n", ClamStatus.FOUND, "Eicar-Test-Signature", Severity.HIGH),
    ("fd[10]: Test.CleanHashSig.UNOFFICIAL FOUND\n", ClamStatus.FOUND, "Test.CleanHashSig.UNOFFICIAL", Severity.HIGH),
    ("fd[10]: Heuristics.Limits.Exceeded.MaxFiles FOUND\n", ClamStatus.LIMIT, "Heuristics.Limits.Exceeded.MaxFiles", None),
    ("fd[10]: Heuristics.Encrypted.Zip FOUND\n", ClamStatus.ENCRYPTED, "Heuristics.Encrypted.Zip", None),
    ("fd[10]: Heuristics.Phishing.Email.SpoofedDomain FOUND\n", ClamStatus.FOUND, None, Severity.MEDIUM),
    ("fd[10]: lstat() failed: No such file ERROR\n", ClamStatus.ERROR, None, None),
    ("garbage", ClamStatus.ERROR, None, None),
    ("", ClamStatus.ERROR, None, None),
])
def test_parse_reply(reply, status, sig, sev):
    r = parse_reply(reply)
    assert r.status is status
    if sig is not None:
        assert r.signature == sig
    assert r.severity is sev


def test_parse_version_with_and_without_db():
    v = parse_version("ClamAV 1.5.4/27800/Tue Oct 13 07:31:02 2026\n")
    assert (v.engine, v.db_version) == ("1.5.4", 27800)
    assert v.db_time == time.mktime(time.strptime("Tue Oct 13 07:31:02 2026", "%a %b %d %H:%M:%S %Y"))
    v = parse_version("ClamAV 1.5.4/27800/Mon Oct  5 07:31:02 2026")  # ctime pads the day
    assert v.db_time is not None
    v = parse_version("ClamAV 1.5.4\n")   # only unofficial databases loaded
    assert v.db_version is None and v.db_time is None
    with pytest.raises(ValueError):
        parse_version("COMMAND UNAVAILABLE")


def test_open_for_scan_refuses_symlink_and_fifo(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    link = tmp_path / "l"
    link.symlink_to(f)
    fifo = tmp_path / "p"
    os.mkfifo(fifo)
    os.close(open_for_scan(str(f)))
    with pytest.raises(OSError):
        open_for_scan(str(link))
    with pytest.raises(OSError):
        open_for_scan(str(fifo))   # must not block


class FakeClamd:
    """Accepts FILDES with SCM_RIGHTS, reads the passed fd, replies based on content."""

    def __init__(self, path, delay=0.0):
        self.path = path
        self.delay = delay
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(path)
        self.sock.listen(8)
        self.seen = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                # Command and the fd-carrying byte may arrive in one segment; always
                # receive with ancillary data so the descriptor is never dropped.
                cmd, fds, _, _ = socket.recv_fds(conn, 64, 1)
                if cmd.startswith(b"nPING"):
                    conn.sendall(b"PONG\n")
                    continue
                if cmd.startswith(b"nVERSION"):
                    conn.sendall(b"ClamAV 1.5.4/27800/Tue Oct 13 07:31:02 2026\n")
                    continue
                if not fds:
                    _, fds, _, _ = socket.recv_fds(conn, 16, 1)
                data = os.read(fds[0], 4096)
                os.close(fds[0])
                self.seen.append(data)
                time.sleep(self.delay)
                reply = b"fd[5]: Bad.Sig FOUND\n" if b"EVIL" in data else b"fd[5]: OK\n"
                try:
                    conn.sendall(reply)
                except OSError:
                    pass

    def close(self):
        self.sock.close()


async def test_fildes_round_trip(tmp_path):
    srv = FakeClamd(str(tmp_path / "clamd.sock"))
    try:
        client = ClamdClient(srv.path)
        assert await client.ping()
        assert (await client.version()).db_version == 27800
        for content, status in ((b"hello", ClamStatus.CLEAN), (b"xxEVILxx", ClamStatus.FOUND)):
            p = tmp_path / "f"
            p.write_bytes(content)
            fd = open_for_scan(str(p))
            try:
                res = await client.scan_fd(fd, 5)
            finally:
                os.close(fd)
            assert res.status is status
        assert srv.seen == [b"hello", b"xxEVILxx"]   # clamd received the file through the fd
    finally:
        srv.close()


async def test_timeout(tmp_path):
    srv = FakeClamd(str(tmp_path / "clamd.sock"), delay=1.0)
    try:
        p = tmp_path / "f"
        p.write_bytes(b"x")
        fd = open_for_scan(str(p))
        try:
            res = await ClamdClient(srv.path).scan_fd(fd, 0.2)
        finally:
            os.close(fd)
        assert res.status is ClamStatus.TIMEOUT
    finally:
        srv.close()


async def test_unavailable(tmp_path):
    with pytest.raises(ClamdUnavailable):
        await ClamdClient(str(tmp_path / "missing.sock"), connect_timeout=0.5).ping()
