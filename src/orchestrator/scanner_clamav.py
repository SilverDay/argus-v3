"""clamd client using FILDES (file-descriptor passing over the Unix socket).

The orchestrator opens each file itself (O_RDONLY|O_NOFOLLOW|O_NONBLOCK, regular
files only) and passes the descriptor to clamd. clamd therefore needs no path
access to USB mounts and can be sandboxed without ReadOnlyPaths= tricks, and
INSTREAM's StreamMaxLength limit does not apply. (clamd(8): "FILDES ... This
command only works on UNIX domain sockets.")

Result mapping (observed with clamd 1.5.4, AlertExceedsMax/AlertEncrypted enabled):
  "fd[N]: OK"                                        -> CLEAN
  "fd[N]: Heuristics.Limits.Exceeded.<Limit> FOUND"  -> LIMIT (skip: scan_limit)
  "fd[N]: Heuristics.Encrypted.<Type> FOUND"         -> ENCRYPTED (uninspectable)
  "fd[N]: Heuristics.<...> FOUND"                    -> FOUND, severity medium
  "fd[N]: <Signature> FOUND"                         -> FOUND, severity high
  anything else / "... ERROR"                        -> ERROR
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import stat
import time
from dataclasses import dataclass
from enum import Enum

from src.shared.models import Severity

_REPLY = re.compile(r"^fd\[\d+\]: (.+) (FOUND|ERROR)$|^fd\[\d+\]: (OK)$")
_VERSION = re.compile(r"^ClamAV ([0-9][^/\s]*)(?:/(\d+)/(.+))?$")
MAX_REPLY = 4096


class ClamStatus(str, Enum):
    CLEAN = "clean"
    FOUND = "found"
    LIMIT = "limit"
    ENCRYPTED = "encrypted"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ClamResult:
    status: ClamStatus
    signature: str = ""
    severity: Severity | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class ClamVersion:
    engine: str
    db_version: int | None
    db_time: float | None        # UNIX time of the newest signature database


class ClamdUnavailable(Exception):
    """clamd cannot be reached at all (mandatory engine failure)."""


def parse_reply(text: str) -> ClamResult:
    text = text.strip("\0\n ")
    m = _REPLY.match(text)
    if not m:
        return ClamResult(ClamStatus.ERROR, text[:200])
    if m.group(3) == "OK":
        return ClamResult(ClamStatus.CLEAN)
    name, kind = m.group(1), m.group(2)
    if kind == "ERROR":
        return ClamResult(ClamStatus.ERROR, name[:200])
    if name.startswith("Heuristics.Limits.Exceeded"):
        return ClamResult(ClamStatus.LIMIT, name)
    if name.startswith("Heuristics.Encrypted"):
        return ClamResult(ClamStatus.ENCRYPTED, name)
    severity = Severity.MEDIUM if name.startswith("Heuristics.") else Severity.HIGH
    return ClamResult(ClamStatus.FOUND, name, severity)


def parse_version(text: str) -> ClamVersion:
    """``ClamAV <engine>[/<db version>/<ctime>]`` (clamd/session.c print_ver).

    The date is ctime() in clamd's local time zone; the appliance runs in UTC and the
    orchestrator parses it in its own local zone, which is the same host setting.
    """
    m = _VERSION.match(text.strip("\0\n "))
    if not m:
        raise ValueError("unrecognised VERSION reply")
    if not m.group(2):
        return ClamVersion(m.group(1), None, None)
    try:
        db_time = time.mktime(time.strptime(" ".join(m.group(3).split()), "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        db_time = None
    return ClamVersion(m.group(1), int(m.group(2)), db_time)


def open_for_scan(path: str) -> int:
    """Open a regular file without following symlinks or blocking on FIFOs."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(0, "not a regular file")
        os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return fd


class ClamdClient:
    def __init__(self, socket_path: str, *, connect_timeout: float = 10.0) -> None:
        self.socket_path = socket_path
        self.connect_timeout = connect_timeout

    async def _open(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(loop.sock_connect(sock, self.socket_path), self.connect_timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            sock.close()
            raise ClamdUnavailable(str(exc) or "connect timeout") from None
        return sock

    @staticmethod
    async def _read_reply(sock: socket.socket) -> str:
        loop = asyncio.get_running_loop()
        buf = b""
        while not buf.endswith(b"\n") and len(buf) < MAX_REPLY:
            chunk = await loop.sock_recv(sock, MAX_REPLY)
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace")

    async def _simple(self, command: bytes) -> str:
        sock = await self._open()
        try:
            await asyncio.get_running_loop().sock_sendall(sock, command)
            reply = await asyncio.wait_for(self._read_reply(sock), self.connect_timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise ClamdUnavailable(str(exc) or "timeout") from None
        finally:
            sock.close()
        return reply.strip()

    async def ping(self) -> bool:
        return await self._simple(b"nPING\n") == "PONG"

    async def version(self) -> ClamVersion:
        return parse_version(await self._simple(b"nVERSION\n"))

    async def scan_fd(self, fd: int, timeout: float) -> ClamResult:
        """Scan an open file descriptor. Raises ClamdUnavailable if clamd cannot be reached."""
        started = time.monotonic()
        sock = await self._open()
        loop = asyncio.get_running_loop()
        try:
            try:
                await loop.sock_sendall(sock, b"nFILDES\n")
                # Tiny ancillary-data message; never blocks meaningfully on a fresh socket.
                sock.setblocking(True)
                socket.send_fds(sock, [b"\0"], [fd])
                sock.setblocking(False)
            except OSError as exc:
                raise ClamdUnavailable(str(exc)) from None
            try:
                reply = await asyncio.wait_for(self._read_reply(sock), timeout)
            except asyncio.TimeoutError:
                return ClamResult(ClamStatus.TIMEOUT, duration_ms=int((time.monotonic() - started) * 1000))
            except OSError as exc:
                raise ClamdUnavailable(str(exc)) from None
            if not reply:
                raise ClamdUnavailable("connection closed without reply")
            result = parse_reply(reply)
            return ClamResult(result.status, result.signature, result.severity,
                              int((time.monotonic() - started) * 1000))
        finally:
            sock.close()
