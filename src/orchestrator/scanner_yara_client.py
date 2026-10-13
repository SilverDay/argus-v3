"""Orchestrator-side client for the isolated YARA worker (spec §3.2 step 6).

One worker session (= one disposable child) per scan. Files are sent as read-only
descriptors, never as paths or content. Requests on a session are serialised.
Any transport failure makes the session unusable (YaraUnavailable); the caller then
records YARA as incomplete for the remaining files.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Any

from src.shared import yara_protocol as yp


class YaraUnavailable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class YaraResult:
    status: str                       # clean | match | timeout | too_large | error
    matches: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""


class YaraSession:
    def __init__(self, sock: socket.socket, rules_version: str, reply_timeout: float) -> None:
        self._sock = sock
        self.rules_version = rules_version
        self._timeout = reply_timeout
        self._buf = b""
        self._next_id = 0
        self._lock = asyncio.Lock()
        self.closed = False

    async def _read_line(self) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        while b"\n" not in self._buf:
            chunk = await loop.sock_recv(self._sock, yp.MAX_LINE)
            if not chunk:
                raise YaraUnavailable("worker_disconnected")
            self._buf += chunk
            if len(self._buf) > yp.MAX_LINE:
                raise YaraUnavailable("reply_too_large")
        line, self._buf = self._buf.split(b"\n", 1)
        try:
            return yp.decode(line)
        except yp.YaraProtocolError:
            raise YaraUnavailable("bad_reply") from None

    async def _request(self, obj: dict[str, Any], fd: int | None = None) -> dict[str, Any]:
        if self.closed:
            raise YaraUnavailable("session_closed")
        try:
            if fd is None:
                await asyncio.get_running_loop().sock_sendall(self._sock, yp.encode(obj))
            else:
                self._sock.setblocking(True)       # tiny message; mirrors the clamd FILDES path
                try:
                    socket.send_fds(self._sock, [yp.encode(obj)], [fd])
                finally:
                    self._sock.setblocking(False)
            return await asyncio.wait_for(self._read_line(), self._timeout)
        except asyncio.TimeoutError:
            self.close()
            raise YaraUnavailable("reply_timeout") from None
        except OSError as exc:
            self.close()
            raise YaraUnavailable(f"transport:{exc.__class__.__name__}") from None
        except YaraUnavailable:
            self.close()
            raise

    async def scan_fd(self, fd: int) -> YaraResult:
        async with self._lock:
            self._next_id += 1
            rid = self._next_id
            reply = await self._request({"op": "scan", "id": rid}, fd)
            if reply.get("id") != rid or reply.get("status") not in yp.STATUSES:
                self.close()
                raise YaraUnavailable(str(reply.get("error", "bad_reply")))
            matches = [m for m in reply.get("matches", []) if isinstance(m, dict)][:yp.MAX_MATCHES]
            return YaraResult(reply["status"], matches, str(reply.get("reason", ""))[:120])

    async def bye(self) -> None:
        if not self.closed:
            try:
                async with self._lock:
                    await self._request({"op": "bye"})
            except YaraUnavailable:
                pass
        self.close()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._sock.close()


class YaraClient:
    def __init__(self, socket_path: str, *, connect_timeout: float = 10.0, reply_timeout: float = 70.0) -> None:
        self.socket_path = socket_path
        self.connect_timeout = connect_timeout
        self.reply_timeout = reply_timeout

    async def session(self) -> YaraSession:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, self.socket_path),
                                   self.connect_timeout)
        except (OSError, asyncio.TimeoutError):
            sock.close()
            raise YaraUnavailable("worker_unreachable") from None
        session = YaraSession(sock, "", self.connect_timeout)
        reply = await session._request({"op": "hello"})
        if reply.get("ok") is not True:
            session.close()
            raise YaraUnavailable(str(reply.get("error", "hello_failed")))
        session.rules_version = str(reply.get("rules_version", ""))
        session._timeout = self.reply_timeout
        return session

    async def ping(self) -> str:
        """Health check: open a session, return the active rules version, close it."""
        session = await self.session()
        await session.bye()
        return session.rules_version
