"""Async client for the privileged device broker (src/broker).

One request per connection keeps the client stateless across broker restarts.
Only connection failures are retried (max 3 attempts, exponential backoff);
a request that reached the broker is never re-sent automatically, because
mount/eject are not idempotent.
"""
from __future__ import annotations

import asyncio
import base64
import os
import socket
from typing import Any

from src.shared import broker_protocol as bp


class BrokerError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class BrokerUnavailable(BrokerError):
    def __init__(self, detail: str = "") -> None:
        super().__init__("broker_unavailable", detail)


class BrokerClient:
    def __init__(self, socket_path: str, hmac_key: bytes, *, timeout: float = 60.0,
                 attempts: int = 3, backoff: float = 0.2) -> None:
        self.socket_path = socket_path
        self._key = bp.check_key(hmac_key)
        self._timeout = timeout
        self._attempts = attempts
        self._backoff = backoff

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        delay = self._backoff
        last: Exception | None = None
        for attempt in range(self._attempts):
            try:
                return await asyncio.open_unix_connection(self.socket_path, limit=bp.MAX_MESSAGE_BYTES)
            except OSError as exc:
                last = exc
                if attempt + 1 < self._attempts:
                    await asyncio.sleep(delay)
                    delay *= 2
        raise BrokerUnavailable(str(last))

    async def call(self, cmd: str, **args: Any) -> dict[str, Any]:
        reader, writer = await self._connect()
        try:
            line, nonce = bp.build_request(self._key, cmd, args)
            writer.write(line)
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.readline(), self._timeout)
            except asyncio.TimeoutError:
                raise BrokerError("timeout", f"no response to {cmd}") from None
            if not resp:
                raise BrokerUnavailable("connection closed")
            try:
                return bp.parse_response(self._key, resp, nonce)
            except bp.ProtocolError as exc:
                raise BrokerError(exc.code, exc.detail) from None
        except (ConnectionError, ValueError) as exc:
            raise BrokerUnavailable(str(exc)) from None
        finally:
            writer.close()

    async def ping(self) -> bool:
        return (await self.call("ping")).get("pong") is True

    async def enumerate(self, sysfs_path: str, session_id: str) -> dict[str, Any]:
        return await self.call("enumerate", sysfs_path=sysfs_path, session_id=session_id)

    async def mount(self, session_id: str, partition_id: str) -> dict[str, Any]:
        return await self.call("mount", session_id=session_id, partition_id=partition_id)

    async def unmount(self, session_id: str) -> None:
        await self.call("unmount", session_id=session_id)

    async def eject(self, session_id: str) -> dict[str, Any]:
        return await self.call("eject", session_id=session_id)

    async def release(self, session_id: str) -> None:
        await self.call("release", session_id=session_id)

    def open_path(self, session_id: str, partition_id: str, rel: bytes) -> tuple[str, int | None, int]:
        """Confined open of ``rel`` inside a mounted volume (blocking; call from a thread).

        Returns (kind, fd or None, size). kind: file | dir | symlink | special | missing | denied.
        The caller owns the returned fd.
        """
        line, nonce = bp.build_request(self._key, "open", {
            "session_id": session_id, "partition_id": partition_id,
            "path_b64": base64.b64encode(rel).decode("ascii")})
        fds: list[int] = []
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as sock:
                sock.settimeout(self._timeout)
                try:
                    sock.connect(self.socket_path)
                    sock.sendall(line)
                    buf = b""
                    while not buf.endswith(b"\n"):
                        data, got, _flags, _addr = socket.recv_fds(sock, bp.MAX_MESSAGE_BYTES, 4)
                        fds.extend(got)
                        if not data:
                            break
                        buf += data
                        if len(buf) > bp.MAX_MESSAGE_BYTES:
                            raise BrokerUnavailable("reply too large")
                except OSError as exc:
                    raise BrokerUnavailable(str(exc)) from None
            try:
                result = bp.parse_response(self._key, buf, nonce)
            except bp.ProtocolError as exc:
                raise BrokerError(exc.code, exc.detail) from None
            kind = result.get("type")
            expect_fd = kind in ("file", "dir")
            if not isinstance(kind, str) or len(fds) != (1 if expect_fd else 0):
                raise BrokerError("bad_request", "unexpected open reply")
            fd = fds.pop() if expect_fd else None
            return kind, fd, int(result.get("size", 0))
        finally:
            for extra in fds:
                os.close(extra)
