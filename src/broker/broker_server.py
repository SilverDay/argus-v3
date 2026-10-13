"""Broker Unix socket server.

* Socket 0660 root:<socket group>; only the configured client uid is accepted
  (SO_PEERCRED). Group write is required for connect(2) — a 0600 root socket
  would lock the unprivileged orchestrator out.
* Every request must carry a valid HMAC, a fresh timestamp and an unused nonce.
* Commands are serialised (one privileged operation at a time) and time-limited.
* Handlers never raise to the client: errors become {"ok": false, "error": code}.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
from typing import Any

from src.shared import broker_protocol as bp
from src.shared.ipc import IPCError, PeerCredentials, remove_stale_socket, peer_credentials

from .commands import COMMANDS
from .commands.open import FDS_KEY
from .context import BrokerContext

log = logging.getLogger(__name__)
_NULL_NONCE = "0" * 32


class BrokerServer:
    def __init__(self, ctx: BrokerContext, *, socket_path: str, hmac_key: bytes, client_uid: int,
                 socket_gid: int | None = None, command_timeout: float = 30.0,
                 max_clock_skew: float = 30.0) -> None:
        self.ctx = ctx
        self.socket_path = socket_path
        self._key = bp.check_key(hmac_key)
        self._client_uid = client_uid
        self._socket_gid = socket_gid
        self._timeout = command_timeout
        self._nonces = bp.NonceCache(max_clock_skew)
        self._lock = asyncio.Lock()
        self._server: asyncio.base_events.Server | None = None
        self._sock: socket.socket | None = None

    def bind(self) -> None:
        """Create the listening socket. Separate from start() so privileges can be dropped in between."""
        remove_stale_socket(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            sock.bind(self.socket_path)
        finally:
            os.umask(old)
        if self._socket_gid is not None:
            os.chown(self.socket_path, 0 if os.geteuid() == 0 else -1, self._socket_gid)
        os.chmod(self.socket_path, 0o660)
        sock.listen(4)
        sock.setblocking(False)
        self._sock = sock

    async def start(self) -> None:
        if self._sock is None:
            self.bind()
        self._server = await asyncio.start_unix_server(self._handle, sock=self._sock,
                                                       limit=bp.MAX_MESSAGE_BYTES)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(OSError, IPCError):
            remove_stale_socket(self.socket_path)

    async def dispatch(self, line: bytes, peer: PeerCredentials) -> tuple[bytes, list[int]]:
        try:
            nonce, cmd, args = bp.verify_request(self._key, line, self._nonces)
        except bp.ProtocolError as exc:
            nonce = exc.detail if len(exc.detail) == 32 else _NULL_NONCE
            log.warning("broker: rejected request from pid=%d: %s", peer.pid, exc.code)
            self.ctx.audit.write("rejected_request", peer_pid=peer.pid, peer_uid=peer.uid, error=exc.code)
            return bp.build_response(self._key, nonce, error=exc.code), []

        handler = COMMANDS.get(cmd)
        if handler is None:
            self.ctx.audit.write("rejected_request", peer_pid=peer.pid, error=bp.E_UNKNOWN_COMMAND)
            return bp.build_response(self._key, nonce, error=bp.E_UNKNOWN_COMMAND), []
        try:
            async with self._lock:
                result: dict[str, Any] = await asyncio.wait_for(handler(self.ctx, args), self._timeout)
        except bp.ProtocolError as exc:
            self.ctx.audit.write("command_failed", command=cmd, peer_pid=peer.pid, error=exc.code)
            return bp.build_response(self._key, nonce, error=exc.code, detail=exc.detail), []
        except asyncio.TimeoutError:
            self.ctx.audit.write("command_timeout", command=cmd, peer_pid=peer.pid)
            return bp.build_response(self._key, nonce, error=bp.E_INTERNAL, detail="command timed out"), []
        except Exception:  # never leak internals to the client
            log.exception("broker: command %s failed", cmd)
            return bp.build_response(self._key, nonce, error=bp.E_INTERNAL), []
        fds = result.pop(FDS_KEY, [])
        try:
            return bp.build_response(self._key, nonce, result=result), fds
        except Exception:
            for fd in fds:
                os.close(fd)
            raise

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, line: bytes, fds: list[int]) -> None:
        """Write a reply; with fds, send the first bytes via sendmsg/SCM_RIGHTS on a dup of
        the transport socket (asyncio streams cannot carry ancillary data)."""
        if not fds:
            writer.write(line)
            await writer.drain()
            return
        try:
            await writer.drain()
            # Closing the dup never affects the transport's own descriptor.
            raw = socket.socket(fileno=os.dup(writer.get_extra_info("socket").fileno()))
            try:
                for _ in range(200):
                    try:
                        sent = socket.send_fds(raw, [line], fds)
                        break
                    except BlockingIOError:
                        await asyncio.sleep(0.005)
                else:
                    raise ConnectionError("peer not reading")
            finally:
                raw.close()
            if sent < len(line):
                writer.write(line[sent:])
                await writer.drain()
        finally:
            for fd in fds:
                os.close(fd)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer = peer_credentials(writer.get_extra_info("socket"))
        except OSError:
            writer.close()
            return
        if peer.uid != self._client_uid:
            log.warning("broker: refused connection from uid=%d pid=%d", peer.uid, peer.pid)
            self.ctx.audit.write("refused_connection", peer_uid=peer.uid, peer_pid=peer.pid)
            writer.close()
            return
        try:
            while True:
                try:
                    line = await reader.readline()
                except (ValueError, asyncio.LimitOverrunError, ConnectionError, OSError):
                    break
                if not line:
                    break
                reply, fds = await self.dispatch(line, peer)
                await self._send(writer, reply, fds)
        finally:
            writer.close()
