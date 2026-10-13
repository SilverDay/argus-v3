"""Newline-delimited JSON ScanEvent IPC over Unix sockets (spec §5.4).

Server (orchestrator side):
  * authenticates every connection by SO_PEERCRED uid (and optionally gid);
  * binds with a restrictive umask so the socket is never briefly world-accessible;
  * never blocks on a slow client: each client has a bounded queue and is
    dropped when it overflows;
  * accepts only client->server event types listed in ``inbound_types``.

Client (GUI side): reconnects with exponential backoff (0.5 s -> 30 s) and reports
connect/disconnect transitions as local IPC_CONNECTED / IPC_DISCONNECTED events.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
import stat
import struct
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from .models import EventType, ModelError, ScanEvent

log = logging.getLogger(__name__)

MAX_LINE_BYTES = 64 * 1024
CLIENT_QUEUE_SIZE = 256
_UCRED = struct.Struct("3i")  # struct ucred { pid_t pid; uid_t uid; gid_t gid; }

INBOUND_OPERATOR_TYPES = frozenset({
    EventType.OPERATOR_PIN_SUBMIT, EventType.OPERATOR_ACK, EventType.LOCKOUT_QUERY,
})


class IPCError(Exception):
    pass


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def peer_credentials(sock: socket.socket) -> PeerCredentials:
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    return PeerCredentials(*_UCRED.unpack(raw))


def encode_event(event: ScanEvent) -> bytes:
    line = json.dumps(event.to_dict(), separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise IPCError("event exceeds maximum line size")
    return line


def decode_event(line: bytes) -> ScanEvent:
    if len(line) > MAX_LINE_BYTES:
        raise IPCError("line exceeds maximum size")
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise IPCError("malformed JSON") from exc
    try:
        return ScanEvent.from_dict(data)
    except ModelError as exc:
        raise IPCError(f"invalid event: {exc}") from exc


def remove_stale_socket(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise IPCError(f"refusing to replace non-socket at {path}")
    os.unlink(path)


InboundHandler = Callable[[ScanEvent, PeerCredentials], Awaitable[None]]


class _Client:
    def __init__(self, writer: asyncio.StreamWriter, creds: PeerCredentials) -> None:
        self.writer = writer
        self.creds = creds
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue(CLIENT_QUEUE_SIZE)


class IPCServer:
    def __init__(
        self,
        path: str,
        *,
        allowed_uids: Iterable[int],
        allowed_gids: Iterable[int] | None = None,
        mode: int = 0o660,
        group_gid: int | None = None,
        inbound_types: Iterable[EventType] = (),
        on_message: InboundHandler | None = None,
    ) -> None:
        self.path = path
        self._allowed_uids = frozenset(allowed_uids)
        self._allowed_gids = frozenset(allowed_gids) if allowed_gids is not None else None
        self._mode = mode
        self._group_gid = group_gid
        self._inbound_types = frozenset(inbound_types)
        self._on_message = on_message
        self._clients: set[_Client] = set()
        self._server: asyncio.base_events.Server | None = None

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def start(self) -> None:
        remove_stale_socket(self.path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)  # socket created as 0600 at most, then widened
        try:
            sock.bind(self.path)
        finally:
            os.umask(old_umask)
        if self._group_gid is not None:
            os.chown(self.path, -1, self._group_gid)
        os.chmod(self.path, self._mode)
        sock.listen(16)
        sock.setblocking(False)
        self._server = await asyncio.start_unix_server(self._handle, sock=sock, limit=MAX_LINE_BYTES)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            for client in list(self._clients):
                self._drop(client)
            await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(FileNotFoundError):
            remove_stale_socket(self.path)

    def _authorized(self, creds: PeerCredentials) -> bool:
        if creds.uid not in self._allowed_uids:
            return False
        return self._allowed_gids is None or creds.gid in self._allowed_gids

    def _drop(self, client: _Client) -> None:
        if client in self._clients:
            self._clients.discard(client)
            with contextlib.suppress(asyncio.QueueFull):
                client.queue.put_nowait(None)
            client.writer.close()

    def broadcast(self, event: ScanEvent) -> None:
        """Queue ``event`` for every client without blocking. Slow clients are dropped."""
        line = encode_event(event)
        for client in list(self._clients):
            try:
                client.queue.put_nowait(line)
            except asyncio.QueueFull:
                log.warning("ipc client pid=%s too slow; disconnecting", client.creds.pid)
                self._drop(client)

    async def _writer_loop(self, client: _Client) -> None:
        try:
            while True:
                line = await client.queue.get()
                if line is None:
                    return
                client.writer.write(line)
                await client.writer.drain()
        except (ConnectionError, OSError):
            self._drop(client)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        try:
            creds = peer_credentials(sock)
        except OSError:
            writer.close()
            return
        if not self._authorized(creds):
            log.warning("ipc %s: rejected peer uid=%d gid=%d pid=%d", self.path, creds.uid, creds.gid, creds.pid)
            writer.close()
            return
        client = _Client(writer, creds)
        self._clients.add(client)
        writer_task = asyncio.create_task(self._writer_loop(client))
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    log.warning("ipc peer pid=%d sent oversized line; disconnecting", creds.pid)
                    break
                except (ConnectionError, OSError):
                    break
                if not line:
                    break
                try:
                    event = decode_event(line)
                except IPCError as exc:
                    log.warning("ipc peer pid=%d sent invalid message: %s", creds.pid, exc)
                    break
                if event.event_type not in self._inbound_types or self._on_message is None:
                    log.warning("ipc peer pid=%d sent disallowed event type %s", creds.pid, event.event_type.value)
                    break
                await self._on_message(event, creds)
        finally:
            self._drop(client)
            writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer_task


EventHandler = Callable[[ScanEvent], Awaitable[None] | None]


class IPCClient:
    def __init__(
        self,
        path: str,
        on_event: EventHandler,
        *,
        initial_backoff: float = 0.5,
        max_backoff: float = 30.0,
    ) -> None:
        self.path = path
        self._on_event = on_event
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._writer: asyncio.StreamWriter | None = None
        self._stopped = asyncio.Event()

    @property
    def connected(self) -> bool:
        return self._writer is not None

    async def _emit(self, event: ScanEvent) -> None:
        result = self._on_event(event)
        if asyncio.iscoroutine(result):
            await result

    async def send(self, event: ScanEvent) -> None:
        if self._writer is None:
            raise IPCError("not connected")
        self._writer.write(encode_event(event))
        await self._writer.drain()

    def stop(self) -> None:
        self._stopped.set()
        if self._writer is not None:
            self._writer.close()

    async def run(self) -> None:
        backoff = self._initial_backoff
        while not self._stopped.is_set():
            try:
                reader, writer = await asyncio.open_unix_connection(self.path, limit=MAX_LINE_BYTES)
            except OSError:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stopped.wait(), backoff)
                backoff = min(backoff * 2, self._max_backoff)
                continue
            self._writer = writer
            backoff = self._initial_backoff
            await self._emit(ScanEvent(EventType.IPC_CONNECTED, None))
            try:
                while True:
                    try:
                        line = await reader.readline()
                    except (asyncio.LimitOverrunError, ValueError, ConnectionError, OSError):
                        break
                    if not line:
                        break
                    try:
                        event = decode_event(line)
                    except IPCError as exc:
                        log.warning("ipc %s: ignoring invalid event: %s", self.path, exc)
                        continue
                    await self._emit(event)
            finally:
                self._writer = None
                writer.close()
                await self._emit(ScanEvent(EventType.IPC_DISCONNECTED, None))
