"""events.sock server (spec §5.4): append from the orchestrator, queries for readers.

* SO_PEERCRED: writer uids (orchestrator) may append and query; reader uids (admin web)
  may only query. Everyone else is disconnected before a byte is read.
* Event types the service generates itself (checkpoints, tamper records) and local IPC
  bookkeeping types cannot be submitted by clients.
* An append is acknowledged only after the SQLite transaction is durable.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
from collections.abc import Callable, Iterable
from typing import Any

from src.shared import events_protocol as proto
from src.shared.ipc import peer_credentials, remove_stale_socket
from src.shared.models import EventType, ModelError, ScanEvent

from .store import EventStore, StoreFull

log = logging.getLogger(__name__)

SERVICE_ONLY_TYPES = frozenset({EventType.AUDIT_CHECKPOINT, EventType.TAMPER_DETECTED,
                                EventType.TAMPER_ACKNOWLEDGED, EventType.IPC_CONNECTED,
                                EventType.IPC_DISCONNECTED})


class EventsServer:
    def __init__(self, store: EventStore, path: str, *, writer_uids: Iterable[int], reader_uids: Iterable[int],
                 group_gid: int | None = None, on_append: Callable[[], None] = lambda: None,
                 status_extra: Callable[[], dict[str, Any]] = dict) -> None:
        self.store = store
        self.path = path
        self.writer_uids = frozenset(writer_uids)
        self.reader_uids = frozenset(reader_uids)
        self.group_gid = group_gid
        self.on_append = on_append
        self.status_extra = status_extra
        self._append_lock = asyncio.Lock()
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        remove_stale_socket(self.path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            sock.bind(self.path)
        finally:
            os.umask(old)
        if self.group_gid is not None:
            os.chown(self.path, -1, self.group_gid)
        os.chmod(self.path, 0o660)
        sock.listen(16)
        sock.setblocking(False)
        self._server = await asyncio.start_unix_server(self._handle, sock=sock, limit=proto.MAX_LINE_BYTES)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            # wait_closed() waits for every connection (Python >= 3.12) and the orchestrator
            # keeps one open: close client connections first or shutdown hangs.
            self._server.close_clients()
            await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(FileNotFoundError):
            remove_stale_socket(self.path)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            creds = peer_credentials(writer.get_extra_info("socket"))
        except OSError:
            writer.close()
            return
        can_write = creds.uid in self.writer_uids
        if not can_write and creds.uid not in self.reader_uids:
            log.warning("events socket: rejected uid=%d pid=%d", creds.uid, creds.pid)
            writer.close()
            return
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    writer.write(proto.encode({"ok": False, "error": proto.E_BAD_REQUEST}))
                    return
                if not line:
                    return
                response = await self._dispatch(line, can_write)
                writer.write(proto.encode(response))
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def _dispatch(self, line: bytes, can_write: bool) -> dict[str, Any]:
        try:
            req = proto.decode(line)
        except proto.EventsProtocolError:
            return {"ok": False, "error": proto.E_BAD_REQUEST}
        op = req.get("op")
        if op in proto.WRITE_OPS and not can_write:
            return {"ok": False, "error": proto.E_FORBIDDEN}
        try:
            if op == "append":
                return await self._append(req.get("event"))
            if op == "ping":
                return {"ok": True}
            if op == "status":
                status = await asyncio.to_thread(self.store.status)
                return {"ok": True, "status": {**status, **self.status_extra()}}
            if op == "last_verdict":
                ev = await asyncio.to_thread(self.store.last_of_type, EventType.VERDICT)
                return {"ok": True, "event": ev.to_dict() if ev else None}
            if op == "recent":
                types = req.get("types")
                if types is not None and (not isinstance(types, list) or not all(isinstance(t, str) for t in types)):
                    return {"ok": False, "error": proto.E_BAD_REQUEST}
                limit, after = req.get("limit", 50), req.get("after_seq", 0)
                if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (limit, after)):
                    return {"ok": False, "error": proto.E_BAD_REQUEST}
                events = await asyncio.to_thread(self.store.recent, limit, after, types)
                return {"ok": True, "events": [e.to_dict() for e in events]}
        except Exception:
            log.exception("events request failed")
            return {"ok": False, "error": proto.E_INTERNAL}
        return {"ok": False, "error": proto.E_BAD_REQUEST}

    async def _append(self, raw: Any) -> dict[str, Any]:
        try:
            event = ScanEvent.from_dict(raw)
        except (ModelError, TypeError, ValueError):
            return {"ok": False, "error": proto.E_INVALID_EVENT}
        if event.event_type in SERVICE_ONLY_TYPES:
            return {"ok": False, "error": proto.E_FORBIDDEN}
        async with self._append_lock:
            try:
                res = await asyncio.to_thread(self.store.append, event)
            except StoreFull:
                return {"ok": False, "error": proto.E_STORE_FULL}
        if res.channels:
            self.on_append()
        return {"ok": True, "seq": res.seq, "duplicate": res.duplicate}
