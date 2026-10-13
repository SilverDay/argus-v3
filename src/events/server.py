"""events.sock server (spec §5.4): append from the orchestrator, queries for readers.

* SO_PEERCRED: writer uids (orchestrator) may append and query; reader uids may only
  query; web-audit uids (admin web) may query and append ``web_auth``/``web_access``
  events only. Everyone else is disconnected before a byte is read.
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
WEB_AUDIT_TYPES = frozenset({EventType.WEB_AUTH, EventType.WEB_ACCESS})
WRITER, WEB, READER = "writer", "web", "reader"


class EventsServer:
    def __init__(self, store: EventStore, path: str, *, writer_uids: Iterable[int], reader_uids: Iterable[int],
                 web_uids: Iterable[int] = (), group_gid: int | None = None,
                 on_append: Callable[[], None] = lambda: None,
                 status_extra: Callable[[], dict[str, Any]] = dict) -> None:
        self.store = store
        self.path = path
        self.writer_uids = frozenset(writer_uids)
        self.reader_uids = frozenset(reader_uids)
        self.web_uids = frozenset(web_uids)
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
        if creds.uid in self.writer_uids:
            role = WRITER
        elif creds.uid in self.web_uids:
            role = WEB
        elif creds.uid in self.reader_uids:
            role = READER
        else:
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
                response = await self._dispatch(line, role)
                writer.write(proto.encode(response))
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def _dispatch(self, line: bytes, role: str) -> dict[str, Any]:
        try:
            req = proto.decode(line)
        except proto.EventsProtocolError:
            return {"ok": False, "error": proto.E_BAD_REQUEST}
        op = req.get("op")
        if op in proto.WRITE_OPS and role == READER:
            return {"ok": False, "error": proto.E_FORBIDDEN}
        try:
            if op == "append":
                return await self._append(req.get("event"), role)
            if op not in proto.READ_OPS:
                return {"ok": False, "error": proto.E_BAD_REQUEST}
            return await self._query(op, req)
        except _BadRequest:
            return {"ok": False, "error": proto.E_BAD_REQUEST}
        except Exception:
            log.exception("events request failed")
            return {"ok": False, "error": proto.E_INTERNAL}

    async def _query(self, op: str, req: dict[str, Any]) -> dict[str, Any]:
        st = self.store
        if op == "ping":
            return {"ok": True}
        if op == "status":
            status = await asyncio.to_thread(st.status)
            return {"ok": True, "status": {**status, **self.status_extra()}}
        if op in ("last_verdict", "last_health"):
            ev = await asyncio.to_thread(st.last_of_type, EventType.VERDICT if op == "last_verdict" else EventType.HEALTH)
            return {"ok": True, "event": ev.to_dict() if ev else None}
        if op == "recent":
            types = _str_list(req.get("types"))
            events = await asyncio.to_thread(st.recent, _int(req, "limit", 50), _int(req, "after_seq", 0), types)
            return {"ok": True, "events": [e.to_dict() for e in events]}
        if op == "page":
            types = _str_list(req.get("types"))
            events = await asyncio.to_thread(st.before, _int(req, "before_seq", 0), _int(req, "limit", 50), types)
            return {"ok": True, "events": [e.to_dict() for e in events]}
        if op == "scans":
            serial = req.get("serial")
            if serial is not None and (not isinstance(serial, str) or len(serial) > 128):
                raise _BadRequest
            rows = await asyncio.to_thread(
                st.scans, verdicts=_str_list(req.get("verdicts")), since=_num(req, "since"), until=_num(req, "until"),
                serial=serial, before_seq=_int(req, "before_seq", 0), limit=_int(req, "limit", 50))
            return {"ok": True, "scans": rows}
        if op == "scan":
            ev = await asyncio.to_thread(st.get, _int(req, "seq", 0))
            if ev is None or ev.event_type != EventType.VERDICT.value:
                return {"ok": True, "event": None}
            return {"ok": True, "event": ev.to_dict()}
        if op == "stats":
            return {"ok": True, "stats": await asyncio.to_thread(st.stats, _int(req, "days", 30))}
        raise _BadRequest

    async def _append(self, raw: Any, role: str) -> dict[str, Any]:
        try:
            event = ScanEvent.from_dict(raw)
        except (ModelError, TypeError, ValueError):
            return {"ok": False, "error": proto.E_INVALID_EVENT}
        if event.event_type in SERVICE_ONLY_TYPES:
            return {"ok": False, "error": proto.E_FORBIDDEN}
        if (role == WEB) != (event.event_type in WEB_AUDIT_TYPES):
            # The web UI may only record its own audit events, and nobody else may forge them.
            return {"ok": False, "error": proto.E_FORBIDDEN}
        async with self._append_lock:
            try:
                res = await asyncio.to_thread(self.store.append, event)
            except StoreFull:
                return {"ok": False, "error": proto.E_STORE_FULL}
        if res.channels:
            self.on_append()
        return {"ok": True, "seq": res.seq, "duplicate": res.duplicate}


class _BadRequest(Exception):
    pass


def _int(req: dict[str, Any], key: str, default: int) -> int:
    value = req.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _BadRequest
    return value


def _num(req: dict[str, Any], key: str) -> float | None:
    value = req.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _BadRequest
    return float(value)


def _str_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 50 or not all(isinstance(v, str) and len(v) <= 64 for v in value):
        raise _BadRequest
    return value
