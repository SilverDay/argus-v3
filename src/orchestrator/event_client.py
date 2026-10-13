"""Orchestrator side of the events service (spec §3.2 step 10, §3.7).

* One writer task sends events over events.sock in publish order.
* ``commit_result`` returns only when the verdict is durable: acknowledged by the events
  service (SQLite synchronous=FULL) or fsync'ed to the local spool.
* If the service is unreachable or refuses a write (disk full), events go to an
  append-only spool in the orchestrator state directory (0600, fsync per line). While the
  spool is not empty every new event is spooled too, so ordering is preserved. The spool
  is replayed on reconnect; the service deduplicates by ``event_id``.
* The spool is bounded (``orchestrator.event_spool_max_mb``). An unreachable events
  service fails the health gate (NOT_READY), so the spool only has to cover a scan in
  progress, not a long outage.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from typing import Any

from src.shared import events_protocol as proto
from src.shared.models import EventType, ScanEvent, ScanResult

from .event_sink import ActiveScanMarker, verdict_event

log = logging.getLogger(__name__)


class EventsUnavailable(Exception):
    pass


class SpoolFull(Exception):
    pass


class EventClient(ActiveScanMarker):
    def __init__(self, socket_path: str, state_dir: str, *, spool_max_bytes: int = 64 * 1024 * 1024,
                 timeout: float = 10.0, retry_interval: float = 5.0) -> None:
        self.socket_path = socket_path
        self.state_dir = state_dir
        self.spool_path = os.path.join(state_dir, "event_spool.jsonl")
        self.marker_path = os.path.join(state_dir, "active_scan.json")
        self.spool_max_bytes = spool_max_bytes
        self.timeout = timeout
        self.retry_interval = retry_interval
        self._queue: asyncio.Queue[tuple[dict[str, Any], asyncio.Future | None]] = asyncio.Queue()
        self._conn: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._task: asyncio.Task | None = None

    # --- sink interface ----------------------------------------------------------------

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._writer(), name="event-client")

    async def publish(self, event: ScanEvent) -> None:
        if event.event_type is EventType.SCAN_PROGRESS:
            return                                    # display-only, not an audit event
        self.start()
        self._queue.put_nowait((event.to_dict(), None))

    async def commit_result(self, result: ScanResult, device: dict[str, Any] | None = None) -> None:
        self.start()
        done: asyncio.Future = asyncio.get_running_loop().create_future()
        self._queue.put_nowait((verdict_event(result, device).to_dict(), done))
        await done                                    # acknowledged or spooled; SpoolFull otherwise

    async def health_failures(self) -> list[str]:
        try:
            status = (await self.request({"op": "status"}))["status"]
        except (EventsUnavailable, KeyError, TypeError):
            return ["event_store_unavailable"]
        failures = []
        if status.get("tamper"):
            failures.append("audit_chain_broken")
        if status.get("store_full"):
            failures.append("event_store_unwritable")
        if self.spool_pending():
            failures.append("event_spool_pending")
        return failures

    def spool_pending(self) -> bool:
        try:
            return os.path.getsize(self.spool_path) > 0
        except OSError:
            return False

    async def close(self, timeout: float = 5.0) -> None:
        if self._task is not None:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._drained(), timeout)
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        self._disconnect()

    async def _drained(self) -> None:
        while not self._queue.empty():
            await asyncio.sleep(0.01)

    # --- queries (separate connection, never blocks the writer) ----------------------------

    async def request(self, req: dict[str, Any]) -> dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path, limit=proto.MAX_LINE_BYTES), self.timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise EventsUnavailable(type(exc).__name__) from None
        try:
            writer.write(proto.encode(req))
            line = await asyncio.wait_for(reader.readline(), self.timeout)
            resp = proto.decode(line)
        except (OSError, asyncio.TimeoutError, proto.EventsProtocolError) as exc:
            raise EventsUnavailable(type(exc).__name__) from None
        finally:
            writer.close()
        if not resp.get("ok"):
            raise EventsUnavailable(str(resp.get("error", "error")))
        return resp

    # --- writer -------------------------------------------------------------------------

    async def _writer(self) -> None:
        while True:
            try:
                item = await asyncio.wait_for(self._queue.get(), self.retry_interval)
            except asyncio.TimeoutError:
                if self.spool_pending():
                    await self._replay()
                continue
            record, done = item
            try:
                await self._handle(record)
                if done is not None and not done.done():
                    done.set_result(None)
            except Exception as exc:  # SpoolFull or unexpected: the commit must see it
                log.critical("event could not be stored or spooled: %s", type(exc).__name__)
                if done is not None and not done.done():
                    done.set_exception(exc)

    async def _handle(self, record: dict[str, Any]) -> None:
        if self.spool_pending() and not await self._replay():
            await asyncio.to_thread(self._spool, record)
            return
        try:
            await self._send(record)
        except EventsUnavailable as exc:
            log.warning("events service unavailable (%s); spooling", exc)
            await asyncio.to_thread(self._spool, record)

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._conn is None:
            try:
                self._conn = await asyncio.wait_for(
                    asyncio.open_unix_connection(self.socket_path, limit=proto.MAX_LINE_BYTES), self.timeout)
            except (OSError, asyncio.TimeoutError) as exc:
                raise EventsUnavailable(type(exc).__name__) from None
        return self._conn

    def _disconnect(self) -> None:
        if self._conn is not None:
            self._conn[1].close()
            self._conn = None

    async def _send(self, record: dict[str, Any]) -> None:
        reader, writer = await self._connect()
        try:
            writer.write(proto.encode({"op": "append", "event": record}))
            await asyncio.wait_for(writer.drain(), self.timeout)
            resp = proto.decode(await asyncio.wait_for(reader.readline(), self.timeout))
        except (OSError, asyncio.TimeoutError, proto.EventsProtocolError) as exc:
            self._disconnect()
            raise EventsUnavailable(type(exc).__name__) from None
        if resp.get("ok"):
            return
        error = str(resp.get("error"))
        if error in proto.RETRYABLE:
            raise EventsUnavailable(error)
        # Rejected as invalid: retrying cannot help. Keep it out of the queue but visible.
        log.error("events service rejected %s event: %s", record.get("event_type"), error)

    # --- spool -----------------------------------------------------------------------------

    def _spool(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        try:
            size = os.path.getsize(self.spool_path)
        except FileNotFoundError:
            size = 0
        if size + len(line) > self.spool_max_bytes:
            raise SpoolFull("event spool limit reached")
        fd = os.open(self.spool_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    async def _replay(self) -> bool:
        """Send the spool in order. True when it is empty afterwards."""
        try:
            with open(self.spool_path, "rb") as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return True
        for raw in lines:
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
            except ValueError:
                log.error("dropping unreadable spool line")
                continue
            try:
                await self._send(record)
            except EventsUnavailable:
                return False                               # keep the spool; duplicates are harmless
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.spool_path)
        log.info("event spool replayed (%d events)", len(lines))
        return True
