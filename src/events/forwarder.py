"""Durable outbound delivery (spec §3.2 step 12, §3.7, §9.2).

Every queue (``siem``, ``alert:webhook``, ``alert:email``, ``alert:syslog``) is worked by its
own task in strict sequence order: the head of the queue blocks later events until it is
delivered or dead-lettered, so a receiver sees events in order. A failed attempt is retried
with exponential backoff (``backoff_initial_seconds`` doubling up to ``backoff_max_seconds``);
after ``max_attempts`` the entry is dead-lettered (status ``dead`` in the database, error
logged) and the queue moves on. Receivers deduplicate on (station_id, seq / event_id).

Acknowledgement: webhook = HTTP 2xx, e-mail = SMTP accepted the message, syslog = the
record was written and flushed on the TLS connection (RFC 5425 has no application-level
acknowledgement; RELP is not used).

Alert outcomes (delivered / dead) are recorded as ``alert_delivery`` events, which go to the
SIEM queue only. SIEM delivery itself is not recorded as events (that would feed itself).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from src.shared.config import FilenamePrivacy, ForwardingConfig, ForwardTransport
from src.shared.models import EventType, ScanEvent
from src.shared.secret_refs import secret_path

from .alerting import (
    PRODUCT_VERSION, Channel, Pseudonymizer, _err, alert_from_event, frame_octet_counting, rfc5424, tls_context,
)
from .store import EventStore, StoredEvent

log = logging.getLogger(__name__)
SIEM = "siem"
Sender = Callable[[StoredEvent], Awaitable[None]]

_SENSITIVE_KEYS = frozenset({"file_path", "original_path", "serial", "file"})


# --- SIEM payload privacy ----------------------------------------------------------------

def sanitize(value: Any, pseudo: Pseudonymizer, key: str = "") -> Any:
    """Apply logging.filename_privacy to paths and serials before an event leaves the device."""
    if pseudo.mode is FilenamePrivacy.PLAIN:
        return value
    if isinstance(value, dict):
        return {k: sanitize(v, pseudo, k) for k, v in value.items()}
    if key == "policy_violations" and isinstance(value, list):
        out = []
        for item in value:                       # "<kind>:<ext>:<partition>/<path>"
            parts = str(item).split(":", 2)
            out.append(":".join(parts[:2] + [pseudo(parts[2]) or "omitted"]) if len(parts) == 3 else "omitted")
        return out
    if isinstance(value, list):
        return [sanitize(v, pseudo, key) for v in value]
    if key in _SENSITIVE_KEYS and isinstance(value, str):
        return pseudo(value)
    return value


def envelope(event: StoredEvent, pseudo: Pseudonymizer) -> dict[str, Any]:
    """Forwarded form. ``hash``/``prev_hash`` let the collector track the chain and gaps; the
    payload is privacy-filtered, so the collector cannot recompute the hash itself."""
    return {"schema": "usb-scan-event/1", "station_id": event.station_id, "seq": event.seq,
            "event_id": event.event_id, "event_type": event.event_type, "scan_id": event.scan_id,
            "timestamp_utc": event.timestamp_utc, "received_utc": event.received_utc,
            "prev_hash": event.prev_hash, "hash": event.hash, "payload": sanitize(event.payload, pseudo)}


def _severity(event: StoredEvent) -> int:
    if event.event_type == EventType.TAMPER_DETECTED.value:
        return 2
    if event.event_type == EventType.VERDICT.value:
        return {"THREAT": 2, "ERROR": 3}.get(str(event.payload.get("verdict")), 5)
    if event.event_type == EventType.HEALTH_GATE_FAILED.value:
        return 3
    return 6


def client_tls_context(cfg: ForwardingConfig) -> ssl.SSLContext:
    ctx = tls_context(cfg.ca_file)
    if cfg.client_cert_file:                         # mTLS station identity (spec §9.2)
        ctx.load_cert_chain(cfg.client_cert_file, secret_path(cfg.client_key_ref))
    return ctx


class SiemSyslogSender:
    """RFC 5424 over TLS (RFC 5425 framing), one persistent connection."""

    def __init__(self, cfg: ForwardingConfig, pseudo: Pseudonymizer, *,
                 connect: Callable[..., Awaitable[tuple[Any, Any]]] | None = None) -> None:
        self.cfg = cfg
        self.pseudo = pseudo
        self.connect = connect or asyncio.open_connection
        self._ctx = client_tls_context(cfg)
        self._writer: Any = None

    async def __call__(self, event: StoredEvent) -> None:
        body = json.dumps(envelope(event, self.pseudo), separators=(",", ":"), ensure_ascii=True)
        data = frame_octet_counting(rfc5424(event.station_id, _severity(event), "EVENT", body))
        try:
            if self._writer is None:
                _reader, self._writer = await asyncio.wait_for(
                    self.connect(self.cfg.host, self.cfg.port, ssl=self._ctx, server_hostname=self.cfg.host),
                    self.cfg.timeout_seconds)
            self._writer.write(data)
            await asyncio.wait_for(self._writer.drain(), self.cfg.timeout_seconds)
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer.wait_closed(), 2)
            self._writer = None


class SiemWebhookSender:
    def __init__(self, cfg: ForwardingConfig, pseudo: Pseudonymizer, token: str | None, *,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.cfg = cfg
        self.pseudo = pseudo
        headers = {"Content-Type": "application/json", "User-Agent": f"usb-scan-station/{PRODUCT_VERSION}"}
        if token:
            if any(c in token for c in "\r\n"):
                raise ValueError("invalid forwarding token")
            headers["Authorization"] = f"Bearer {token}"
        kwargs: dict[str, Any] = ({"transport": transport} if transport is not None
                                  else {"verify": client_tls_context(cfg)})
        self._http = httpx.AsyncClient(headers=headers, timeout=float(cfg.timeout_seconds), follow_redirects=False,
                                       **kwargs)

    def __repr__(self) -> str:
        return "SiemWebhookSender(<token hidden>)"

    async def __call__(self, event: StoredEvent) -> None:
        body = json.dumps(envelope(event, self.pseudo), separators=(",", ":"), ensure_ascii=True).encode()
        resp = await self._http.post(self.cfg.url, content=body)
        if not 200 <= resp.status_code < 300:
            raise RuntimeError(f"http_{resp.status_code}")

    async def aclose(self) -> None:
        await self._http.aclose()


def alert_sender(channel: Channel, pseudo: Pseudonymizer) -> Sender:
    async def send(event: StoredEvent) -> None:
        await channel.send(alert_from_event(event, pseudo))
    return send


def unavailable_sender(name: str) -> Sender:
    async def send(event: StoredEvent) -> None:
        raise RuntimeError(f"{name}_unavailable")
    return send


# --- engine ----------------------------------------------------------------------------------

class Forwarder:
    def __init__(self, store: EventStore, senders: dict[str, Sender], *, max_attempts: int = 10,
                 backoff_initial: float = 5.0, backoff_max: float = 600.0,
                 clock: Callable[[], float] = time.time, idle_wait: float = 30.0) -> None:
        self.store = store
        self.senders = senders
        self.max_attempts = max_attempts
        self.backoff_initial = backoff_initial
        self.backoff_max = backoff_max
        self.clock = clock
        self.idle_wait = idle_wait
        self._wake = {name: asyncio.Event() for name in senders}
        self._tasks: list[asyncio.Task] = []

    def wake(self) -> None:
        for ev in self._wake.values():
            ev.set()

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._run(name), name=f"forward-{name}") for name in self.senders]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    def backoff(self, attempts: int) -> float:
        return min(self.backoff_max, self.backoff_initial * 2 ** max(0, attempts - 1))

    async def _sleep(self, name: str, seconds: float) -> None:
        ev = self._wake[name]
        ev.clear()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(ev.wait(), max(0.0, seconds))

    async def _run(self, name: str) -> None:
        while True:
            try:
                progressed = await self.step(name)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("forwarder %s: unexpected error", name)
                progressed = False
            if not progressed:
                delivery, due = await asyncio.to_thread(self.store.next_delivery, name)
                wait = self.idle_wait if delivery is None else min(self.idle_wait, due - self.clock())
                await self._sleep(name, wait)

    async def step(self, name: str) -> bool:
        """Try the head of one queue once. True if it was delivered or dead-lettered."""
        delivery, due = await asyncio.to_thread(self.store.next_delivery, name)
        if delivery is None or due > self.clock():
            return False
        seq = delivery.event.seq
        try:
            await self.senders[name](delivery.event)
        except Exception as exc:
            attempts = delivery.attempts + 1
            dead = attempts >= self.max_attempts
            error = _err(exc)
            await asyncio.to_thread(self.store.mark_failed, name, seq, error,
                                    self.clock() + self.backoff(attempts), dead)
            if dead:
                log.error("DEAD LETTER %s seq=%d after %d attempts (%s)", name, seq, attempts, error)
                await self._record(name, delivery.event, f"dead:{error}")
                return True
            log.warning("%s delivery of seq=%d failed (%s); attempt %d/%d", name, seq, error, attempts,
                        self.max_attempts)
            return False
        await asyncio.to_thread(self.store.mark_delivered, name, seq)
        await self._record(name, delivery.event, "delivered")
        return True

    async def _record(self, name: str, event: StoredEvent, status: str) -> None:
        if name == SIEM:
            return
        res = await asyncio.to_thread(self.store.append, ScanEvent(EventType.ALERT_DELIVERY, event.scan_id, {
            "channel": name, "status": status, "event_seq": event.seq, "event_type": event.event_type}))
        if res.channels:
            self.wake()

    async def aclose(self) -> None:
        await self.stop()
        for sender in self.senders.values():
            close = getattr(sender, "aclose", None)
            if close is not None:
                await close()


def build_siem_sender(cfg: ForwardingConfig, pseudo: Pseudonymizer, resolve: Callable[[str], bytes]) -> Sender:
    if cfg.transport is ForwardTransport.WEBHOOK:
        token = resolve(cfg.token_ref).decode("utf-8").strip() if cfg.token_ref else None
        return SiemWebhookSender(cfg, pseudo, token)
    return SiemSyslogSender(cfg, pseudo)
