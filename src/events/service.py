"""usb-scan-events service assembly: store + socket server + forwarder + maintenance.

Start-up (spec §3.7, plan Phase 8):
  1. ``PRAGMA integrity_check`` — failure raises StoreCorrupt and the service exits
     (systemd keeps restarting it; the orchestrator reports NOT_READY meanwhile).
  2. Hash chain and checkpoint verification — failure records a TAMPER_DETECTED event
     (alerted and forwarded) and sets the persistent tamper flag; the orchestrator's health
     gate then reports ``audit_chain_broken`` (NOT_READY) until an administrator runs
     ``python -m src.events --acknowledge-tamper`` after investigating.
Periodic: checkpoint every ``checkpoint_interval_hours``, re-verification and retention
pruning every hour.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from typing import Any

from src.shared.config import Config
from src.shared.models import EventType, ScanEvent

from .alerting import build_alert_channels, build_pseudonymizer, enabled_alert_channels, wants_alert
from .forwarder import SIEM, Forwarder, Sender, alert_sender, build_siem_sender, unavailable_sender
from .server import EventsServer
from .store import EventStore, VerifyResult

log = logging.getLogger(__name__)
MIN_KEY_BYTES = 32


def make_router(cfg: Config) -> Callable[[EventType, dict[str, Any]], list[str]]:
    siem = cfg.events.forwarding.enabled
    alert_channels = enabled_alert_channels(cfg.alerts)

    def route(event_type: EventType, payload: dict[str, Any]) -> list[str]:
        channels = [SIEM] if siem else []
        if alert_channels and wants_alert(cfg.alerts, event_type, payload):
            channels.extend(alert_channels)
        return channels
    return route


def open_store(cfg: Config) -> EventStore:
    return EventStore(cfg.events.db_path, cfg.station.station_id, min_free_mb=cfg.events.min_free_mb,
                      router=make_router(cfg))


def check_integrity(store: EventStore, key: bytes | None) -> VerifyResult:
    res = store.verify()
    if res.ok and key is not None:
        cps = store.verify_checkpoints(key)
        if not cps.ok:
            return cps
        res.checkpoints = cps.checked          # report both: events walked, checkpoints checked
    return res


def record_tamper(store: EventStore, res: VerifyResult) -> bool:
    """Persist the tamper flag and emit one TAMPER_DETECTED event per distinct finding."""
    current = store.tamper_state()
    if current and current.get("reason") == res.reason and current.get("first_bad_seq") == res.first_bad_seq:
        return False
    log.critical("AUDIT CHAIN VERIFICATION FAILED: %s at seq %s", res.reason, res.first_bad_seq)
    store.set_tamper(res)
    store.append(ScanEvent(EventType.TAMPER_DETECTED, None, {"reason": res.reason, "first_bad_seq": res.first_bad_seq,
                                                             "checked": res.checked}))
    return True


def acknowledge_tamper(store: EventStore, actor: str, note: str) -> int:
    previous = store.tamper_state()
    seq, digest = store.reanchor()
    store.append(ScanEvent(EventType.TAMPER_ACKNOWLEDGED, None, {
        "actor": actor[:64], "note": note[:500], "previous": previous, "anchor_seq": seq, "anchor_hash": digest}))
    return seq


class EventsService:
    def __init__(self, cfg: Config, key: bytes, resolve: Callable[[str], bytes], *, writer_uids: frozenset[int],
                 reader_uids: frozenset[int], group_gid: int | None, web_uids: frozenset[int] = frozenset()) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError("events.hmac_key_ref must provide at least 32 bytes")
        self.cfg = cfg
        self.key = key
        self.store = open_store(cfg)
        pseudo = build_pseudonymizer(cfg, resolve)
        senders: dict[str, Sender] = {}
        self.unavailable: list[str] = []
        if cfg.events.forwarding.enabled:
            try:
                senders[SIEM] = build_siem_sender(cfg.events.forwarding, pseudo, resolve)
            except Exception as exc:          # queue keeps events until fixed
                log.error("SIEM forwarding unavailable: %s", type(exc).__name__)
                senders[SIEM] = unavailable_sender(SIEM)
                self.unavailable.append(SIEM)
        channels, unavailable = build_alert_channels(cfg, resolve)
        for name, ch in channels.items():
            senders[name] = alert_sender(ch, pseudo)
        for name in unavailable:
            senders[name] = unavailable_sender(name)
        self.unavailable.extend(unavailable)
        e = cfg.events
        self.forwarder = Forwarder(self.store, senders, max_attempts=e.max_attempts,
                                   backoff_initial=e.backoff_initial_seconds, backoff_max=e.backoff_max_seconds)
        self.server = EventsServer(self.store, e.socket_path, writer_uids=writer_uids, reader_uids=reader_uids,
                                   web_uids=web_uids, group_gid=group_gid, on_append=self.forwarder.wake,
                                   status_extra=lambda: {"channels_unavailable": list(self.unavailable)})
        self._tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        res = await asyncio.to_thread(check_integrity, self.store, self.key)
        if not res.ok:
            await asyncio.to_thread(record_tamper, self.store, res)
        else:
            log.info("audit chain verified (%d events)", res.checked)
        await self.server.start()
        self.forwarder.start()
        self.forwarder.wake()
        self._tasks = [asyncio.create_task(self._checkpoints()), asyncio.create_task(self._maintenance())]

    async def _checkpoints(self) -> None:
        interval = self.cfg.events.checkpoint_interval_hours * 3600
        while True:
            age = await asyncio.to_thread(self.store.last_checkpoint_age)
            if age is None or age >= interval:
                try:
                    await asyncio.to_thread(self.store.checkpoint, self.key)
                    self.forwarder.wake()
                except Exception as exc:
                    log.error("checkpoint failed: %s", type(exc).__name__)
                age = 0.0
            await asyncio.sleep(max(60.0, interval - age))

    async def _maintenance(self) -> None:
        while True:
            await asyncio.sleep(3600)
            try:
                res = await asyncio.to_thread(check_integrity, self.store, self.key)
                if not res.ok and await asyncio.to_thread(record_tamper, self.store, res):
                    self.forwarder.wake()
                removed = await asyncio.to_thread(self.store.prune, self.cfg.events.retention_days)
                if removed:
                    log.info("retention: pruned %d events", removed)
            except Exception as exc:
                log.error("maintenance failed: %s", type(exc).__name__)

    async def close(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.server.close()
        await self.forwarder.aclose()
        with contextlib.suppress(Exception):
            self.store.close()
