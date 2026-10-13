"""Scan orchestrator state machine (spec §3.1–§3.5, §3.8, §4.2).

STARTING -> NOT_READY | IDLE -> VALIDATING -> MOUNTING -> SCANNING -> EVALUATING
  -> [OPERATOR_HOLD] -> EJECTING -> RESULT | EJECT_FAILED ; REJECTED ; ERROR

* One device at a time; a second insertion is rejected and signalled (FR-USB-06).
* The verdict is committed durably before ejection starts (spec §3.2 step 10).
* Removal at any stage cancels the job; partial results are evaluated (a confirmed
  threat stays THREAT, everything else becomes INCOMPLETE) and the session is released.
* "Safe to remove" is only reported after a successful unmount (spec §3.5).
* Operator PINs are verified here (never in the GUI); lockout is persistent.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.shared.auth import AuthManager
from src.shared.config import Config
from src.shared.ipc import PeerCredentials
from src.shared.models import (
    DeviceLifecycle, EventType, GUIState, ScanEvent, ScanResult, Verdict,
)

from . import device_check
from .broker_client import BrokerClient, BrokerError
from .event_sink import JsonlEventSink
from .health import HealthReport, read_cpu_temp, run_checks
from .scan_session import DeviceRejected, ScanSession
from .scanner_clamav import ClamdClient
from .scanner_yara_client import YaraClient
from .usb_monitor import UsbEvent

log = logging.getLogger(__name__)
IDLE_STATES = (GUIState.IDLE, GUIState.NOT_READY, GUIState.STARTING)
WAITING_FOR_REMOVAL = (GUIState.RESULT, GUIState.EJECT_FAILED, GUIState.REJECTED, GUIState.ERROR)


@dataclass
class HoldState:
    authenticated: bool = False
    acknowledged: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass
class ActiveDevice:
    port: str
    sysfs_path: str
    scan_id: str
    session_id: str
    task: asyncio.Task | None = None
    removed: bool = False
    expect_removal: bool = False     # our own logical eject will produce a udev remove
    detached: bool = False           # logically removed; physical removal not observable
    displaying: bool = False         # job only shows a final result; may be superseded
    result: ScanResult | None = None
    timer: asyncio.Task | None = None


class Orchestrator:
    def __init__(self, cfg: Config, broker: BrokerClient, clamd: ClamdClient, sink: JsonlEventSink,
                 broadcast: Callable[[ScanEvent], None], *, auth: AuthManager | None = None,
                 sysfs_root: str = "/sys", gui_uids: frozenset[int] = frozenset()) -> None:
        self.cfg = cfg
        self.broker = broker
        self.clamd = clamd
        self.yara = YaraClient(cfg.yara.socket_path,
                               reply_timeout=cfg.yara.per_file_timeout_seconds + 10) if cfg.yara.enabled else None
        self.sink = sink
        self._broadcast = broadcast
        self.auth = auth
        self.sysfs_root = sysfs_root
        self.gui_uids = gui_uids
        self.state = GUIState.STARTING
        self.state_payload: dict[str, Any] = {}
        self.health = HealthReport()
        self.active: ActiveDevice | None = None
        self.hold: HoldState | None = None
        self.last_result: ScanResult | None = None
        self._lock = asyncio.Lock()

    # --- publishing ---------------------------------------------------------

    async def publish(self, event: ScanEvent) -> None:
        self._broadcast(event)
        await self.sink.publish(event)

    async def set_state(self, state: GUIState, scan_id: str | None = None, **payload: Any) -> None:
        self.state = state
        self.state_payload = {"state": state.value, **payload}
        await self.publish(ScanEvent(EventType.STATE_CHANGED, scan_id, dict(self.state_payload)))

    def snapshot(self, creds: PeerCredentials) -> list[ScanEvent]:
        """Current state for a (re)connecting client; includes the verdict while it is shown."""
        scan_id = self.active.scan_id if self.active else None
        events = []
        if self.active is not None and self.active.result is not None:
            events.append(ScanEvent(EventType.VERDICT, scan_id, self.gui_verdict_payload(self.active.result)))
        events.append(ScanEvent(EventType.STATE_CHANGED, scan_id,
                                dict(self.state_payload or {"state": self.state.value})))
        return events

    @staticmethod
    def gui_verdict_payload(result: ScanResult) -> dict[str, Any]:
        """What the public screen may show: no file paths, no device serials (spec §4.4)."""
        return {
            "verdict": result.verdict.value,
            "reason_codes": result.reason_codes,
            "coverage": result.coverage.to_dict(),
            "threats": [{"engine": t.engine, "signature": t.signature_name, "severity": t.severity.value}
                        for t in result.threats],
            "policy_violation_count": len(result.policy_violations),
        }

    # --- health -------------------------------------------------------------

    async def check_health(self) -> None:
        report = await run_checks(self.cfg, self.broker, self.clamd, yara=self.yara)
        changed = report.failures != self.health.failures
        self.health = report
        if changed or self.state is GUIState.STARTING:
            await self.publish(ScanEvent(EventType.HEALTH, None, {
                "passed": report.passed, "failures": report.failures, "warnings": report.warnings}))
            if report.failures:
                await self.publish(ScanEvent(EventType.HEALTH_GATE_FAILED, None, {"failures": report.failures}))
        if self.state in IDLE_STATES:
            target = GUIState.IDLE if report.passed else GUIState.NOT_READY
            if target is not self.state or changed:
                await self.set_state(target, failures=report.failures)

    async def recover_interrupted(self) -> None:
        stale = self.sink.take_stale_marker()
        if stale is None:
            return
        await self.publish(ScanEvent(EventType.SCAN_INTERRUPTED, stale["scan_id"], {
            "reason": "orchestrator_restart_or_power_loss", "safe_to_remove": False}))
        with contextlib.suppress(BrokerError):
            await self.broker.release(stale["session_id"])

    # --- USB events ---------------------------------------------------------

    async def on_usb_event(self, ev: UsbEvent) -> None:
        async with self._lock:
            if ev.action == "add":
                await self._on_add(ev)
            else:
                await self._on_remove(ev)

    async def _on_add(self, ev: UsbEvent) -> None:
        act = self.active
        if act is not None and act.displaying:   # removed device's result is on screen: new insertion wins
            if act.task is not None and not act.task.done():
                act.task.cancel()
            self._clear_active()
            await self.set_state(GUIState.IDLE)
            act = None
        if act is not None and act.port == ev.port and not act.detached:
            return  # duplicate add for the device we already handle
        if act is not None and not act.detached:
            await self.publish(ScanEvent(EventType.DEVICE_REJECTED, None,
                                         {"reason": "second_device", "port": ev.port}))
            return
        if act is not None and act.detached:
            self._clear_active()      # a new insertion implies the previous device is gone
            await self.set_state(GUIState.IDLE)
        if self.state is not GUIState.IDLE:
            await self.publish(ScanEvent(EventType.DEVICE_REJECTED, None,
                                         {"reason": "station_not_ready", "port": ev.port}))
            return
        self.active = ActiveDevice(ev.port, ev.sysfs_path, str(uuid.uuid4()), str(uuid.uuid4()))
        self.active.task = asyncio.create_task(self._process(self.active), name=f"scan-{ev.port}")

    async def _on_remove(self, ev: UsbEvent) -> None:
        act = self.active
        if act is None or act.port != ev.port:
            return
        if act.expect_removal:
            act.expect_removal = False
            act.detached = True
            return
        act.removed = True
        await self.publish(ScanEvent(EventType.DEVICE_REMOVED, act.scan_id, {"port": ev.port}))
        if act.task is not None and not act.task.done():
            act.task.cancel()
        elif self.state in WAITING_FOR_REMOVAL:
            # e.g. EJECT_FAILED: the broker may still hold mounts for this session.
            with contextlib.suppress(BrokerError):
                await self.broker.release(act.session_id)
            self._clear_active()
            await self.set_state(GUIState.IDLE)
            await self.check_health()

    def _clear_active(self) -> None:
        if self.active and self.active.timer:
            self.active.timer.cancel()
        self.active = None
        self.hold = None

    # --- job ----------------------------------------------------------------

    async def _wait_for_storage(self, port: str) -> bool:
        deadline = time.monotonic() + self.cfg.orchestrator.storage_wait_seconds
        while time.monotonic() < deadline:
            if device_check.has_block_device(self.sysfs_root, port):
                return True
            await asyncio.sleep(0.25)
        return False

    async def _process(self, act: ActiveDevice) -> None:
        scan = ScanSession(self.cfg, self.broker, self.clamd, self.publish, scan_id=act.scan_id,
                           session_id=act.session_id, sysfs_path=act.sysfs_path,
                           read_temp=lambda: read_cpu_temp(self.cfg.orchestrator.thermal_zone_path),
                           yara=self.yara)
        committed = False
        try:
            await self.set_state(GUIState.VALIDATING, act.scan_id)
            await asyncio.sleep(self.cfg.device.insertion_debounce_ms / 1000)
            reason = device_check.precheck(self.sysfs_root, act.port)
            if reason is None and not await self._wait_for_storage(act.port):
                reason = "no_storage_device"
            if reason:
                raise DeviceRejected(reason)
            self.sink.mark_active(act.scan_id, act.session_id)
            await self.publish(ScanEvent(EventType.SCAN_STARTED, act.scan_id, {"port": act.port}))
            await scan.validate()

            await self.set_state(GUIState.MOUNTING, act.scan_id)
            await scan.mount_all()

            await self.set_state(GUIState.SCANNING, act.scan_id)
            extra: list[str] = []
            try:
                await asyncio.wait_for(scan.scan(), self.cfg.scan.global_timeout_seconds)
            except asyncio.TimeoutError:
                extra.append("global_timeout")

            await self.set_state(GUIState.EVALUATING, act.scan_id)
            result = scan.finalize(interrupted=bool(extra), extra_reasons=extra)
            await self._commit(act, result)
            committed = True

            if self._hold_applies(result):
                await self._operator_hold(act)
            await self._eject(act, result)
        except asyncio.CancelledError:
            if not act.removed:
                raise
            await self._handle_removed(act, scan, committed)
        except DeviceRejected as exc:
            await self._finish_rejected(act, scan, exc)
        except Exception as exc:  # appliance fault: never leave the device mounted
            log.exception("scan job failed")
            await self._finish_error(act, scan, committed, exc)
        finally:
            self.sink.clear_active()

    async def _commit(self, act: ActiveDevice, result: ScanResult) -> None:
        act.result = result
        self.last_result = result
        await self.sink.commit_result(result)
        self._broadcast(ScanEvent(EventType.VERDICT, act.scan_id, self.gui_verdict_payload(result)))

    def _hold_applies(self, result: ScanResult) -> bool:
        oh = self.cfg.operator_hold
        return oh.enabled and result.verdict in oh.allowed_verdicts and result.verdict is not Verdict.THREAT

    async def _operator_hold(self, act: ActiveDevice) -> None:
        self.hold = HoldState()
        seconds = self.cfg.operator_hold.max_duration_seconds or 60
        await self.set_state(GUIState.OPERATOR_HOLD, act.scan_id, remaining_s=seconds)
        await self.publish(ScanEvent(EventType.OPERATOR_HOLD_ENTERED, act.scan_id, {"max_seconds": seconds}))
        reason = "timeout"
        try:
            await asyncio.wait_for(self.hold.acknowledged.wait(), seconds)
            reason = "acknowledged"
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            reason = "removed"
            raise
        finally:
            self.hold = None
            await self.publish(ScanEvent(EventType.OPERATOR_HOLD_EXITED, act.scan_id, {"reason": reason}))

    async def _lifecycle(self, act: ActiveDevice, lifecycle: DeviceLifecycle, **extra: Any) -> None:
        await self.publish(ScanEvent(EventType.LIFECYCLE_CHANGED, act.scan_id, {"lifecycle": lifecycle.value, **extra}))

    async def _eject(self, act: ActiveDevice, result: ScanResult) -> None:
        await self.set_state(GUIState.EJECTING, act.scan_id, verdict=result.verdict.value)
        try:
            await self.broker.unmount(act.session_id)
        except BrokerError as exc:
            await self._lifecycle(act, DeviceLifecycle.EJECT_FAILED, error=exc.code)
            await self.set_state(GUIState.EJECT_FAILED, act.scan_id, verdict=result.verdict.value,
                                 safe_to_remove=False)
            return
        await self._lifecycle(act, DeviceLifecycle.UNMOUNTED)
        power_off = False
        act.expect_removal = True
        try:
            res = await self.broker.eject(act.session_id)
            power_off = True
            await self._lifecycle(act, DeviceLifecycle.POWER_OFF_REQUESTED, method=res.get("method"))
            if res.get("method") != "remove":
                act.expect_removal = False
        except BrokerError as exc:
            act.expect_removal = False
            log.warning("eject failed after successful unmount: %s", exc.code)
            with contextlib.suppress(BrokerError):
                await self.broker.release(act.session_id)
        await self._lifecycle(act, DeviceLifecycle.SAFE_TO_REMOVE)
        await self.set_state(GUIState.RESULT, act.scan_id, verdict=result.verdict.value,
                             safe_to_remove=True, power_off=power_off)
        act.timer = asyncio.create_task(self._result_timeout(act, self.cfg.orchestrator.result_display_seconds))

    async def _result_timeout(self, act: ActiveDevice, seconds: float) -> None:
        await asyncio.sleep(seconds)
        async with self._lock:
            # detached: our eject removed the device logically; expect_removal still set means
            # the udev remove never arrived. A device that is still attached keeps its result.
            if self.active is act and (act.detached or act.expect_removal):
                self.active = None
                await self.set_state(GUIState.IDLE)

    async def _release_quietly(self, act: ActiveDevice, scan: ScanSession) -> bool:
        if not scan.enumerated:
            return True
        try:
            await self.broker.release(act.session_id)
            return True
        except BrokerError as exc:
            log.error("broker release failed: %s", exc.code)
            return False

    async def _handle_removed(self, act: ActiveDevice, scan: ScanSession, committed: bool) -> None:
        await self._release_quietly(act, scan)
        await self._lifecycle(act, DeviceLifecycle.REMOVED)
        if not committed:
            result = scan.finalize(interrupted=True, extra_reasons=["device_removed"])
            await self._commit(act, result)
        verdict = act.result.verdict.value if act.result else Verdict.INCOMPLETE.value
        await self.set_state(GUIState.RESULT, act.scan_id, verdict=verdict, safe_to_remove=False, removed=True)
        act.displaying = True
        await asyncio.sleep(self.cfg.orchestrator.removed_result_display_seconds)
        if self.active is act:
            self.active = None
            await self.set_state(GUIState.IDLE)

    async def _finish_rejected(self, act: ActiveDevice, scan: ScanSession, exc: DeviceRejected) -> None:
        released = await self._release_quietly(act, scan)
        result = scan.rejected_result(exc.reason)
        await self._commit(act, result)
        await self.publish(ScanEvent(EventType.DEVICE_REJECTED, act.scan_id,
                                     {"reason": exc.reason, "port": act.port}))
        await self.set_state(GUIState.REJECTED, act.scan_id, reason=exc.reason, safe_to_remove=released)
        if act.removed:
            self._clear_active()
            await self.set_state(GUIState.IDLE)

    async def _finish_error(self, act: ActiveDevice, scan: ScanSession, committed: bool, exc: Exception) -> None:
        released = await self._release_quietly(act, scan)
        if not committed:
            scan.facts.appliance_fault = True
            scan.facts.engine_errors.append(f"{type(exc).__name__}"[:100])
            result = scan.finalize(extra_reasons=["appliance_error"])
            await self._commit(act, result)
        await self.set_state(GUIState.ERROR, act.scan_id,
                             verdict=(act.result.verdict.value if act.result else Verdict.ERROR.value),
                             reason=getattr(exc, "code", type(exc).__name__), safe_to_remove=released)

    # --- operator RPC (GUI only) -------------------------------------------

    async def on_operator_message(self, event: ScanEvent, creds: PeerCredentials) -> None:
        if creds.uid not in self.gui_uids:
            log.warning("operator message from non-GUI uid=%d ignored", creds.uid)
            return
        if event.event_type is EventType.OPERATOR_PIN_SUBMIT:
            await self._pin_submit(event)
        elif event.event_type is EventType.OPERATOR_ACK:
            if self.hold is not None and self.hold.authenticated:
                self.hold.acknowledged.set()
        elif event.event_type is EventType.LOCKOUT_QUERY:
            locked = self.auth.is_locked_out() if self.auth else False
            await self.publish(ScanEvent(EventType.LOCKOUT_STATE, None, {"locked_out": locked}))

    async def _pin_submit(self, event: ScanEvent) -> None:
        pin = event.payload.get("pin")
        if self.auth is None:
            await self.publish(ScanEvent(EventType.AUTH_RESULT, None, {"success": False, "reason": "pin_not_configured"}))
            return
        if not isinstance(pin, str):
            await self.publish(ScanEvent(EventType.AUTH_RESULT, None, {"success": False, "reason": "invalid"}))
            return
        outcome = await asyncio.to_thread(self.auth.attempt, pin)
        payload: dict[str, Any] = {"success": outcome.success, "locked_out": outcome.locked_out,
                                   "level": "operator", "interface": "touchscreen"}
        if outcome.success:
            if self.hold is not None:
                self.hold.authenticated = True
            if self.last_result is not None:
                payload["last_scan"] = self.gui_verdict_payload(self.last_result)
            payload["health"] = {"passed": self.health.passed, "failures": self.health.failures}
        await self.publish(ScanEvent(EventType.AUTH_RESULT, None, payload))
