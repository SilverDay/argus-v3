"""Kiosk main window: maps orchestrator events to screens (spec §4.2–§4.4).

The orchestrator is the single source of truth for state. This window does not model
transitions; it shows the screen for the state the orchestrator announces (validated
against the 13 known GUI states) and renders the payload. Operator input is sent back
as OPERATOR_PIN_SUBMIT / OPERATOR_ACK / LOCKOUT_QUERY events — the only messages the
orchestrator accepts from the GUI.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QCoreApplication, QTimer, Qt
from PySide6.QtWidgets import QLabel, QMainWindow, QStackedWidget, QWidget

from src.shared.config import Config
from src.shared.models import EventType, GUIState, ScanEvent

from .presentation import DISCONNECTED, REJECT_REASONS, state_look, tr
from .screens import (
    AmbientScreen, IdleScreen, NotReadyScreen, OperatorHoldScreen, RejectedScreen, ResultScreen,
    ScanningScreen, StateScreen,
)
from .widgets.operator_panel import OperatorPanel
from .widgets.pin_overlay import PinOverlay

log = logging.getLogger(__name__)
WINDOW_TITLE = "usb-scan-kiosk"


class MainWindow(QMainWindow):
    def __init__(self, cfg: Config, send: Callable[[ScanEvent], None],
                 languages: list[tuple[str, str]] | None = None,
                 on_language: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self.cfg = cfg
        self._send = send
        self._on_language = on_language
        self.setWindowTitle(WINDOW_TITLE)
        self.connected = False
        self.state: str | None = None
        self.last_payload: dict[str, Any] = {}
        self.last_verdict: dict[str, Any] = {}
        self.health: dict[str, Any] = {}
        self.hold_active = False
        self._pending_auth = False

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.screens: dict[str, StateScreen] = {}
        for state in GUIState:
            look = state_look(state.value)
            if state is GUIState.IDLE:
                screen = IdleScreen(look, cfg.gui.long_press_ms)
                screen.operator_area.activated.connect(self.open_pin)
            elif state is GUIState.NOT_READY:
                screen = NotReadyScreen(look)
            elif state is GUIState.REJECTED:
                screen = RejectedScreen(look)
            elif state is GUIState.SCANNING:
                screen = ScanningScreen(look)
            elif state is GUIState.RESULT:
                screen = ResultScreen(look, show_signatures=cfg.gui.show_signature_names)
            elif state is GUIState.OPERATOR_HOLD:
                screen = OperatorHoldScreen(look)
                screen.request_pin.connect(self.open_pin)
            else:
                screen = StateScreen(look)
            self.screens[state.value] = screen
            self.stack.addWidget(screen)
        self.disconnected = StateScreen(DISCONNECTED)
        self.stack.addWidget(self.disconnected)
        self.ambient = AmbientScreen(cfg.station.station_id)
        self.stack.addWidget(self.ambient)
        self.ambient.mousePressEvent = lambda e: self._wake()          # touch wakes ambient mode
        self.stack.setCurrentWidget(self.disconnected)

        self.pin = PinOverlay(self, min_length=cfg.pin.min_length, max_length=cfg.pin.max_length)
        self.pin.pin_submitted.connect(self._submit_pin)
        self.operator = OperatorPanel(self)
        self.operator.set_languages(languages or [("en", "English")], cfg.gui.language)
        self.operator.acknowledge.connect(lambda: self._send(ScanEvent(EventType.OPERATOR_ACK, None)))
        self.operator.language_selected.connect(self._language)

        self.toast = QLabel(self)
        self.toast.setAlignment(Qt.AlignCenter)
        self.toast.setStyleSheet("background: #ff6f00; color: black; font-size: 20px; padding: 10px;")
        self.toast.hide()
        self._toast_timer = QTimer(self, singleShot=True, interval=5000)
        self._toast_timer.timeout.connect(self.toast.hide)

        self._ambient_timer = QTimer(self, singleShot=True, interval=cfg.gui.ambient_after_seconds * 1000)
        self._ambient_timer.timeout.connect(self._enter_ambient)

    # --- event dispatch -------------------------------------------------------

    def handle_event(self, event: ScanEvent) -> None:
        t, p = event.event_type, event.payload
        if t is EventType.IPC_CONNECTED:
            self.connected = True
        elif t is EventType.IPC_DISCONNECTED:
            self.connected = False
            self.state = None
            self._close_overlays()
            self._ambient_timer.stop()
            self.stack.setCurrentWidget(self.disconnected)      # never keep a stale result on screen
        elif t is EventType.STATE_CHANGED:
            self._show_state(str(p.get("state", "")), p)
        elif t is EventType.VERDICT:
            self.last_verdict = dict(p)
            result = self.screens[GUIState.RESULT.value]
            result.set_verdict(self.last_verdict)
        elif t is EventType.SCAN_PROGRESS and self.state == GUIState.SCANNING.value:
            self.screens[GUIState.SCANNING.value].update_progress(p)
        elif t is EventType.HEALTH:
            self.health = dict(p)
            self.ambient.set_health(bool(p.get("passed")))
        elif t is EventType.DEVICE_REJECTED and p.get("reason") in ("second_device", "station_not_ready"):
            self.show_toast(tr(REJECT_REASONS.get(str(p.get("reason")), "")) or QCoreApplication.translate("usbscan", "Device not accepted."))
        elif t is EventType.OPERATOR_HOLD_ENTERED:
            self.hold_active = True
        elif t is EventType.OPERATOR_HOLD_EXITED:
            self.hold_active = False
            self._close_overlays()
        elif t is EventType.AUTH_RESULT:
            self._auth_result(p)
        elif t is EventType.LOCKOUT_STATE:
            self.pin.set_locked(bool(p.get("locked_out")))

    def _show_state(self, state: str, payload: dict[str, Any]) -> None:
        if state not in self.screens:
            log.warning("ignoring unknown GUI state from orchestrator: %r", state[:40])
            return
        self.state = state
        self.last_payload = dict(payload)
        screen = self.screens[state]
        screen.update_payload(payload)
        if self.stack.currentWidget() is not self.ambient or state != GUIState.IDLE.value:
            self.stack.setCurrentWidget(screen)
        if state == GUIState.IDLE.value:
            self._ambient_timer.start()
        else:
            self._ambient_timer.stop()                     # any activity wakes ambient mode
            if self.stack.currentWidget() is self.ambient:
                self.stack.setCurrentWidget(screen)
        if state not in (GUIState.IDLE.value, GUIState.OPERATOR_HOLD.value, GUIState.RESULT.value,
                         GUIState.NOT_READY.value):
            self._close_overlays()

    # --- ambient --------------------------------------------------------------

    def _enter_ambient(self) -> None:
        if self.state == GUIState.IDLE.value and not self.pin.isVisible() and not self.operator.isVisible():
            self.ambient.refresh()
            self.ambient.timer.start()
            self.stack.setCurrentWidget(self.ambient)

    def _wake(self) -> None:
        if self.stack.currentWidget() is self.ambient:
            self.ambient.timer.stop()
            self.stack.setCurrentWidget(self.screens[GUIState.IDLE.value])
            self._ambient_timer.start()

    # --- operator ---------------------------------------------------------------

    def open_pin(self) -> None:
        if not self.connected:
            return
        self._send(ScanEvent(EventType.LOCKOUT_QUERY, None))
        self.pin.open()

    def _submit_pin(self, pin: str) -> None:
        self._pending_auth = True
        self._send(ScanEvent(EventType.OPERATOR_PIN_SUBMIT, None, {"pin": pin}))

    def _auth_result(self, p: dict[str, Any]) -> None:
        if not self._pending_auth:
            return                                  # a result for another client's attempt
        self._pending_auth = False
        if p.get("success"):
            self.pin.hide()
            self.operator.open(p.get("last_scan"), p.get("health"),
                               hold_active=self.hold_active and self.state == GUIState.OPERATOR_HOLD.value)
        elif p.get("locked_out"):
            self.pin.set_locked(True)
        else:
            self.pin.show_failure()

    def _language(self, code: str) -> None:
        if self._on_language is not None:
            self._on_language(code)

    def _close_overlays(self) -> None:
        self.pin.hide()
        self.operator.hide()
        self._pending_auth = False

    def show_toast(self, text: str) -> None:
        self.toast.setText(text)
        self.toast.setGeometry(0, self.height() - 60, self.width(), 60)
        self.toast.show()
        self.toast.raise_()
        self._toast_timer.start()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt API
        for overlay in (self.pin, self.operator):
            if overlay.isVisible():
                overlay.setGeometry(self.rect())
        super().resizeEvent(event)


def current_screen_name(window: MainWindow) -> str:
    """Test/diagnostic helper: name of the visible screen."""
    w: QWidget = window.stack.currentWidget()
    if w is window.disconnected:
        return "DISCONNECTED"
    if w is window.ambient:
        return "AMBIENT"
    return next(name for name, screen in window.screens.items() if screen is w)
