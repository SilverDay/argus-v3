"""Screens for the 13 GUI states plus ambient and disconnected views (spec §4.2, §4.4).

Screens only render what the orchestrator sent. No file paths or device identifiers are
shown: the orchestrator does not send them, and payload keys other than the ones rendered
here are ignored on purpose (spec §4.1 "no full sensitive filenames on the public screen").
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from PySide6.QtCore import QCoreApplication, QTimer, Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .presentation import REJECT_REASONS, REMOVAL_TEXT, Look, tr, verdict_look
from .widgets.icons import StatusIcon


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


class StateScreen(QWidget):
    """Colour + icon + title + message (+ optional detail line)."""

    def __init__(self, look: Look, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("stateScreen")
        self.setAttribute(Qt.WA_StyledBackground, True)     # paint the background on the whole screen
        self.icon = StatusIcon(look.icon)
        self.icon.setFixedSize(120, 120)
        self.title = QLabel()
        self.title.setWordWrap(True)
        self.title.setAlignment(Qt.AlignCenter)
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignCenter)
        self.detail = QLabel()
        self.detail.setWordWrap(True)
        self.detail.setAlignment(Qt.AlignCenter)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(24, 24, 24, 24)
        self.body.addStretch(1)
        self.body.addWidget(self.icon, alignment=Qt.AlignHCenter)
        self.body.addWidget(self.title)
        self.body.addWidget(self.message)
        self.body.addWidget(self.detail)
        self.body.addStretch(1)
        self.apply(look)

    def apply(self, look: Look, detail: str = "") -> None:
        self.setStyleSheet(f"#stateScreen {{ background: {look.background}; }}"
                           f"QLabel {{ color: {look.foreground}; background: transparent; }}")
        self.title.setStyleSheet("font-size: 34px; font-weight: bold;")
        self.message.setStyleSheet("font-size: 22px;")
        self.detail.setStyleSheet("font-size: 18px;")
        self.icon.set_kind(look.icon, look.foreground)
        self.title.setText(tr(look.title))
        self.message.setText(tr(look.message))
        self.detail.setText(detail)
        self.detail.setVisible(bool(detail))

    def update_payload(self, payload: dict[str, Any]) -> None:
        """Default: state screens have no dynamic content."""


class NotReadyScreen(StateScreen):
    def update_payload(self, payload: dict[str, Any]) -> None:
        failures = [str(f) for f in payload.get("failures", [])][:4]
        # Support code for IT, not a diagnosis for the public.
        self.detail.setText(QCoreApplication.translate("usbscan", "Support code: {c}").format(c=" · ".join(failures)) if failures else "")
        self.detail.setVisible(bool(failures))


class RejectedScreen(StateScreen):
    def update_payload(self, payload: dict[str, Any]) -> None:
        reason = str(payload.get("reason", ""))
        text = tr(REJECT_REASONS.get(reason, "")) if reason in REJECT_REASONS else ""
        code = QCoreApplication.translate("usbscan", "Reason code: {c}").format(c=reason) if reason else ""
        self.detail.setText("\n".join(t for t in (text, code) if t))
        self.detail.setVisible(bool(reason))


class ScanningScreen(StateScreen):
    def update_progress(self, p: dict[str, Any]) -> None:
        self.detail.setText(QCoreApplication.translate("usbscan", "{s} of {d} files checked · {b} read · {t} s").format(
            s=int(p.get("files_scanned", 0)), d=int(p.get("files_discovered", 0)),
            b=_fmt_bytes(int(p.get("bytes_read", 0))), t=int(float(p.get("elapsed_s", 0)))))
        self.detail.setVisible(True)

    def update_payload(self, payload: dict[str, Any]) -> None:
        self.detail.setText(QCoreApplication.translate("usbscan", "Starting…"))
        self.detail.setVisible(True)


class ResultScreen(StateScreen):
    """Final verdict, coverage summary and removal instruction (spec §3.5, §4.2)."""

    def __init__(self, look: Look, parent: QWidget | None = None, *, show_signatures: bool = True) -> None:
        super().__init__(look, parent)
        self.show_signatures = show_signatures
        self.removal = QLabel()
        self.removal.setWordWrap(True)
        self.removal.setAlignment(Qt.AlignCenter)
        self.body.insertWidget(self.body.count() - 1, self.removal)
        self.verdict: dict[str, Any] = {}

    def set_verdict(self, verdict: dict[str, Any]) -> None:
        self.verdict = verdict

    def update_payload(self, payload: dict[str, Any]) -> None:
        name = str(payload.get("verdict") or self.verdict.get("verdict") or "")
        self.apply(verdict_look(name))
        lines = []
        cov = self.verdict.get("coverage") if self.verdict.get("verdict") == name else None
        if cov:
            lines.append(QCoreApplication.translate("usbscan", "{s} of {d} files checked · {p} of {q} partitions").format(
                s=cov.get("files_scanned", 0), d=cov.get("files_discovered", 0),
                p=cov.get("partitions_scanned", 0), q=cov.get("partitions_discovered", 0)))
            not_checked = sum(int(cov.get(k, 0)) for k in ("files_skipped", "files_failed", "files_uninspectable"))
            if not_checked:
                lines.append(QCoreApplication.translate("usbscan", "{n} files could not be checked").format(n=not_checked))
        threats = self.verdict.get("threats", []) if self.verdict.get("verdict") == name else []
        if threats:
            if self.show_signatures:
                names = sorted({str(t.get("signature", ""))[:60] for t in threats})[:3]
                lines.append(QCoreApplication.translate("usbscan", "Detections: {n}").format(n=", ".join(names)))
            else:
                lines.append(QCoreApplication.translate("usbscan", "{n} detections").format(n=len(threats)))
        if "restricted_extension_scope" in self.verdict.get("reason_codes", []):
            lines.append(QCoreApplication.translate("usbscan", "Only selected file types were checked."))   # spec §6.2 disclosure
        self.detail.setText("\n".join(lines))
        self.detail.setVisible(bool(lines))
        if payload.get("removed"):
            removal = REMOVAL_TEXT["removed"]
        elif payload.get("safe_to_remove"):
            removal = REMOVAL_TEXT["safe"]
        else:
            removal = REMOVAL_TEXT["unsafe"]
        self.removal.setText(tr(removal))
        self.removal.setStyleSheet("font-size: 24px; font-weight: bold; padding: 8px;"
                                   "border: 2px solid white; border-radius: 8px;")


class OperatorHoldScreen(StateScreen):
    """Countdown display; the timeout itself is enforced by the orchestrator (spec §3.5)."""
    request_pin = Signal()

    def __init__(self, look: Look, parent: QWidget | None = None) -> None:
        super().__init__(look, parent)
        self.remaining = 0
        self.countdown = QLabel()
        self.countdown.setAlignment(Qt.AlignCenter)
        self.countdown.setStyleSheet("font-size: 28px;")
        self.pin_button = QPushButton(QCoreApplication.translate("usbscan", "Operator PIN"))
        self.pin_button.setMinimumSize(220, 64)
        self.pin_button.setStyleSheet("font-size: 22px; color: white; background: #00695c; border-radius: 8px;")
        self.pin_button.clicked.connect(self.request_pin)
        self.body.insertWidget(self.body.count() - 1, self.countdown)
        self.body.insertWidget(self.body.count() - 1, self.pin_button, alignment=Qt.AlignHCenter)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)

    def update_payload(self, payload: dict[str, Any]) -> None:
        self.remaining = int(payload.get("remaining_s", 0))
        self._render()
        self.timer.start()

    def _tick(self) -> None:
        self.remaining = max(0, self.remaining - 1)
        self._render()
        if self.remaining == 0:
            self.timer.stop()

    def _render(self) -> None:
        self.countdown.setText(QCoreApplication.translate("usbscan", "Automatic release in {n} s").format(n=self.remaining))

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.timer.stop()
        super().hideEvent(event)


class LongPressArea(QWidget):
    """Invisible reserved region; a press held for ``duration_ms`` emits ``activated``."""
    activated = Signal()

    def __init__(self, duration_ms: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(96, 96)                      # ≥ 48×48 touch target
        self.setAttribute(Qt.WA_AcceptTouchEvents, True)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(duration_ms)
        self.timer.timeout.connect(self.activated)

    def _down(self) -> None:
        self.timer.start()

    def _up(self) -> None:
        self.timer.stop()

    def mousePressEvent(self, e) -> None:  # noqa: N802
        self._down()

    def mouseReleaseEvent(self, e) -> None:  # noqa: N802
        self._up()

    def event(self, e) -> bool:
        from PySide6.QtCore import QEvent
        if e.type() == QEvent.TouchBegin:
            self._down()
            return True
        if e.type() in (QEvent.TouchEnd, QEvent.TouchCancel):
            self._up()
            return True
        return super().event(e)


class IdleScreen(StateScreen):
    def __init__(self, look: Look, long_press_ms: int, parent: QWidget | None = None) -> None:
        super().__init__(look, parent)
        self.operator_area = LongPressArea(long_press_ms)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self.operator_area)
        self.body.insertLayout(0, row)


class AmbientScreen(QWidget):
    """Minimal idle view: station ID, date/time, health — no user or file details (spec §4.4)."""

    def __init__(self, station_id: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ambient")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet("#ambient { background: #000000; } QLabel { color: #b0bec5; background: transparent; }")
        self.station = QLabel(station_id)
        self.clock = QLabel()
        self.health = QLabel()
        for w, size in ((self.station, 22), (self.clock, 40), (self.health, 20)):
            w.setAlignment(Qt.AlignCenter)
            w.setStyleSheet(f"font-size: {size}px;")
        col = QVBoxLayout(self)
        col.addStretch(1)
        col.addWidget(self.clock)
        col.addWidget(self.station)
        col.addWidget(self.health)
        col.addStretch(1)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)
        self.refresh()

    def set_health(self, passed: bool) -> None:
        self.health.setText(QCoreApplication.translate("usbscan", "● Ready") if passed else QCoreApplication.translate("usbscan", "● Not ready"))

    def refresh(self) -> None:
        self.clock.setText(datetime.now().strftime("%Y-%m-%d  %H:%M"))
