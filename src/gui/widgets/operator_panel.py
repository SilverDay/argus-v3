"""Operator functions after a successful PIN (spec §4.3): last scan summary, health,
language, and — only during OPERATOR_HOLD — acknowledging the result.
No high-risk actions exist here by design; those need the named-admin web UI.
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import QCoreApplication, Qt, Signal
from PySide6.QtWidgets import QComboBox, QFrame, QLabel, QPushButton, QVBoxLayout, QWidget

from ..presentation import tr


class OperatorPanel(QFrame):
    acknowledge = Signal()
    language_selected = Signal(str)
    closed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("operatorPanel")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet(
            "#operatorPanel { background: #101418; } QLabel { color: white; font-size: 18px; }"
            "QPushButton, QComboBox { font-size: 22px; min-height: 56px; color: white; background: #37474f; }")
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.health = QLabel("")
        self.health.setWordWrap(True)
        self.language = QComboBox()
        self.language.setMinimumHeight(56)
        self.language.activated.connect(lambda i: self.language_selected.emit(self.language.itemData(i)))
        self.ack_button = QPushButton(QCoreApplication.translate("usbscan", "Acknowledge and release device"))
        self.ack_button.clicked.connect(self._ack)
        close = QPushButton(QCoreApplication.translate("usbscan", "Close"))
        close.clicked.connect(self.close_panel)
        col = QVBoxLayout(self)
        title = QLabel(QCoreApplication.translate("usbscan", "Operator"))
        title.setStyleSheet("font-size: 26px; font-weight: bold;")
        col.addWidget(title, alignment=Qt.AlignHCenter)
        for w in (self.summary, self.health, self.language, self.ack_button, close):
            col.addWidget(w)
        self.hide()

    def set_languages(self, languages: list[tuple[str, str]], current: str) -> None:
        self.language.clear()
        for code, label in languages:
            self.language.addItem(label, code)
        idx = self.language.findData(current)
        self.language.setCurrentIndex(max(idx, 0))

    def open(self, last_scan: dict[str, Any] | None, health: dict[str, Any] | None, hold_active: bool) -> None:
        if last_scan:
            cov = last_scan.get("coverage", {})
            self.summary.setText(QCoreApplication.translate("usbscan", "Last scan: {v} — {s} of {d} files scanned, {t} detections").format(
                v=last_scan.get("verdict", "?"), s=cov.get("files_scanned", 0),
                d=cov.get("files_discovered", 0), t=len(last_scan.get("threats", []))))
        else:
            self.summary.setText(QCoreApplication.translate("usbscan", "No scan since start."))
        if health:
            failures = health.get("failures") or []
            self.health.setText(QCoreApplication.translate("usbscan", "Health: OK") if not failures else
                                QCoreApplication.translate("usbscan", "Health: {f}").format(f=", ".join(failures)))
        self.ack_button.setVisible(hold_active)
        if self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        self.show()
        self.raise_()

    def _ack(self) -> None:
        self.acknowledge.emit()
        self.close_panel()

    def close_panel(self) -> None:
        self.hide()
        self.closed.emit()
