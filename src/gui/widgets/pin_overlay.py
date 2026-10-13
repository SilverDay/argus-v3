"""Operator PIN overlay (spec §4.3, §10.1, AC-S06).

* Digit positions are shuffled with a CSPRNG (secrets.SystemRandom) on EVERY show.
* Entered digits are displayed as dots only; nothing is logged.
* The GUI never verifies the PIN: ``pin_submitted`` hands it to the IPC layer, which
  sends it to the orchestrator (persistent lockout lives there). The local buffer is
  cleared on submit, cancel and hide.
"""
from __future__ import annotations

import secrets

from PySide6.QtCore import QCoreApplication, Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from ..presentation import tr

_rng = secrets.SystemRandom()
BUTTON_SIZE = 72          # ≥ 48 px minimum touch target (spec §4.1)


class PinOverlay(QFrame):
    pin_submitted = Signal(str)
    cancelled = Signal()

    def __init__(self, parent: QWidget | None = None, *, min_length: int = 6, max_length: int = 12) -> None:
        super().__init__(parent)
        self.setObjectName("pinOverlay")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet(
            "#pinOverlay { background: #101418; }"
            "QLabel { color: white; } "
            "QPushButton { font-size: 28px; color: white; background: #37474f; border-radius: 8px; }"
            "QPushButton:pressed { background: #546e7a; } QPushButton:disabled { color: #78909c; }")
        self.min_length = min_length
        self.max_length = max_length
        self._buffer: list[str] = []
        self._digit_buttons: list[QPushButton] = []
        self._locked = False

        self.title = QLabel(QCoreApplication.translate("usbscan", "Operator PIN"))
        self.title.setStyleSheet("font-size: 26px; font-weight: bold;")
        self.dots = QLabel("")
        self.dots.setStyleSheet("font-size: 34px; letter-spacing: 6px;")
        self.dots.setAccessibleName(QCoreApplication.translate("usbscan", "Entered digits"))
        self.status = QLabel("")
        self.status.setStyleSheet("font-size: 18px; color: #ffcc80;")
        self.status.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        for i in range(10):
            b = QPushButton("")
            b.setFixedSize(BUTTON_SIZE, BUTTON_SIZE)
            b.clicked.connect(lambda _=False, btn=b: self._press(btn.text()))
            self._digit_buttons.append(b)
        self.back_button = QPushButton("⌫")
        self.back_button.setAccessibleName(QCoreApplication.translate("usbscan", "Delete last digit"))
        self.ok_button = QPushButton("✓")
        self.ok_button.setAccessibleName(QCoreApplication.translate("usbscan", "Confirm"))
        for b in (self.back_button, self.ok_button):
            b.setFixedSize(BUTTON_SIZE, BUTTON_SIZE)
        self.back_button.clicked.connect(self._backspace)
        self.ok_button.clicked.connect(self._submit)
        self._grid = grid

        cancel = QPushButton(QCoreApplication.translate("usbscan", "Cancel"))
        cancel.setMinimumHeight(56)
        cancel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        cancel.clicked.connect(self.cancel)

        col = QVBoxLayout()
        col.addWidget(self.title, alignment=Qt.AlignHCenter)
        col.addWidget(self.dots, alignment=Qt.AlignHCenter)
        col.addWidget(self.status, alignment=Qt.AlignHCenter)
        col.addLayout(grid)
        col.addWidget(cancel)
        outer = QHBoxLayout(self)
        outer.addStretch(1)
        outer.addLayout(col)
        outer.addStretch(1)
        self.hide()

    # --- layout -------------------------------------------------------------

    def layout_digits(self) -> list[str]:
        """Current digit order (row-major) as displayed."""
        return [b.text() for b in self._digit_buttons]

    def _shuffle(self) -> None:
        digits = list("0123456789")
        _rng.shuffle(digits)
        for button, digit in zip(self._digit_buttons, digits):
            button.setText(digit)
            button.setAccessibleName(digit)
        # 3x4 grid: nine digits, then backspace / last digit / confirm.
        positions = [(r, c) for r in range(3) for c in range(3)] + [(3, 1)]
        for button, (r, c) in zip(self._digit_buttons, positions):
            self._grid.addWidget(button, r, c)
        self._grid.addWidget(self.back_button, 3, 0)
        self._grid.addWidget(self.ok_button, 3, 2)

    # --- input --------------------------------------------------------------

    def _render(self) -> None:
        self.dots.setText("●" * len(self._buffer))
        self.ok_button.setEnabled(not self._locked and len(self._buffer) >= self.min_length)
        for b in self._digit_buttons:
            b.setEnabled(not self._locked and len(self._buffer) < self.max_length)
        self.back_button.setEnabled(not self._locked and bool(self._buffer))

    def _press(self, digit: str) -> None:
        if self._locked or len(self._buffer) >= self.max_length or not (digit.isascii() and digit.isdigit()):
            return
        self._buffer.append(digit)
        self._render()

    def _backspace(self) -> None:
        if self._buffer:
            self._buffer.pop()
        self._render()

    def _clear(self) -> None:
        for i in range(len(self._buffer)):
            self._buffer[i] = ""
        self._buffer.clear()
        self._render()

    def _submit(self) -> None:
        if self._locked or len(self._buffer) < self.min_length:
            return
        pin = "".join(self._buffer)
        self._clear()
        self.status.setText(QCoreApplication.translate("usbscan", "Checking…"))
        self.pin_submitted.emit(pin)

    # --- public API ---------------------------------------------------------

    def open(self) -> None:
        self._clear()
        self._shuffle()                     # new random layout on every presentation
        self.status.setText(QCoreApplication.translate("usbscan", "Locked. Try again later.") if self._locked else "")
        self._render()
        if self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        self.show()
        self.raise_()

    def cancel(self) -> None:
        self._clear()
        self.hide()
        self.cancelled.emit()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt API
        # Only drop the digits here: during teardown child widgets may already be gone.
        for i in range(len(self._buffer)):
            self._buffer[i] = ""
        self._buffer.clear()
        super().hideEvent(event)

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        if locked:
            self._clear()
            self.status.setText(QCoreApplication.translate("usbscan", "Too many attempts. Locked. Try again later."))
        self._render()

    def show_failure(self) -> None:
        self.status.setText(QCoreApplication.translate("usbscan", "Wrong PIN."))
        self._shuffle()
        self._render()
