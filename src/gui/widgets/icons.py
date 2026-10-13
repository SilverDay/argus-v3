"""Vector status icons painted with QPainter (no image files, scale to any screen)."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget


class StatusIcon(QWidget):
    KINDS = ("check", "cross", "warn", "question", "info", "block", "spinner", "hand", "usb")

    def __init__(self, kind: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._kind = kind
        self._color = QColor("#ffffff")
        self._angle = 0
        self._spin = QTimer(self)
        self._spin.setInterval(80)
        self._spin.timeout.connect(self._tick)
        self.setMinimumSize(96, 96)
        self.set_kind(kind)

    @property
    def kind(self) -> str:
        return self._kind

    def set_kind(self, kind: str, color: str = "#ffffff") -> None:
        self._kind = kind if kind in self.KINDS else "info"
        self._color = QColor(color)
        if self._kind == "spinner":
            self._spin.start()
        else:
            self._spin.stop()
        self.update()

    def _tick(self) -> None:
        self._angle = (self._angle + 30) % 360
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        side = min(self.width(), self.height()) - 8
        r = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pen = QPen(self._color, max(4.0, side / 14), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen)
        c = r.center()
        u = side / 2
        k = self._kind
        if k == "spinner":
            p.drawArc(r.adjusted(u * .2, u * .2, -u * .2, -u * .2), int(self._angle * 16), 270 * 16)
            return
        p.drawEllipse(r)
        if k == "check":
            path = QPainterPath(QPointF(c.x() - u * .45, c.y()))
            path.lineTo(c.x() - u * .1, c.y() + u * .35)
            path.lineTo(c.x() + u * .5, c.y() - u * .35)
            p.drawPath(path)
        elif k in ("cross", "block"):
            if k == "cross":
                p.drawLine(QPointF(c.x() - u * .4, c.y() - u * .4), QPointF(c.x() + u * .4, c.y() + u * .4))
            p.drawLine(QPointF(c.x() + u * .4, c.y() - u * .4), QPointF(c.x() - u * .4, c.y() + u * .4))
        elif k == "warn":
            p.drawLine(QPointF(c.x(), c.y() - u * .5), QPointF(c.x(), c.y() + u * .15))
            p.drawPoint(QPointF(c.x(), c.y() + u * .45))
        elif k == "question":
            path = QPainterPath(QPointF(c.x() - u * .3, c.y() - u * .25))
            path.cubicTo(c.x() - u * .3, c.y() - u * .65, c.x() + u * .35, c.y() - u * .65, c.x() + u * .3, c.y() - u * .2)
            path.cubicTo(c.x() + u * .25, c.y() + u * .05, c.x(), c.y(), c.x(), c.y() + u * .2)
            p.drawPath(path)
            p.drawPoint(QPointF(c.x(), c.y() + u * .5))
        elif k == "info":
            p.drawPoint(QPointF(c.x(), c.y() - u * .45))
            p.drawLine(QPointF(c.x(), c.y() - u * .15), QPointF(c.x(), c.y() + u * .5))
        elif k == "hand":
            p.drawRect(QRectF(c.x() - u * .3, c.y() - u * .2, u * .6, u * .65))
            for i in range(4):
                x = c.x() - u * .25 + i * u * .17
                p.drawLine(QPointF(x, c.y() - u * .2), QPointF(x, c.y() - u * .55))
        elif k == "usb":
            p.drawLine(QPointF(c.x(), c.y() + u * .55), QPointF(c.x(), c.y() - u * .45))
            p.drawLine(QPointF(c.x(), c.y() + u * .15), QPointF(c.x() - u * .35, c.y() - u * .1))
            p.drawLine(QPointF(c.x(), c.y() + u * .25), QPointF(c.x() + u * .35, c.y() - u * .05))
            p.drawEllipse(QPointF(c.x(), c.y() - u * .5), u * .08, u * .08)
