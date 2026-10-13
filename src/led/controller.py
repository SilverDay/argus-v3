"""LED controller: renders the current pattern on a background thread.

The orchestrator's events select the pattern (``on_event``); the render thread
computes ``frame(pattern, t)`` at ``frames_per_second`` and writes only changes.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable

from src.shared.config import LedConfig
from src.shared.models import EventType, ScanEvent

from .drivers import LedDriver
from .patterns import OFF, Pattern, frame, pattern_for


class LedController:
    def __init__(self, driver: LedDriver, cfg: LedConfig, clock: Callable[[], float] = time.monotonic) -> None:
        self.driver = driver
        self.cfg = cfg
        self.clock = clock
        self._lock = threading.Lock()
        self._pattern = pattern_for(None)
        self._since = clock()
        self._state: str | None = None
        self._verdict: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def pattern(self) -> Pattern:
        with self._lock:
            return self._pattern

    def _select(self) -> None:
        new = pattern_for(self._state, self._verdict)
        with self._lock:
            if new != self._pattern:
                self._pattern = new
                self._since = self.clock()          # patterns start at phase 0

    def on_event(self, event: ScanEvent) -> None:
        p = event.payload
        if event.event_type is EventType.STATE_CHANGED:
            self._state = str(p.get("state")) if p.get("state") else None
            if p.get("verdict"):
                self._verdict = str(p["verdict"])
            elif self._state not in ("RESULT", "OPERATOR_HOLD"):
                self._verdict = None
        elif event.event_type is EventType.VERDICT:
            self._verdict = str(p.get("verdict")) if p.get("verdict") else None
        elif event.event_type is EventType.IPC_DISCONNECTED:
            self._state, self._verdict = None, None
        else:
            return
        self._select()

    def render_once(self) -> None:
        with self._lock:
            pattern, since = self._pattern, self._since
        self.driver.set(frame(pattern, self.clock() - since))

    def _run(self) -> None:
        period = 1.0 / self.cfg.frames_per_second
        while not self._stop.is_set():
            self.render_once()
            self._stop.wait(period)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="led-render", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(2)
        self.driver.set(OFF)
        self.driver.close()
