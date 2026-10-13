"""RGB LED drivers. Production: native ``lgpio`` software PWM (python3-lgpio).

The rpi-lgpio compatibility shim is deliberately not used (project rule). lgpio
functions raise ``lgpio.error`` on failure (the module's default behaviour).
"""
from __future__ import annotations

import logging
from typing import Protocol

from src.shared.config import LedConfig, LedDriverKind

from .patterns import Color

log = logging.getLogger(__name__)


class LedDriver(Protocol):
    def set(self, color: Color) -> None: ...
    def close(self) -> None: ...


def _duties(color: Color, cfg: LedConfig) -> tuple[float, float, float]:
    k = cfg.brightness_percent / 100.0
    duties = tuple(round(max(0.0, min(1.0, c)) * k * 100.0, 1) for c in color)
    if cfg.common_anode:                         # common anode: GPIO low = LED on
        duties = tuple(round(100.0 - d, 1) for d in duties)
    return duties  # type: ignore[return-value]


class StubDriver:
    """Development / test driver: records what would be written."""

    def __init__(self, cfg: LedConfig) -> None:
        self.cfg = cfg
        self.history: list[tuple[float, float, float]] = []
        self.closed = False

    def set(self, color: Color) -> None:
        self.history.append(_duties(color, self.cfg))

    def close(self) -> None:
        self.history.append(_duties((0.0, 0.0, 0.0), self.cfg))
        self.closed = True


class LgpioDriver:
    def __init__(self, cfg: LedConfig, lgpio_module=None) -> None:
        if lgpio_module is None:
            import lgpio as lgpio_module           # python3-lgpio (system package)
        self.lg = lgpio_module
        self.cfg = cfg
        self.gpios = (cfg.pin_red, cfg.pin_green, cfg.pin_blue)
        self.handle = self.lg.gpiochip_open(cfg.gpiochip)
        claimed = []
        try:
            off = 1 if cfg.common_anode else 0
            for gpio in self.gpios:
                self.lg.gpio_claim_output(self.handle, gpio, off)
                claimed.append(gpio)
        except Exception:
            for gpio in claimed:
                self.lg.gpio_free(self.handle, gpio)
            self.lg.gpiochip_close(self.handle)
            raise
        self._last: tuple[float, float, float] | None = None

    def set(self, color: Color) -> None:
        duties = _duties(color, self.cfg)
        if duties == self._last:
            return                                  # only queue PWM changes (tx_pwm queue)
        for gpio, duty in zip(self.gpios, duties):
            self.lg.tx_pwm(self.handle, gpio, self.cfg.pwm_frequency_hz, duty)
        self._last = duties

    def close(self) -> None:
        off = 1 if self.cfg.common_anode else 0
        for gpio in self.gpios:
            try:
                self.lg.tx_pwm(self.handle, gpio, 0, 0)     # frequency 0 = PWM off
                self.lg.gpio_write(self.handle, gpio, off)
                self.lg.gpio_free(self.handle, gpio)
            except Exception as exc:                        # best effort during shutdown
                log.warning("LED GPIO %d release failed: %s", gpio, exc)
        self.lg.gpiochip_close(self.handle)


def select_driver(cfg: LedConfig) -> LedDriver:
    if cfg.driver is LedDriverKind.STUB:
        return StubDriver(cfg)
    if cfg.driver is LedDriverKind.LGPIO:
        return LgpioDriver(cfg)                      # errors propagate: production must be loud
    try:
        return LgpioDriver(cfg)
    except Exception as exc:                         # ImportError, lgpio.error, OSError
        log.warning("LED: lgpio unavailable (%s); using stub driver", type(exc).__name__)
        return StubDriver(cfg)
