import asyncio
import os
import subprocess
import sys
import time

import pytest

from src.led import drivers
from src.led.controller import LedController
from src.led.drivers import LgpioDriver, StubDriver, select_driver
from src.led.patterns import (
    AMBER, BLUE, GREEN, OFF, RED, WHITE, frame, pattern_for,
)
from src.shared.config import load_config_from_dict
from src.shared.ipc import IPCClient, IPCServer
from src.shared.models import EventType, GUIState, ScanEvent, Verdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def led_cfg(**kw):
    return load_config_from_dict({"led": {"driver": "stub", **kw}}).led


# --- patterns (spec §3.3 LED column) ------------------------------------------

@pytest.mark.parametrize("verdict,kind,colors,hz", [
    ("CLEAN", "solid", (GREEN,), 0),
    ("THREAT", "pulse", (RED,), 4),
    ("SUSPICIOUS", "pulse", (AMBER,), 2),
    ("INCOMPLETE", "alternate", (WHITE, AMBER), 1),
    ("ERROR", "blink", (WHITE,), 2),
    ("REJECTED", "alternate", (WHITE, AMBER), 2),
    ("NOT_READY", "solid", (WHITE,), 0),
])
def test_verdict_patterns_match_spec(verdict, kind, colors, hz):
    p = pattern_for("RESULT", verdict)
    assert p.kind == kind and p.hz == hz and (p.a, p.b)[:len(colors)] == colors


def test_every_state_and_verdict_has_a_pattern():
    for s in GUIState:
        assert pattern_for(s.value, "CLEAN") is not None
    for v in Verdict:
        assert pattern_for("RESULT", v.value).name


def test_state_patterns():
    assert pattern_for("IDLE").a == BLUE and pattern_for("IDLE").kind == "pulse"
    assert pattern_for("SCANNING") == pattern_for("VALIDATING") and pattern_for("SCANNING").a == AMBER
    assert pattern_for("OPERATOR_HOLD", "SUSPICIOUS") == pattern_for("RESULT", "SUSPICIOUS")
    assert pattern_for(None).a == WHITE                         # orchestrator unreachable
    assert pattern_for("RESULT", None).name == "white_blink"    # unknown verdict fails to ERROR
    eject_failed = pattern_for("EJECT_FAILED")
    others = {pattern_for("RESULT", v.value).name for v in Verdict}
    assert eject_failed.name not in others                      # "do not remove" stands out


def test_frames():
    pulse = pattern_for("RESULT", "THREAT")                     # 4 Hz -> 0.25 s period
    assert frame(pulse, 0.0) == pytest.approx((0.1, 0, 0))
    assert frame(pulse, 0.125) == pytest.approx((1.0, 0, 0))
    blink = pattern_for("RESULT", "ERROR")                      # 2 Hz
    assert frame(blink, 0.1) == WHITE and frame(blink, 0.3) == OFF
    alt = pattern_for("RESULT", "INCOMPLETE")                   # 1 Hz
    assert frame(alt, 0.2) == WHITE and frame(alt, 0.7) == AMBER
    assert frame(pattern_for("RESULT", "CLEAN"), 123.4) == GREEN


# --- controller ---------------------------------------------------------------

class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def ev(t, payload):
    return ScanEvent(t, None, payload)


def test_controller_follows_events():
    cfg = led_cfg()
    clock = Clock()
    drv = StubDriver(cfg)
    c = LedController(drv, cfg, clock)
    assert c.pattern.a == WHITE                                 # nothing connected yet
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "IDLE"}))
    assert c.pattern.a == BLUE
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "SCANNING"}))
    c.on_event(ev(EventType.VERDICT, {"verdict": "THREAT"}))
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "EJECTING"}))
    assert c.pattern.a == WHITE
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "RESULT", "verdict": "THREAT"}))
    assert c.pattern.name == "red_pulse"
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "IDLE"}))
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "RESULT"}))  # stale verdict must not leak
    assert c.pattern.name == "white_blink"
    c.on_event(ev(EventType.IPC_DISCONNECTED, {}))
    assert c.pattern.a == WHITE


def test_render_writes_duties_and_restarts_phase():
    cfg = led_cfg(brightness_percent=50)
    clock = Clock()
    drv = StubDriver(cfg)
    c = LedController(drv, cfg, clock)
    clock.t = 10.0
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "RESULT", "verdict": "THREAT"}))
    c.render_once()
    assert drv.history[-1] == (5.0, 0.0, 0.0)                   # pulse starts at 10 % of 50 %
    clock.t = 10.125
    c.render_once()
    assert drv.history[-1] == (50.0, 0.0, 0.0)


def test_common_anode_inverts():
    cfg = led_cfg(common_anode=True)
    drv = StubDriver(cfg)
    drv.set(GREEN)
    assert drv.history[-1] == (100.0, 0.0, 100.0)


def test_stop_turns_led_off():
    cfg = led_cfg()
    drv = StubDriver(cfg)
    c = LedController(drv, cfg)
    c.start()
    c.on_event(ev(EventType.STATE_CHANGED, {"state": "RESULT", "verdict": "CLEAN"}))
    time.sleep(0.1)
    c.stop()
    assert drv.closed and drv.history[-1] == (0.0, 0.0, 0.0)
    assert (0.0, 100.0, 0.0) in drv.history


# --- lgpio driver (fake module with the real API surface) ----------------------

class FakeLgpio:
    class error(Exception):
        pass

    def __init__(self, fail_claim=None):
        self.calls = []
        self.fail_claim = fail_claim

    def gpiochip_open(self, chip):
        self.calls.append(("open", chip))
        return 7

    def gpio_claim_output(self, h, gpio, level=0, lFlags=0):
        if gpio == self.fail_claim:
            raise self.error("GPIO busy")
        self.calls.append(("claim", gpio, level))
        return 0

    def tx_pwm(self, h, gpio, freq, duty, pulse_offset=0, pulse_cycles=0):
        self.calls.append(("pwm", gpio, freq, duty))
        return 0

    def gpio_write(self, h, gpio, level):
        self.calls.append(("write", gpio, level))
        return 0

    def gpio_free(self, h, gpio):
        self.calls.append(("free", gpio))
        return 0

    def gpiochip_close(self, h):
        self.calls.append(("close", h))
        return 0


def test_lgpio_driver_claims_pwms_and_releases():
    lg = FakeLgpio()
    cfg = led_cfg(driver="lgpio", gpiochip=4)
    d = LgpioDriver(cfg, lgpio_module=lg)
    assert lg.calls[:4] == [("open", 4), ("claim", 17, 0), ("claim", 27, 0), ("claim", 22, 0)]
    d.set(AMBER)
    d.set(AMBER)                                               # unchanged: no extra PWM commands
    pwm = [c for c in lg.calls if c[0] == "pwm"]
    assert pwm == [("pwm", 17, 200, 100.0), ("pwm", 27, 200, 35.0), ("pwm", 22, 200, 0.0)]
    d.close()
    assert ("pwm", 17, 0, 0) in lg.calls and ("free", 22) in lg.calls and lg.calls[-1] == ("close", 7)


def test_lgpio_claim_failure_releases_everything():
    lg = FakeLgpio(fail_claim=27)
    with pytest.raises(FakeLgpio.error):
        LgpioDriver(led_cfg(driver="lgpio"), lgpio_module=lg)
    assert ("free", 17) in lg.calls and lg.calls[-1] == ("close", 7)


def test_driver_selection(monkeypatch):
    def broken(cfg, lgpio_module=None):
        raise ImportError("no lgpio")
    monkeypatch.setattr(drivers, "LgpioDriver", broken)
    assert isinstance(select_driver(led_cfg(driver="auto")), StubDriver)    # development fallback
    with pytest.raises(ImportError):
        select_driver(led_cfg(driver="lgpio"))                              # production: loud
    assert isinstance(select_driver(led_cfg(driver="stub")), StubDriver)


def test_distinct_gpios_required():
    from src.shared.config import ConfigError
    with pytest.raises(ConfigError, match="different GPIOs"):
        load_config_from_dict({"led": {"pin_red": 17, "pin_green": 17}})


# --- end to end: real state socket -----------------------------------------------

async def test_led_follows_orchestrator_socket(tmp_path):
    path = str(tmp_path / "state.sock")
    server = IPCServer(path, allowed_uids={os.getuid()},
                       on_connect=lambda creds: [ScanEvent(EventType.STATE_CHANGED, None, {"state": "IDLE"})])
    await server.start()
    cfg = led_cfg()
    controller = LedController(StubDriver(cfg), cfg)
    client = IPCClient(path, controller.on_event, initial_backoff=0.02)
    task = asyncio.create_task(client.run())
    try:
        for _ in range(100):
            if controller.pattern.a == BLUE:
                break
            await asyncio.sleep(0.02)
        assert controller.pattern.name == "blue_pulse"
        server.broadcast(ScanEvent(EventType.STATE_CHANGED, "s", {"state": "RESULT", "verdict": "CLEAN"}))
        for _ in range(100):
            if controller.pattern.a == GREEN:
                break
            await asyncio.sleep(0.02)
        assert controller.pattern.name == "green_solid"
        await server.close()                                   # orchestrator gone -> NOT_READY white
        for _ in range(100):
            if controller.pattern.a == WHITE:
                break
            await asyncio.sleep(0.02)
        assert controller.pattern.a == WHITE
    finally:
        client.stop()
        await asyncio.wait_for(task, 2)


def test_service_process_starts_and_stops_cleanly(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"led:\n  driver: stub\norchestrator:\n  state_socket: {tmp_path}/none.sock\n"
                   "logging:\n  file: ''\n")
    proc = subprocess.Popen([sys.executable, "-m", "src.led", "--config", str(cfg)], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    proc.terminate()
    out, _ = proc.communicate(timeout=10)
    assert proc.returncode == 0, out
    assert "Traceback" not in out
    assert "using stub driver" not in out          # driver: stub selected explicitly, no fallback warning


def test_wiring_test_drives_each_channel_then_off(capsys):
    from src.led.__main__ import wiring_test
    from src.led.drivers import StubDriver
    from src.shared.config import load_config_from_dict
    cfg = load_config_from_dict({"led": {"driver": "stub"}}).led
    drv = StubDriver(cfg)
    assert wiring_test(cfg, sleep=lambda s: None, driver=drv) == 0
    assert drv.history[:5] == [(100.0, 0.0, 0.0), (0.0, 100.0, 0.0), (0.0, 0.0, 100.0),
                               (100.0, 100.0, 100.0), (0.0, 0.0, 0.0)]
    assert drv.closed
    assert "BCM red=17 green=27 blue=22" in capsys.readouterr().out
