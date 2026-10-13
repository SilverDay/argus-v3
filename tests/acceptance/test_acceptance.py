"""pytest entry for the on-device acceptance checks (Pi only, full stack, as root).

    sudo .venv/bin/python -m pytest tests/acceptance/            # non-disruptive checks
    sudo USB_SCAN_ACCEPTANCE_DESTRUCTIVE=1 .venv/bin/python -m pytest tests/acceptance/

The same checks, with reports and the interactive helpers, are in run_acceptance.py. A
PENDING or SKIP result (manual step still needed) is reported as a skip, never as a pass.
"""
import os

import pytest

CONFIG = os.environ.get("USB_SCAN_CONFIG", "/etc/usb-scan/scan_station.yaml")
DESTRUCTIVE = os.environ.get("USB_SCAN_ACCEPTANCE_DESTRUCTIVE") == "1"

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not os.path.exists(CONFIG) or not os.path.exists("/run/usb-scan/broker.sock"),
    reason="station acceptance: run as root on a provisioned station")


@pytest.fixture(scope="module")
def station():
    from src.shared.config import load_config
    from tests.acceptance.station import Station
    st = Station(load_config(CONFIG), config_path=CONFIG)
    yield st
    st.events.close()


def _assert(result):
    from tests.acceptance.station import FAIL, PASS
    if result.status not in (PASS, FAIL):
        pytest.skip(f"{result.check_id} {result.status}: {'; '.join(result.details)}")
    assert result.status == PASS, "\n".join(result.details)


def _baseline(st):
    from tests.acceptance.run_acceptance import BASELINE
    return st.load_state(BASELINE)


def test_pre(station):
    from tests.acceptance.run_acceptance import check_pre
    _assert(check_pre(station))


def test_ac_f05_synthetic_scan(station):
    from tests.acceptance.run_acceptance import check_f05
    _assert(check_f05(station))


def test_ac_f07_coverage_metrics(station):
    from tests.acceptance.run_acceptance import check_f07
    base = _baseline(station)
    _assert(check_f07(station, base["seq"] if base else 0))


def test_ac_s01_read_only_root(station):
    from tests.acceptance.run_acceptance import check_s01
    _assert(check_s01(station))


def test_ac_s02_usbguard_rejection(station):
    from tests.acceptance.run_acceptance import check_s02
    _assert(check_s02(station, _baseline(station)))


def test_ac_s04_broker_and_socket_isolation(station):
    from tests.acceptance.run_acceptance import check_s04
    _assert(check_s04(station, CONFIG))


def test_ac_r03_power_loss_recovery(station):
    from tests.acceptance.run_acceptance import check_r03
    _assert(check_r03(station))


@pytest.mark.skipif(not DESTRUCTIVE, reason="set USB_SCAN_ACCEPTANCE_DESTRUCTIVE=1")
def test_ac_s05_lockout_survives_gui_restart(station):
    from tests.acceptance.run_acceptance import check_s05
    _assert(check_s05(station, CONFIG))


@pytest.mark.skipif(not DESTRUCTIVE, reason="set USB_SCAN_ACCEPTANCE_DESTRUCTIVE=1")
def test_ac_r01_health_gate(station):
    from tests.acceptance.run_acceptance import check_r01
    _assert(check_r01(station))


@pytest.mark.skipif(not DESTRUCTIVE, reason="set USB_SCAN_ACCEPTANCE_DESTRUCTIVE=1")
def test_ac_r04_crash_recovery(station):
    from tests.acceptance.run_acceptance import check_r04
    _assert(check_r04(station))


def test_ac_s06_pin_pad_randomised(station):
    from tests.acceptance.run_acceptance import check_s06
    _assert(check_s06(station))
