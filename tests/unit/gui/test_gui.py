import json

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest

from src.gui.main_window import current_screen_name
from src.gui.presentation import STATES, VERDICTS
from src.shared.models import EventType, GUIState, ScanEvent


def ev(t, payload=None):
    return ScanEvent(t, None, payload or {})


def state(window, name, **payload):
    window.handle_event(ev(EventType.STATE_CHANGED, {"state": name, **payload}))


def all_text(widget):
    from PySide6.QtWidgets import QLabel, QPushButton
    widgets = [*widget.findChildren(QLabel), *widget.findChildren(QPushButton)]
    return " | ".join(w.text() for w in widgets if w.isVisible())


# --- states ------------------------------------------------------------------

def test_every_state_has_a_screen_with_colour_icon_and_text(window):
    assert set(window.screens) == {s.value for s in GUIState}
    assert set(STATES) == {s.value for s in GUIState}
    for s in GUIState:
        state(window, s.value, verdict="CLEAN")
        assert current_screen_name(window) == s.value
        screen = window.screens[s.value]
        assert screen.title.text() and screen.icon.kind     # never colour alone


def test_full_sequence_driven_by_events(window):
    seq = ["STARTING", "IDLE", "VALIDATING", "MOUNTING", "SCANNING", "EVALUATING",
           "OPERATOR_HOLD", "EJECTING", "RESULT"]
    for name in seq:
        state(window, name)
        assert current_screen_name(window) == name


def test_unknown_state_ignored(window):
    state(window, "IDLE")
    state(window, "PWNED")
    assert current_screen_name(window) == "IDLE"


def test_starts_and_falls_back_to_disconnected(window):
    state(window, "RESULT", verdict="CLEAN", safe_to_remove=True)
    window.handle_event(ev(EventType.IPC_DISCONNECTED))
    assert current_screen_name(window) == "DISCONNECTED"   # never a stale result


# --- result screen -------------------------------------------------------------

VERDICT = {
    "verdict": "THREAT", "reason_codes": ["malware_detected"],
    "coverage": {"files_scanned": 9, "files_discovered": 10, "partitions_scanned": 1,
                 "partitions_discovered": 1, "files_skipped": 1, "files_failed": 0, "files_uninspectable": 0},
    "threats": [{"engine": "clamav", "signature": "Win.Test.Evil", "severity": "high",
                 "file_path": "part1/Users/alice/secret-salary.xlsx"}],   # must never be rendered
}


@pytest.mark.parametrize("verdict", list(VERDICTS))
def test_result_colours_per_verdict(window, verdict):
    window.handle_event(ev(EventType.VERDICT, {**VERDICT, "verdict": verdict}))
    state(window, "RESULT", verdict=verdict, safe_to_remove=True)
    screen = window.screens["RESULT"]
    assert VERDICTS[verdict].background in screen.styleSheet()
    assert screen.title.text() == VERDICTS[verdict].title


def test_result_redacts_paths_and_shows_coverage_and_removal(window):
    window.handle_event(ev(EventType.VERDICT, VERDICT))
    state(window, "RESULT", verdict="THREAT", safe_to_remove=True)
    text = all_text(window.screens["RESULT"])
    assert "secret-salary" not in text and "alice" not in text and "part1" not in text
    assert "9 of 10 files checked" in text and "Win.Test.Evil" in text
    assert "1 files could not be checked" in text
    assert "You can now remove the device." in text


def test_result_unsafe_and_removed_texts(window):
    state(window, "RESULT", verdict="INCOMPLETE", safe_to_remove=False)
    assert "Do not remove the device yet." in all_text(window.screens["RESULT"])
    state(window, "RESULT", verdict="INCOMPLETE", safe_to_remove=False, removed=True)
    assert "removed before the check finished" in all_text(window.screens["RESULT"])


def test_signature_names_can_be_hidden(qtbot, sent):
    from src.gui.main_window import MainWindow
    from src.shared.config import load_config_from_dict
    w = MainWindow(load_config_from_dict({"gui": {"show_signature_names": False}}), sent.append)
    qtbot.addWidget(w)
    w.show()
    w.handle_event(ev(EventType.VERDICT, VERDICT))
    state(w, "RESULT", verdict="THREAT", safe_to_remove=True)
    text = all_text(w.screens["RESULT"])
    assert "Win.Test.Evil" not in text and "1 detections" in text


def test_restricted_scope_disclosed(window):
    window.handle_event(ev(EventType.VERDICT, {**VERDICT, "verdict": "CLEAN", "threats": [],
                                               "reason_codes": ["no_detections", "restricted_extension_scope"]}))
    state(window, "RESULT", verdict="CLEAN", safe_to_remove=True)
    assert "Only selected file types were checked." in all_text(window.screens["RESULT"])


def test_rejected_and_not_ready_details(window):
    state(window, "REJECTED", reason="hid_interface")
    assert "keyboard or mouse" in all_text(window.screens["REJECTED"])
    state(window, "NOT_READY", failures=["clamav_unavailable", "signatures_stale"])
    assert "clamav_unavailable" in all_text(window.screens["NOT_READY"])


def test_progress_counters(window):
    state(window, "SCANNING")
    window.handle_event(ev(EventType.SCAN_PROGRESS, {"files_scanned": 5, "files_discovered": 8,
                                                     "bytes_read": 2048, "elapsed_s": 3.2}))
    assert "5 of 8 files checked" in window.screens["SCANNING"].detail.text()


def test_second_device_toast(window):
    state(window, "SCANNING")
    window.handle_event(ev(EventType.DEVICE_REJECTED, {"reason": "second_device"}))
    assert window.toast.isVisible() and "one device" in window.toast.text()
    assert current_screen_name(window) == "SCANNING"


# --- PIN overlay (AC-S06) ---------------------------------------------------------

def test_pin_layout_randomised_every_presentation(window):
    layouts = []
    for _ in range(100):
        window.pin.open()
        layout = window.pin.layout_digits()
        assert sorted(layout) == list("0123456789")
        layouts.append(tuple(layout))
        window.pin.cancel()
    assert all(a != b for a, b in zip(layouts, layouts[1:]))
    assert len(set(layouts)) > 90


def _type(pin_overlay, digits):
    by_text = {b.text(): b for b in pin_overlay._digit_buttons}
    for d in digits:
        by_text[d].click()


def test_pin_shows_dots_and_submits_via_ipc_only(window, sent):
    state(window, "IDLE")
    window.open_pin()
    assert sent[-1].event_type is EventType.LOCKOUT_QUERY
    _type(window.pin, "48291")
    assert window.pin.dots.text() == "●●●●●"
    assert not window.pin.ok_button.isEnabled()          # minimum length 6
    _type(window.pin, "6")
    assert window.pin.dots.text() == "●" * 6 and "482916" not in all_text(window.pin)
    window.pin.ok_button.click()
    submit = sent[-1]
    assert submit.event_type is EventType.OPERATOR_PIN_SUBMIT and submit.payload == {"pin": "482916"}
    assert window.pin._buffer == [] and window.pin.dots.text() == ""
    assert "482916" not in repr(submit)                  # redacted repr


def test_pin_buffer_cleared_on_cancel_and_hide(window):
    window.open_pin()
    _type(window.pin, "1234")
    window.pin.cancel()
    assert window.pin._buffer == []
    window.open_pin()
    _type(window.pin, "1234")
    window.pin.hide()
    assert window.pin._buffer == []


def test_pin_max_length(window):
    window.open_pin()
    _type(window.pin, "1" * 20)
    assert len(window.pin._buffer) == window.cfg.pin.max_length


def test_auth_success_opens_operator_panel(window, sent):
    window.handle_event(ev(EventType.VERDICT, VERDICT))
    window.open_pin()
    _type(window.pin, "482916")
    window.pin.ok_button.click()
    window.handle_event(ev(EventType.AUTH_RESULT, {"success": True, "locked_out": False,
                                                   "last_scan": VERDICT, "health": {"failures": []}}))
    assert not window.pin.isVisible() and window.operator.isVisible()
    assert "THREAT" in window.operator.summary.text()
    assert not window.operator.ack_button.isVisible()     # only during OPERATOR_HOLD


def test_auth_failure_and_lockout(window):
    window.open_pin()
    _type(window.pin, "000001")
    window.pin.ok_button.click()
    window.handle_event(ev(EventType.AUTH_RESULT, {"success": False, "locked_out": False}))
    assert window.pin.isVisible() and "Wrong PIN" in window.pin.status.text()
    assert sorted(window.pin.layout_digits()) == list("0123456789")   # re-shuffled layout
    _type(window.pin, "000001")
    window.pin.ok_button.click()
    window.handle_event(ev(EventType.AUTH_RESULT, {"success": False, "locked_out": True}))
    assert "Locked" in window.pin.status.text()
    assert not any(b.isEnabled() for b in window.pin._digit_buttons)


def test_foreign_auth_result_ignored(window):
    window.handle_event(ev(EventType.AUTH_RESULT, {"success": True}))
    assert not window.operator.isVisible()


def test_lockout_state_from_orchestrator(window):
    window.open_pin()
    window.handle_event(ev(EventType.LOCKOUT_STATE, {"locked_out": True}))
    assert not window.pin.ok_button.isEnabled()


# --- long press & operator hold ----------------------------------------------------

def test_long_press_opens_pin_only_after_duration(window, qtbot):
    state(window, "IDLE")
    area = window.screens["IDLE"].operator_area
    QTest.mousePress(area, Qt.LeftButton, pos=QPoint(10, 10))
    QTest.mouseRelease(area, Qt.LeftButton, pos=QPoint(10, 10), delay=100)
    qtbot.wait(600)
    assert not window.pin.isVisible()                    # short tap: nothing
    QTest.mousePress(area, Qt.LeftButton, pos=QPoint(10, 10))
    qtbot.waitUntil(window.pin.isVisible, timeout=2000)   # held for long_press_ms (500 in tests)
    QTest.mouseRelease(area, Qt.LeftButton, pos=QPoint(10, 10))


def test_operator_hold_countdown_and_ack(window, sent, qtbot):
    window.handle_event(ev(EventType.OPERATOR_HOLD_ENTERED, {"max_seconds": 60}))
    state(window, "OPERATOR_HOLD", remaining_s=3)
    screen = window.screens["OPERATOR_HOLD"]
    assert "3 s" in screen.countdown.text()
    qtbot.waitUntil(lambda: "1 s" in screen.countdown.text(), timeout=3000)
    screen.pin_button.click()
    _type(window.pin, "482916")
    window.pin.ok_button.click()
    window.handle_event(ev(EventType.AUTH_RESULT, {"success": True, "locked_out": False}))
    assert window.operator.ack_button.isVisible()
    window.operator.ack_button.click()
    assert sent[-1].event_type is EventType.OPERATOR_ACK


def test_hold_exit_closes_overlays(window):
    window.handle_event(ev(EventType.OPERATOR_HOLD_ENTERED, {}))
    state(window, "OPERATOR_HOLD", remaining_s=30)
    window.open_pin()
    window.handle_event(ev(EventType.OPERATOR_HOLD_EXITED, {"reason": "timeout"}))
    assert not window.pin.isVisible()


def test_pin_not_offered_while_disconnected(window):
    window.handle_event(ev(EventType.IPC_DISCONNECTED))
    window.open_pin()
    assert not window.pin.isVisible()


# --- ambient mode (spec §4.4) -----------------------------------------------------

def test_ambient_after_idle_and_wake_on_insertion(window):
    state(window, "IDLE")
    window._ambient_timer.setInterval(50)
    window._ambient_timer.start()
    QTest.qWait(150)
    assert current_screen_name(window) == "AMBIENT"
    assert "station-test" in all_text(window.ambient)
    state(window, "IDLE")                                 # periodic re-announce keeps ambient
    assert current_screen_name(window) == "AMBIENT"
    state(window, "VALIDATING")                           # insertion wakes without touch
    assert current_screen_name(window) == "VALIDATING"


def test_payload_is_never_rendered_raw(window):
    state(window, "SCANNING", verdict="<b>x</b>", junk=json.dumps({"a": 1}))
    assert "junk" not in all_text(window.screens["SCANNING"])


# --- translations (spec §4.1) --------------------------------------------------

def test_no_unextractable_tr_literals():
    """pyside6-lupdate gives bare tr("...") calls an empty context, so they would never be
    translated at runtime (context "usbscan"). Literals must use the explicit forms."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[3] / "src" / "gui"
    offenders = [f"{p.name}:{i}" for p in root.rglob("*.py")
                 for i, line in enumerate(p.read_text().splitlines(), 1)
                 if re.search(r'(?<![.\w])tr\("', line)]
    assert offenders == []


def test_translation_loaded_at_runtime(qtbot, tmp_path, sent):
    import shutil
    import subprocess
    if not (shutil.which("pyside6-lupdate") and shutil.which("pyside6-lrelease")):
        pytest.skip("Qt translation tools not installed")
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[3]
    ts = tmp_path / "usbscan_de.ts"
    subprocess.run(["pyside6-lupdate", *map(str, (root / "src/gui").glob("*.py")), "-ts", str(ts)],
                   check=True, capture_output=True)
    text = ts.read_text().replace(
        "<source>Threat detected</source>\n        <translation type=\"unfinished\"></translation>",
        "<source>Threat detected</source>\n        <translation>Bedrohung erkannt</translation>")
    ts.write_text(text)
    subprocess.run(["pyside6-lrelease", str(ts), "-qm", str(tmp_path / "usbscan_de.qm")],
                   check=True, capture_output=True)
    from PySide6.QtWidgets import QApplication
    from src.gui.app import Translator, available_languages
    from src.gui.main_window import MainWindow
    from src.shared.config import load_config_from_dict
    assert ("de", "Deutsch") in available_languages(str(tmp_path))
    translator = Translator(QApplication.instance(), str(tmp_path))
    assert translator.set_language("de")
    try:
        w = MainWindow(load_config_from_dict({}), sent.append)
        qtbot.addWidget(w)
        w.handle_event(ev(EventType.IPC_CONNECTED))
        state(w, "RESULT", verdict="THREAT", safe_to_remove=True)
        assert w.screens["RESULT"].title.text() == "Bedrohung erkannt"
    finally:
        translator.set_language("en")
