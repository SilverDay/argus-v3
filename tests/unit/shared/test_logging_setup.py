import json
import logging
import re

import pytest

from src.shared.logging_setup import (
    JsonFormatter, Rfc5424Formatter, redact_text, scan_id_var, setup_logging,
)


@pytest.fixture(autouse=True)
def _restore_root():
    root = logging.getLogger()
    saved = (list(root.handlers), root.level)
    yield
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    for h in saved[0]:
        root.addHandler(h)
    root.setLevel(saved[1])


def _lines(path):
    return [json.loads(l) for l in path.read_text().splitlines()]


def test_json_file_logging_with_scan_id(tmp_path):
    log_file = tmp_path / "scan.jsonl"
    setup_logging("DEBUG", file_path=str(log_file), station_id="station-001")
    log = logging.getLogger("usbscan.test")
    log.info("before scan")
    token = scan_id_var.set("scan-42")
    try:
        log.warning("in scan", extra={"fields": {"files": 3}})
    finally:
        scan_id_var.reset(token)
    a, b = _lines(log_file)
    assert "scan_id" not in a and a["station_id"] == "station-001"
    assert b["scan_id"] == "scan-42" and b["fields"] == {"files": 3} and b["level"] == "WARNING"
    assert re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", b["ts"])
    assert (log_file.stat().st_mode & 0o777) == 0o640


def test_pin_and_secrets_redacted(tmp_path):
    log_file = tmp_path / "scan.jsonl"
    setup_logging("DEBUG", file_path=str(log_file))
    log = logging.getLogger("usbscan.test")
    log.debug("operator pin=%s submitted", "482916")
    log.info("x", extra={"fields": {"pin": "482916", "api_key": "abc", "ok": 1}})
    text = log_file.read_text()
    assert "482916" not in text and "abc" not in text
    assert _lines(log_file)[1]["fields"]["ok"] == 1


@pytest.mark.parametrize("raw", ["pin=123456", "PIN: 123456", "password = 'hunter2'", "api_key=XYZ"])
def test_redact_text(raw):
    out = redact_text(raw)
    assert "***" in out
    assert not any(s in out for s in ("123456", "hunter2", "XYZ"))


def test_level_filtering(tmp_path):
    log_file = tmp_path / "scan.jsonl"
    setup_logging("WARNING", file_path=str(log_file))
    logging.getLogger("x").info("hidden")
    logging.getLogger("x").error("shown")
    assert [l["msg"] for l in _lines(log_file)] == ["shown"]


def test_rfc5424_format():
    rec = logging.LogRecord("usbscan.orch", logging.ERROR, __file__, 1, "clamd down", (), None)
    rec.station_id = 'st"1]'
    rec.scan_id = "scan-1"
    out = Rfc5424Formatter().format(rec)
    # <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG ; facility user(1)*8 + err(3) = 11
    assert re.match(r'^<11>1 \S+Z \S+ usb-scan \d+ usbscan\.orch \[usbscan@32473 station_id="st\\"1\\]" scan_id="scan-1"\] clamd down$', out), out


def test_json_formatter_redacts_exception_text():
    try:
        raise RuntimeError("token=abcdef")
    except RuntimeError:
        import sys
        rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
    doc = json.loads(JsonFormatter().format(rec))
    assert "abcdef" not in doc["exc"]
