import json
from datetime import datetime, timezone

import pytest

from src.shared.models import (
    CoverageMetrics, EventType, GUIState, ModelError, ScanEvent, ScanMetadata,
    ScanResult, Severity, SkipReason, ThreatEntry, Verdict,
)


def test_seven_verdicts_and_thirteen_gui_states():
    assert {v.value for v in Verdict} == {
        "CLEAN", "THREAT", "SUSPICIOUS", "INCOMPLETE", "ERROR", "REJECTED", "NOT_READY"}
    assert len(GUIState) == 13


def test_coverage_contains_all_required_metrics():
    d = CoverageMetrics().to_dict()
    for key in ("partitions_discovered", "partitions_scanned", "partitions_excluded",
                "files_discovered", "files_scanned", "files_skipped", "files_failed",
                "files_uninspectable", "bytes_enumerated", "bytes_read", "skip_reasons",
                "clamav_complete", "yara_complete", "vt_complete"):
        assert key in d


def test_record_skip_counts_reason():
    c = CoverageMetrics()
    c.record_skip(SkipReason.TOO_LARGE)
    c.record_skip(SkipReason.TOO_LARGE)
    c.record_skip(SkipReason.ENCRYPTED)
    assert c.files_skipped == 3
    assert c.to_dict()["skip_reasons"] == {"encrypted": 1, "too_large": 2}


def _result():
    meta = ScanMetadata("scan-1", "station-001", "1-1",
                        datetime(2026, 10, 13, 9, 0, tzinfo=timezone.utc))
    cov = CoverageMetrics(files_discovered=2, files_scanned=2, clamav_complete=True)
    return ScanResult(meta, Verdict.THREAT, cov,
                      threats=[ThreatEntry("a.exe", "clamav", "Eicar-Test-Signature", "0" * 64)])


def test_scan_result_round_trip_through_json():
    r = _result()
    again = ScanResult.from_dict(json.loads(json.dumps(r.to_dict())))
    assert again == r
    assert r.to_dict()["schema_version"] == "1.5"
    assert r.to_dict()["metadata"]["session_start_utc"] == "2026-10-13T09:00:00Z"


def test_from_dict_rejects_bad_input():
    d = _result().to_dict()
    d["verdict"] = "PROBABLY_FINE"
    with pytest.raises(ModelError):
        ScanResult.from_dict(d)
    d = _result().to_dict()
    d["coverage"]["files_scanned"] = True  # bool is not an int here
    with pytest.raises(ModelError):
        ScanResult.from_dict(d)
    d = _result().to_dict()
    d["coverage"]["bytes_read"] = -1
    with pytest.raises(ModelError):
        ScanResult.from_dict(d)
    d = _result().to_dict()
    d["threats"][0]["severity"] = "catastrophic"
    with pytest.raises(ModelError):
        ScanResult.from_dict(d)


def test_scan_event_round_trip_and_validation():
    e = ScanEvent(EventType.VERDICT, "scan-1", {"verdict": "CLEAN"})
    assert ScanEvent.from_dict(e.to_dict()) == e
    bad = e.to_dict() | {"event_type": "rm_rf"}
    with pytest.raises(ModelError):
        ScanEvent.from_dict(bad)
    with pytest.raises(ModelError):
        ScanEvent.from_dict(e.to_dict() | {"timestamp_utc": "2026-10-13T09:00:00"})  # naive
    with pytest.raises(ModelError):
        ScanEvent.from_dict(e.to_dict() | {"schema_version": "2.0"})
    with pytest.raises(ModelError):
        ScanEvent.from_dict(e.to_dict() | {"event_id": "not-a-uuid"})


def test_scan_event_repr_redacts_pin():
    e = ScanEvent(EventType.OPERATOR_PIN_SUBMIT, None, {"pin": "482916", "nested": {"token": "x"}})
    text = repr(e)
    assert "482916" not in text
    assert "'x'" not in text


def test_threat_default_severity_is_high():
    assert ThreatEntry("f", "clamav", "sig", "0" * 64).severity is Severity.HIGH
