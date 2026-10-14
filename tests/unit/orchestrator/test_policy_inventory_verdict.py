import os

import pytest

from src.orchestrator import inventory
from src.orchestrator.policy import ExtensionPolicy
from src.orchestrator.verdict_engine import ScanFacts, evaluate
from src.shared.config import load_config_from_dict
from src.shared.models import CoverageMetrics, Severity, SkipReason, ThreatEntry, Verdict


# --- extension policy ---------------------------------------------------------

@pytest.mark.parametrize("name,blocked", [
    ("setup.EXE", "exe"), ("invoice.pdf.exe", "exe"), ("evil.exe.", "exe"), ("evil.exe  ", "exe"),
    ("ｅｖｉｌ.ｅｘｅ", "exe"),            # full-width characters normalise via NFKC
    ("archive.tar.gz", "tar.gz"), ("readme", None), (".exe", None), ("photo.jpg", None),
])
def test_block_matching(name, blocked):
    assert ExtensionPolicy(block=["EXE", ".tar.gz"]).blocked(name) == blocked


def test_allow_scope():
    p = ExtensionPolicy(allow=["pdf"])
    assert p.restricted_scope
    assert p.in_scope("A.PDF") and not p.in_scope("a.docx") and not p.in_scope("README")
    assert ExtensionPolicy().in_scope("anything")


# --- inventory ---------------------------------------------------------------

def _tree(tmp_path):
    root = tmp_path / "mnt"
    (root / "a" / "b").mkdir(parents=True)
    (root / "top.txt").write_text("1")
    (root / "a" / "mid.bin").write_bytes(b"22")
    (root / "a" / "b" / "deep.dat").write_bytes(b"333")
    (root / "escape").symlink_to("/etc/passwd")
    os.mkfifo(root / "pipe")
    return root


def test_walk_finds_regular_files_never_follows_links(tmp_path):
    root = _tree(tmp_path)
    stats = inventory.InventoryStats()
    files = list(inventory.walk(str(root), max_files=100, max_depth=10, max_bytes=10**9, stats=stats))
    assert sorted(f.rel for f in files) == ["a/b/deep.dat", "a/mid.bin", "top.txt"]
    assert (stats.files, stats.bytes, stats.symlinks, stats.special, stats.truncated) == (3, 6, 1, 1, None)
    assert all(not f.path.startswith("/etc") for f in files)


def test_walk_limits(tmp_path):
    root = _tree(tmp_path)
    stats = inventory.InventoryStats()
    list(inventory.walk(str(root), max_files=2, max_depth=10, max_bytes=10**9, stats=stats))
    assert stats.truncated is SkipReason.SCAN_LIMIT and stats.files == 2
    stats = inventory.InventoryStats()
    files = list(inventory.walk(str(root), max_files=100, max_depth=1, max_bytes=10**9, stats=stats))
    assert stats.truncated is SkipReason.RECURSION_LIMIT and "a/b/deep.dat" not in [f.rel for f in files]


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses directory permissions")
def test_unreadable_directory_counted(tmp_path):
    root = _tree(tmp_path)
    os.chmod(root / "a", 0)
    try:
        stats = inventory.InventoryStats()
        list(inventory.walk(str(root), max_files=100, max_depth=10, max_bytes=10**9, stats=stats))
        assert stats.unreadable == 1
    finally:
        os.chmod(root / "a", 0o755)


def test_display_path_sanitises():
    raw = b"bad\x1b[31m\xffname".decode("utf-8", "surrogateescape")
    assert inventory.display_path(raw) == "bad?[31m�name"


# --- verdict engine ----------------------------------------------------------

CFG = load_config_from_dict(None)


def facts(**cov):
    base = dict(partitions_discovered=1, partitions_scanned=1, files_discovered=2, files_scanned=2,
                clamav_complete=True)
    base.update(cov)
    return ScanFacts(CoverageMetrics(**base))


def threat(sev=Severity.HIGH):
    return ThreatEntry("part1/x", "clamav", "Sig", "0" * 64, sev)


def test_clean():
    assert evaluate(facts(), CFG) == (Verdict.CLEAN, ["no_detections"])


def test_threat_beats_everything():
    f = facts(clamav_complete=False, files_failed=1)
    f.threats.append(threat())
    f.appliance_fault = True
    assert evaluate(f, CFG)[0] is Verdict.THREAT


def test_error_beats_incomplete():
    f = facts(clamav_complete=False)
    f.appliance_fault = True
    assert evaluate(f, CFG)[0] is Verdict.ERROR


@pytest.mark.parametrize("change", [
    dict(clamav_complete=False), dict(partitions_excluded=1), dict(files_failed=1),
    dict(files_uninspectable=1), dict(partitions_discovered=0, partitions_scanned=0),
])
def test_incomplete_conditions(change):
    assert evaluate(facts(**change), CFG)[0] is Verdict.INCOMPLETE


def test_skip_reasons_other_than_policy_make_incomplete():
    f = facts()
    f.coverage.record_skip(SkipReason.TOO_LARGE_FOR_ENGINE)
    assert evaluate(f, CFG)[0] is Verdict.INCOMPLETE
    f = facts()
    f.coverage.record_skip(SkipReason.POLICY_EXCLUSION)
    f.restricted_scope = True
    assert evaluate(f, CFG) == (Verdict.CLEAN, ["no_detections", "restricted_extension_scope"])


def test_incomplete_beats_suspicious_and_interrupted():
    f = facts(clamav_complete=False)
    f.threats.append(threat(Severity.MEDIUM))
    assert evaluate(f, CFG)[0] is Verdict.INCOMPLETE
    f = facts()
    f.interrupted = True
    assert "scan_interrupted" in evaluate(f, CFG)[1]


def test_suspicious_and_policy_severity():
    f = facts()
    f.threats.append(threat(Severity.MEDIUM))
    assert evaluate(f, CFG)[0] is Verdict.SUSPICIOUS
    f = facts()
    f.policy_violations.append("blocked_extension:exe:part1/a.exe")
    assert evaluate(f, CFG)[0] is Verdict.SUSPICIOUS
    strict = load_config_from_dict({"scan": {"blocked_extension_severity": "threat"}})
    assert evaluate(f, strict)[0] is Verdict.THREAT


def test_incomplete_vt_coverage_never_changes_verdict():
    f = facts(vt_complete=False)
    vt = load_config_from_dict({"virustotal": {"enabled": True, "api_key_ref": "env:VT"}})
    assert evaluate(f, vt)[0] is Verdict.CLEAN


def test_partition_exclusion_respects_require_full_coverage():
    cfg = load_config_from_dict({"device": {"require_full_coverage": False}})
    assert evaluate(facts(partitions_excluded=1), cfg)[0] is Verdict.CLEAN
