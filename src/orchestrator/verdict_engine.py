"""Verdict evaluation (spec §3.3, §3.4, §6.2).

Precedence (highest first):
  1. THREAT      — any high-severity detection or high-severity policy violation
  2. ERROR       — appliance/engine fault prevented reliable processing, or a mandatory
                   engine failed with on_quota_or_network_failure=error (VirusTotal)
  3. INCOMPLETE  — anything required was not inspected (engines, partitions, files, limits)
  4. SUSPICIOUS  — medium/low detections or medium-severity policy violations
  5. CLEAN       — everything required inspected by all mandatory engines, nothing found
A confirmed threat always wins; missing inspection can never become CLEAN.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.shared.config import Config, EngineRole, PolicySeverity
from src.shared.models import CoverageMetrics, Severity, ThreatEntry, Verdict


@dataclass
class ScanFacts:
    coverage: CoverageMetrics
    threats: list[ThreatEntry] = field(default_factory=list)
    policy_violations: list[str] = field(default_factory=list)
    engine_errors: list[str] = field(default_factory=list)
    appliance_fault: bool = False        # e.g. clamd unreachable, thermal halt
    engine_failures: list[str] = field(default_factory=list)   # required engine failed, policy = error
    interrupted: bool = False            # device removed / global timeout / cancelled
    restricted_scope: bool = False


def evaluate(facts: ScanFacts, cfg: Config) -> tuple[Verdict, list[str]]:
    cov = facts.coverage
    reasons: list[str] = []
    policy_sev = cfg.scan.blocked_extension_severity

    if any(t.severity is Severity.HIGH for t in facts.threats):
        reasons.append("malware_detected")
    if facts.policy_violations and policy_sev is PolicySeverity.THREAT:
        reasons.append("policy_violation_high")
    if reasons:
        return Verdict.THREAT, reasons + _incomplete_reasons(facts, cfg)

    if facts.appliance_fault:
        return Verdict.ERROR, ["appliance_fault", *facts.engine_errors[:5]]
    if facts.engine_failures:
        return Verdict.ERROR, ["required_engine_failed", *facts.engine_failures[:5]]

    incomplete = _incomplete_reasons(facts, cfg)
    if incomplete:
        return Verdict.INCOMPLETE, incomplete

    if facts.threats:
        reasons.append("low_confidence_detection")
    if facts.policy_violations:
        reasons.append("policy_violation")
    if reasons:
        return Verdict.SUSPICIOUS, reasons

    clean = ["no_detections"]
    if facts.restricted_scope:
        clean.append("restricted_extension_scope")   # must be disclosed (spec §6.2)
    return Verdict.CLEAN, clean


def _incomplete_reasons(facts: ScanFacts, cfg: Config) -> list[str]:
    cov = facts.coverage
    out: list[str] = []
    if facts.interrupted:
        out.append("scan_interrupted")
    if not cov.clamav_complete:
        out.append("clamav_incomplete")
    if cfg.yara.enabled and cfg.yara.role is EngineRole.MANDATORY and cov.yara_complete is not True:
        out.append("yara_incomplete")
    if cfg.virustotal.enabled and cfg.virustotal.role is EngineRole.MANDATORY and cov.vt_complete is not True:
        out.append("virustotal_incomplete")
    if cov.partitions_discovered == 0:
        out.append("no_partitions")
    if cov.partitions_excluded and cfg.device.require_full_coverage:
        out.append("partition_not_inspected")
    if cov.has_uninspected_content():
        out.append("content_not_inspected")
    return out
