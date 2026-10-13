"""Mandatory health gates (spec §3.8, AC-R01). Any failure -> NOT_READY.

Failure codes: broker_unavailable, clamav_unavailable, signatures_unknown,
signatures_stale, yara_ruleset_missing, disk_space_low, event_store_unwritable,
clock_invalid, thermal_limit. Warnings (do not block): pin_not_configured,
thermal_unknown.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field

from src.shared.config import Config, EngineRole

from .broker_client import BrokerClient, BrokerError
from .scanner_clamav import ClamdClient, ClamdUnavailable


@dataclass
class HealthReport:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.failures


def read_cpu_temp(path: str) -> float | None:
    try:
        with open(path) as fh:
            return int(fh.read().strip()) / 1000.0     # millidegrees Celsius
    except (OSError, ValueError):
        return None


async def run_checks(cfg: Config, broker: BrokerClient, clamd: ClamdClient, *,
                     now: float | None = None) -> HealthReport:
    now = time.time() if now is None else now
    rep = HealthReport()

    try:
        if not await broker.ping():
            rep.failures.append("broker_unavailable")
    except BrokerError:
        rep.failures.append("broker_unavailable")

    try:
        if not await clamd.ping():
            rep.failures.append("clamav_unavailable")
        else:
            ver = await clamd.version()
            rep.details["clamav_engine"] = ver.engine
            rep.details["clamav_db_version"] = ver.db_version
            if ver.db_time is None:
                rep.failures.append("signatures_unknown")
            else:
                age_h = (now - ver.db_time) / 3600
                rep.details["signature_age_hours"] = round(age_h, 1)
                if age_h > cfg.clamav.max_signature_age_hours:
                    rep.failures.append("signatures_stale")
    except (ClamdUnavailable, ValueError):
        rep.failures.append("clamav_unavailable")

    if cfg.yara.enabled and cfg.yara.role is EngineRole.MANDATORY:
        if not all(os.path.exists(p) for p in (cfg.yara.rules_path, cfg.yara.ruleset_signature_path)):
            rep.failures.append("yara_ruleset_missing")

    try:
        free_mb = shutil.disk_usage(cfg.station.data_dir).free // (1024 * 1024)
        rep.details["free_disk_mb"] = free_mb
        if free_mb < cfg.health.min_free_disk_mb:
            rep.failures.append("disk_space_low")
    except OSError:
        rep.failures.append("disk_space_low")

    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(cfg.events.db_path), prefix=".probe-"):
            pass
    except OSError:
        rep.failures.append("event_store_unwritable")

    if time.gmtime(now).tm_year < cfg.health.min_valid_year:
        rep.failures.append("clock_invalid")

    temp = read_cpu_temp(cfg.orchestrator.thermal_zone_path)
    rep.details["cpu_temp_c"] = temp
    if temp is None:
        rep.warnings.append("thermal_unknown")
    elif temp > cfg.health.max_cpu_temp_c:
        rep.failures.append("thermal_limit")

    hash_path = cfg.pin.hash_ref.partition(":")[2] if cfg.pin.hash_ref.startswith("file:") else None
    if hash_path is not None and not os.path.exists(hash_path):
        rep.warnings.append("pin_not_configured")
    return rep
