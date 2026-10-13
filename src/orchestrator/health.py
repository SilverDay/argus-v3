"""Mandatory health gates (spec §3.8, AC-R01). Any failure -> NOT_READY.

Failure codes: broker_unavailable, clamav_unavailable, signatures_unknown,
signatures_stale, yara_unavailable (mandatory YARA without a verified ruleset or
reachable worker), disk_space_low, clock_invalid, thermal_limit, and the event sink's
own failures (event_store_unavailable, event_store_unwritable, audit_chain_broken,
event_spool_pending) and synthetic_scan_failed (added by the orchestrator
from the last synthetic EICAR scan, src/orchestrator/synthetic.py). Warnings (do not block): pin_not_configured,
thermal_unknown.
"""
from __future__ import annotations

import os
import shutil
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from src.shared.config import Config, EngineRole

from .broker_client import BrokerClient, BrokerError
from .scanner_clamav import ClamdClient, ClamdUnavailable
from .scanner_yara_client import YaraClient, YaraUnavailable


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
                     yara: YaraClient | None = None, now: float | None = None,
                     events: Callable[[], Awaitable[list[str]]] | None = None) -> HealthReport:
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
            rep.details["clamav_db_time"] = ver.db_time
            if ver.db_time is None:
                rep.failures.append("signatures_unknown")
            else:
                age_h = (now - ver.db_time) / 3600
                rep.details["signature_age_hours"] = round(age_h, 1)
                if age_h > cfg.clamav.max_signature_age_hours:
                    rep.failures.append("signatures_stale")
    except (ClamdUnavailable, ValueError):
        rep.failures.append("clamav_unavailable")

    if cfg.yara.enabled:
        try:
            if yara is None:
                raise YaraUnavailable("yara_client_missing")
            rep.details["yara_rules_version"] = await yara.ping()
        except YaraUnavailable as exc:
            rep.details["yara_error"] = exc.reason
            if cfg.yara.role is EngineRole.MANDATORY:
                rep.failures.append("yara_unavailable")
            else:
                rep.warnings.append("yara_unavailable")

    try:
        free_mb = shutil.disk_usage(cfg.station.data_dir).free // (1024 * 1024)
        rep.details["free_disk_mb"] = free_mb
        if free_mb < cfg.health.min_free_disk_mb:
            rep.failures.append("disk_space_low")
    except OSError:
        rep.failures.append("disk_space_low")

    if events is None:
        rep.failures.append("event_store_unavailable")
    else:
        rep.failures.extend(await events())

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
