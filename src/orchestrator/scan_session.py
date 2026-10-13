"""One device scan: enumerate -> mount -> inventory -> ClamAV -> facts (spec §3.2).

All counters live on ``self.facts`` and are updated as work happens, so if the task is
cancelled (device removed, global timeout) the partial facts are still available
for an INCOMPLETE/THREAT verdict.
"""
from __future__ import annotations

import asyncio
import hashlib
import itertools
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from src.shared.config import Config
from src.shared.models import (
    CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, SkipReason, ThreatEntry, Verdict, utc_now,
)

from . import inventory
from .broker_client import BrokerClient, BrokerError
from .policy import ExtensionPolicy
from .scanner_clamav import ClamdClient, ClamdUnavailable, ClamResult, ClamStatus, open_for_scan
from .verdict_engine import ScanFacts, evaluate

log = logging.getLogger(__name__)
Publish = Callable[[ScanEvent], Awaitable[None]]
CHUNK = 256
GB = 1024 ** 3
MB = 1024 ** 2

# clamd limit heuristics -> skip reason (other limits map to SCAN_LIMIT).
_LIMIT_REASON = {
    "Heuristics.Limits.Exceeded.MaxRecursion": SkipReason.RECURSION_LIMIT,
    "Heuristics.Limits.Exceeded.MaxFileSize": SkipReason.TOO_LARGE_FOR_ENGINE,
}


class DeviceRejected(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


@dataclass
class VolumeOutcome:
    partition_id: str
    status: str
    fs_type: str
    mounted: bool = False
    reason: str = ""


@dataclass
class DeviceInfo:
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    capacity_bytes: int = 0


def _sha256_file(path: str, limit: int) -> str:
    h = hashlib.sha256()
    fd = open_for_scan(path)
    with os.fdopen(fd, "rb") as fh:
        read = 0
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
            read += len(chunk)
            if read > limit:
                return ""
    return h.hexdigest()


class ScanSession:
    def __init__(self, cfg: Config, broker: BrokerClient, clamd: ClamdClient, publish: Publish, *,
                 scan_id: str, session_id: str, sysfs_path: str,
                 read_temp: Callable[[], float | None] = lambda: None) -> None:
        self.cfg = cfg
        self.broker = broker
        self.clamd = clamd
        self.publish = publish
        self.scan_id = scan_id
        self.session_id = session_id
        self.sysfs_path = sysfs_path
        self.read_temp = read_temp
        self.metadata = ScanMetadata(scan_id, cfg.station.station_id, sysfs_path.rsplit("/", 1)[-1],
                                     session_start_utc=utc_now())
        self.policy = ExtensionPolicy(cfg.scan.block_extensions, cfg.scan.allow_extensions)
        self.facts = ScanFacts(CoverageMetrics(), restricted_scope=self.policy.restricted_scope)
        self.facts.coverage.yara_complete = None if not cfg.yara.enabled else False
        self.facts.coverage.vt_complete = None if not cfg.virustotal.enabled else False
        self.device = DeviceInfo()
        self.volumes: list[VolumeOutcome] = []
        self.mounts: list[tuple[str, str]] = []      # (partition_id, mount_path)
        self.notes: list[str] = []
        self.enumerated = False
        self._in_scope = 0
        self._last_progress = 0.0
        self._started = time.monotonic()

    # --- stages ------------------------------------------------------------

    async def validate(self) -> None:
        """Enumerate through the broker; raise DeviceRejected for out-of-policy devices."""
        try:
            res = await self.broker.enumerate(self.sysfs_path, self.session_id)
        except BrokerError as exc:
            if exc.code in ("invalid_argument", "device_in_use", "not_found"):
                raise DeviceRejected(f"broker_{exc.code}", exc.detail) from None
            raise
        self.enumerated = True
        dev = res.get("device", {})
        self.device = DeviceInfo(str(dev.get("vendor_id", "")), str(dev.get("product_id", "")),
                                 str(dev.get("serial", "")), int(dev.get("capacity_bytes", 0) or 0))
        limit = self.cfg.device.max_device_capacity_gb * GB
        if self.device.capacity_bytes > limit:
            raise DeviceRejected("capacity_exceeded",
                                 f"{self.device.capacity_bytes} bytes > {self.cfg.device.max_device_capacity_gb} GB")
        for v in res.get("volumes", []):
            self.volumes.append(VolumeOutcome(str(v["partition_id"]), str(v["status"]), str(v.get("fs_type", ""))))
        self.facts.coverage.partitions_discovered = len(self.volumes)

    async def mount_all(self) -> None:
        cov = self.facts.coverage
        for vol in self.volumes:
            if vol.status != "supported":
                vol.reason = f"partition_{vol.status}"
                cov.partitions_excluded += 1
                continue
            try:
                res = await self.broker.mount(self.session_id, vol.partition_id)
            except BrokerError as exc:
                vol.reason = f"mount_{exc.code}"
                cov.partitions_excluded += 1
                self.facts.engine_errors.append(f"{vol.partition_id}:{exc.code}")
                continue
            vol.mounted = True
            self.mounts.append((vol.partition_id, str(res["mount_path"])))

    async def scan(self) -> None:
        """Inventory and scan every mounted volume. Cancellation leaves partial facts."""
        cov = self.facts.coverage
        sem = asyncio.Semaphore(self.cfg.clamav.concurrency)
        for pid, path in self.mounts:
            stats = inventory.InventoryStats()
            gen = inventory.walk(path, max_files=self.cfg.scan.max_files, max_depth=self.cfg.scan.max_depth,
                                 max_bytes=self.cfg.scan.max_bytes_total_gb * GB, stats=stats)
            while True:
                batch = await asyncio.to_thread(lambda: list(itertools.islice(gen, CHUNK)))
                if not batch:
                    break
                cov.files_discovered += len(batch)
                cov.bytes_enumerated += sum(e.size for e in batch)
                await asyncio.gather(*(self._scan_one(pid, e, sem) for e in batch))
                if self.facts.appliance_fault:
                    return
                await self._check_thermal()
                await self._progress(pid)
            if stats.unreadable:
                for _ in range(stats.unreadable):
                    cov.record_uninspectable(SkipReason.UNREADABLE)
            if stats.truncated:
                cov.record_skip(stats.truncated)
                self.notes.append(f"{pid}:traversal_limit")
            if stats.special:
                self.notes.append(f"{pid}:special_files={stats.special}")
            if stats.symlinks:
                self.notes.append(f"{pid}:symlinks={stats.symlinks}")
            cov.partitions_scanned += 1
        await self._progress(None, force=True)

    async def _scan_one(self, pid: str, entry: inventory.FileEntry, sem: asyncio.Semaphore) -> None:
        cov = self.facts.coverage
        name = os.path.basename(entry.rel)
        if not self.policy.in_scope(name):
            cov.record_skip(SkipReason.POLICY_EXCLUSION)
            return
        self._in_scope += 1
        blocked = self.policy.blocked(name)
        if blocked:
            self.facts.policy_violations.append(f"blocked_extension:{blocked}:{pid}/{inventory.display_path(entry.rel)}")
        if entry.size > self.cfg.clamav.max_file_size_mb * MB:
            cov.record_skip(SkipReason.TOO_LARGE_FOR_ENGINE)
            return
        async with sem:
            if self.facts.appliance_fault:
                return
            try:
                fd = await asyncio.to_thread(open_for_scan, entry.path)
            except OSError:
                cov.record_uninspectable(SkipReason.UNREADABLE)
                return
            try:
                result = await self.clamd.scan_fd(fd, float(self.cfg.clamav.per_file_timeout_seconds))
            except ClamdUnavailable as exc:
                self.facts.appliance_fault = True
                self.facts.engine_errors.append(f"clamd_unavailable:{exc}"[:200])
                cov.record_failed(SkipReason.ENGINE_ERROR)
                return
            finally:
                os.close(fd)
        await self._record(pid, entry, result)

    async def _record(self, pid: str, entry: inventory.FileEntry, result: ClamResult) -> None:
        cov = self.facts.coverage
        if result.status in (ClamStatus.CLEAN, ClamStatus.FOUND):
            cov.files_scanned += 1
            cov.bytes_read += entry.size
        if result.status is ClamStatus.FOUND:
            sha = await asyncio.to_thread(self._safe_sha256, entry.path)
            self.facts.threats.append(ThreatEntry(f"{pid}/{inventory.display_path(entry.rel)}", "clamav",
                                                  result.signature, sha, result.severity))
            await self.publish(ScanEvent(EventType.DETECTION, self.scan_id,
                                         {"engine": "clamav", "signature": result.signature,
                                          "severity": result.severity.value}))
        elif result.status is ClamStatus.LIMIT:
            cov.record_skip(_LIMIT_REASON.get(result.signature, SkipReason.SCAN_LIMIT))
        elif result.status is ClamStatus.ENCRYPTED:
            cov.record_uninspectable(SkipReason.ENCRYPTED)
        elif result.status is ClamStatus.TIMEOUT:
            cov.record_failed(SkipReason.TIMEOUT)
        elif result.status is ClamStatus.ERROR:
            cov.record_failed(SkipReason.ENGINE_ERROR)
            self.facts.engine_errors.append(f"clamd_error:{result.signature}"[:200])

    def _safe_sha256(self, path: str) -> str:
        try:
            return _sha256_file(path, self.cfg.clamav.max_file_size_mb * MB)
        except OSError:
            return ""

    async def _check_thermal(self) -> None:
        temp = self.read_temp()
        if temp is not None and temp > self.cfg.health.max_cpu_temp_c:
            self.facts.appliance_fault = True
            self.facts.engine_errors.append(f"thermal_limit:{temp:.0f}C")

    async def _progress(self, pid: str | None, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_progress) * 1000 < self.cfg.scan.progress_interval_ms:
            return
        self._last_progress = now
        cov = self.facts.coverage
        # No file names: the public screen must not show them (spec §4.1, §4.4).
        await self.publish(ScanEvent(EventType.SCAN_PROGRESS, self.scan_id, {
            "partition_id": pid, "files_discovered": cov.files_discovered, "files_scanned": cov.files_scanned,
            "bytes_read": cov.bytes_read, "elapsed_s": round(now - self._started, 1),
            "partitions": f"{cov.partitions_scanned}/{cov.partitions_discovered}",
        }))

    # --- result ------------------------------------------------------------

    def finalize(self, *, interrupted: bool = False, extra_reasons: list[str] | None = None) -> ScanResult:
        cov = self.facts.coverage
        self.facts.interrupted = self.facts.interrupted or interrupted
        cov.clamav_complete = (
            not self.facts.appliance_fault and not self.facts.interrupted
            and cov.files_failed == 0 and cov.files_uninspectable == 0
            and cov.files_scanned == self._in_scope
            and not any(n for r, n in cov.skip_reasons.items() if r is not SkipReason.POLICY_EXCLUSION)
        )
        verdict, reasons = evaluate(self.facts, self.cfg)
        self.metadata.session_end_utc = utc_now()
        return ScanResult(
            metadata=self.metadata, verdict=verdict, coverage=cov, threats=list(self.facts.threats),
            policy_violations=list(self.facts.policy_violations), engine_errors=list(self.facts.engine_errors),
            reason_codes=reasons + (extra_reasons or []) + self.notes
            + [v.reason for v in self.volumes if v.reason],
        )

    def rejected_result(self, reason: str) -> ScanResult:
        self.metadata.session_end_utc = utc_now()
        return ScanResult(self.metadata, Verdict.REJECTED, self.facts.coverage, reason_codes=[reason])

    def summary(self) -> dict[str, Any]:
        return {"device": self.device.__dict__, "volumes": [v.__dict__ for v in self.volumes]}

