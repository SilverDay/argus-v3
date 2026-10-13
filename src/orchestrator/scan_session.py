"""One device scan: enumerate -> mount -> inventory -> ClamAV/YARA/VT -> facts (spec §3.2).

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
from dataclasses import dataclass
from typing import Any

from src.shared.config import Config, EngineRole, FailurePolicy, normalise_partition_type
from src.shared.models import (
    CoverageMetrics, EventType, ScanEvent, ScanMetadata, ScanResult, Severity, SkipReason, ThreatEntry, Verdict,
    utc_now,
)

from . import inventory
from .broker_client import BrokerClient, BrokerError
from .policy import ExtensionPolicy
from .quarantine import Evidence
from .scanner_clamav import ClamdClient, ClamdUnavailable, ClamResult, ClamStatus, open_for_scan
from .scanner_yara_client import YaraClient, YaraResult, YaraSession, YaraUnavailable
from .verdict_engine import ScanFacts, evaluate
from .virustotal import VirusTotalClient, VtSession

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
    part_type: str = ""
    size_bytes: int = 0
    mounted: bool = False
    reason: str = ""


@dataclass
class DeviceInfo:
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    capacity_bytes: int = 0


def _sha256_fd(fd: int, limit: int) -> str:
    """Hash the exact file description that was scanned (no re-open, no TOCTOU)."""
    h = hashlib.sha256()
    offset = 0
    while chunk := os.pread(fd, 1024 * 1024, offset):
        h.update(chunk)
        offset += len(chunk)
        if offset > limit:
            return ""
    return h.hexdigest()


class ScanSession:
    def __init__(self, cfg: Config, broker: BrokerClient, clamd: ClamdClient, publish: Publish, *,
                 scan_id: str, session_id: str, sysfs_path: str,
                 read_temp: Callable[[], float | None] = lambda: None,
                 yara: YaraClient | None = None, vt: VirusTotalClient | None = None) -> None:
        self.cfg = cfg
        self.vt = vt if cfg.virustotal.enabled else None
        self._vt_session: VtSession | None = None
        self._vt_budget = cfg.virustotal.large_file_hash_budget_mb * MB
        self._vt_hashed = 0                  # in-scope files whose hash was submitted
        self._vt_missed: dict[str, int] = {}  # reason -> files not looked up
        self._vt_finished = False
        self._vt_applied = False
        self._evidence: list[tuple[ThreatEntry, str, inventory.FileEntry]] = []
        self.yara = yara if cfg.yara.enabled else None
        self._yara_session: YaraSession | None = None
        self._yara_scanned = 0
        self._yara_issues: dict[str, int] = {}
        self._yara_elapsed = 0.0
        self._yara_unavailable: str | None = None
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
            self.volumes.append(VolumeOutcome(str(v["partition_id"]), str(v["status"]), str(v.get("fs_type", "")),
                                              str(v.get("part_type", "")), int(v.get("size_bytes", 0) or 0)))
        self.facts.coverage.partitions_discovered = len(self.volumes)

    async def mount_all(self) -> None:
        cov = self.facts.coverage
        excludable = {normalise_partition_type(t) for t in self.cfg.device.excludable_partition_types}
        for vol in self.volumes:
            if (vol.status == "unrecognized" and vol.part_type and normalise_partition_type(vol.part_type) in excludable
                    and 0 < vol.size_bytes <= self.cfg.device.excludable_partition_max_mb * MB):
                vol.reason = f"partition_out_of_scope:{vol.part_type}"
                cov.partitions_out_of_scope += 1
                continue
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
        if self.cfg.yara.enabled:
            await self._open_yara()
        if self.vt is not None:
            self._vt_session = VtSession(self.vt)
        try:
            await self._scan_volumes()
            if self._vt_session is not None and not self.facts.appliance_fault:
                self._vt_finished = await self._vt_session.finish(float(self.cfg.virustotal.finish_wait_seconds))
                for threat in self._apply_vt():
                    await self.publish(ScanEvent(EventType.DETECTION, self.scan_id, {
                        "engine": "virustotal", "signature": threat.signature_name,
                        "severity": threat.severity.value}))
        finally:
            if self._yara_session is not None:
                await self._yara_session.bye()
            if self._vt_session is not None:
                await self._vt_session.close()

    async def _scan_volumes(self) -> None:
        cov = self.facts.coverage
        sem = asyncio.Semaphore(self.cfg.clamav.concurrency)
        for pid, path in self.mounts:
            stats = inventory.InventoryStats()
            gen = inventory.walk(path, max_files=self.cfg.scan.max_files, max_depth=self.cfg.scan.max_depth,
                                 max_bytes=self.cfg.scan.max_bytes_total_gb * GB, stats=stats,
                                 privileged=self._privileged(pid))
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
            if stats.privileged_opens:
                self.notes.append(f"{pid}:privileged_opens={stats.privileged_opens}")
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
            if self._vt_session is not None:      # hash-only lookups have no size threshold
                async with sem:
                    fd = await asyncio.to_thread(self._open_file, pid, entry)
                    if fd is None:
                        self._vt_miss("unreadable")
                        return
                    try:
                        await self._vt_submit(pid, entry, fd)
                    finally:
                        os.close(fd)
            return
        async with sem:
            if self.facts.appliance_fault:
                return
            fd = await asyncio.to_thread(self._open_file, pid, entry)
            if fd is None:
                cov.record_uninspectable(SkipReason.UNREADABLE)
                return
            try:
                result = await self.clamd.scan_fd(fd, float(self.cfg.clamav.per_file_timeout_seconds))
                yres = await self._yara_scan(fd)
                sha = await self._vt_submit(pid, entry, fd) if self._vt_session is not None else ""
                if not sha and (result.status is ClamStatus.FOUND or (yres is not None and yres.status == "match")):
                    sha = await asyncio.to_thread(self._safe_sha256, fd)
            except ClamdUnavailable as exc:
                self.facts.appliance_fault = True
                self.facts.engine_errors.append(f"clamd_unavailable:{exc}"[:200])
                cov.record_failed(SkipReason.ENGINE_ERROR)
                return
            finally:
                os.close(fd)
        await self._record(pid, entry, result, sha)
        if yres is not None:
            await self._record_yara(pid, entry, yres, sha)

    # --- VirusTotal hash reputation (spec §3.2 step 7) -------------------------

    def _vt_miss(self, reason: str) -> None:
        self._vt_missed[reason] = self._vt_missed.get(reason, 0) + 1

    async def _vt_submit(self, pid: str, entry: inventory.FileEntry, fd: int) -> str:
        """Hash the scanned descriptor within the hashing budget and queue the lookup."""
        assert self._vt_session is not None
        if entry.size > self._vt_budget:
            self._vt_miss("hash_budget")
            return ""
        self._vt_budget -= entry.size
        sha = await asyncio.to_thread(self._safe_sha256, fd, entry.size)
        if not sha:
            self._vt_miss("hash_failed")
            return ""
        self._vt_hashed += 1
        self._vt_session.submit(sha, (pid, entry))
        return sha

    def _apply_vt(self) -> list[ThreatEntry]:
        """Turn reputation results into findings (owner thresholds). Idempotent."""
        if self._vt_session is None or self._vt_applied:
            return []
        self._vt_applied = True
        vt = self.cfg.virustotal
        found = []
        for sha, res in self._vt_session.results.items():
            if res.malicious < vt.suspicious_min_malicious:
                continue
            sev = Severity.HIGH if res.malicious >= vt.threat_min_malicious else Severity.MEDIUM
            sig = f"VirusTotal.malicious={res.malicious}/{res.total}"
            for pid, entry in self._vt_session.refs[sha]:
                threat = ThreatEntry(f"{pid}/{inventory.display_path(entry.rel)}", "virustotal", sig, sha, sev)
                self._add_threat(threat, pid, entry)
                found.append(threat)
        return found

    def _vt_coverage(self) -> None:
        cov = self.facts.coverage
        session = self._vt_session
        if session is None:
            cov.vt_complete = False
            if self.vt is None:
                self.notes.append("virustotal_unavailable:client_missing")
                if self.cfg.virustotal.role is EngineRole.MANDATORY and \
                        self.cfg.virustotal.on_quota_or_network_failure is FailurePolicy.ERROR:
                    self.facts.engine_failures.append("virustotal_client_missing")
            return
        cov.vt_complete = (
            session.complete and self._vt_finished and not self._vt_missed
            and not self.facts.appliance_fault and not self.facts.interrupted
            and self._vt_hashed == self._in_scope
        )
        if session.failure:
            self.notes.append(f"virustotal_unavailable:{session.failure}")
            vt = self.cfg.virustotal
            if vt.role is EngineRole.MANDATORY and vt.on_quota_or_network_failure is FailurePolicy.ERROR:
                self.facts.engine_failures.append(f"virustotal_{session.failure}")
        elif not self._vt_finished:
            self.notes.append(f"virustotal_pending={len(session.refs) - len(session.results)}")
        self.notes.extend(f"virustotal_{k}={v}" for k, v in sorted(self._vt_missed.items()))

    def _add_threat(self, threat: ThreatEntry, pid: str, entry: inventory.FileEntry) -> None:
        self.facts.threats.append(threat)
        self._evidence.append((threat, pid, entry))

    def evidence(self) -> list[Evidence]:
        """High-severity detections eligible for quarantine (owner decision, Phase 7)."""
        device = {"vendor_id": self.device.vendor_id, "product_id": self.device.product_id,
                  "serial": self.device.serial}
        return [Evidence(t.sha256, t.file_path, t.engine, t.signature_name,
                         (lambda pid=pid, entry=entry: self._open_file(pid, entry)), device)
                for t, pid, entry in self._evidence if t.severity is Severity.HIGH and t.sha256]

    # --- YARA (isolated worker, spec §3.2 step 6) -----------------------------

    async def _open_yara(self) -> None:
        if self.yara is None:
            self._yara_unavailable = "yara_client_missing"
            return
        try:
            self._yara_session = await self.yara.session()
            self.notes.append(f"yara_rules={self._yara_session.rules_version}")
        except YaraUnavailable as exc:
            self._yara_unavailable = f"yara_unavailable:{exc.reason}"

    def _yara_lost(self, reason: str) -> None:
        if self._yara_unavailable is None:
            self._yara_unavailable = reason
        if self._yara_session is not None:
            self._yara_session.close()
            self._yara_session = None

    async def _yara_scan(self, fd: int) -> YaraResult | None:
        """Scan the same descriptor with YARA; None if YARA is off or no longer usable."""
        if self._yara_session is None:
            return None
        if self._yara_elapsed > self.cfg.yara.global_budget_seconds:
            self._yara_lost("yara_budget_exceeded")      # worker kills its child on disconnect/budget
            return None
        started = time.monotonic()
        try:
            return await self._yara_session.scan_fd(fd)
        except YaraUnavailable as exc:
            self._yara_lost(f"yara_unavailable:{exc.reason}")
            return None
        finally:
            self._yara_elapsed += time.monotonic() - started

    async def _record_yara(self, pid: str, entry: inventory.FileEntry, res: YaraResult, sha: str) -> None:
        if res.status in ("clean", "match"):
            self._yara_scanned += 1
        else:
            self._yara_issues[res.status] = self._yara_issues.get(res.status, 0) + 1
        for m in res.matches:
            sev = {"high": Severity.HIGH, "low": Severity.LOW}.get(str(m.get("severity")), Severity.MEDIUM)
            sig = f"{m.get('namespace', '')}.{m.get('rule', '')}"[:200]
            self._add_threat(ThreatEntry(f"{pid}/{inventory.display_path(entry.rel)}", "yara", sig, sha, sev), pid, entry)
            await self.publish(ScanEvent(EventType.DETECTION, self.scan_id,
                                         {"engine": "yara", "signature": sig, "severity": sev.value}))

    async def _record(self, pid: str, entry: inventory.FileEntry, result: ClamResult, sha: str = "") -> None:
        cov = self.facts.coverage
        if result.status in (ClamStatus.CLEAN, ClamStatus.FOUND):
            cov.files_scanned += 1
            cov.bytes_read += entry.size
        if result.status is ClamStatus.FOUND:
            self._add_threat(ThreatEntry(f"{pid}/{inventory.display_path(entry.rel)}", "clamav",
                                         result.signature, sha, result.severity), pid, entry)
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

    def _privileged(self, pid: str) -> inventory.Privileged:
        """Broker-confined open for content hidden by on-media permissions (blocking)."""
        def opener(rel: bytes) -> tuple[str, int | None, int]:
            try:
                return self.broker.open_path(self.session_id, pid, rel)
            except BrokerError:
                return "unreadable", None, 0
        return opener

    def _open_file(self, pid: str, entry: inventory.FileEntry) -> int | None:
        """Open for scanning: direct first, broker-confined open if permissions deny it."""
        try:
            return open_for_scan(entry.path)
        except PermissionError:
            kind, fd, _ = self._privileged(pid)(os.fsencode(entry.rel))
            if kind == "file" and fd is not None:
                return fd
            if fd is not None:
                os.close(fd)
            return None
        except OSError:
            return None

    def _safe_sha256(self, fd: int, limit: int | None = None) -> str:
        try:
            return _sha256_fd(fd, self.cfg.clamav.max_file_size_mb * MB if limit is None else limit)
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
        if self.cfg.yara.enabled:
            cov.yara_complete = (
                self._yara_unavailable is None and not self._yara_issues
                and not self.facts.appliance_fault and not self.facts.interrupted
                and self._yara_scanned == self._in_scope
            )
            if self._yara_unavailable:
                self.notes.append(self._yara_unavailable)
            self.notes.extend(f"yara_{k}={v}" for k, v in sorted(self._yara_issues.items()))
        if self.cfg.virustotal.enabled:
            self._apply_vt()                 # results gathered before a cancellation still count
            self._vt_coverage()
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

