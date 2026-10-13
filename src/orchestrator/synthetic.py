"""End-to-end synthetic scan for maintenance validation (spec §3.8, AC-F05).

The orchestrator writes two files into a private directory below its state directory:
the EICAR anti-malware test string and a harmless control file. It opens them exactly
as it opens files on a USB medium (``open_for_scan``), passes the descriptors to clamd
(FILDES) and, when enabled, to the YARA worker, and evaluates the outcome with the
production verdict engine. The files are unlinked as soon as they are open.

Deterministic expectation (``passed``):
* ClamAV reports EICAR as FOUND;
* ClamAV reports the control file as clean;
* the verdict engine returns THREAT.
YARA results are recorded but not asserted, because the deployed rule set is not
required to contain an EICAR rule; a YARA transport failure is recorded as an error.
VirusTotal is never queried (no test hashes leave the station).

Not covered here: USBGuard, the broker and the mount path. Those are exercised with a
real reference medium (AC-F01/F02, tests/acceptance/MANUAL_TEST_CHECKLIST.md).
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from typing import Any

from src.shared.config import Config
from src.shared.models import CoverageMetrics, Severity, SkipReason, ThreatEntry, Verdict

from .scanner_clamav import ClamdClient, ClamdUnavailable, ClamStatus, open_for_scan
from .scanner_yara_client import YaraClient, YaraUnavailable
from .verdict_engine import ScanFacts, evaluate

# Split so this source file is not itself detected as the test file.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CONTROL = b"USB scan station synthetic scan control file. Harmless text.\n"
EXPECTED_VERDICT = Verdict.THREAT


def _write(directory: str, name: str, data: bytes) -> int:
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        return open_for_scan(path)
    finally:
        os.unlink(path)


async def run_synthetic_scan(cfg: Config, clamd: ClamdClient, yara: YaraClient | None,
                             workdir: str, trigger: str) -> dict[str, Any]:
    """Run one synthetic scan and return the SYNTHETIC_SCAN event payload."""
    started = time.monotonic()
    os.makedirs(workdir, mode=0o700, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="synthetic-", dir=workdir)
    cov = CoverageMetrics(partitions_discovered=1, partitions_scanned=1)
    cov.yara_complete = None if yara is None else False
    facts = ScanFacts(coverage=cov)
    out: dict[str, Any] = {"trigger": trigger, "expected_verdict": EXPECTED_VERDICT.value}
    fds: dict[str, int] = {}
    try:
        fds["test_file"] = _write(tmp, "eicar.com", EICAR)
        fds["control_file"] = _write(tmp, "control.txt", CONTROL)
        cov.files_discovered = len(fds)
        cov.bytes_enumerated = len(EICAR) + len(CONTROL)

        clam: dict[str, Any] = {}
        timeout = float(cfg.clamav.per_file_timeout_seconds)
        try:
            for name, fd in fds.items():
                res = await clamd.scan_fd(fd, timeout)
                clam[name] = res.status.value
                if name == "test_file":
                    clam["signature"] = res.signature[:120]
                if res.status is ClamStatus.FOUND:
                    facts.threats.append(ThreatEntry(f"synthetic/{name}", "clamav", res.signature[:120], "",
                                                     res.severity or Severity.HIGH))
                if res.status in (ClamStatus.CLEAN, ClamStatus.FOUND):
                    cov.files_scanned += 1
                else:
                    cov.record_failed(SkipReason.TIMEOUT if res.status is ClamStatus.TIMEOUT else SkipReason.ENGINE_ERROR)
            cov.bytes_read = cov.bytes_enumerated
            cov.clamav_complete = cov.files_scanned == len(fds)
        except ClamdUnavailable as exc:
            clam["error"] = str(exc)[:120]
            facts.appliance_fault = True
            facts.engine_errors.append("clamav_unavailable")
        out["clamav"] = clam

        if yara is not None:
            yres: dict[str, Any] = {}
            try:
                session = await yara.session()
                try:
                    for name, fd in fds.items():
                        r = await session.scan_fd(fd)
                        yres[name] = r.status
                        yres[f"{name}_matches"] = [str(m.get("rule", ""))[:80] for m in r.matches][:10]
                finally:
                    await session.bye()
                cov.yara_complete = all(yres.get(n) in ("clean", "match") for n in fds)
            except YaraUnavailable as exc:
                yres["error"] = exc.reason[:120]
            out["yara"] = yres
    except OSError as exc:
        facts.appliance_fault = True
        facts.engine_errors.append("synthetic_fixture_unavailable")
        out["error"] = f"{type(exc).__name__}: {exc.strerror or exc}"[:160]
    finally:
        for fd in fds.values():
            os.close(fd)
        shutil.rmtree(tmp, ignore_errors=True)

    verdict, reasons = evaluate(facts, cfg)
    out["verdict"] = verdict.value
    out["reason_codes"] = reasons[:10]
    out["coverage"] = cov.to_dict()
    clam = out.get("clamav", {})
    out["passed"] = (verdict is EXPECTED_VERDICT and clam.get("test_file") == ClamStatus.FOUND.value
                     and clam.get("control_file") == ClamStatus.CLEAN.value)
    out["duration_ms"] = int((time.monotonic() - started) * 1000)
    return out
