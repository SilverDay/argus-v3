"""Phase 7 modules wired into the orchestrator (VirusTotal, quarantine, alerting)."""
import asyncio
import hashlib
import json
import os

import httpx

from src.orchestrator.alerting import AlertDispatcher, Pseudonymizer, WebhookChannel
from src.orchestrator.quarantine import Quarantine
from src.orchestrator.virustotal import VirusTotalClient, VtCache
from src.shared.models import EventType
from tests.unit.orchestrator.test_orchestrator import committed, of_type, run_scan, start, verdicts
from tests.unit.orchestrator.test_quarantine import make_store

VT_ON = {"enabled": True, "api_key_ref": "credential:vt", "rate_limit_per_minute": 1000, "finish_wait_seconds": 5}


def vt_factory(tmp_path, verdict_by_content: dict[bytes, int | None], fail: int | None = None):
    """VT answers by file content: malicious count, None = unknown hash; ``fail`` = HTTP status for all."""
    by_sha = {hashlib.sha256(c).hexdigest(): m for c, m in verdict_by_content.items()}
    lookups = []

    def handler(request):
        sha = request.url.path.rsplit("/", 1)[-1]
        lookups.append(sha)
        if fail is not None:
            return httpx.Response(fail, json={"error": {"code": "QuotaExceededError", "message": "x"}})
        mal = by_sha.get(sha)
        if mal is None:
            return httpx.Response(404, json={"error": {"code": "NotFoundError", "message": "x"}})
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {
            "malicious": mal, "undetected": 70 - mal, "harmless": 0}}}})

    def build(cfg, _):
        return VirusTotalClient(cfg.virustotal, "key", transport=httpx.MockTransport(handler),
                                cache=VtCache(str(tmp_path / "vt.db"), 0))
    return build, lookups


# --- VirusTotal ---------------------------------------------------------------------

async def test_vt_high_count_is_threat_even_if_clamav_clean(harness, env):
    (env["part1"] / "new.bin").write_bytes(b"novel sample")
    build, lookups = vt_factory(env["tmp"], {b"novel sample": 12})
    orch, *_, events, sink = harness({"virustotal": VT_ON}, vt=build)
    await start(orch)
    await run_scan(orch)
    (v,) = verdicts(events)
    assert v["verdict"] == "THREAT" and v["coverage"]["vt_complete"] is True
    assert {"engine": "virustotal", "signature": "VirusTotal.malicious=12/70", "severity": "high"} in v["threats"]
    assert len(lookups) == 3                                     # every in-scope file, hash only
    rec = committed(sink)[-1]
    assert rec["threats"][0]["file_path"] == "part1/new.bin"
    assert {"engine": "virustotal", "signature": "VirusTotal.malicious=12/70", "severity": "high"} in \
        of_type(events, EventType.DETECTION)


async def test_vt_low_count_is_suspicious(harness, env):
    (env["part1"] / "new.bin").write_bytes(b"grey")
    build, _ = vt_factory(env["tmp"], {b"grey": 2})
    orch, *_, events, _ = harness({"virustotal": VT_ON}, vt=build)
    await start(orch)
    await run_scan(orch)
    assert verdicts(events)[0]["verdict"] == "SUSPICIOUS"


async def test_vt_unknown_hashes_are_clean(harness, env):
    build, lookups = vt_factory(env["tmp"], {})
    orch, *_, events, _ = harness({"virustotal": VT_ON}, vt=build)
    await start(orch)
    await run_scan(orch)
    (v,) = verdicts(events)
    assert v["verdict"] == "CLEAN" and v["coverage"]["vt_complete"] is True and len(lookups) == 2


async def test_vt_advisory_quota_failure_does_not_change_verdict(harness, env):
    for i in range(6):
        (env["part1"] / f"f{i}.txt").write_text(f"file {i}")
    build, lookups = vt_factory(env["tmp"], {}, fail=429)
    orch, *_, events, _ = harness({"virustotal": VT_ON}, vt=build)
    await start(orch)
    await run_scan(orch)
    (v,) = verdicts(events)
    assert v["verdict"] == "CLEAN" and v["coverage"]["vt_complete"] is False
    assert "virustotal_unavailable:quota" in v["reason_codes"]
    assert len(lookups) <= 2              # circuit breaker: at most the 2 in-flight requests, not all 8 files


async def test_vt_mandatory_failure_policies(harness, env):
    mandatory = VT_ON | {"role": "mandatory", "network_outage_policy_ref": "SOC-RUNBOOK-12"}
    for policy, expected in (("incomplete", "INCOMPLETE"), ("error", "ERROR")):
        build, _ = vt_factory(env["tmp"], {}, fail=503)
        orch, *_, events, _ = harness({"virustotal": mandatory | {"on_quota_or_network_failure": policy}}, vt=build)
        await start(orch)
        await run_scan(orch)
        assert verdicts(events)[0]["verdict"] == expected, policy


async def test_vt_mandatory_without_client_is_not_ready(harness, env):
    mandatory = VT_ON | {"role": "mandatory", "network_outage_policy_ref": "SOC-RUNBOOK-12",
                         "on_quota_or_network_failure": "incomplete"}
    orch, *_ = harness({"virustotal": mandatory})               # key could not be resolved -> no client
    await orch.check_health()
    assert "virustotal_unavailable" in orch.health.failures
    orch2, *_ = harness({"virustotal": VT_ON})                  # advisory: warning only
    await orch2.check_health()
    assert "virustotal_unavailable" in orch2.health.warnings and orch2.health.passed


async def test_vt_hashes_files_too_large_for_clamav(harness, env):
    big = b"B" * (1024 * 1024 + 10)
    (env["part1"] / "big.iso").write_bytes(big)
    build, lookups = vt_factory(env["tmp"], {big: 30})
    orch, *_, events, _ = harness({"virustotal": VT_ON, "clamav": {"max_file_size_mb": 1}}, vt=build)
    await start(orch)
    await run_scan(orch)
    (v,) = verdicts(events)
    assert v["verdict"] == "THREAT"                               # VT has no size threshold
    assert hashlib.sha256(big).hexdigest() in lookups


async def test_vt_hash_budget_exhausted_is_reported(harness, env):
    (env["part1"] / "big.iso").write_bytes(b"B" * (2 * 1024 * 1024))
    build, _ = vt_factory(env["tmp"], {})
    orch, *_, events, _ = harness({"virustotal": VT_ON | {"large_file_hash_budget_mb": 1}}, vt=build)
    await start(orch)
    await run_scan(orch)
    (v,) = verdicts(events)
    assert v["coverage"]["vt_complete"] is False and "virustotal_hash_budget=1" in v["reason_codes"]
    assert v["verdict"] == "CLEAN"                                 # advisory


# --- alerting -----------------------------------------------------------------------

def webhook_factory(posts, status=200):
    def build(cfg, orch_ref):
        hook = cfg.alerts.webhook
        ch = WebhookChannel(hook, "tok", transport=httpx.MockTransport(
            lambda r: (posts.append(json.loads(r.content)), httpx.Response(status))[1]),
            sleep=lambda s: asyncio.sleep(0))
        return AlertDispatcher(cfg.alerts, [ch], lambda ev: orch_ref[0].publish(ev),
                               Pseudonymizer(cfg.logging.filename_privacy, b"pseudo-key"))
    return build


HOOK = {"webhook": {"enabled": True, "url": "https://soc.example.org/hook"}}


async def test_threat_scan_posts_webhook(harness, env):
    """Plan Phase 7 acceptance: malware scan with webhook configured -> webhook POSTed with THREAT."""
    (env["part1"] / "eicar.com").write_bytes(b"..EVIL..")
    posts = []
    orch, *_, events, _ = harness({"alerts": HOOK}, alerts=webhook_factory(posts))
    await start(orch)
    await run_scan(orch)
    await orch.alerts.drain()
    (alert,) = posts
    assert alert["verdict"] == "THREAT" and alert["threats"][0]["signature"] == "Win.Test.Evil"
    assert "eicar" not in json.dumps(alert)                       # filename_privacy=hash by default
    assert alert["device"]["serial"].startswith("hmac:")
    assert of_type(events, EventType.ALERT_DELIVERY) == [
        {"channel": "webhook", "status": "delivered", "alert_kind": "verdict", "verdict": "THREAT"}]
    assert orch.state.value == "RESULT"


async def test_clean_scan_sends_no_alert_and_failure_never_changes_verdict(harness, env):
    posts = []
    orch, *_, events, _ = harness({"alerts": HOOK}, alerts=webhook_factory(posts))
    await start(orch)
    await run_scan(orch)
    await orch.alerts.drain()
    assert posts == [] and verdicts(events)[0]["verdict"] == "CLEAN"

    (env["part1"] / "x.exe").write_bytes(b"..EVIL..")
    failing = []
    orch2, *_, events2, sink2 = harness({"alerts": HOOK}, alerts=webhook_factory(failing, status=500))
    await start(orch2)
    await run_scan(orch2)
    await orch2.alerts.drain()
    assert len(failing) == 2                                       # first try + one retry
    assert of_type(events2, EventType.ALERT_DELIVERY)[0]["status"] == "failed:http_500"
    assert committed(sink2)[-1]["verdict"] == "THREAT"


async def test_not_ready_alert(harness, env):
    posts = []
    orch, broker, *_ = harness({"alerts": HOOK}, alerts=webhook_factory(posts))
    broker.alive = False
    await orch.check_health()
    await orch.alerts.drain()
    assert posts[0]["verdict"] == "NOT_READY" and "broker_unavailable" in posts[0]["reason_codes"]
    await orch.check_health()                                       # unchanged failure: no repeat
    await orch.alerts.drain()
    assert len(posts) == 1


# --- quarantine -----------------------------------------------------------------------

def quarantine_factory(env):
    store, mi, sysfs = make_store(env["tmp"])

    def build(cfg, _):
        return Quarantine(cfg.quarantine, cfg.station.station_id, mountinfo_path=mi, sysfs_root=sysfs)
    return build, store


async def test_threat_evidence_is_quarantined_before_eject(harness, env):
    (env["part1"] / "x.exe").write_bytes(b"..EVIL..")
    (env["part1"] / "h.txt").write_bytes(b"HEUR")                  # medium: never quarantined
    build, store = quarantine_factory(env)
    orch, broker, *_, events, _ = harness({"quarantine": {"quarantine_on_threat": True, "path": str(store)}},
                                          quarantine=build)
    await start(orch)
    await run_scan(orch)
    (q,) = of_type(events, EventType.QUARANTINE_RESULT)
    assert q["status"] == "completed" and q["outcomes"] == {"stored": 1}
    (item,) = q["item_ids"]
    scan_dir = store / orch.active.scan_id
    assert (scan_dir / f"{item}.bin").read_bytes() == b"..EVIL.."
    assert json.loads((scan_dir / f"{item}.json").read_text())["original_path"] == "part1/x.exe"
    types = [e.event_type for e in events]
    assert types.index(EventType.QUARANTINE_RESULT) < max(
        i for i, e in enumerate(events) if e.event_type is EventType.LIFECYCLE_CHANGED)
    assert [c[0] for c in broker.calls] == ["enumerate", "mount", "unmount", "eject"]   # no other access


async def test_unverified_store_skips_quarantine_but_keeps_verdict(harness, env):
    (env["part1"] / "x.exe").write_bytes(b"..EVIL..")
    build, store = quarantine_factory(env)
    os.chmod(store, 0o755)
    orch, *_, events, sink = harness({"quarantine": {"quarantine_on_threat": True, "path": str(store)}},
                                     quarantine=build)
    await orch.check_health()
    assert "quarantine_unavailable" in orch.health.warnings and orch.health.passed
    await run_scan(orch)
    assert of_type(events, EventType.QUARANTINE_RESULT) == [{"status": "unavailable", "reason": "path_permissions"}]
    assert committed(sink)[-1]["verdict"] == "THREAT" and orch.state.value == "RESULT"


async def test_no_quarantine_for_non_threat(harness, env):
    (env["part1"] / "h.txt").write_bytes(b"HEUR")
    build, store = quarantine_factory(env)
    orch, *_, events, _ = harness({"quarantine": {"quarantine_on_threat": True, "path": str(store)}},
                                  quarantine=build)
    await start(orch)
    await run_scan(orch)
    assert verdicts(events)[0]["verdict"] == "SUSPICIOUS"
    assert of_type(events, EventType.QUARANTINE_RESULT) == [] and os.listdir(store) == []
