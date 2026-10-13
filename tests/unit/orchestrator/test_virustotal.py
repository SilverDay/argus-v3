import asyncio
import hashlib
import json

import httpx
import pytest

from src.orchestrator.virustotal import (
    API_BASE, RateLimiter, VirusTotalClient, VtCache, VtLookupError, VtResult, VtSession,
)
from src.shared.config import load_config_from_dict

SHA = hashlib.sha256(b"x").hexdigest()
KEY = "k" * 64


def vt_cfg(**kw):
    return load_config_from_dict({"virustotal": {"enabled": True, "api_key_ref": "credential:vt",
                                                 "rate_limit_per_minute": 1000, **kw}}).virustotal


def stats_body(malicious=0, suspicious=0, undetected=60, unsupported=5):
    return {"data": {"type": "file", "id": SHA, "attributes": {"last_analysis_stats": {
        "failure": 0, "harmless": 0, "malicious": malicious, "suspicious": suspicious, "timeout": 0,
        "type-unsupported": unsupported, "undetected": undetected}}}}


def not_found():
    return httpx.Response(404, json={"error": {"code": "NotFoundError", "message": "Resource not found."}})


def client(tmp_path, handler, ttl=7, **kw):
    cfg = vt_cfg(cache_ttl_days=ttl, **kw)
    return VirusTotalClient(cfg, KEY, transport=httpx.MockTransport(handler),
                            cache=VtCache(str(tmp_path / "vt.db"), ttl))


async def test_lookup_request_and_parsing(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=stats_body(malicious=7, suspicious=1))

    c = client(tmp_path, handler)
    res = await c.lookup(SHA)
    assert res == VtResult(SHA, True, 7, 1, 73)
    (req,) = seen
    assert str(req.url) == f"{API_BASE}/files/{SHA}" and req.method == "GET"
    assert req.headers["x-apikey"] == KEY
    assert req.url.scheme == "https"
    assert KEY not in repr(c)
    await c.aclose()


async def test_unknown_hash(tmp_path):
    c = client(tmp_path, lambda r: not_found())
    assert await c.lookup(SHA) == VtResult(SHA, False)
    await c.aclose()


@pytest.mark.parametrize("response,kind", [
    (httpx.Response(429, json={"error": {"code": "SomeQuotaError", "message": "x"}}), "quota"),
    (httpx.Response(401, json={"error": {"code": "WrongCredentialsError", "message": "x"}}), "auth"),
    (httpx.Response(403, json={"error": {"code": "ForbiddenError", "message": "x"}}), "auth"),
    (httpx.Response(404, text="<html>proxy says no</html>"), "http_404"),    # not VT's NotFoundError
    (httpx.Response(503, text="down"), "http_503"),
    (httpx.Response(200, json={"data": {"attributes": {}}}), "protocol"),
    (httpx.Response(200, json=stats_body() | {"data": {"attributes": {"last_analysis_stats": {"malicious": True}}}}),
     "protocol"),
    (httpx.Response(200, text="not json"), "protocol"),
    (httpx.Response(302, headers={"Location": "https://elsewhere.example/"}), "http_302"),  # no redirects
])
async def test_failures_are_classified(tmp_path, response, kind):
    c = client(tmp_path, lambda r: response)
    with pytest.raises(VtLookupError) as exc:
        await c.lookup(SHA)
    assert exc.value.kind == kind
    await c.aclose()


async def test_transport_error_is_network(tmp_path):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)
    c = client(tmp_path, handler)
    with pytest.raises(VtLookupError, match="network"):
        await c.lookup(SHA)
    await c.aclose()


async def test_invalid_hash_rejected(tmp_path):
    c = client(tmp_path, lambda r: not_found())
    for bad in ("", SHA.upper(), SHA[:-1], "../" + SHA[3:]):
        with pytest.raises(ValueError):
            await c.lookup(bad)
    await c.aclose()


async def test_cache_hits_and_ttls(tmp_path):
    now = [1_000_000.0]
    cache = VtCache(str(tmp_path / "vt.db"), 7, clock=lambda: now[0])
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json=stats_body(malicious=3)) if len(calls) == 1 else not_found()

    c = VirusTotalClient(vt_cfg(), KEY, transport=httpx.MockTransport(handler), cache=cache)
    first = await c.lookup(SHA)
    again = await c.lookup(SHA)
    assert not first.cached and again.cached and again.malicious == 3 and len(calls) == 1
    now[0] += 8 * 86_400                                   # known hash expires after cache_ttl_days
    assert (await c.lookup(SHA)).found is False and len(calls) == 2
    assert (await c.lookup(SHA)).cached                   # unknown hash cached ...
    now[0] += 86_401                                       # ... but for one day at most
    assert cache.get(SHA) is None
    now[0] -= 10 * 86_400                                  # clock jumped backwards: entry not trusted
    assert cache.get(SHA) is None
    await c.aclose()


async def test_cache_disabled_with_ttl_zero(tmp_path):
    calls = []

    def handler(request):
        calls.append(1)
        return not_found()

    c = client(tmp_path, handler, ttl=0)
    await c.lookup(SHA)
    await c.lookup(SHA)
    assert len(calls) == 2 and not (tmp_path / "vt.db").exists()
    await c.aclose()


def test_cache_file_is_private(tmp_path):
    VtCache(str(tmp_path / "vt.db"), 7)
    assert (tmp_path / "vt.db").stat().st_mode & 0o777 == 0o600


async def test_rate_limiter_sliding_window():
    now = [0.0]
    slept = []

    async def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    lim = RateLimiter(2, clock=lambda: now[0], sleep=sleep)
    await lim.acquire()
    now[0] = 10.0
    await lim.acquire()
    await lim.acquire()                                    # third call waits until t=60
    assert slept == [50.0] and now[0] == 60.0            # until the t=0 stamp leaves the window
    await lim.acquire()                                    # window now holds t=10 and t=60
    assert slept[-1] == pytest.approx(10.0)


async def test_session_dedups_and_completes(tmp_path):
    requested = []

    def handler(request):
        requested.append(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json=stats_body(malicious=1))

    c = client(tmp_path, handler)
    s = VtSession(c)
    s.submit(SHA, "a")
    s.submit(SHA, "b")
    assert await s.finish(5)
    assert requested == [SHA] and s.refs[SHA] == ["a", "b"] and s.complete
    await c.aclose()


async def test_session_circuit_breaker_uses_cache_only(tmp_path):
    shas = [hashlib.sha256(bytes([i])).hexdigest() for i in range(4)]
    cache = VtCache(str(tmp_path / "vt.db"), 7)
    cache.put(VtResult(shas[3], True, 9, 0, 70))
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, json={"error": {"code": "QuotaExceeded", "message": "x"}})

    c = VirusTotalClient(vt_cfg(), KEY, transport=httpx.MockTransport(handler), cache=cache)
    s = VtSession(c, workers=1)
    for i, sha in enumerate(shas):
        s.submit(sha, i)
    assert await s.finish(5)
    assert s.failure == "quota" and len(calls) == 1         # no further network lookups
    assert set(s.results) == {shas[3]} and not s.complete    # cached result still used
    await c.aclose()


async def test_session_finish_timeout(tmp_path):
    gate = asyncio.Event()

    async def slow(request):
        await gate.wait()
        return not_found()

    c = client(tmp_path, slow)
    s = VtSession(c)
    s.submit(SHA, 1)
    assert await s.finish(0.05) is False and not s.complete
    assert await VtSession(c).finish(0) is True            # nothing pending
    await c.aclose()


def test_body_never_contains_key_in_logs(tmp_path, caplog):
    caplog.set_level("DEBUG")

    async def go():
        c = client(tmp_path, lambda r: httpx.Response(200, json=stats_body()))
        await c.lookup(SHA)
        await c.aclose()
    asyncio.run(go())
    assert KEY not in caplog.text and json.dumps(KEY) not in caplog.text
