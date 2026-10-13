"""VirusTotal hash-only reputation lookups (spec §3.2 step 7, §6.2).

* Only SHA-256 hashes leave the appliance: ``GET /api/v3/files/{sha256}``. No uploads.
* Authentication: ``X-Apikey`` header (VT API v3, as used by the official vt-py client).
* 200 -> ``data.attributes.last_analysis_stats``; 404 with error code ``NotFoundError`` ->
  hash unknown to VT. Every other answer (quota 429, auth 401/403, server errors,
  unexpected bodies, transport errors) is a lookup failure: the session stops issuing
  network lookups (circuit breaker) and VT coverage becomes incomplete.
* TLS certificate verification is always on; ``ca_file`` only adds trust anchors.
* Results are cached in SQLite: known hashes for ``cache_ttl_days``, unknown hashes
  for at most one day (a new sample may become known quickly). TTL 0 disables the cache.
* A sliding-window limiter enforces ``rate_limit_per_minute`` across all sessions.
"""
from __future__ import annotations

import asyncio
import collections
import contextlib
import logging
import os
import re
import sqlite3
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from src.shared.config import VirusTotalConfig

log = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)    # request lines would log every hash

API_BASE = "https://www.virustotal.com/api/v3"
UNKNOWN_TTL_SECONDS = 86_400
_SHA256 = re.compile(r"[0-9a-f]{64}")
DAY = 86_400


@dataclass(frozen=True)
class VtResult:
    sha256: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    total: int = 0
    cached: bool = False


class VtLookupError(Exception):
    """Lookup failed; ``kind`` is quota | auth | network | http_<status> | protocol."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def tls_context(ca_file: str = "") -> ssl.SSLContext:
    """System trust store (+ optional extra CA). Hostname and chain are always verified."""
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


# --- cache -------------------------------------------------------------------

class VtCache:
    def __init__(self, path: str, ttl_days: int, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self.ttl = ttl_days * DAY
        self.clock = clock
        if self.enabled:
            if not os.path.exists(path):
                os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
            with contextlib.closing(self._db()) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE IF NOT EXISTS vt_cache (sha256 TEXT PRIMARY KEY, found INTEGER NOT NULL,"
                           " malicious INTEGER NOT NULL, suspicious INTEGER NOT NULL, total INTEGER NOT NULL,"
                           " fetched_at REAL NOT NULL)")

    @property
    def enabled(self) -> bool:
        return self.ttl > 0

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5, isolation_level=None)

    def get(self, sha: str) -> VtResult | None:
        if not self.enabled:
            return None
        db = self._db()
        try:
            row = db.execute("SELECT found, malicious, suspicious, total, fetched_at FROM vt_cache WHERE sha256=?",
                             (sha,)).fetchone()
        finally:
            db.close()
        if row is None:
            return None
        found, mal, sus, total, fetched = row
        ttl = self.ttl if found else min(self.ttl, UNKNOWN_TTL_SECONDS)
        age = self.clock() - fetched
        if age < 0 or age > ttl:                # a clock jump backwards also invalidates the entry
            return None
        return VtResult(sha, bool(found), mal, sus, total, cached=True)

    def put(self, res: VtResult) -> None:
        if not self.enabled:
            return
        db = self._db()
        try:
            db.execute("INSERT OR REPLACE INTO vt_cache VALUES (?,?,?,?,?,?)",
                       (res.sha256, int(res.found), res.malicious, res.suspicious, res.total, self.clock()))
            cutoff = self.clock() - self.ttl
            db.execute("DELETE FROM vt_cache WHERE fetched_at < ?", (cutoff,))
        finally:
            db.close()


# --- rate limit ----------------------------------------------------------------

class RateLimiter:
    """At most ``per_minute`` acquisitions in any 60 s window."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self.per_minute = per_minute
        self.clock = clock
        self.sleep = sleep
        self._stamps: collections.deque[float] = collections.deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = self.clock()
                while self._stamps and now - self._stamps[0] >= 60.0:
                    self._stamps.popleft()
                if len(self._stamps) < self.per_minute:
                    self._stamps.append(now)
                    return
                await self.sleep(60.0 - (now - self._stamps[0]))


# --- client --------------------------------------------------------------------

def _parse_stats(body: Any) -> tuple[int, int, int]:
    try:
        stats = body["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError):
        raise VtLookupError("protocol") from None
    if not isinstance(stats, dict) or not all(
            isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in stats.values()):
        raise VtLookupError("protocol")
    return stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values())


class VirusTotalClient:
    def __init__(self, cfg: VirusTotalConfig, api_key: str, *, transport: httpx.AsyncBaseTransport | None = None,
                 limiter: RateLimiter | None = None, cache: VtCache | None = None) -> None:
        if not api_key or any(c in api_key for c in "\r\n"):
            raise ValueError("invalid VirusTotal API key")
        self.cfg = cfg
        self.limiter = limiter or RateLimiter(cfg.rate_limit_per_minute)
        self.cache = cache if cache is not None else VtCache(cfg.cache_path, cfg.cache_ttl_days)
        kwargs: dict[str, Any] = {"transport": transport} if transport is not None else {"verify": tls_context(cfg.ca_file)}
        self._http = httpx.AsyncClient(base_url=API_BASE, headers={"X-Apikey": api_key, "Accept": "application/json"},
                                       timeout=float(cfg.request_timeout_seconds), follow_redirects=False, **kwargs)

    def __repr__(self) -> str:
        return "VirusTotalClient(<api key hidden>)"

    async def aclose(self) -> None:
        await self._http.aclose()

    async def cached(self, sha: str) -> VtResult | None:
        return await asyncio.to_thread(self.cache.get, sha)

    async def lookup(self, sha: str) -> VtResult:
        if not _SHA256.fullmatch(sha):
            raise ValueError("expected a lowercase hex SHA-256")
        hit = await self.cached(sha)
        if hit is not None:
            return hit
        await self.limiter.acquire()
        try:
            resp = await self._http.get(f"/files/{sha}")
        except httpx.HTTPError as exc:
            raise VtLookupError("network") from exc
        res = self._interpret(sha, resp)
        with contextlib.suppress(sqlite3.Error, OSError):
            await asyncio.to_thread(self.cache.put, res)
        return res

    @staticmethod
    def _interpret(sha: str, resp: httpx.Response) -> VtResult:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code == 200:
            mal, sus, total = _parse_stats(body)
            return VtResult(sha, True, mal, sus, total)
        code = body.get("error", {}).get("code") if isinstance(body, dict) and isinstance(body.get("error"), dict) else None
        if resp.status_code == 404 and code == "NotFoundError":
            return VtResult(sha, False)
        if resp.status_code == 429:
            raise VtLookupError("quota")
        if resp.status_code in (401, 403):
            raise VtLookupError("auth")
        raise VtLookupError(f"http_{resp.status_code}")


# --- per-scan session ----------------------------------------------------------------

class VtSession:
    """Collects hashes during a scan and looks them up concurrently with scanning."""

    def __init__(self, client: VirusTotalClient, workers: int = 2) -> None:
        self.client = client
        self.results: dict[str, VtResult] = {}
        self.refs: dict[str, list[Any]] = {}
        self.failure: str | None = None
        self._pending = 0
        self._idle = asyncio.Event()
        self._idle.set()
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._workers = [asyncio.create_task(self._work()) for _ in range(max(1, workers))]

    def submit(self, sha: str, ref: Any) -> None:
        if sha not in self.refs:
            self.refs[sha] = []
            self._pending += 1
            self._idle.clear()
            self._queue.put_nowait(sha)
        self.refs[sha].append(ref)

    async def _work(self) -> None:
        while True:
            sha = await self._queue.get()
            try:
                if self.failure is None:
                    self.results[sha] = await self.client.lookup(sha)
                else:                                   # circuit open: cache only
                    hit = await self.client.cached(sha)
                    if hit is not None:
                        self.results[sha] = hit
            except VtLookupError as exc:
                if self.failure is None:
                    self.failure = exc.kind
                    log.warning("VirusTotal lookup failed (%s); remaining hashes use the cache only", exc.kind)
            except Exception as exc:                     # never kill the worker silently
                if self.failure is None:
                    self.failure = "internal"
                log.error("VirusTotal worker error: %s", type(exc).__name__)
            finally:
                self._pending -= 1
                if self._pending == 0:
                    self._idle.set()

    async def finish(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for outstanding lookups; True if all were processed."""
        try:
            if not self._idle.is_set():
                await asyncio.wait_for(self._idle.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            await self.close()

    async def close(self) -> None:
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)

    @property
    def complete(self) -> bool:
        return self.failure is None and len(self.results) == len(self.refs)
