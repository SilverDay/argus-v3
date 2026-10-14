"""Cross-process atomicity of the session store (gunicorn runs several workers, each with
its own SQLite connection; a threading lock does not serialise them)."""
import multiprocessing as mp

import pytest

from src.web.sessions import SessionStore

WORKERS = 4
ROUNDS = 150


def _store(path):
    return SessionStore(path, idle_seconds=900, max_seconds=3600)


def _totp_worker(path, barrier, out):
    store = _store(path)
    barrier.wait()
    out.put([c for c in range(1, ROUNDS + 1) if store.accept_totp("ada", c)])
    store.close()


def _pending_worker(path, barrier, out):
    store = _store(path)
    barrier.wait()
    out.put([i for i in range(ROUNDS) if store.take_pending(f"state-{i}", "binding") is not None])
    store.close()


def _failure_worker(path, barrier, out):
    store = _store(path)
    barrier.wait()
    for _ in range(ROUNDS):
        store.record_failure(["user:ada"], 10_000, 60)
    out.put([])
    store.close()


def _run(target, path):
    ctx = mp.get_context("fork")
    barrier, out = ctx.Barrier(WORKERS), ctx.Queue()
    procs = [ctx.Process(target=target, args=(path, barrier, out)) for _ in range(WORKERS)]
    for p in procs:
        p.start()
    results = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    return results


def test_totp_step_accepted_by_exactly_one_worker(tmp_path):
    path = str(tmp_path / "web.db")
    _store(path).close()
    wins = [c for r in _run(_totp_worker, path) for c in r]
    assert sorted(wins) == sorted(set(wins)), "a TOTP step was accepted twice (replay across workers)"


def test_pending_oidc_login_consumed_once(tmp_path):
    path = str(tmp_path / "web.db")
    s = _store(path)
    for i in range(ROUNDS):
        s.put_pending(f"state-{i}", "binding", "nonce", "verifier")
    s.close()
    taken = [i for r in _run(_pending_worker, path) for i in r]
    assert sorted(taken) == list(range(ROUNDS))       # each exactly once


def test_failure_counter_loses_no_increment(tmp_path):
    path = str(tmp_path / "web.db")
    _store(path).close()
    _run(_failure_worker, path)
    s = _store(path)
    count = s._db.execute("SELECT count FROM login_failures WHERE key='user:ada'").fetchone()[0]
    s.close()
    assert count == WORKERS * ROUNDS
