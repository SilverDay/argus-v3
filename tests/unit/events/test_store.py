import os
import sqlite3

import pytest

from src.events.store import EventStore, StoreCorrupt, StoreFull, genesis_hash
from src.shared.models import EventType, ScanEvent

KEY = b"k" * 32


def ev(i=0, t=EventType.SCAN_STARTED, **payload):
    return ScanEvent(t, "scan-1", {"i": i, **payload})


_OPEN: list = []


@pytest.fixture(autouse=True)
def _close_connections():
    yield
    while _OPEN:
        _OPEN.pop().close()


def store(tmp_path, **kw):
    s = EventStore(str(tmp_path / "events.db"), "station-001", **kw)
    _OPEN.append(s)
    return s


def raw(tmp_path):
    db = sqlite3.connect(str(tmp_path / "events.db"), isolation_level=None)
    _OPEN.append(db)
    return db


def test_append_chains_and_persists(tmp_path):
    s = store(tmp_path)
    r1 = s.append(ev(1))
    r2 = s.append(ev(2))
    assert (r1.seq, r2.seq) == (1, 2)
    assert s.get(1).prev_hash == genesis_hash("station-001") and s.get(2).prev_hash == s.get(1).hash
    assert s.verify().ok and s.verify().checked == 2
    s.close()
    s2 = store(tmp_path)                                      # reopen: chain continues
    assert s2.append(ev(3)).seq == 3 and s2.verify().ok
    assert (tmp_path / "events.db").stat().st_mode & 0o777 == 0o600
    for pragma, expected in (("journal_mode", "wal"), ("synchronous", 2)):  # 2 = FULL
        assert s2._db.execute(f"PRAGMA {pragma}").fetchone()[0] == expected


def test_duplicate_event_id_is_idempotent(tmp_path):
    s = store(tmp_path)
    e = ev(1)
    assert s.append(e).seq == 1
    again = s.append(e)
    assert again.duplicate and again.seq == 1 and s.head()[0] == 1


@pytest.mark.parametrize("attack,reason", [
    ("UPDATE events SET payload='{\"i\":99}' WHERE seq=2", "modified"),
    ("UPDATE events SET event_type='verdict' WHERE seq=2", "modified"),
    ("DELETE FROM events WHERE seq=2", "gap"),
    ("DELETE FROM events WHERE seq=3", "truncated"),
    ("UPDATE events SET prev_hash='00' WHERE seq=3", "broken_link"),
])
def test_tampering_detected(tmp_path, attack, reason):
    s = store(tmp_path)
    for i in range(3):
        s.append(ev(i))
    raw(tmp_path).execute(attack)
    res = s.verify()
    assert not res.ok and res.reason == reason


def test_rewritten_chain_caught_by_checkpoint(tmp_path):
    from src.events.store import record_hash
    s = store(tmp_path)
    for i in range(3):
        s.append(ev(i))
    s.checkpoint(KEY)
    assert s.verify_checkpoints(KEY).ok
    # Attacker without the key rewrites event 2 and recomputes every following hash.
    db = raw(tmp_path)
    rows = db.execute("SELECT seq, event_id, event_type, scan_id, station_id, timestamp_utc, received_utc, payload,"
                      " prev_hash FROM events ORDER BY seq").fetchall()
    prev = rows[0][8]
    for seq, eid, et, sid, st, ts, rc, payload, _ in rows:
        if seq == 2:
            payload = '{"i":42}'
        h = record_hash(prev, seq, eid, et, sid, st, ts, rc, payload)
        db.execute("UPDATE events SET payload=?, prev_hash=?, hash=? WHERE seq=?", (payload, prev, h, seq))
        prev = h
    assert s.verify().ok                                       # chain alone cannot tell
    res = s.verify_checkpoints(KEY)
    assert not res.ok and res.reason in ("checkpoint_mismatch", "checkpoint_mac")
    assert not s.verify_checkpoints(b"x" * 32).ok             # forged/wrong key


def test_delivery_queue_ordering_and_dead_letter(tmp_path):
    s = store(tmp_path, router=lambda t, p: ["siem"] + (["alert:webhook"] if t is EventType.VERDICT else []))
    s.append(ev(1))
    s.append(ev(2, EventType.VERDICT))
    d, due = s.next_delivery("siem")
    assert d.event.seq == 1 and due == 0
    s.mark_failed("siem", 1, "network", next_attempt=100.0, dead=False)
    d, due = s.next_delivery("siem")
    assert d.event.seq == 1 and d.attempts == 1 and due == 100.0     # head of line blocks later events
    s.mark_failed("siem", 1, "network", next_attempt=0, dead=True)
    assert s.next_delivery("siem")[0].event.seq == 2
    s.mark_delivered("siem", 2)
    assert s.next_delivery("siem")[0] is None
    assert s.next_delivery("alert:webhook")[0].event.event_type == "verdict"
    assert s.queue_stats()["siem"] == {"pending": 0, "delivered": 1, "dead": 1}


def test_prune_keeps_pending_and_moves_anchor(tmp_path):
    now = [1_000_000.0]
    s = store(tmp_path, router=lambda t, p: ["siem"], clock=lambda: now[0])
    for i in range(5):
        s.append(ev(i))
    for seq in (1, 2):
        s.mark_delivered("siem", seq)
    now[0] += 200 * 86_400
    assert s.prune(180) == 2                                   # seq 3 still pending
    assert s.get(1) is None and s.get(3) is not None
    assert s.verify().ok                                       # verification starts at the new anchor
    s.append(ev(9))
    assert s.verify().ok and s.head()[0] == 6


def test_reanchor_after_tamper(tmp_path):
    s = store(tmp_path)
    for i in range(3):
        s.append(ev(i))
    raw(tmp_path).execute("UPDATE events SET payload='{}' WHERE seq=2")
    res = s.verify()
    s.set_tamper(res)
    assert s.tamper_state()["reason"] == "modified"
    s.reanchor()
    assert s.tamper_state() is None and s.verify().ok
    assert s.get(2) is not None                               # damaged history kept for forensics


def test_disk_full_refuses_writes(tmp_path):
    s = store(tmp_path, min_free_mb=10 ** 9)
    with pytest.raises(StoreFull):
        s.append(ev(1))
    assert s.head()[0] == 0


def test_corrupt_database_refused(tmp_path):
    path = tmp_path / "events.db"
    s = store(tmp_path)
    for i in range(50):
        s.append(ev(i, blob="x" * 2000))
    s.close()
    with open(path, "r+b") as fh:                              # damage a b-tree page
        fh.seek(4096 * 3)
        fh.write(os.urandom(4096))
    with pytest.raises((StoreCorrupt, sqlite3.DatabaseError)):
        store(tmp_path)
