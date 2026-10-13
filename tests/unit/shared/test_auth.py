import logging

import bcrypt
import pytest

from src.shared.auth import (
    AuthError, AuthManager, SqliteLockoutStore, hash_cost, hash_pin, load_deny_list,
    validate_pin_format, verify_pin,
)

GOOD_PIN = "482916"


@pytest.fixture(scope="module")
def pin_hash():
    return hash_pin(GOOD_PIN)


class Clock:
    """Wall clock plus a boot clock; ``advance`` moves both, ``jump`` moves wall time only."""

    def __init__(self, t=1_800_000_000.0):
        self.t = t
        self.boot_id = "boot-1"
        self.boottime = 100.0

    def __call__(self):
        return self.t

    def boot(self):
        return self.boot_id, self.boottime

    def advance(self, seconds):
        self.t += seconds
        self.boottime += seconds

    def reboot(self, wall_delta):
        self.boot_id = self.boot_id + "x"
        self.boottime = 5.0
        self.t += wall_delta


_open_stores = []


@pytest.fixture
def db(tmp_path):
    yield str(tmp_path / "events.db")
    while _open_stores:
        _open_stores.pop().close()


def store(db):
    s = SqliteLockoutStore(db)
    _open_stores.append(s)
    return s


def manager(db, pin_hash, clock, **kw):
    return AuthManager(store(db), lambda level: pin_hash, clock=clock, boot_clock=clock.boot, **kw)


# --- format -----------------------------------------------------------------

@pytest.mark.parametrize("pin", ["482916", "3901457", "105938274615"])
def test_valid_pins(pin):
    assert validate_pin_format(pin) is None


@pytest.mark.parametrize("pin,reason", [
    ("12345", "at least"), ("1234567890123", "at most"),
    ("111111", "repeat"), ("123456", "sequential"), ("654321", "sequential"),
    ("890123", "sequential"), ("21098765", "sequential"),
    ("48291a", "digits"), ("４８２９１６", "digits"), ("٤٨٢٩١٦", "digits"), (" 482916", "digits"), ("", "digits"),
])
def test_invalid_pins(pin, reason):
    assert reason in validate_pin_format(pin)


def test_deny_list(tmp_path):
    p = tmp_path / "deny.txt"
    p.write_text("# common\n482916\n\n")
    deny = load_deny_list(str(p))
    assert "deny list" in validate_pin_format(GOOD_PIN, deny_list=deny)


# --- hashing ----------------------------------------------------------------

def test_hash_uses_cost_12_and_verifies(pin_hash):
    assert hash_cost(pin_hash) == 12
    assert GOOD_PIN not in pin_hash
    assert verify_pin(GOOD_PIN, pin_hash)
    assert not verify_pin("482917", pin_hash)


def test_hash_refuses_low_cost_and_weak_pin():
    with pytest.raises(AuthError):
        hash_pin(GOOD_PIN, cost=10)
    with pytest.raises(AuthError, match="sequential"):
        hash_pin("123456")


def test_verify_rejects_weak_hash_and_garbage():
    weak = bcrypt.hashpw(GOOD_PIN.encode(), bcrypt.gensalt(rounds=4)).decode()
    assert not verify_pin(GOOD_PIN, weak)
    assert not verify_pin(GOOD_PIN, "not-a-hash")
    assert not verify_pin(GOOD_PIN, "")


def test_verify_handles_overlong_input(pin_hash):
    # bcrypt 5.0.0 raises ValueError for >72 bytes; we must return False instead.
    assert not verify_pin("9" * 100, pin_hash)
    assert not verify_pin("", pin_hash)


def test_auth_error_never_contains_pin():
    with pytest.raises(AuthError) as exc:
        hash_pin("123456")
    assert "123456" not in str(exc.value)


# --- lockout ----------------------------------------------------------------

def test_success_and_failure(db, pin_hash):
    m = manager(db, pin_hash, Clock())
    assert m.verify(GOOD_PIN)
    assert not m.verify("000001")


def test_lockout_after_five_failures_blocks_correct_pin(db, pin_hash):
    m = manager(db, pin_hash, Clock())
    for i in range(4):
        out = m.attempt("000001")
        assert not out.success and not out.locked_out
    out = m.attempt("000001")
    assert out.lockout_triggered and out.locked_out
    assert m.is_locked_out()
    assert not m.verify(GOOD_PIN)


def test_lockout_persists_across_restart(db, pin_hash):
    clock = Clock()
    m = manager(db, pin_hash, clock)
    for _ in range(5):
        m.attempt("000001")
    _open_stores.pop().close()  # process exit
    restarted = manager(db, pin_hash, clock)  # e.g. GUI/orchestrator restart (AC-S05)
    assert restarted.is_locked_out()
    assert not restarted.verify(GOOD_PIN)


def test_lockout_expires_after_15_minutes_and_counter_resets(db, pin_hash):
    clock = Clock()
    m = manager(db, pin_hash, clock)
    for _ in range(5):
        m.attempt("000001")
    clock.advance(15 * 60 - 1)
    assert m.is_locked_out()
    clock.advance(2)
    assert not m.is_locked_out()
    assert not m.attempt("000001").locked_out  # one failure after expiry does not relock
    assert m.verify(GOOD_PIN)


def test_success_resets_failure_count(db, pin_hash):
    m = manager(db, pin_hash, Clock())
    for _ in range(4):
        m.attempt("000001")
    assert m.verify(GOOD_PIN)
    for _ in range(4):
        m.attempt("000001")
    assert not m.is_locked_out()


def test_no_hash_computed_while_locked_out(db, pin_hash):
    calls = []

    def loader(level):
        calls.append(level)
        return pin_hash

    m = AuthManager(store(db), loader, clock=(c := Clock()), boot_clock=c.boot)
    for _ in range(5):
        m.attempt("000001")
    n = len(calls)
    m.attempt(GOOD_PIN)
    assert len(calls) == n


def _lock(m):
    for _ in range(5):
        m.attempt("000001")
    assert m.is_locked_out()


def test_same_boot_wall_clock_jumps_do_not_matter(db, pin_hash):
    clock = Clock()
    m = manager(db, pin_hash, clock)
    _lock(m)
    clock.t -= 86400                      # backwards jump: no extension
    clock.boottime += 15 * 60 + 1
    assert not m.is_locked_out()
    _lock(m)
    clock.t += 86400                      # forward jump: no early release
    assert m.is_locked_out()


def test_reboot_with_clock_behind_extends_at_most_one_period(db, pin_hash):
    clock = Clock()
    m = manager(db, pin_hash, clock)
    _lock(m)
    clock.reboot(wall_delta=-7 * 86400)   # RTC lost: wall clock now a week behind
    assert m.is_locked_out()              # fail closed, lockout re-armed from now
    clock.advance(15 * 60 - 1)
    assert m.is_locked_out()
    clock.advance(2)
    assert not m.is_locked_out()          # ...but not for the whole week
    assert m.verify(GOOD_PIN)


def test_reboot_with_sane_clock_uses_wall_time(db, pin_hash):
    clock = Clock()
    m = manager(db, pin_hash, clock)
    _lock(m)
    clock.reboot(wall_delta=60)
    assert m.is_locked_out()
    clock.advance(15 * 60)
    assert not m.is_locked_out()


def test_system_boot_clock_reads_real_values():
    from src.shared.auth import system_boot_clock
    boot_id, boottime = system_boot_clock()
    assert len(boot_id) == 36 and boottime > 0


def test_clear_lockout(db, pin_hash):
    m = manager(db, pin_hash, Clock())
    for _ in range(5):
        m.attempt("000001")
    m.clear_lockout()
    assert not m.is_locked_out()
    assert m.verify(GOOD_PIN)


def test_lockout_scoped_per_interface(db, pin_hash):
    m = manager(db, pin_hash, Clock())
    for _ in range(5):
        m.attempt("000001", interface="touchscreen")
    assert m.is_locked_out(interface="touchscreen")
    assert not m.is_locked_out(interface="maintenance-cli")


def test_crash_during_verification_counts_as_failure(db, pin_hash):
    def exploding_loader(level):
        raise RuntimeError("process killed")

    m = AuthManager(store(db), exploding_loader, clock=(c := Clock()), boot_clock=c.boot)
    for _ in range(5):
        assert not m.verify(GOOD_PIN)
    assert m.is_locked_out()


def test_pin_never_logged(db, pin_hash, caplog):
    caplog.set_level(logging.DEBUG)
    m = manager(db, pin_hash, Clock())
    m.verify(GOOD_PIN)
    m.verify("739104")
    assert GOOD_PIN not in caplog.text and "739104" not in caplog.text
