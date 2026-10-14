"""Local account management CLI (spec §10.2, 1.5.10)."""
import os
import sqlite3
import stat

import pytest

from src.web import accounts_admin as adm
from src.web import totp
from src.web.local_accounts import parse_accounts

PASS = "Correct-Horse-Battery-9"


@pytest.fixture
def station(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    cfg = tmp_path / "scan_station.yaml"
    cfg.write_text(f"""
station: {{station_id: hq-lobby-01}}
admin_web: {{enabled: true, public_url: "https://scan.example.org", state_dir: "{tmp_path / 'web'}"}}
host: {{management_networks: ["10.0.0.0/8"]}}
auth:
  web:
    oidc_enabled: false
    local_enabled: true
    local: {{accounts_ref: "file:{secrets / 'web-accounts'}"}}
""")
    audits = []
    monkeypatch.setattr(adm, "audit_as", lambda user, sock, ev: audits.append((user, ev.payload)) or True)
    seeds = []
    real_new = totp.new_seed
    monkeypatch.setattr(totp, "new_seed", lambda: seeds.append(real_new()) or seeds[-1])
    monkeypatch.setattr("builtins.input", lambda prompt="": totp.hotp(totp._key(seeds[-1]),
                                                                         int(__import__("time").time() // 30)))
    answers = []
    monkeypatch.setattr(adm.getpass, "getpass", lambda prompt="": answers.pop(0))

    def run(*args, passphrases=()):
        answers[:] = list(passphrases)
        return adm.main(["--config", str(cfg), "--group", "root", *args])

    return run, secrets / "web-accounts", audits, seeds, tmp_path


def accounts(path):
    return parse_accounts(path.read_text())


def test_add_enrols_totp_and_audits(station):
    run, path, audits, seeds, _ = station
    assert run("add", "Ada", "--role", "admin", passphrases=[PASS, PASS]) == 0
    a = accounts(path)["ada"]
    assert a.role == "admin" and a.totp_seed == seeds[-1] and not a.disabled
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert audits == [("usbscan-web", {"result": "account_change", "action": "add", "user": "ada", "actor": "root",
                                       "role": "admin", "method": "cli", "reason": ""})]
    assert PASS not in path.read_text()


def test_lifecycle_and_session_revocation(station):
    run, path, audits, seeds, tmp = station
    run("add", "ada", "--role", "operator", passphrases=[PASS, PASS])
    (tmp / "web").mkdir()
    db = sqlite3.connect(tmp / "web" / "web.db")
    db.execute("CREATE TABLE sessions (token_hash TEXT, user TEXT, method TEXT)")
    db.executemany("INSERT INTO sessions VALUES (?,?,?)", [("t1", "ada", "local+totp"), ("t2", "ada", "oidc")])
    db.commit()
    assert run("role", "ada", "admin") == 0 and accounts(path)["ada"].role == "admin"
    assert db.execute("SELECT token_hash FROM sessions").fetchall() == [("t2",)]     # OIDC session untouched
    assert run("disable", "ada") == 0 and accounts(path)["ada"].disabled
    assert run("enable", "ada") == 0 and not accounts(path)["ada"].disabled
    old_seed = accounts(path)["ada"].totp_seed
    assert run("totp", "ada") == 0 and accounts(path)["ada"].totp_seed not in ("", old_seed)
    old_hash = accounts(path)["ada"].hash
    assert run("passwd", "ada", passphrases=["Another-Long-Pass-7", "Another-Long-Pass-7"]) == 0
    assert accounts(path)["ada"].hash != old_hash
    assert run("remove", "ada") == 0 and accounts(path) == {}
    assert [p["action"] for _, p in audits] == ["add", "role", "disable", "enable", "totp", "passwd", "remove"]
    db.close()


@pytest.mark.parametrize("bad", ["short", "ada-is-my-name-1234", "x" * 20, "ä" * 40])
def test_passphrase_policy(station, bad):
    run, path, _, _, _ = station
    assert run("add", "ada", "--role", "viewer", passphrases=[bad, bad, bad]) == 1
    assert not path.exists()


def test_mismatch_and_fail_closed_audit(station, monkeypatch):
    run, path, audits, _, _ = station
    assert run("add", "ada", "--role", "viewer", passphrases=[PASS, "other", PASS, "x", PASS, "y"]) == 1
    monkeypatch.setattr(adm, "audit_as", lambda *a: False)
    assert run("add", "ada", "--role", "viewer", passphrases=[PASS, PASS]) == 1
    assert not path.exists() and audits == []


def test_wrong_totp_confirmation_changes_nothing(station, monkeypatch):
    run, path, audits, _, _ = station
    monkeypatch.setattr("builtins.input", lambda prompt="": "000000")
    monkeypatch.setattr(totp, "verify", lambda seed, code, now=None: None)
    assert run("add", "ada", "--role", "viewer", passphrases=[PASS, PASS]) == 1
    assert not path.exists() and audits == []


def test_errors(station):
    run, path, _, _, _ = station
    assert run("passwd", "nobody") == 1
    assert run("add", "Bad Name", "--role", "admin") == 1
    path.write_text("garbage\n")
    assert run("add", "ada", "--role", "admin", passphrases=[PASS, PASS]) == 1
    assert path.read_text() == "garbage\n"                 # an invalid file is never overwritten


def test_real_audit_child_drops_privileges(tmp_path):
    """audit_as runs the append as the given account: here 'nobody', which the events
    socket does not know, so the append fails and the caller fails closed."""
    from src.shared.models import EventType, ScanEvent
    assert adm.audit_as("nobody", str(tmp_path / "missing.sock"),
                        ScanEvent(EventType.WEB_AUTH, None, {"result": "account_change"})) is False
