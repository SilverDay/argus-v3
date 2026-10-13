import io
import pathlib
import os

import bcrypt
import pytest

from src.shared import pin_admin
from src.shared.auth import verify_pin
from src.shared.config import load_config_from_dict
from src.shared.secret_refs import resolve_secret


def cfg(tmp_path, **pin):
    return load_config_from_dict({"pin": {"hash_ref": f"file:{tmp_path}/secrets/operator_pin.hash", **pin}}).pin


def test_set_pin_writes_protected_bcrypt_hash(tmp_path):
    c = cfg(tmp_path)
    path = pin_admin.set_pin(c, "481516", "481516", gid=None)
    st = os.stat(path)
    assert st.st_mode & 0o777 == 0o640
    hashed = pathlib.Path(path).read_text().strip()
    assert hashed.startswith("$2b$12$") and "481516" not in hashed
    assert verify_pin("481516", resolve_secret(c.hash_ref).decode())     # the orchestrator's read path
    assert not [n for n in os.listdir(tmp_path / "secrets") if n.endswith(".tmp")]


@pytest.mark.parametrize("first,second,match", [
    ("481516", "481517", "do not match"),
    ("12345", "12345", "at least 6"),
    ("123456", "123456", "sequential"),
    ("987654", "987654", "sequential"),
    ("777777", "777777", "repeat"),
    ("12a456", "12a456", "only digits"),
    ("1234567890123", "1234567890123", "at most"),
])
def test_policy_rejections_write_nothing(tmp_path, first, second, match):
    with pytest.raises(pin_admin.PinSetupError, match=match):
        pin_admin.set_pin(cfg(tmp_path), first, second, gid=None)
    assert not (tmp_path / "secrets" / "operator_pin.hash").exists()


def test_deny_list_and_cost(tmp_path):
    deny = tmp_path / "deny.txt"
    deny.write_text("# common\n246810\n")
    with pytest.raises(pin_admin.PinSetupError, match="deny list"):
        pin_admin.set_pin(cfg(tmp_path, deny_list_path=str(deny)), "246810", "246810", gid=None)
    path = pin_admin.set_pin(cfg(tmp_path, bcrypt_cost=13), "592614", "592614", gid=None)
    assert pathlib.Path(path).read_text().startswith("$2b$13$")


def test_replacing_keeps_atomicity(tmp_path):
    c = cfg(tmp_path)
    path = pin_admin.set_pin(c, "481516", "481516", gid=None)
    pin_admin.set_pin(c, "592614", "592614", gid=None)
    hashed = pathlib.Path(path).read_text().strip()
    assert bcrypt.checkpw(b"592614", hashed.encode()) and not bcrypt.checkpw(b"481516", hashed.encode())


def test_only_file_refs(tmp_path):
    c = load_config_from_dict({"pin": {"hash_ref": "credential:operator_pin"}}).pin
    with pytest.raises(pin_admin.PinSetupError, match="file:"):
        pin_admin.set_pin(c, "481516", "481516", gid=None)


def test_stdin_entry_and_no_echo_of_value(tmp_path, capsys, monkeypatch):
    first, second = pin_admin.read_twice(io.StringIO("592614\n592614\n"))
    assert first == second == "592614"
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text(f"pin: {{hash_ref: 'file:{tmp_path}/secrets/operator_pin.hash'}}\n")
    monkeypatch.setattr(pin_admin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pin_admin, "read_twice", lambda: ("592614", "592614"))
    monkeypatch.setattr(pin_admin.grp, "getgrnam", lambda name: type("G", (), {"gr_gid": os.getgid()}))
    monkeypatch.setattr(pin_admin.os, "fchown", lambda fd, uid, gid: None)
    assert pin_admin.main(["--config", str(cfgfile)]) == 0
    out = capsys.readouterr()
    assert "592614" not in out.out + out.err
    monkeypatch.setattr(pin_admin, "read_twice", lambda: ("592614", "111111"))
    assert pin_admin.main(["--config", str(cfgfile)]) == 1
    out = capsys.readouterr()
    assert "592614" not in out.out + out.err and "111111" not in out.out + out.err


def test_requires_root(monkeypatch, capsys):
    monkeypatch.setattr(pin_admin.os, "geteuid", lambda: 1000)
    assert pin_admin.main([]) == 2
