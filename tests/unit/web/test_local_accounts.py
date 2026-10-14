"""Accounts file v2 and live reload (spec §10.2, 1.5.10)."""
import os

import bcrypt
import pytest

from src.shared.config import ConfigError, load_config_from_dict
from src.web.local_accounts import Account, AccountsError, AccountsFile, format_accounts, parse_accounts
from src.web.totp import new_seed

HASH = bcrypt.hashpw(b"correct horse battery", bcrypt.gensalt(12)).decode()


def test_v2_lines_round_trip():
    seed = new_seed()
    text = f"ada:admin:{HASH}:{seed}\nolaf:operator:{HASH}::disabled\nvic:viewer:{HASH}\n"
    accounts = parse_accounts(text)
    assert accounts["ada"].totp_seed == seed and not accounts["ada"].disabled
    assert accounts["olaf"].disabled and accounts["olaf"].totp_seed == ""
    assert parse_accounts(format_accounts(accounts)) == accounts
    assert len(seed) == 32                       # 160-bit seed


@pytest.mark.parametrize("line", [
    f"ada:admin:{HASH}:not-base32!",
    f"ada:admin:{HASH}:AAAA",                     # too short
    f"ada:admin:{HASH}:{'A' * 32}:locked",        # unknown flag
    f"ada:admin:{HASH}:{'A' * 32}:disabled:x",    # too many fields
])
def test_invalid_v2_lines(line):
    with pytest.raises(AccountsError):
        parse_accounts(line)


def write(path, text, mode=0o640):
    path.write_text(text)
    os.chmod(path, mode)


def test_live_reload_and_fail_closed(tmp_path):
    f = tmp_path / "web-accounts"
    write(f, f"ada:admin:{HASH}\n")
    src = AccountsFile(f"file:{f}")
    assert list(src.current()) == ["ada"]
    write(f, f"ada:admin:{HASH}\nvic:viewer:{HASH}\n")
    os.utime(f, ns=(1, 1))                        # make sure the signature changes
    assert sorted(src.current()) == ["ada", "vic"]
    write(f, "garbage line\n")
    assert src.current() == {}                    # unparseable -> no local login at all
    write(f, f"ada:admin:{HASH}\n", mode=0o644)   # world-readable secret file is refused
    assert src.current() == {}
    f.unlink()
    assert src.current() == {}


def test_account_line_format():
    a = Account("ada", "admin", HASH.encode(), "A" * 32, True)
    assert a.line() == f"ada:admin:{HASH}:{'A' * 32}:disabled"


def _web(**auth):
    return {"admin_web": {"enabled": True, "public_url": "https://scan.example.org"},
            "host": {"management_networks": ["10.0.0.0/8"]}, "auth": {"web": auth}}


def test_config_requires_at_least_one_method():
    with pytest.raises(ConfigError, match="oidc_enabled and/or auth.web.local_enabled"):
        load_config_from_dict(_web(oidc_enabled=False, local_enabled=False))
    cfg = load_config_from_dict(_web(oidc_enabled=False, local_enabled=True))
    assert cfg.auth.web.local.require_totp is True


def test_config_local_needs_file_ref_and_old_key_is_named():
    with pytest.raises(ConfigError, match="file: reference"):
        load_config_from_dict(_web(oidc_enabled=False, local_enabled=True,
                                   local={"accounts_ref": "credential:web_accounts"}))
    with pytest.raises(ConfigError, match="renamed in spec 1.5.10"):
        load_config_from_dict(_web(oidc_enabled=False, local_fallback_allowed=True))
