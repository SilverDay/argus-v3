import json
import os

import pytest

from src.yara_worker.rules import RulesetError, RuleStore, accepted_version, load_ruleset
from tests.unit.yara_worker.bundle import MINISIGN, make_bundle, make_keypair, yara_cfg

pytestmark = pytest.mark.skipif(MINISIGN is None, reason="minisign not installed")

GOOD = 'rule evil { meta: severity = "high" strings: $a = "EVILMARK" condition: $a }'


@pytest.fixture
def keys(tmp_path):
    return make_keypair(str(tmp_path))


@pytest.fixture
def env(tmp_path, keys):
    pub, sec = keys
    rules = str(tmp_path / "rules")
    return {"pub": pub, "sec": sec, "rules": rules, "state": str(tmp_path / "state")}


def cfg(env):
    return yara_cfg(env["rules"], env["pub"], env["state"])


def test_valid_bundle_loads_and_records_version(env):
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD}, version=3)
    rs = load_ruleset(cfg(env))
    assert rs.version == 3 and rs.rule_files == 1 and rs.version_id.startswith("3:")
    assert [m.rule for m in rs.rules.match(data=b"..EVILMARK..")] == ["evil"]
    assert accepted_version(cfg(env)) == 3


def test_signature_from_other_key_rejected(env, tmp_path):
    _, other_sec = make_keypair(str(tmp_path), "other")
    make_bundle(env["rules"], other_sec, {"base.yar": GOOD})
    with pytest.raises(RulesetError, match="signature verification failed"):
        load_ruleset(cfg(env))


def test_rule_file_changed_after_signing_rejected(env):
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD})
    with open(os.path.join(env["rules"], "base.yar"), "a") as fh:
        fh.write("\nrule sneaky { condition: true }\n")
    with pytest.raises(RulesetError, match="does not match the signed manifest"):
        load_ruleset(cfg(env))


def test_manifest_changed_after_signing_rejected(env):
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD}, version=1)
    path = os.path.join(env["rules"], "manifest.json")
    with open(path) as fh:
        data = json.load(fh)
    data["version"] = 99
    with open(path, "w") as fh:
        json.dump(data, fh)
    with pytest.raises(RulesetError, match="signature"):
        load_ruleset(cfg(env))


def test_unlisted_files_are_not_compiled(env):
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD})
    with open(os.path.join(env["rules"], "extra.yar"), "w") as fh:
        fh.write("rule everything { condition: true }")
    rs = load_ruleset(cfg(env))
    assert rs.rules.match(data=b"harmless") == []


@pytest.mark.parametrize("name", ["../evil.yar", "sub/dir.yar", "rules.txt", ".hidden.yar"])
def test_signed_but_unsafe_names_rejected(env, name):
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD}, manifest_files={name: "0" * 64})
    with pytest.raises(RulesetError, match="invalid rule file name"):
        load_ruleset(cfg(env))


def test_include_directive_rejected(env):
    make_bundle(env["rules"], env["sec"], {"base.yar": 'include "/etc/passwd"\n' + GOOD})
    with pytest.raises(RulesetError, match="does not compile"):
        load_ruleset(cfg(env))


def test_rollback_refused_and_last_known_good_kept(env):
    store = RuleStore(cfg(env))
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD}, version=5)
    assert store.reload() and store.active.version == 5
    make_bundle(env["rules"], env["sec"], {"base.yar": GOOD}, version=4)      # validly signed but older
    assert not store.reload()
    assert "older than accepted version 5" in store.last_error
    assert store.active.version == 5
    make_bundle(env["rules"], env["sec"], {"base.yar": "rule broken { condition: }"}, version=6)
    assert not store.reload() and store.active.version == 5                    # syntax error keeps v5


def test_missing_bundle(env):
    with pytest.raises(RulesetError, match="manifest unreadable"):
        load_ruleset(cfg(env))
