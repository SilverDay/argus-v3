from pathlib import Path

import pytest
import yaml

from src.shared.config import (
    Config, ConfigError, EngineRole, FailurePolicy, load_config, load_config_from_dict,
)
from src.shared.models import Verdict

TEMPLATE = Path(__file__).resolve().parents[3] / "config" / "scan_station.yaml"


def template() -> dict:
    return yaml.safe_load(TEMPLATE.read_text())


def test_template_loads_and_matches_defaults():
    cfg = load_config(TEMPLATE)
    assert cfg == Config()
    assert cfg.clamav.role is EngineRole.MANDATORY
    assert cfg.pin.bcrypt_cost == 12


def test_empty_document_uses_defaults():
    assert load_config_from_dict(None) == Config()


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


def test_unknown_key_rejected():
    d = template()
    d["scan"]["max_filez"] = 1
    with pytest.raises(ConfigError, match="unknown key"):
        load_config_from_dict(d)


@pytest.mark.parametrize("section,key,value", [
    ("scan", "max_files", "many"),
    ("scan", "max_files", True),
    ("yara", "enabled", "yes"),
    ("virustotal", "role", "sometimes"),
    ("clamav", "per_file_timeout_seconds", 0),
    ("pin", "bcrypt_cost", 10),
])
def test_type_and_range_errors(section, key, value):
    d = template()
    d[section][key] = value
    with pytest.raises(ConfigError):
        load_config_from_dict(d)


def test_vt_mandatory_requires_strict_failure_policy():
    d = template()
    d["virustotal"].update(enabled=True, role="mandatory", api_key_ref="credential:vt_key",
                           on_quota_or_network_failure="continue")
    with pytest.raises(ConfigError, match="on_quota_or_network_failure"):
        load_config_from_dict(d)
    d["virustotal"]["on_quota_or_network_failure"] = "incomplete"
    cfg = load_config_from_dict(d)
    assert cfg.virustotal.on_quota_or_network_failure is FailurePolicy.INCOMPLETE


def test_vt_mandatory_requires_enabled_and_credential():
    d = template()
    d["virustotal"].update(role="mandatory", on_quota_or_network_failure="error")
    with pytest.raises(ConfigError) as exc:
        load_config_from_dict(d)
    assert "enabled=true" in str(exc.value) and "api_key_ref" in str(exc.value)


def test_yara_mandatory_requires_signed_ruleset():
    d = template()
    d["yara"].update(enabled=True, role="mandatory")
    with pytest.raises(ConfigError, match="ruleset_signature_path"):
        load_config_from_dict(d)
    d["yara"].update(ruleset_signature_path="/var/lib/usb-scan/rules/active.sig",
                     trust_anchor_path="/etc/usb-scan/yara-trust.pub")
    assert load_config_from_dict(d).yara.role is EngineRole.MANDATORY


def test_oidc_requires_mfa():
    d = template()
    d["auth"]["web"]["require_mfa"] = False
    with pytest.raises(ConfigError, match="require_mfa"):
        load_config_from_dict(d)


@pytest.mark.parametrize("hold,match", [
    ({"enabled": True, "max_duration_seconds": None, "allowed_verdicts": ["CLEAN"]}, "max_duration"),
    ({"enabled": True, "max_duration_seconds": 10, "allowed_verdicts": ["CLEAN"]}, "15..300"),
    ({"enabled": True, "max_duration_seconds": 301, "allowed_verdicts": ["CLEAN"]}, "15..300"),
    ({"enabled": True, "max_duration_seconds": 60, "allowed_verdicts": []}, "allowed_verdicts"),
    ({"enabled": True, "max_duration_seconds": 60, "allowed_verdicts": ["THREAT"]}, "CLEAN/SUSPICIOUS"),
])
def test_operator_hold_rules(hold, match):
    d = template()
    d["operator_hold"] = hold
    with pytest.raises(ConfigError, match=match):
        load_config_from_dict(d)


def test_operator_hold_valid():
    d = template()
    d["operator_hold"] = {"enabled": True, "max_duration_seconds": 60,
                          "allowed_verdicts": ["CLEAN", "SUSPICIOUS"]}
    cfg = load_config_from_dict(d)
    assert cfg.operator_hold.allowed_verdicts == (Verdict.CLEAN, Verdict.SUSPICIOUS)


def test_clamav_cannot_be_advisory():
    d = template()
    d["clamav"]["role"] = "advisory"
    with pytest.raises(ConfigError, match="mandatory"):
        load_config_from_dict(d)


@pytest.mark.parametrize("value", [
    "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
])
def test_credential_hash_in_yaml_rejected(value):
    d = template()
    d["station"]["station_id"] = value
    with pytest.raises(ConfigError, match="hashes"):
        load_config_from_dict(d)


@pytest.mark.parametrize("ref", ["my-plain-api-key", "file:relative/path", "file:/etc/../shadow",
                                 "env:lower_case", "credential:../x"])
def test_secret_fields_require_valid_reference(ref):
    d = template()
    d["virustotal"]["api_key_ref"] = ref
    with pytest.raises(ConfigError, match="api_key_ref"):
        load_config_from_dict(d)


def test_restricted_extension_scope_flag():
    d = template()
    d["scan"]["allow_extensions"] = ["pdf"]
    assert load_config_from_dict(d).restricted_extension_scope is True


def test_extension_both_blocked_and_allowed():
    d = template()
    d["scan"].update(block_extensions=[".EXE"], allow_extensions=["exe"])
    with pytest.raises(ConfigError, match="both blocked and allowed"):
        load_config_from_dict(d)


def test_invalid_station_id():
    d = template()
    d["station"]["station_id"] = "../etc"
    with pytest.raises(ConfigError, match="station_id"):
        load_config_from_dict(d)


def test_yaml_tags_are_not_executed(tmp_path):
    p = tmp_path / "evil.yaml"
    p.write_text("station: !!python/object/apply:os.system ['true']\n")
    with pytest.raises(ConfigError, match="YAML"):
        load_config(p)
