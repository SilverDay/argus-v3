from pathlib import Path

import pytest
import yaml

from src.shared.config import (
    Config, ConfigError, EngineRole, load_config, load_config_from_dict,
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


@pytest.mark.parametrize("key,value", [("role", "mandatory"), ("role", "advisory"),
                                       ("on_quota_or_network_failure", "error"),
                                       ("network_outage_policy_ref", "SOC-RUNBOOK-12")])
def test_vt_is_advisory_only(key, value):
    """Spec §15.2 #4 (1.5.9): no mandatory VirusTotal; the removed keys name the decision."""
    d = template()
    d["virustotal"].update(enabled=True, api_key_ref="credential:vt_key", **{key: value})
    with pytest.raises(ConfigError, match="advisory-only"):
        load_config_from_dict(d)


def test_vt_enabled_requires_credential():
    d = template()
    d["virustotal"].update(enabled=True)
    with pytest.raises(ConfigError, match="api_key_ref"):
        load_config_from_dict(d)


def test_yara_rules_require_signed_bundle_paths():
    d = template()
    d["yara"].update(role="mandatory")
    with pytest.raises(ConfigError, match="enabled=true"):
        load_config_from_dict(d)
    d["yara"].update(enabled=True, trust_anchor_path="relative.pub")
    with pytest.raises(ConfigError, match="trust_anchor_path"):
        load_config_from_dict(d)
    d["yara"].update(trust_anchor_path="/etc/usb-scan/yara-rules.pub")
    assert load_config_from_dict(d).yara.role is EngineRole.MANDATORY


@pytest.mark.parametrize("change,match", [
    ({"max_file_size_mb": 600, "memory_limit_mb": 1024}, "twice"),
    ({"per_file_timeout_seconds": 100, "global_budget_seconds": 60}, "below"),
])
def test_yara_resource_rules(change, match):
    d = template()
    d["yara"].update(enabled=True, **change)
    with pytest.raises(ConfigError, match=match):
        load_config_from_dict(d)


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


@pytest.mark.parametrize("value,ok", [
    ("e3c9e316-0b5c-4db8-817d-f92df00215ae", True), ("E3C9E316-0B5C-4DB8-817D-F92DF00215AE", True),
    ("0x27", True), ("0xc", True), ("27", False), ("0x123", False), ("msr", False),
])
def test_excludable_partition_types_validated(value, ok):
    d = template()
    d["device"]["excludable_partition_types"] = [value]
    if ok:
        load_config_from_dict(d)
    else:
        with pytest.raises(ConfigError, match="partition type"):
            load_config_from_dict(d)


def test_normalise_partition_type():
    from src.shared.config import normalise_partition_type
    assert normalise_partition_type("0x0C") == "0xc"
    assert normalise_partition_type("E3C9E316-0B5C-4DB8-817D-F92DF00215AE") == "e3c9e316-0b5c-4db8-817d-f92df00215ae"
