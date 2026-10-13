"""Typed configuration loader for /etc/usb-scan/scan_station.yaml (spec §6).

The YAML is parsed with ``yaml.safe_load`` and mapped onto frozen dataclasses.
Unknown keys, wrong types, out-of-range values and failed cross-field rules
(spec §6.2) all raise ``ConfigError`` before the configuration is activated.
The config holds no secrets: credential fields are secret references (see
``secret_refs``), and any value that looks like a credential hash is refused.
"""
from __future__ import annotations

import dataclasses
import re
import types
import typing
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from .models import Verdict
from .secret_refs import SecretError, validate_ref

DEFAULT_CONFIG_PATH = Path("/etc/usb-scan/scan_station.yaml")
MAX_CONFIG_BYTES = 1024 * 1024

# Values that look like password/PIN hashes must never live in the YAML (spec §6.1).
_HASH_LIKE = re.compile(r"^\$(2[abxy]|argon2(id|i|d)|scrypt|pbkdf2[-\w]*|[156])\$")


class ConfigError(ValueError):
    """Raised for any invalid configuration."""


class EngineRole(str, Enum):
    MANDATORY = "mandatory"
    ADVISORY = "advisory"


class FailurePolicy(str, Enum):
    CONTINUE = "continue"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class PolicySeverity(str, Enum):
    """Verdict produced by a blocked-extension policy violation (spec §3.4)."""
    THREAT = "threat"
    SUSPICIOUS = "suspicious"


class FilenamePrivacy(str, Enum):
    PLAIN = "plain"
    HASH = "hash"
    OMIT = "omit"


class NtfsDriver(str, Enum):
    """Kernel ntfs3 vs FUSE ntfs-3g (spec FR-USB-05: validate before deployment)."""
    NTFS3 = "ntfs3"
    NTFS_3G = "ntfs-3g"


class SyslogTransport(str, Enum):
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


# --- Schema -----------------------------------------------------------------
# Bounds are declared with field metadata: field(default=..., metadata=_range(lo, hi)).

def _range(lo: float, hi: float) -> dict[str, Any]:
    return {"range": (lo, hi)}


def _secret_ref() -> dict[str, Any]:
    return {"secret_ref": True}


@dataclass(frozen=True)
class StationConfig:
    station_id: str = "station-001"
    data_dir: str = "/var/lib/usb-scan"
    log_dir: str = "/var/log/usb-scan"
    run_dir: str = "/run/usb-scan"


@dataclass(frozen=True)
class DeviceConfig:
    max_device_capacity_gb: int = field(default=2048, metadata=_range(1, 1_000_000))
    internal_device_sysfs_prefixes: tuple[str, ...] = ()
    require_full_coverage: bool = True
    insertion_debounce_ms: int = field(default=500, metadata=_range(0, 10_000))


@dataclass(frozen=True)
class BrokerConfig:
    socket_path: str = "/run/usb-scan/broker.sock"
    client_user: str = "usbscan"
    socket_group: str = "usbscan"
    read_group: str = "usbscan-read"
    mounts_dir: str = "/run/usb-scan/mounts"
    audit_log: str = "/var/log/usb-scan/broker-audit.log"
    hmac_key_ref: str = field(default="file:/etc/usb-scan/secrets/broker-hmac.key", metadata=_secret_ref())
    ntfs_driver: NtfsDriver = NtfsDriver.NTFS3
    command_timeout_seconds: int = field(default=30, metadata=_range(5, 300))
    max_clock_skew_seconds: int = field(default=30, metadata=_range(1, 300))


@dataclass(frozen=True)
class ScanConfig:
    global_timeout_seconds: int = field(default=3600, metadata=_range(60, 86_400))
    max_files: int = field(default=500_000, metadata=_range(1, 100_000_000))
    max_depth: int = field(default=64, metadata=_range(1, 4096))
    max_bytes_total_gb: int = field(default=2048, metadata=_range(1, 1_000_000))
    block_extensions: tuple[str, ...] = ()
    allow_extensions: tuple[str, ...] = ()
    blocked_extension_severity: PolicySeverity = PolicySeverity.SUSPICIOUS
    progress_interval_ms: int = field(default=500, metadata=_range(100, 5000))


@dataclass(frozen=True)
class ClamAVConfig:
    role: EngineRole = EngineRole.MANDATORY
    socket_path: str = "/var/run/clamav/clamd.ctl"
    max_signature_age_hours: int = field(default=24, metadata=_range(1, 24 * 30))
    per_file_timeout_seconds: int = field(default=120, metadata=_range(1, 3600))
    max_file_size_mb: int = field(default=4000, metadata=_range(1, 4095))
    connect_timeout_seconds: int = field(default=10, metadata=_range(1, 120))


@dataclass(frozen=True)
class YaraConfig:
    enabled: bool = False
    role: EngineRole = EngineRole.ADVISORY
    rules_path: str = "/var/lib/usb-scan/rules/active"
    ruleset_signature_path: str = ""
    trust_anchor_path: str = ""
    per_file_timeout_seconds: int = field(default=60, metadata=_range(1, 3600))
    global_budget_seconds: int = field(default=1800, metadata=_range(10, 86_400))
    memory_limit_mb: int = field(default=1024, metadata=_range(64, 8192))


@dataclass(frozen=True)
class VirusTotalConfig:
    enabled: bool = False
    role: EngineRole = EngineRole.ADVISORY
    api_key_ref: str = field(default="", metadata=_secret_ref())
    on_quota_or_network_failure: FailurePolicy = FailurePolicy.CONTINUE
    cache_ttl_days: int = field(default=7, metadata=_range(0, 365))
    rate_limit_per_minute: int = field(default=4, metadata=_range(1, 10_000))
    large_file_hash_budget_mb: int = field(default=4096, metadata=_range(1, 1_000_000))
    request_timeout_seconds: int = field(default=15, metadata=_range(1, 120))


@dataclass(frozen=True)
class OperatorHoldConfig:
    enabled: bool = False
    max_duration_seconds: int | None = 60          # spec §3.5 default
    allowed_verdicts: tuple[Verdict, ...] = (Verdict.CLEAN,)


@dataclass(frozen=True)
class PinConfig:
    hash_algorithm: str = "bcrypt"
    bcrypt_cost: int = field(default=12, metadata=_range(12, 16))
    hash_ref: str = field(default="file:/etc/usb-scan/secrets/operator_pin.hash", metadata=_secret_ref())
    min_length: int = field(default=6, metadata=_range(6, 32))
    max_length: int = field(default=12, metadata=_range(6, 32))
    max_failed_attempts: int = field(default=5, metadata=_range(1, 100))
    lockout_minutes: int = field(default=15, metadata=_range(1, 24 * 60))
    deny_list_path: str = ""


@dataclass(frozen=True)
class WebAuthConfig:
    oidc_enabled: bool = True
    require_mfa: bool = True
    local_fallback_allowed: bool = False


@dataclass(frozen=True)
class AuthConfig:
    web: WebAuthConfig = WebAuthConfig()


@dataclass(frozen=True)
class QuarantineConfig:
    quarantine_on_threat: bool = False
    path: str = "/var/lib/usb-scan/quarantine"
    retention_days: int = field(default=30, metadata=_range(1, 3650))
    min_free_mb: int = field(default=1024, metadata=_range(1, 1_000_000))
    export_enabled: bool = False


@dataclass(frozen=True)
class AdminWebConfig:
    enabled: bool = False
    bind_host: str = "127.0.0.1"
    bind_port: int = field(default=8080, metadata=_range(1, 65535))


@dataclass(frozen=True)
class SyslogConfig:
    enabled: bool = False
    host: str = ""
    port: int = field(default=6514, metadata=_range(1, 65535))
    transport: SyslogTransport = SyslogTransport.TLS
    ca_file: str = ""


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: str = "/var/log/usb-scan/usb-scan.jsonl"
    filename_privacy: FilenamePrivacy = FilenamePrivacy.HASH
    pseudonymization_key_ref: str = field(default="", metadata=_secret_ref())
    syslog: SyslogConfig = SyslogConfig()


@dataclass(frozen=True)
class EventsConfig:
    db_path: str = "/var/lib/usb-scan/db/events.db"
    hmac_key_ref: str = field(default="file:/etc/usb-scan/secrets/hmac.key", metadata=_secret_ref())
    checkpoint_interval_hours: int = field(default=1, metadata=_range(1, 168))


@dataclass(frozen=True)
class HealthConfig:
    min_free_disk_mb: int = field(default=512, metadata=_range(1, 1_000_000))
    max_cpu_temp_c: int = field(default=80, metadata=_range(40, 100))
    min_valid_year: int = field(default=2026, metadata=_range(2024, 2100))


@dataclass(frozen=True)
class Config:
    schema_version: int = field(default=1, metadata=_range(1, 1))
    station: StationConfig = StationConfig()
    device: DeviceConfig = DeviceConfig()
    broker: BrokerConfig = BrokerConfig()
    scan: ScanConfig = ScanConfig()
    clamav: ClamAVConfig = ClamAVConfig()
    yara: YaraConfig = YaraConfig()
    virustotal: VirusTotalConfig = VirusTotalConfig()
    operator_hold: OperatorHoldConfig = OperatorHoldConfig()
    pin: PinConfig = PinConfig()
    auth: AuthConfig = AuthConfig()
    quarantine: QuarantineConfig = QuarantineConfig()
    admin_web: AdminWebConfig = AdminWebConfig()
    logging: LoggingConfig = LoggingConfig()
    events: EventsConfig = EventsConfig()
    health: HealthConfig = HealthConfig()

    @property
    def restricted_extension_scope(self) -> bool:
        """Non-empty allow_extensions restricts scope and must be disclosed (spec §6.2)."""
        return bool(self.scan.allow_extensions)


# --- Generic typed builder --------------------------------------------------

def _build(tp: Any, value: Any, path: str, meta: typing.Mapping[str, Any] | None = None) -> Any:
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)

    if origin in (typing.Union, types.UnionType):
        if value is None and type(None) in args:
            return None
        inner = [a for a in args if a is not type(None)]
        if len(inner) != 1:
            raise ConfigError(f"{path}: unsupported union type")
        return _build(inner[0], value, path, meta)

    if dataclasses.is_dataclass(tp):
        return _build_dataclass(tp, value, path)

    if origin is tuple:
        if not isinstance(value, list):
            raise ConfigError(f"{path}: expected a list")
        return tuple(_build(args[0], v, f"{path}[{i}]") for i, v in enumerate(value))

    if isinstance(tp, type) and issubclass(tp, Enum):
        if not isinstance(value, str):
            raise ConfigError(f"{path}: expected one of {[m.value for m in tp]}")
        try:
            return tp(value)
        except ValueError:
            raise ConfigError(f"{path}: invalid value {value!r}; expected one of {[m.value for m in tp]}") from None

    if tp is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{path}: expected true/false")
        return value

    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{path}: expected an integer")
        if meta and "range" in meta:
            lo, hi = meta["range"]
            if not lo <= value <= hi:
                raise ConfigError(f"{path}: {value} outside allowed range {lo}..{hi}")
        return value

    if tp is str:
        if not isinstance(value, str):
            raise ConfigError(f"{path}: expected a string")
        if _HASH_LIKE.match(value):
            raise ConfigError(f"{path}: credential hashes must not be stored in the config file")
        if meta and meta.get("secret_ref") and value:
            try:
                validate_ref(value)
            except SecretError as exc:
                raise ConfigError(f"{path}: {exc}") from None
        return value

    raise ConfigError(f"{path}: unsupported schema type {tp!r}")


def _build_dataclass(cls: type, value: Any, path: str) -> Any:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ConfigError(f"{path or '<root>'}: expected a mapping")
    hints = typing.get_type_hints(cls)
    fields = {f.name: f for f in dataclasses.fields(cls)}
    unknown = sorted(set(value) - set(fields))
    if unknown:
        raise ConfigError(f"{path or '<root>'}: unknown key(s): {', '.join(map(str, unknown))}")
    kwargs = {}
    for name, f in fields.items():
        if name in value:
            sub = f"{path}.{name}" if path else name
            kwargs[name] = _build(hints[name], value[name], sub, f.metadata)
    return cls(**kwargs)


# --- Cross-field rules (spec §6.2 and project rules) ------------------------

def validate(cfg: Config) -> None:
    errors: list[str] = []

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", cfg.station.station_id):
        errors.append("station.station_id: must be 1-64 chars [A-Za-z0-9_.-]")

    for name in ("socket_path", "mounts_dir", "audit_log"):
        value = getattr(cfg.broker, name)
        if not value.startswith("/") or ".." in value.split("/"):
            errors.append(f"broker.{name}: must be an absolute path without '..'")
    if not cfg.broker.hmac_key_ref:
        errors.append("broker.hmac_key_ref is required")
    for name in ("client_user", "socket_group", "read_group"):
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", getattr(cfg.broker, name)):
            errors.append(f"broker.{name}: invalid user/group name")

    if cfg.clamav.role is not EngineRole.MANDATORY:
        errors.append("clamav.role: ClamAV is the mandatory engine and cannot be advisory")

    vt = cfg.virustotal
    if vt.role is EngineRole.MANDATORY:
        if not vt.enabled:
            errors.append("virustotal.role=mandatory requires virustotal.enabled=true")
        if not vt.api_key_ref:
            errors.append("virustotal.role=mandatory requires virustotal.api_key_ref")
        if vt.on_quota_or_network_failure not in (FailurePolicy.INCOMPLETE, FailurePolicy.ERROR):
            errors.append("virustotal.role=mandatory requires on_quota_or_network_failure in {incomplete, error}")
    if vt.enabled and not vt.api_key_ref:
        errors.append("virustotal.enabled=true requires virustotal.api_key_ref")

    y = cfg.yara
    if y.role is EngineRole.MANDATORY:
        if not y.enabled:
            errors.append("yara.role=mandatory requires yara.enabled=true")
        if not (y.rules_path and y.ruleset_signature_path and y.trust_anchor_path):
            errors.append("yara.role=mandatory requires rules_path, ruleset_signature_path and trust_anchor_path")

    if cfg.auth.web.oidc_enabled and not cfg.auth.web.require_mfa:
        errors.append("auth.web.require_mfa must be true when OIDC is enabled")
    if not cfg.auth.web.oidc_enabled and cfg.admin_web.enabled and not cfg.auth.web.local_fallback_allowed:
        errors.append("admin_web.enabled requires OIDC or an explicitly allowed local fallback")

    oh = cfg.operator_hold
    if oh.enabled:
        if oh.max_duration_seconds is None or not 15 <= oh.max_duration_seconds <= 300:
            errors.append("operator_hold.max_duration_seconds must be set within 15..300 when enabled")
        if not oh.allowed_verdicts:
            errors.append("operator_hold.allowed_verdicts must list CLEAN and/or SUSPICIOUS when enabled")
        bad = [v.value for v in oh.allowed_verdicts if v not in (Verdict.CLEAN, Verdict.SUSPICIOUS)]
        if bad:
            errors.append(f"operator_hold.allowed_verdicts may only contain CLEAN/SUSPICIOUS, got {bad}")
    elif oh.max_duration_seconds is not None and not 15 <= oh.max_duration_seconds <= 300:
        errors.append("operator_hold.max_duration_seconds must be within 15..300")

    if cfg.pin.hash_algorithm != "bcrypt":
        errors.append("pin.hash_algorithm must be 'bcrypt'")
    if cfg.pin.max_length < cfg.pin.min_length:
        errors.append("pin.max_length must be >= pin.min_length")
    if not cfg.pin.hash_ref:
        errors.append("pin.hash_ref is required")

    if cfg.quarantine.export_enabled and not cfg.quarantine.quarantine_on_threat:
        errors.append("quarantine.export_enabled requires quarantine.quarantine_on_threat")

    if cfg.logging.level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        errors.append("logging.level must be DEBUG/INFO/WARNING/ERROR/CRITICAL")
    if cfg.logging.syslog.enabled and not cfg.logging.syslog.host:
        errors.append("logging.syslog.enabled requires logging.syslog.host")

    for name in ("block_extensions", "allow_extensions"):
        for ext in getattr(cfg.scan, name):
            if not re.fullmatch(r"\.?[^\s/\\.][^\s/\\]*", ext):
                errors.append(f"scan.{name}: invalid extension {ext!r}")
    overlap = {e.lower().lstrip(".") for e in cfg.scan.block_extensions} & {
        e.lower().lstrip(".") for e in cfg.scan.allow_extensions}
    if overlap:
        errors.append(f"scan: extensions both blocked and allowed: {sorted(overlap)}")

    if errors:
        raise ConfigError("invalid configuration:\n  - " + "\n  - ".join(errors))


def load_config_from_dict(data: Any) -> Config:
    cfg = _build_dataclass(Config, data, "")
    validate(cfg)
    return cfg


def load_config_from_string(text: str) -> Config:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error: {exc}") from None
    return load_config_from_dict(data)


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> Config:
    p = Path(path)
    try:
        with p.open("rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read config {p}: {exc.strerror}") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"config {p} exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"config {p} is not valid UTF-8") from None
    return load_config_from_string(text)
