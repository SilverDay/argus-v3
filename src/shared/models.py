"""Core data models shared by all services (spec §3.3, §3.4, §3.5, §3.7, §4.2).

Every dataclass serialises to plain JSON types via ``to_dict()`` and can be
rebuilt with ``from_dict()``. ``from_dict()`` treats its input as untrusted:
unknown enum values or wrong types raise ``ModelError``.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.5"

# Payload keys whose values must never appear in reprs or logs.
SENSITIVE_PAYLOAD_KEYS = frozenset({"pin", "password", "passphrase", "secret", "token", "api_key"})


class ModelError(ValueError):
    """Raised when serialised data does not match the model schema."""


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    THREAT = "THREAT"
    SUSPICIOUS = "SUSPICIOUS"
    INCOMPLETE = "INCOMPLETE"
    ERROR = "ERROR"
    REJECTED = "REJECTED"
    NOT_READY = "NOT_READY"


class ScanStage(str, Enum):
    AUTHORIZING = "AUTHORIZING"
    ENUMERATING = "ENUMERATING"
    MOUNTING = "MOUNTING"
    SCANNING = "SCANNING"
    EVALUATING = "EVALUATING"
    EJECTING = "EJECTING"


class GUIState(str, Enum):
    STARTING = "STARTING"
    NOT_READY = "NOT_READY"
    IDLE = "IDLE"
    VALIDATING = "VALIDATING"
    MOUNTING = "MOUNTING"
    SCANNING = "SCANNING"
    EVALUATING = "EVALUATING"
    OPERATOR_HOLD = "OPERATOR_HOLD"
    EJECTING = "EJECTING"
    RESULT = "RESULT"
    EJECT_FAILED = "EJECT_FAILED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class DeviceLifecycle(str, Enum):
    PRESENT = "present"
    MOUNTED = "mounted"
    UNMOUNTED = "unmounted"
    POWER_OFF_REQUESTED = "power_off_requested"
    SAFE_TO_REMOVE = "safe_to_remove"
    REMOVED = "removed"
    EJECT_FAILED = "eject_failed"


class SkipReason(str, Enum):
    TOO_LARGE = "too_large"
    ENCRYPTED = "encrypted"
    UNREADABLE = "unreadable"
    UNSUPPORTED = "unsupported"
    RECURSION_LIMIT = "recursion_limit"
    SCAN_LIMIT = "scan_limit"
    TIMEOUT = "timeout"
    POLICY_EXCLUSION = "policy_exclusion"
    TOO_LARGE_FOR_ENGINE = "too_large_for_engine"
    ENGINE_ERROR = "engine_error"


class FileOutcome(str, Enum):
    """Per-file engine outcome (spec §3.2 step 5)."""
    SCANNED = "scanned"
    DETECTED = "detected"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ENCRYPTED = "encrypted"
    UNSUPPORTED = "unsupported"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EventType(str, Enum):
    """Known ScanEvent types. Unknown types are rejected by ScanEvent.from_dict."""
    # Orchestrator -> clients
    STATE_CHANGED = "state_changed"
    SCAN_STARTED = "scan_started"
    SCAN_INTERRUPTED = "scan_interrupted"
    SCAN_PROGRESS = "scan_progress"
    ENGINE_STAGE = "engine_stage"
    DETECTION = "detection"
    VERDICT = "verdict"
    LIFECYCLE_CHANGED = "lifecycle_changed"
    DEVICE_REJECTED = "device_rejected"
    DEVICE_REMOVED = "device_removed"
    HEALTH = "health"
    HEALTH_GATE_FAILED = "health_gate_failed"
    OPERATOR_HOLD_ENTERED = "operator_hold_entered"
    OPERATOR_HOLD_EXITED = "operator_hold_exited"
    AUTH_RESULT = "auth_result"
    LOCKOUT_STATE = "lockout_state"
    QUARANTINE_RESULT = "quarantine_result"      # no paths in the payload (protected sidecar only)
    ALERT_DELIVERY = "alert_delivery"
    AUDIT_CHECKPOINT = "audit_checkpoint"        # HMAC over the chain head (events service)
    TAMPER_DETECTED = "tamper_detected"          # audit chain verification failed
    TAMPER_ACKNOWLEDGED = "tamper_acknowledged"  # administrator re-anchored after investigation
    # Clients -> orchestrator (restricted operator RPC)
    OPERATOR_PIN_SUBMIT = "operator_pin_submit"
    OPERATOR_ACK = "operator_ack"
    LOCKOUT_QUERY = "lockout_query"
    # Connection bookkeeping (local only, never sent on the wire by the server)
    IPC_CONNECTED = "ipc_connected"
    IPC_DISCONNECTED = "ipc_disconnected"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(ts: datetime) -> str:
    if ts.tzinfo is None:
        raise ModelError("timestamps must be timezone-aware")
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise ModelError(f"{name}: expected ISO 8601 string")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelError(f"{name}: invalid timestamp") from exc
    if ts.tzinfo is None:
        raise ModelError(f"{name}: timestamp must include a UTC offset")
    return ts.astimezone(timezone.utc)


def _req(data: Any, key: str, typ: type | tuple[type, ...]) -> Any:
    if not isinstance(data, dict):
        raise ModelError("expected an object")
    if key not in data:
        raise ModelError(f"missing field: {key}")
    value = data[key]
    # bool is a subclass of int; never accept it where an int is expected.
    if isinstance(value, bool) and bool not in (typ if isinstance(typ, tuple) else (typ,)):
        raise ModelError(f"{key}: unexpected type bool")
    if not isinstance(value, typ):
        raise ModelError(f"{key}: unexpected type {type(value).__name__}")
    return value


def _enum(enum_cls: type[Enum], value: Any, name: str) -> Any:
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise ModelError(f"{name}: unknown value") from exc


def _non_negative(name: str, value: int) -> None:
    if value < 0:
        raise ModelError(f"{name}: must be >= 0")


_COUNTER_FIELDS = (
    "partitions_discovered", "partitions_scanned", "partitions_excluded", "partitions_out_of_scope",
    "files_discovered", "files_scanned", "files_skipped", "files_failed",
    "files_uninspectable", "bytes_enumerated", "bytes_read",
)


@dataclass
class CoverageMetrics:
    partitions_discovered: int = 0
    partitions_scanned: int = 0
    partitions_excluded: int = 0
    partitions_out_of_scope: int = 0     # excluded by explicit deployment policy (FR-USB-04)
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    files_uninspectable: int = 0
    bytes_enumerated: int = 0
    bytes_read: int = 0
    clamav_complete: bool = False
    yara_complete: bool | None = None   # None = engine not enabled
    vt_complete: bool | None = None     # None = engine not enabled
    skip_reasons: dict[SkipReason, int] = field(default_factory=dict)

    def _count_reason(self, reason: SkipReason) -> None:
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def record_skip(self, reason: SkipReason) -> None:
        """Not scanned by decision or limit (policy exclusion, size, engine limits)."""
        self.files_skipped += 1
        self._count_reason(reason)

    def record_uninspectable(self, reason: SkipReason) -> None:
        """Content exists but could not be read or decoded (unreadable, encrypted)."""
        self.files_uninspectable += 1
        self._count_reason(reason)

    def record_failed(self, reason: SkipReason) -> None:
        """Engine failed on the file (timeout, engine error)."""
        self.files_failed += 1
        self._count_reason(reason)

    def has_uninspected_content(self) -> bool:
        """True if anything other than an explicit policy exclusion was not inspected."""
        if self.files_failed or self.files_uninspectable:
            return True
        return any(n for r, n in self.skip_reasons.items() if r is not SkipReason.POLICY_EXCLUSION)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {name: getattr(self, name) for name in _COUNTER_FIELDS}
        d["clamav_complete"] = self.clamav_complete
        d["yara_complete"] = self.yara_complete
        d["vt_complete"] = self.vt_complete
        d["skip_reasons"] = {r.value: n for r, n in sorted(self.skip_reasons.items(), key=lambda i: i[0].value)}
        return d

    @classmethod
    def from_dict(cls, data: Any) -> CoverageMetrics:
        kwargs: dict[str, Any] = {}
        for name in _COUNTER_FIELDS:
            kwargs[name] = _req(data, name, int)
            _non_negative(name, kwargs[name])
        kwargs["clamav_complete"] = _req(data, "clamav_complete", bool)
        for name in ("yara_complete", "vt_complete"):
            kwargs[name] = _req(data, name, (bool, type(None)))
        raw = _req(data, "skip_reasons", dict)
        reasons: dict[SkipReason, int] = {}
        for key, count in raw.items():
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ModelError("skip_reasons: counts must be non-negative integers")
            reasons[_enum(SkipReason, key, "skip_reasons")] = count
        kwargs["skip_reasons"] = reasons
        return cls(**kwargs)


@dataclass
class ThreatEntry:
    file_path: str
    engine: str
    signature_name: str
    sha256: str
    severity: Severity = Severity.HIGH

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "engine": self.engine,
            "signature_name": self.signature_name,
            "sha256": self.sha256,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, data: Any) -> ThreatEntry:
        return cls(
            file_path=_req(data, "file_path", str),
            engine=_req(data, "engine", str),
            signature_name=_req(data, "signature_name", str),
            sha256=_req(data, "sha256", str),
            severity=_enum(Severity, _req(data, "severity", str), "severity"),
        )


@dataclass
class ScanMetadata:
    scan_id: str
    station_id: str
    device_sysfs_id: str
    session_start_utc: datetime
    session_end_utc: datetime | None = None
    firmware_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "station_id": self.station_id,
            "device_sysfs_id": self.device_sysfs_id,
            "session_start_utc": format_utc(self.session_start_utc),
            "session_end_utc": format_utc(self.session_end_utc) if self.session_end_utc else None,
            "firmware_version": self.firmware_version,
        }

    @classmethod
    def from_dict(cls, data: Any) -> ScanMetadata:
        end = _req(data, "session_end_utc", (str, type(None)))
        return cls(
            scan_id=_req(data, "scan_id", str),
            station_id=_req(data, "station_id", str),
            device_sysfs_id=_req(data, "device_sysfs_id", str),
            session_start_utc=parse_utc(_req(data, "session_start_utc", str), "session_start_utc"),
            session_end_utc=parse_utc(end, "session_end_utc") if end is not None else None,
            firmware_version=_req(data, "firmware_version", (str, type(None))),
        )


@dataclass
class ScanResult:
    metadata: ScanMetadata
    verdict: Verdict
    coverage: CoverageMetrics
    threats: list[ThreatEntry] = field(default_factory=list)
    policy_violations: list[str] = field(default_factory=list)
    engine_errors: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "metadata": self.metadata.to_dict(),
            "verdict": self.verdict.value,
            "coverage": self.coverage.to_dict(),
            "threats": [t.to_dict() for t in self.threats],
            "policy_violations": list(self.policy_violations),
            "engine_errors": list(self.engine_errors),
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_dict(cls, data: Any) -> ScanResult:
        def str_list(key: str) -> list[str]:
            items = _req(data, key, list)
            if not all(isinstance(i, str) for i in items):
                raise ModelError(f"{key}: expected list of strings")
            return items

        return cls(
            schema_version=_req(data, "schema_version", str),
            metadata=ScanMetadata.from_dict(_req(data, "metadata", dict)),
            verdict=_enum(Verdict, _req(data, "verdict", str), "verdict"),
            coverage=CoverageMetrics.from_dict(_req(data, "coverage", dict)),
            threats=[ThreatEntry.from_dict(t) for t in _req(data, "threats", list)],
            policy_violations=str_list("policy_violations"),
            engine_errors=str_list("engine_errors"),
            reason_codes=str_list("reason_codes"),
        )


def redact_payload(payload: Any) -> Any:
    """Return a copy of ``payload`` with sensitive keys replaced (recursive)."""
    if isinstance(payload, dict):
        return {
            k: ("***" if isinstance(k, str) and k.lower() in SENSITIVE_PAYLOAD_KEYS else redact_payload(v))
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [redact_payload(v) for v in payload]
    return payload


@dataclass
class ScanEvent:
    event_type: EventType
    scan_id: str | None
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp_utc: datetime = field(default_factory=utc_now)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = SCHEMA_VERSION

    def __repr__(self) -> str:
        # Never expose sensitive payload values (e.g. a submitted PIN) via repr/logging.
        return (
            f"ScanEvent(event_type={self.event_type.value!r}, scan_id={self.scan_id!r}, "
            f"event_id={self.event_id!r}, payload={redact_payload(self.payload)!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "scan_id": self.scan_id,
            "timestamp_utc": format_utc(self.timestamp_utc),
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: Any) -> ScanEvent:
        schema = _req(data, "schema_version", str)
        if schema.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            raise ModelError("schema_version: incompatible major version")
        event_id = _req(data, "event_id", str)
        try:
            uuid.UUID(event_id)
        except ValueError as exc:
            raise ModelError("event_id: not a UUID") from exc
        return cls(
            schema_version=schema,
            event_id=event_id,
            event_type=_enum(EventType, _req(data, "event_type", str), "event_type"),
            scan_id=_req(data, "scan_id", (str, type(None))),
            timestamp_utc=parse_utc(_req(data, "timestamp_utc", str), "timestamp_utc"),
            payload=_req(data, "payload", dict),
        )
