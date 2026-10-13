"""Runtime context shared by broker command handlers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.shared.broker_protocol import E_INVALID_ARGUMENT, ProtocolError

from .audit import AuditLog
from .session import SessionRegistry
from .sysenv import SysEnv


@dataclass
class BrokerContext:
    env: SysEnv
    audit: AuditLog
    mounts_dir: str
    read_gid: int
    ntfs_driver: str = "ntfs3"
    internal_prefixes: tuple[str, ...] = ()
    sessions: SessionRegistry = field(default_factory=SessionRegistry)


def require_args(args: dict[str, Any], *names: str) -> None:
    """Exact argument set: missing or extra keys are rejected."""
    if set(args) != set(names):
        raise ProtocolError(E_INVALID_ARGUMENT, f"expected arguments: {', '.join(names) or 'none'}")
