"""Broker-side scan session state.

A session binds one orchestrator session_id to one physical USB device identity
(sysfs realpath + busnum/devnum + diskseq). Partition handles (``partN``) are
issued by the broker; filesystem UUIDs are attacker-controlled and are never
used to select a device. Only one session may exist at a time (FR-USB-06).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from src.shared.broker_protocol import E_NOT_FOUND, E_SESSION_CONFLICT, ProtocolError

from .probe import ProbeResult
from .sysfs import BlockInfo, UsbDevice


@dataclass
class Partition:
    partition_id: str
    block: BlockInfo
    probe: ProbeResult
    kernel_fs_type: str = ""      # value for mount -t; empty if not mountable


@dataclass
class Session:
    session_id: str
    device: UsbDevice
    partitions: dict[str, Partition] = field(default_factory=dict)
    mounts: dict[str, str] = field(default_factory=dict)   # partition_id -> mount path
    root_fds: dict[str, int] = field(default_factory=dict) # partition_id -> O_PATH fd of mount root
    opens: int = 0                                          # confined opens served (audited in aggregate)

    def close_root_fds(self) -> None:
        """Must happen before unmounting: any open fd keeps the mount busy."""
        for fd in self.root_fds.values():
            os.close(fd)
        self.root_fds.clear()


class SessionRegistry:
    def __init__(self) -> None:
        self._active: Session | None = None

    @property
    def active(self) -> Session | None:
        return self._active

    def open(self, session: Session) -> None:
        if self._active is not None:
            raise ProtocolError(E_SESSION_CONFLICT, "another device session is active")
        self._active = session

    def get(self, session_id: str) -> Session:
        if self._active is None or self._active.session_id != session_id:
            raise ProtocolError(E_NOT_FOUND, "unknown session")
        return self._active

    def close(self, session_id: str) -> None:
        self.get(session_id)
        self._active = None
