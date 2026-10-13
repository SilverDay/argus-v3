"""Durable local event sink used until the events service exists (Phase 8).

Events are appended as JSON lines and fsync'ed; ``commit_result`` must return only
after the verdict is on disk, because ejection starts afterwards (spec §3.2 step 10).
A small marker file records the scan in progress so a crash or power loss can be
reported as an interrupted scan on the next start (AC-R03).
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from src.shared.models import EventType, ScanEvent, ScanResult


def _write_line(path: str, obj: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o640)
    try:
        os.write(fd, json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


class JsonlEventSink:
    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.events_path = os.path.join(directory, "events.jsonl")
        self.marker_path = os.path.join(directory, "active_scan.json")
        self._lock = asyncio.Lock()

    async def publish(self, event: ScanEvent) -> None:
        if event.event_type is EventType.SCAN_PROGRESS:
            return  # progress is display-only; not an audit event
        async with self._lock:
            await asyncio.to_thread(_write_line, self.events_path, event.to_dict())

    async def commit_result(self, result: ScanResult) -> None:
        event = ScanEvent(EventType.VERDICT, result.metadata.scan_id, result.to_dict())
        async with self._lock:
            await asyncio.to_thread(_write_line, self.events_path, event.to_dict())

    # --- crash recovery marker ----------------------------------------------

    def mark_active(self, scan_id: str, session_id: str) -> None:
        tmp = self.marker_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW, 0o640)
        try:
            os.write(fd, json.dumps({"scan_id": scan_id, "session_id": session_id}).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.marker_path)

    def clear_active(self) -> None:
        try:
            os.unlink(self.marker_path)
        except FileNotFoundError:
            pass

    def take_stale_marker(self) -> dict[str, str] | None:
        try:
            with open(self.marker_path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        self.clear_active()
        if isinstance(data, dict) and isinstance(data.get("scan_id"), str) and isinstance(data.get("session_id"), str):
            return data
        return None
