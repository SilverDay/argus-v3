"""Synchronous events.sock client for the admin web (Flask/gunicorn workers are sync).

One short connection per request; the web uid has the events service's "web" role:
queries plus appending its own ``web_auth`` / ``web_access`` audit events.
"""
from __future__ import annotations

import socket
from typing import Any

from src.shared import events_protocol as proto
from src.shared.models import ScanEvent


class EventsUnavailable(Exception):
    pass


class EventsClient:
    def __init__(self, socket_path: str, timeout: float = 5.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, req: dict[str, Any]) -> dict[str, Any]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(proto.encode(req))
                buf = bytearray()
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > proto.MAX_LINE_BYTES:
                        raise EventsUnavailable("response too large")
            resp = proto.decode(bytes(buf))
        except (OSError, proto.EventsProtocolError) as exc:
            raise EventsUnavailable(type(exc).__name__) from None
        if not resp.get("ok"):
            raise EventsUnavailable(str(resp.get("error", "error")))
        return resp

    def query(self, op: str, **args: Any) -> dict[str, Any]:
        return self.request({"op": op, **args})

    def audit(self, event: ScanEvent) -> None:
        """Record a web audit event. Raises EventsUnavailable: callers fail closed."""
        self.request({"op": "append", "event": event.to_dict()})
