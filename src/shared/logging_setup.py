"""Structured JSON logging with scan_id context and optional RFC 5424 syslog (spec §3.7).

* ``scan_id_var`` is a ContextVar; when set it is attached to every record.
* Structured fields are passed as ``extra={"fields": {...}}``.
* Sensitive values (PIN, passwords, tokens, keys) are redacted both in structured
  fields and in ``key=value`` / ``key: value`` fragments of the message text.
* Remote syslog uses RFC 5424 with RFC 6587 octet-counting framing over TCP/TLS
  (RFC 5425). TLS always verifies the server certificate and hostname.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import socket
import ssl
import threading
from datetime import datetime, timezone
from typing import Any

from .models import redact_payload

scan_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("scan_id", default=None)

_SENSITIVE_TEXT = re.compile(
    r"(?i)\b(pin|password|passphrase|passwd|secret|token|api[_-]?key)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)


def redact_text(text: str) -> str:
    return _SENSITIVE_TEXT.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)


class ContextFilter(logging.Filter):
    """Attach scan_id/station_id and redact sensitive content in place."""

    def __init__(self, station_id: str | None = None) -> None:
        super().__init__()
        self.station_id = station_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.scan_id = scan_id_var.get()
        record.station_id = self.station_id
        # Freeze the message so later handlers never see unredacted args.
        record.msg = redact_text(record.getMessage())
        record.args = None
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            record.fields = redact_payload(fields)
        return True


def _utc_iso(created: float) -> str:
    return datetime.fromtimestamp(created, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": _utc_iso(record.created),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        for key in ("station_id", "scan_id"):
            value = getattr(record, key, None)
            if value is not None:
                doc[key] = value
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            doc["fields"] = redact_payload(fields)
        if record.exc_info:
            doc["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(doc, ensure_ascii=False, default=str)


_SYSLOG_SEVERITY = {
    logging.CRITICAL: 2, logging.ERROR: 3, logging.WARNING: 4, logging.INFO: 6, logging.DEBUG: 7,
}
_SD_ESCAPE = re.compile(r'(["\\\]])')


def _sd_value(value: Any) -> str:
    return _SD_ESCAPE.sub(r"\\\1", str(value))


class Rfc5424Formatter(logging.Formatter):
    """Format records as complete RFC 5424 messages (including <PRI>)."""

    def __init__(self, app_name: str = "usb-scan", facility: int = 1, enterprise_id: str = "32473") -> None:
        super().__init__()
        self.app_name = app_name[:48]
        self.facility = facility  # 1 = user-level
        self.sd_id = f"usbscan@{enterprise_id}"
        self.hostname = (socket.gethostname() or "-")[:255]

    def format(self, record: logging.LogRecord) -> str:
        severity = _SYSLOG_SEVERITY.get(record.levelno, 6 if record.levelno < logging.WARNING else 3)
        pri = self.facility * 8 + severity
        params = []
        for key in ("station_id", "scan_id"):
            value = getattr(record, key, None)
            if value is not None:
                params.append(f'{key}="{_sd_value(value)}"')
        sd = f"[{self.sd_id} {' '.join(params)}]" if params else "-"
        msgid = re.sub(r"[^\x21-\x7e]", "_", record.name)[:32] or "-"
        body = redact_text(record.getMessage())
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            body += " " + json.dumps(redact_payload(fields), ensure_ascii=False, default=str)
        return f"<{pri}>1 {_utc_iso(record.created)} {self.hostname} {self.app_name} {os.getpid()} {msgid} {sd} {body}"


class Rfc5424SyslogHandler(logging.Handler):
    """Send RFC 5424 messages over UDP, TCP or TLS. Delivery failures never raise."""

    def __init__(self, host: str, port: int, transport: str = "tls", ca_file: str | None = None,
                 timeout: float = 5.0) -> None:
        super().__init__()
        if transport not in ("udp", "tcp", "tls"):
            raise ValueError("transport must be udp, tcp or tls")
        self.host, self.port, self.transport, self.timeout = host, port, transport, timeout
        self._ssl_ctx: ssl.SSLContext | None = None
        if transport == "tls":
            self._ssl_ctx = ssl.create_default_context(cafile=ca_file or None)
            self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._sock: socket.socket | None = None
        self._sock_lock = threading.Lock()
        self.setFormatter(Rfc5424Formatter())

    def _connect(self) -> socket.socket:
        if self.transport == "udp":
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self._ssl_ctx is not None:
            return self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
        return raw

    def emit(self, record: logging.LogRecord) -> None:
        try:
            data = self.format(record).encode("utf-8")
            with self._sock_lock:
                if self._sock is None:
                    self._sock = self._connect()
                if self.transport == "udp":
                    self._sock.sendto(data, (self.host, self.port))
                else:
                    self._sock.sendall(str(len(data)).encode() + b" " + data)
        except Exception:
            with self._sock_lock:
                if self._sock is not None:
                    self._sock.close()
                    self._sock = None
            self.handleError(record)

    def close(self) -> None:
        with self._sock_lock:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
        super().close()


class _PrivateFileHandler(logging.FileHandler):
    """FileHandler that creates the log file with mode 0640."""

    def _open(self):  # noqa: ANN202 - signature defined by logging.FileHandler
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o640)
        return os.fdopen(fd, self.mode, encoding=self.encoding)


def setup_logging(
    level: str = "INFO",
    *,
    file_path: str | None = None,
    station_id: str | None = None,
    syslog: dict[str, Any] | None = None,
    console: bool = False,
) -> logging.Logger:
    """Configure the root logger. Returns it. Safe to call more than once."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(level.upper())
    context = ContextFilter(station_id)
    handlers: list[logging.Handler] = []
    if file_path:
        fh = _PrivateFileHandler(file_path, encoding="utf-8")
        fh.setFormatter(JsonFormatter())
        handlers.append(fh)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(JsonFormatter())
        handlers.append(sh)
    if syslog:
        handlers.append(Rfc5424SyslogHandler(**syslog))
    for handler in handlers:
        handler.addFilter(context)
        root.addHandler(handler)
    return root
