"""Alert dispatch (spec §3.7): webhook, e-mail and syslog (RFC 5424 JSON or CEF) channels.

* Alerts are sent asynchronously after the verdict is committed and never change it.
* Channels are independent: one failing channel does not affect the others
  (``asyncio.gather(..., return_exceptions=True)``); each outcome is recorded as an
  ``alert_delivery`` event without secrets or file names.
* Transport security: webhook https only; SMTP with STARTTLS (mandatory, fails if the
  server does not offer it) or implicit TLS; syslog over TLS (RFC 5425 octet-counting
  framing). Certificates and host names are always verified; ``ca_file`` adds trust.
* Privacy (spec §3.7): file paths and device serials follow ``logging.filename_privacy``.
  ``hash`` uses HMAC-SHA256 with the pseudonymisation key; without a key the values are
  omitted (an unkeyed hash of a file name can be brute-forced).
* Interim delivery is best effort with one webhook retry. The durable, acknowledged
  delivery queue belongs to the events service (Phase 8).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
from collections.abc import Awaitable, Callable
from email.message import EmailMessage
from typing import Any, Protocol

import httpx

from src.shared.config import AlertsConfig, AlertSyslogFormat, Config, FilenamePrivacy, SmtpSecurity
from src.shared.models import EventType, ScanEvent, ScanResult, Verdict, format_utc, utc_now

log = logging.getLogger(__name__)
PRODUCT_VERSION = "0.1.0"
MAX_THREATS = 50
Publish = Callable[[ScanEvent], Awaitable[None]]

_SYSLOG_SEVERITY = {"THREAT": 2, "ERROR": 3, "NOT_READY": 3}          # crit / err; others warning (4)
_CEF_SEVERITY = {"THREAT": 10, "ERROR": 7, "NOT_READY": 7, "SUSPICIOUS": 6, "INCOMPLETE": 5, "REJECTED": 4}
FACILITY_LOCAL0 = 16


def tls_context(ca_file: str = "") -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


# --- privacy -------------------------------------------------------------------------

class Pseudonymizer:
    def __init__(self, mode: FilenamePrivacy, key: bytes | None) -> None:
        self.mode = mode
        self.key = key

    def __call__(self, value: str) -> str | None:
        if not value or self.mode is FilenamePrivacy.OMIT:
            return None
        if self.mode is FilenamePrivacy.PLAIN:
            return value
        if not self.key:
            return None                              # fail closed: no unkeyed hashes
        return "hmac:" + hmac.new(self.key, value.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()[:32]


# --- alert documents ---------------------------------------------------------------------

def verdict_alert(result: ScanResult, device: dict[str, Any], pseudo: Pseudonymizer) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "kind": "verdict",
        "station_id": result.metadata.station_id,
        "scan_id": result.metadata.scan_id,
        "timestamp_utc": format_utc(utc_now()),
        "verdict": result.verdict.value,
        "reason_codes": list(result.reason_codes)[:50],
        "threats": [{"engine": t.engine, "signature": t.signature_name, "severity": t.severity.value,
                     "sha256": t.sha256, "file": pseudo(t.file_path)} for t in result.threats[:MAX_THREATS]],
        "threat_count": len(result.threats),
        "policy_violation_count": len(result.policy_violations),
        "coverage": result.coverage.to_dict(),
        "device": {"vendor_id": str(device.get("vendor_id", "")), "product_id": str(device.get("product_id", "")),
                   "serial": pseudo(str(device.get("serial", "")))},
    }


def health_alert(station_id: str, failures: list[str]) -> dict[str, Any]:
    return {"schema_version": "1", "kind": "not_ready", "station_id": station_id, "scan_id": None,
            "timestamp_utc": format_utc(utc_now()), "verdict": Verdict.NOT_READY.value,
            "reason_codes": list(failures)}


def _summary(alert: dict[str, Any]) -> str:
    sigs = sorted({t["signature"] for t in alert.get("threats", [])})
    text = f"{alert['verdict']} on {alert['station_id']}"
    if sigs:
        text += ": " + ", ".join(sigs[:5])
    return text


# --- syslog formats -------------------------------------------------------------------------

def _cef_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value: str) -> str:
    return (value.replace("\\", "\\\\").replace("=", "\\=").replace("\r\n", "\\n")
            .replace("\n", "\\n").replace("\r", "\\r"))


def format_cef(alert: dict[str, Any]) -> str:
    verdict = alert["verdict"]
    threats = alert.get("threats", [])
    ext = {
        "rt": str(int(utc_now().timestamp() * 1000)),
        "dvchost": alert["station_id"],
        "act": verdict,
        "cnt": str(alert.get("threat_count", 0)),
        "cs1Label": "reasonCodes", "cs1": ",".join(alert.get("reason_codes", []))[:1000],
    }
    if alert.get("scan_id"):
        ext["externalId"] = alert["scan_id"]
    if threats:
        ext["cs2Label"] = "signatures"
        ext["cs2"] = ",".join(sorted({t["signature"] for t in threats}))[:1000]
        if threats[0].get("sha256"):
            ext["fileHash"] = threats[0]["sha256"]
        if threats[0].get("file"):
            ext["fname"] = threats[0]["file"]
    header = "|".join(_cef_header(x) for x in (
        "Argus", "USB Scan Station", PRODUCT_VERSION, f"{alert['kind']}:{verdict}", _summary(alert)[:200],
        str(_CEF_SEVERITY.get(verdict, 5))))
    return f"CEF:0|{header}|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items())


def format_rfc5424(alert: dict[str, Any], body: str) -> bytes:
    pri = FACILITY_LOCAL0 * 8 + _SYSLOG_SEVERITY.get(alert["verdict"], 4)
    host = "".join(c for c in alert["station_id"] if 33 <= ord(c) <= 126)[:255] or "-"
    msg = f"<{pri}>1 {format_utc(utc_now())} {host} usb-scan {os.getpid()} ALERT - {body}"
    return msg.encode("ascii", "replace")


def frame_octet_counting(msg: bytes) -> bytes:
    """RFC 5425 §4.3 / RFC 6587 §3.4.1: MSG-LEN SP SYSLOG-MSG."""
    return str(len(msg)).encode() + b" " + msg


# --- channels -------------------------------------------------------------------------------

class Channel(Protocol):
    name: str

    async def send(self, alert: dict[str, Any]) -> None: ...


class WebhookChannel:
    name = "webhook"

    def __init__(self, cfg, token: str | None, *, transport: httpx.AsyncBaseTransport | None = None,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self.cfg = cfg
        headers = {"Content-Type": "application/json", "User-Agent": f"usb-scan-station/{PRODUCT_VERSION}"}
        if token:
            if any(c in token for c in "\r\n"):
                raise ValueError("invalid webhook token")
            headers["Authorization"] = f"Bearer {token}"
        kwargs: dict[str, Any] = {"transport": transport} if transport is not None else {"verify": tls_context(cfg.ca_file)}
        self._http = httpx.AsyncClient(headers=headers, timeout=float(cfg.timeout_seconds), follow_redirects=False,
                                       **kwargs)
        self.sleep = sleep

    def __repr__(self) -> str:
        return "WebhookChannel(<token hidden>)"

    async def _post(self, body: bytes) -> None:
        resp = await self._http.post(self.cfg.url, content=body)
        if not 200 <= resp.status_code < 300:
            raise RuntimeError(f"http_{resp.status_code}")

    async def send(self, alert: dict[str, Any]) -> None:
        body = json.dumps(alert, ensure_ascii=True, separators=(",", ":")).encode()
        try:
            await self._post(body)
        except (httpx.HTTPError, RuntimeError) as exc:
            log.warning("webhook delivery failed (%s); retrying once", _err(exc))
            await self.sleep(self.cfg.retry_delay_seconds)
            await self._post(body)

    async def aclose(self) -> None:
        await self._http.aclose()


class EmailChannel:
    name = "email"

    def __init__(self, cfg, password: str | None, *, smtp_factory: Callable[..., Any] | None = None,
                 smtp_ssl_factory: Callable[..., Any] | None = None) -> None:
        self.cfg = cfg
        self.password = password
        self.smtp_factory = smtp_factory or smtplib.SMTP
        self.smtp_ssl_factory = smtp_ssl_factory or smtplib.SMTP_SSL

    def __repr__(self) -> str:
        return "EmailChannel(<credentials hidden>)"

    def _message(self, alert: dict[str, Any]) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = f"[USB Scan Station {alert['station_id']}] {alert['verdict']}"
        msg["From"] = self.cfg.from_addr
        msg["To"] = ", ".join(self.cfg.to_addrs)
        msg.set_content(_summary(alert) + "\n\n" + json.dumps(alert, indent=2, ensure_ascii=True) + "\n")
        return msg

    def _send_blocking(self, msg: EmailMessage) -> None:
        ctx = tls_context(self.cfg.ca_file)
        timeout = float(self.cfg.timeout_seconds)
        if self.cfg.security is SmtpSecurity.TLS:
            smtp = self.smtp_ssl_factory(self.cfg.smtp_host, self.cfg.smtp_port, timeout=timeout, context=ctx)
        else:
            smtp = self.smtp_factory(self.cfg.smtp_host, self.cfg.smtp_port, timeout=timeout)
        with smtp:
            if self.cfg.security is SmtpSecurity.STARTTLS:
                smtp.ehlo()
                smtp.starttls(context=ctx)          # raises SMTPNotSupportedError if not offered
                smtp.ehlo()
            if self.cfg.username:
                smtp.login(self.cfg.username, self.password or "")
            smtp.send_message(msg)

    async def send(self, alert: dict[str, Any]) -> None:
        await asyncio.to_thread(self._send_blocking, self._message(alert))


class SyslogChannel:
    name = "syslog"

    def __init__(self, cfg, *, connect: Callable[..., Awaitable[tuple[Any, Any]]] | None = None) -> None:
        self.cfg = cfg
        self.connect = connect or asyncio.open_connection

    def render(self, alert: dict[str, Any]) -> bytes:
        if self.cfg.format is AlertSyslogFormat.CEF:
            body = format_cef(alert)
        else:
            body = json.dumps(alert, ensure_ascii=True, separators=(",", ":"))
        return frame_octet_counting(format_rfc5424(alert, body))

    async def send(self, alert: dict[str, Any]) -> None:
        data = self.render(alert)
        _reader, writer = await asyncio.wait_for(
            self.connect(self.cfg.host, self.cfg.port, ssl=tls_context(self.cfg.ca_file),
                         server_hostname=self.cfg.host), self.cfg.timeout_seconds)
        try:
            writer.write(data)
            await asyncio.wait_for(writer.drain(), self.cfg.timeout_seconds)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), self.cfg.timeout_seconds)
            except (OSError, asyncio.TimeoutError, ssl.SSLError):
                pass


def _err(exc: BaseException) -> str:
    """Error label without message text (messages can echo URLs or server banners)."""
    if isinstance(exc, RuntimeError) and str(exc).startswith("http_"):
        return str(exc)
    return type(exc).__name__


# --- dispatcher --------------------------------------------------------------------------------

class AlertDispatcher:
    def __init__(self, cfg: AlertsConfig, channels: list[Channel], publish: Publish,
                 pseudo: Pseudonymizer, unavailable: list[str] | None = None) -> None:
        self.cfg = cfg
        self.channels = channels
        self.publish = publish
        self.pseudo = pseudo
        self.unavailable = unavailable or []          # configured channels that could not be built
        self._tasks: set[asyncio.Task] = set()

    @property
    def active(self) -> bool:
        return bool(self.channels)

    def wants(self, verdict: Verdict) -> bool:
        return self.active and verdict in self.cfg.verdicts

    def on_result(self, result: ScanResult, device: dict[str, Any]) -> None:
        if self.wants(result.verdict):
            self._spawn(verdict_alert(result, device, self.pseudo))

    def on_not_ready(self, station_id: str, failures: list[str]) -> None:
        if self.active and self.cfg.not_ready:
            self._spawn(health_alert(station_id, failures))

    def _spawn(self, alert: dict[str, Any]) -> None:
        task = asyncio.create_task(self.send(alert), name="alert-dispatch")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def send(self, alert: dict[str, Any]) -> list[tuple[str, str]]:
        outcomes = await asyncio.gather(*(ch.send(alert) for ch in self.channels), return_exceptions=True)
        results = []
        for ch, out in zip(self.channels, outcomes):
            status = "delivered" if out is None else f"failed:{_err(out)}"
            if out is not None:
                log.error("alert channel %s failed: %s", ch.name, _err(out))
            results.append((ch.name, status))
            try:
                await self.publish(ScanEvent(EventType.ALERT_DELIVERY, alert.get("scan_id"), {
                    "channel": ch.name, "status": status, "alert_kind": alert["kind"], "verdict": alert["verdict"]}))
            except Exception as exc:              # recording must not break other channels
                log.error("alert delivery event not recorded: %s", type(exc).__name__)
        return results

    async def drain(self, timeout: float = 30.0) -> None:
        if self._tasks:
            await asyncio.wait(set(self._tasks), timeout=timeout)

    async def aclose(self) -> None:
        await self.drain()
        for ch in self.channels:
            close = getattr(ch, "aclose", None)
            if close is not None:
                await close()


def build_dispatcher(cfg: Config, publish: Publish, resolve: Callable[[str], bytes]) -> AlertDispatcher:
    """Create the configured channels. A channel whose secret cannot be resolved is left out
    and reported (health warning ``alert_channel_unavailable``)."""
    a = cfg.alerts
    channels: list[Channel] = []
    unavailable: list[str] = []

    def secret(ref: str) -> str | None:
        return resolve(ref).decode("utf-8").strip() if ref else None

    if a.webhook.enabled:
        try:
            channels.append(WebhookChannel(a.webhook, secret(a.webhook.token_ref)))
        except Exception as exc:
            log.error("webhook alert channel unavailable: %s", type(exc).__name__)
            unavailable.append("webhook")
    if a.email.enabled:
        try:
            channels.append(EmailChannel(a.email, secret(a.email.password_ref)))
        except Exception as exc:
            log.error("e-mail alert channel unavailable: %s", type(exc).__name__)
            unavailable.append("email")
    if a.syslog.enabled:
        channels.append(SyslogChannel(a.syslog))
    key = None
    if cfg.logging.filename_privacy is FilenamePrivacy.HASH and cfg.logging.pseudonymization_key_ref:
        try:
            key = resolve(cfg.logging.pseudonymization_key_ref)
        except Exception as exc:
            log.error("pseudonymisation key unavailable (%s): file names and serials are omitted",
                      type(exc).__name__)
    return AlertDispatcher(a, channels, publish, Pseudonymizer(cfg.logging.filename_privacy, key), unavailable)
