import json
import re
import smtplib
import ssl
from datetime import datetime, timezone

import httpx
import pytest

from src.events.alerting import (
    EmailChannel, Pseudonymizer, SyslogChannel, WebhookChannel, alert_from_event, build_alert_channels,
    build_pseudonymizer, enabled_alert_channels, format_cef, health_alert, verdict_alert, wants_alert,
)
from src.shared.config import FilenamePrivacy, load_config_from_dict
from src.shared.models import CoverageMetrics, EventType, ScanMetadata, ScanResult, Severity, ThreatEntry, Verdict

TOKEN = "t0ken-secret"


def result(verdict=Verdict.THREAT):
    meta = ScanMetadata("3f2b6c1e-0000-4000-8000-000000000001", "station-001", "1-1",
                        datetime(2026, 10, 13, tzinfo=timezone.utc))
    threats = [ThreatEntry("part1/docs/salary 2026.exe", "clamav", "Win.Test.Evil", "a" * 64, Severity.HIGH)]
    return ScanResult(meta, verdict, CoverageMetrics(files_scanned=3), threats, ["blocked_extension:exe:part1/x.exe"],
                      reason_codes=["malware_detected"])


DEVICE = {"vendor_id": "0781", "product_id": "5583", "serial": "4C530001230904107362"}


def alert_cfg(**sections):
    return load_config_from_dict({"alerts": sections}).alerts


# --- privacy ------------------------------------------------------------------------

def test_pseudonymizer_modes():
    assert Pseudonymizer(FilenamePrivacy.PLAIN, None)("a/b") == "a/b"
    assert Pseudonymizer(FilenamePrivacy.OMIT, b"k")("a/b") is None
    keyed = Pseudonymizer(FilenamePrivacy.HASH, b"k")
    assert keyed("a/b") == keyed("a/b") != Pseudonymizer(FilenamePrivacy.HASH, b"other")("a/b")
    assert re.fullmatch(r"hmac:[0-9a-f]{32}", keyed("a/b"))
    assert Pseudonymizer(FilenamePrivacy.HASH, None)("a/b") is None      # no unkeyed hashes


def test_verdict_alert_applies_privacy():
    alert = verdict_alert(result(), DEVICE, Pseudonymizer(FilenamePrivacy.HASH, b"k"))
    text = json.dumps(alert)
    assert "salary" not in text and DEVICE["serial"] not in text and "x.exe" not in text
    assert alert["verdict"] == "THREAT" and alert["threats"][0]["sha256"] == "a" * 64
    assert alert["threats"][0]["file"].startswith("hmac:") and alert["policy_violation_count"] == 1
    plain = verdict_alert(result(), DEVICE, Pseudonymizer(FilenamePrivacy.PLAIN, None))
    assert plain["threats"][0]["file"] == "part1/docs/salary 2026.exe"


# --- webhook ------------------------------------------------------------------------

async def test_webhook_posts_json_with_bearer():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(204)

    cfg = alert_cfg(webhook={"enabled": True, "url": "https://siem.example.org/hook"}).webhook
    ch = WebhookChannel(cfg, TOKEN, transport=httpx.MockTransport(handler))
    await ch.send({"verdict": "THREAT", "station_id": "s"})
    (req,) = seen
    assert req.method == "POST" and str(req.url) == "https://siem.example.org/hook"
    assert req.headers["authorization"] == f"Bearer {TOKEN}" and json.loads(req.content)["verdict"] == "THREAT"
    assert TOKEN not in repr(ch)
    await ch.aclose()


async def test_webhook_non_2xx_is_a_failure():
    cfg = alert_cfg(webhook={"enabled": True, "url": "https://h.example/x"}).webhook
    ch = WebhookChannel(cfg, None, transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(RuntimeError, match="http_503"):          # the durable queue retries
        await ch.send({})
    await ch.aclose()


def test_webhook_url_must_be_https():
    from src.shared.config import ConfigError
    for url in ("http://h.example/x", "ftp://h/x", "https://user:pw@h.example/x", ""):
        with pytest.raises(ConfigError):
            alert_cfg(webhook={"enabled": True, "url": url})


# --- e-mail -------------------------------------------------------------------------

class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None, context=None, starttls_ok=True):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.log = []
        self.starttls_ok = starttls_ok
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.log.append("quit")

    def ehlo(self):
        self.log.append("ehlo")

    def starttls(self, context=None):
        if not self.starttls_ok:
            raise smtplib.SMTPNotSupportedError("STARTTLS extension not supported by server.")
        assert isinstance(context, ssl.SSLContext) and context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname
        self.log.append("starttls")

    def login(self, user, password):
        self.log.append(("login", user, password))

    def send_message(self, msg):
        self.log.append(("send", msg))


EMAIL = {"enabled": True, "smtp_host": "smtp.example.org", "from_addr": "station@example.org",
         "to_addrs": ["soc@example.org"], "username": "station", "password_ref": "credential:smtp"}


async def test_email_starttls_login_and_send():
    FakeSMTP.instances.clear()
    ch = EmailChannel(alert_cfg(email=EMAIL).email, "pw", smtp_factory=FakeSMTP)
    alert = verdict_alert(result(), DEVICE, Pseudonymizer(FilenamePrivacy.OMIT, None))
    await ch.send(alert)
    (smtp,) = FakeSMTP.instances
    assert (smtp.host, smtp.port) == ("smtp.example.org", 587)
    steps = [s if isinstance(s, str) else s[0] for s in smtp.log]
    assert steps == ["ehlo", "starttls", "ehlo", "login", "send", "quit"]
    msg = smtp.log[4][1]
    assert msg["Subject"] == "[USB Scan Station station-001] THREAT" and msg["To"] == "soc@example.org"
    assert "pw" not in repr(ch)


async def test_email_without_starttls_fails_closed():
    def factory(*a, **kw):
        return FakeSMTP(*a, starttls_ok=False, **kw)
    ch = EmailChannel(alert_cfg(email=EMAIL).email, "pw", smtp_factory=factory)
    with pytest.raises(smtplib.SMTPNotSupportedError):
        await ch.send(health_alert("station-001", ["clamav_unavailable"]))
    assert not any(isinstance(s, tuple) for s in FakeSMTP.instances[-1].log)   # no login, no send


async def test_email_implicit_tls():
    FakeSMTP.instances.clear()
    cfg = alert_cfg(email=EMAIL | {"security": "tls", "smtp_port": 465}).email
    ch = EmailChannel(cfg, "pw", smtp_factory=None, smtp_ssl_factory=FakeSMTP)
    await ch.send(health_alert("station-001", ["x"]))
    (smtp,) = FakeSMTP.instances
    assert smtp.port == 465 and isinstance(smtp.context, ssl.SSLContext) and "starttls" not in smtp.log


def test_email_header_injection_impossible():
    from src.shared.config import ConfigError
    with pytest.raises(ConfigError):
        alert_cfg(email=EMAIL | {"from_addr": "a@example.org\r\nBcc: x@example.org"})
    with pytest.raises(ConfigError):
        alert_cfg(email=EMAIL | {"password_ref": ""})          # username without password


# --- syslog -------------------------------------------------------------------------

SYSLOG = {"enabled": True, "host": "siem.example.org"}


def test_rfc5424_frame():
    ch = SyslogChannel(alert_cfg(syslog=SYSLOG).syslog)
    data = ch.render(verdict_alert(result(), DEVICE, Pseudonymizer(FilenamePrivacy.OMIT, None)))
    length, _, msg = data.partition(b" ")
    assert int(length) == len(msg)                                      # octet counting (RFC 5425)
    m = re.match(rb"<(\d+)>1 (\S+) station-001 usb-scan \d+ ALERT - (\{.*\})$", msg)
    assert m and int(m.group(1)) == 16 * 8 + 2                         # local0.crit for THREAT
    assert m.group(2).endswith(b"Z") and json.loads(m.group(3))["verdict"] == "THREAT"


def test_cef_escaping():
    alert = verdict_alert(result(), DEVICE, Pseudonymizer(FilenamePrivacy.PLAIN, None))
    alert["threats"][0]["signature"] = "Evil|Sig=1\\x"
    alert["reason_codes"] = ["a=b", "line\nbreak"]
    cef = format_cef(alert)
    assert cef.startswith("CEF:0|Argus|USB Scan Station|0.1.0|verdict:THREAT|THREAT on station-001: Evil\\|Sig=1\\\\x|10|")
    ext = cef.split("|", 7)[7]
    assert "cs1=a\\=b,line\\nbreak" in ext and "cs2=Evil|Sig\\=1\\\\x" in ext
    assert "fname=part1/docs/salary 2026.exe" in ext and "\n" not in cef


async def test_syslog_send_uses_tls_with_hostname():
    sent = {}

    class Writer:
        def write(self, data):
            sent["data"] = data

        async def drain(self):
            pass

        def close(self):
            sent["closed"] = True

        async def wait_closed(self):
            pass

    async def connect(host, port, ssl=None, server_hostname=None):
        sent.update(host=host, port=port, ssl=ssl, sni=server_hostname)
        return None, Writer()

    ch = SyslogChannel(alert_cfg(syslog=SYSLOG | {"format": "cef"}).syslog, connect=connect)
    await ch.send(health_alert("station-001", ["clamav_unavailable"]))
    assert sent["port"] == 6514 and sent["sni"] == "siem.example.org" and sent["closed"]
    assert sent["ssl"].verify_mode is ssl.CERT_REQUIRED
    assert b"CEF:0|Argus|USB Scan Station|0.1.0|not_ready:NOT_READY|" in sent["data"]


# --- alerts from stored events ----------------------------------------------------------

def stored(event_type, payload, seq=7):
    from src.events.store import StoredEvent
    return StoredEvent(seq, "e-%d" % seq, event_type.value, "scan-1", "station-001", "t", "t", payload, "p", "h")


def test_alert_from_events():
    pseudo = Pseudonymizer(FilenamePrivacy.HASH, b"k")
    payload = result().to_dict() | {"device": DEVICE}
    a = alert_from_event(stored(EventType.VERDICT, payload), pseudo)
    assert a["verdict"] == "THREAT" and a["event_seq"] == 7 and a["device"]["serial"].startswith("hmac:")
    h = alert_from_event(stored(EventType.HEALTH_GATE_FAILED, {"failures": ["broker_unavailable"]}), pseudo)
    assert h["verdict"] == "NOT_READY" and h["reason_codes"] == ["broker_unavailable"]
    t = alert_from_event(stored(EventType.TAMPER_DETECTED, {"reason": "modified", "first_bad_seq": 3}), pseudo)
    assert t["kind"] == "tamper" and t["reason_codes"] == ["modified@3"]
    with pytest.raises(ValueError):
        alert_from_event(stored(EventType.SCAN_STARTED, {}), pseudo)


def test_alert_selection():
    cfg = alert_cfg(verdicts=["THREAT"], not_ready=False)
    assert wants_alert(cfg, EventType.VERDICT, {"verdict": "THREAT"})
    assert not wants_alert(cfg, EventType.VERDICT, {"verdict": "SUSPICIOUS"})
    assert not wants_alert(cfg, EventType.HEALTH_GATE_FAILED, {})
    assert wants_alert(cfg, EventType.TAMPER_DETECTED, {})          # always alerted
    assert not wants_alert(cfg, EventType.ALERT_DELIVERY, {})
    from src.shared.config import ConfigError
    with pytest.raises(ConfigError):
        alert_cfg(verdicts=["CLEAN"])


def test_build_channels_reports_unresolvable_secrets():
    cfg = load_config_from_dict({"alerts": {
        "webhook": {"enabled": True, "url": "https://h.example/x", "token_ref": "credential:hook"},
        "email": EMAIL, "syslog": SYSLOG}, "logging": {"filename_privacy": "hash",
                                                       "pseudonymization_key_ref": "credential:pseudo"}})

    def resolve(ref):
        if ref == "credential:pseudo":
            return b"key"
        raise OSError("missing")

    channels, unavailable = build_alert_channels(cfg, resolve)
    assert unavailable == ["alert:webhook", "alert:email"] and list(channels) == ["alert:syslog"]
    assert build_pseudonymizer(cfg, resolve).key == b"key"
    assert enabled_alert_channels(cfg.alerts) == ["alert:webhook", "alert:email", "alert:syslog"]
