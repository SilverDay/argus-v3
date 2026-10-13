import json
import re
import smtplib
import ssl
from datetime import datetime, timezone

import httpx
import pytest

from src.orchestrator.alerting import (
    AlertDispatcher, EmailChannel, Pseudonymizer, SyslogChannel, WebhookChannel, build_dispatcher, format_cef,
    health_alert, verdict_alert,
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

async def no_sleep(_):
    return None


async def test_webhook_posts_json_with_bearer():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(204)

    cfg = alert_cfg(webhook={"enabled": True, "url": "https://siem.example.org/hook"}).webhook
    ch = WebhookChannel(cfg, TOKEN, transport=httpx.MockTransport(handler), sleep=no_sleep)
    await ch.send({"verdict": "THREAT", "station_id": "s"})
    (req,) = seen
    assert req.method == "POST" and str(req.url) == "https://siem.example.org/hook"
    assert req.headers["authorization"] == f"Bearer {TOKEN}" and json.loads(req.content)["verdict"] == "THREAT"
    assert TOKEN not in repr(ch)
    await ch.aclose()


async def test_webhook_retries_once_then_fails():
    codes = [500, 200]
    slept = []

    async def sleep(s):
        slept.append(s)

    cfg = alert_cfg(webhook={"enabled": True, "url": "https://h.example/x"}).webhook
    ch = WebhookChannel(cfg, None, transport=httpx.MockTransport(lambda r: httpx.Response(codes.pop(0))), sleep=sleep)
    await ch.send({})
    assert slept == [5] and not codes
    ch2 = WebhookChannel(cfg, None, transport=httpx.MockTransport(lambda r: httpx.Response(503)), sleep=no_sleep)
    with pytest.raises(RuntimeError, match="http_503"):
        await ch2.send({})
    await ch.aclose()
    await ch2.aclose()


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


# --- dispatcher -------------------------------------------------------------------------

class Recorder:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.got = name, fail, []

    async def send(self, alert):
        if self.fail:
            raise ConnectionRefusedError("refused by https://secret-host/?token=abc")
        self.got.append(alert)


async def test_channels_are_independent_and_recorded():
    events = []

    async def publish(ev):
        events.append(ev)

    good, bad = Recorder("webhook"), Recorder("email", fail=True)
    d = AlertDispatcher(alert_cfg(), [bad, good], publish, Pseudonymizer(FilenamePrivacy.OMIT, None))
    d.on_result(result(), DEVICE)
    await d.drain()
    assert len(good.got) == 1
    rec = {e.payload["channel"]: e.payload["status"] for e in events}
    assert events[0].event_type is EventType.ALERT_DELIVERY
    assert rec == {"email": "failed:ConnectionRefusedError", "webhook": "delivered"}
    assert "token" not in json.dumps([e.payload for e in events])      # no error text leaks


async def test_alert_selection():
    good = Recorder("webhook")

    async def publish(ev):
        pass

    d = AlertDispatcher(alert_cfg(verdicts=["THREAT"], not_ready=False), [good], publish,
                        Pseudonymizer(FilenamePrivacy.OMIT, None))
    d.on_result(result(Verdict.CLEAN), DEVICE)
    d.on_result(result(Verdict.SUSPICIOUS), DEVICE)
    d.on_not_ready("station-001", ["x"])
    d.on_result(result(Verdict.THREAT), DEVICE)
    await d.drain()
    assert [a["verdict"] for a in good.got] == ["THREAT"]
    from src.shared.config import ConfigError
    with pytest.raises(ConfigError):
        alert_cfg(verdicts=["CLEAN"])


def test_build_dispatcher_reports_unresolvable_secrets():
    cfg = load_config_from_dict({"alerts": {
        "webhook": {"enabled": True, "url": "https://h.example/x", "token_ref": "credential:hook"},
        "email": EMAIL, "syslog": SYSLOG}, "logging": {"filename_privacy": "hash",
                                                       "pseudonymization_key_ref": "credential:pseudo"}})

    def resolve(ref):
        if ref == "credential:pseudo":
            return b"key"
        raise OSError("missing")

    async def publish(ev):
        pass

    d = build_dispatcher(cfg, publish, resolve)
    assert d.unavailable == ["webhook", "email"] and [c.name for c in d.channels] == ["syslog"]
    assert d.pseudo.key == b"key"
