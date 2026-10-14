# USB Scan Station

An autonomous malware-scanning kiosk for USB storage, built on a Raspberry Pi 5 with
Raspberry Pi OS Lite (Debian 13 trixie).
- **Use:** a person inserts a stick, the station scans it read-only and shows a verdict on
  the touchscreen. Nobody types anything.
- **Verdicts:** CLEAN, THREAT, SUSPICIOUS, INCOMPLETE, ERROR, REJECTED, NOT_READY.
- **Fail closed:** anything that was not inspected is never reported as CLEAN.

Engines:
- ClamAV, mandatory, via file-descriptor passing;
- optional YARA, in an isolated worker with signed rule bundles;
- optional VirusTotal hash reputation (advisory only, hash lookups only).

USBGuard admits mass-storage-only devices. A small root broker mounts them read-only. A
durable events service keeps a tamper-evident audit chain and forwards to SIEM and alert
channels. A read-only admin web (OIDC and/or local accounts, both with MFA) shows status and
history.

## Documentation

| For | Document |
|---|---|
| People using the station | [docs/operator-guide.md](docs/operator-guide.md) · [Deutsch](docs/operator-guide.de.md) |
| Installing a station | [docs/installation.md](docs/installation.md), [docs/hardware-wiring.md](docs/hardware-wiring.md) (LED pins) |
| Operating a station (IT) | [docs/admin-guide.md](docs/admin-guide.md) |
| Provisioning reference | [docs/deployment.md](docs/deployment.md) |
| Hardening status | [docs/hardening-checklist.md](docs/hardening-checklist.md) |
| Secrets, escrow, rebuild | [docs/secret-recovery.md](docs/secret-recovery.md) |
| Acceptance testing | [tests/acceptance/MANUAL_TEST_CHECKLIST.md](tests/acceptance/MANUAL_TEST_CHECKLIST.md), [docs/acceptance-notes.md](docs/acceptance-notes.md) |
| Why it is built this way | [docs/architecture-decisions.md](docs/architecture-decisions.md) |
| Requirements (authoritative) | [docs/USB-Scan-Station-Spec-v1.5.md](docs/USB-Scan-Station-Spec-v1.5.md) |
| Component design notes | `docs/*-design-notes.md` |

## Layout

| Path | Contents |
|---|---|
| `src/broker/` | privileged device broker (root, allowlisted RPC) |
| `src/orchestrator/` | scan daemon and state machine (`usbscan`) |
| `src/yara_worker/` | isolated YARA worker and bundle installer |
| `src/gui/` | PySide6 kiosk (pure display client), translations in `translations/` |
| `src/led/` | status LED (lgpio) |
| `src/events/` | audit store, SIEM forwarding, alerts |
| `src/web/` | read-only admin web (Flask + htmx) |
| `src/shared/` | config, models, IPC, auth, secret references |
| `src/host/` | firewall/sysctl/sshd rendering |
| `config/`, `systemd/`, `scripts/` | configuration template, units, provisioning and hardening scripts |
| `tests/unit/`, `tests/integration/`, `tests/acceptance/` | CI tests (no hardware), clamd/loopback tests (root), on-device acceptance |

## Development

```
python3 -m venv --system-site-packages .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests/unit/                 # no hardware required
sudo .venv/bin/python -m pytest tests/integration/     # clamd + loop devices
```

`src/shared/` runs on any laptop. Hardware-specific parts use stubs in tests.

## License

MIT (LICENSE.md). Third-party components keep their own licenses (PySide6 under LGPLv3,
ClamAV under GPLv2, …); see docs/architecture-decisions.md ADR-002.
