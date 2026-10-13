"""Entry point: python -m src.orchestrator [--config PATH]  (runs as user usbscan)."""
from __future__ import annotations

import argparse
import asyncio
import grp
import logging
import os
import pwd
import signal
import sys

from src.shared.auth import AuthManager, SqliteLockoutStore
from src.shared.config import ConfigError, load_config
from src.shared.ipc import INBOUND_OPERATOR_TYPES, IPCServer
from src.shared.logging_setup import setup_logging
from src.shared.sd_notify import notify, watchdog_loop
from src.shared.secret_refs import SecretError, resolve_secret

from .broker_client import BrokerClient
from .event_client import EventClient
from .orchestrator import Orchestrator
from .quarantine import Quarantine
from .scanner_clamav import ClamdClient
from .usb_monitor import UsbMonitor
from .virustotal import VirusTotalClient

log = logging.getLogger("usb-scan.orchestrator")


def _uids(names: tuple[str, ...]) -> frozenset[int]:
    out = set()
    for name in names:
        try:
            out.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            log.warning("state socket client user %s does not exist", name)
    return frozenset(out)


async def run(cfg, key: bytes) -> None:
    loop = asyncio.get_running_loop()
    broker = BrokerClient(cfg.broker.socket_path, key, timeout=cfg.broker.command_timeout_seconds + 5)
    clamd = ClamdClient(cfg.clamav.socket_path, connect_timeout=cfg.clamav.connect_timeout_seconds)
    sink = EventClient(cfg.events.socket_path, cfg.orchestrator.state_dir,
                       spool_max_bytes=cfg.orchestrator.event_spool_max_mb * 1024 * 1024)
    sink.start()

    auth = None
    try:
        # Authoritative lockout state lives with the orchestrator (owner decision, Phase 8);
        # every attempt is also recorded as an AUTH_RESULT event in the audit chain.
        store = SqliteLockoutStore(os.path.join(cfg.orchestrator.state_dir, "auth.db"))
        auth = AuthManager(store, lambda level: resolve_secret(cfg.pin.hash_ref).decode("ascii"),
                           max_failures=cfg.pin.max_failed_attempts,
                           lockout_seconds=cfg.pin.lockout_minutes * 60, min_cost=cfg.pin.bcrypt_cost)
    except Exception as exc:  # operator overlay unavailable; scanning still works
        log.error("operator authentication unavailable: %s", type(exc).__name__)

    clients = _uids(cfg.orchestrator.client_users)
    gui_uids = _uids((cfg.orchestrator.gui_user,))
    try:
        group_gid = grp.getgrnam(cfg.orchestrator.socket_group).gr_gid
    except KeyError:
        group_gid = None

    vt = None
    if cfg.virustotal.enabled:
        try:
            vt = VirusTotalClient(cfg.virustotal, resolve_secret(cfg.virustotal.api_key_ref).decode("utf-8").strip())
        except Exception as exc:  # health gate reports virustotal_unavailable
            log.error("VirusTotal client unavailable: %s", type(exc).__name__)
    quarantine = Quarantine(cfg.quarantine, cfg.station.station_id) if cfg.quarantine.quarantine_on_threat else None

    orch: Orchestrator | None = None
    server = IPCServer(cfg.orchestrator.state_socket, allowed_uids=clients, group_gid=group_gid,
                       inbound_types=INBOUND_OPERATOR_TYPES,
                       on_message=lambda ev, creds: orch.on_operator_message(ev, creds),
                       on_connect=lambda creds: orch.snapshot(creds))
    orch = Orchestrator(cfg, broker, clamd, sink, server.broadcast, auth=auth, gui_uids=gui_uids,
                        vt=vt, quarantine=quarantine)
    await server.start()

    await orch.recover_interrupted()
    await orch.check_health()

    usb_events: asyncio.Queue = asyncio.Queue()
    monitor = UsbMonitor(loop, usb_events.put_nowait, cfg.device.internal_device_sysfs_prefixes)
    for ev in monitor.start():          # coldplug: devices present at start are scanned afresh
        usb_events.put_nowait(ev)

    async def usb_loop() -> None:
        while True:
            await orch.on_usb_event(await usb_events.get())

    async def health_loop() -> None:
        while True:
            await asyncio.sleep(cfg.orchestrator.health_interval_seconds)
            await orch.check_health()

    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    # Maintenance: `systemctl kill -s SIGUSR1 --kill-whom=main usb-scan-orchestrator`
    # runs the synthetic EICAR scan now (spec §3.8, AC-F05).
    synthetic_request = asyncio.Event()
    loop.add_signal_handler(signal.SIGUSR1, synthetic_request.set)
    tasks = [asyncio.create_task(t) for t in (usb_loop(), health_loop(), watchdog_loop(),
                                              orch.synthetic_loop(synthetic_request))]
    notify("READY=1")
    log.info("orchestrator ready (state %s)", orch.state.value)
    await stop.wait()
    notify("STOPPING=1")
    monitor.stop()
    for t in tasks:
        t.cancel()
    if orch.active and orch.active.task and not orch.active.task.done():
        orch.active.task.cancel()
    await sink.close()
    if vt is not None:
        await vt.aclose()
    await server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usbscand")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    opts = parser.parse_args(argv)
    try:
        cfg = load_config(opts.config)
        key = resolve_secret(cfg.broker.hmac_key_ref, env_override="USB_SCAN_HMAC_KEY")
    except (ConfigError, SecretError) as exc:
        print(f"usbscand: startup failed: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.logging.level, file_path=cfg.logging.file or None,
                  station_id=cfg.station.station_id, console=True)
    asyncio.run(run(cfg, key))
    return 0


if __name__ == "__main__":
    sys.exit(main())
