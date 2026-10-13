"""Entry point: python -m src.events [--config PATH] [--verify | --acknowledge-tamper NOTE]

Runs as user usbscan-events. ``--verify`` checks the database and chain and exits 0/1.
``--acknowledge-tamper`` (administrator, after investigation) re-anchors verification at the
current head and records who acknowledged it; the damaged history stays for forensics.
"""
from __future__ import annotations

import argparse
import asyncio
import grp
import logging
import os
import pwd
import signal
import sys

from src.shared.config import ConfigError, load_config
from src.shared.logging_setup import setup_logging
from src.shared.sd_notify import notify, watchdog_loop
from src.shared.secret_refs import SecretError, resolve_secret

from .service import EventsService, acknowledge_tamper, check_integrity, open_store
from .store import StoreCorrupt, StoreError

log = logging.getLogger("usb-scan.events")


def _uids(names: tuple[str, ...]) -> frozenset[int]:
    out = set()
    for name in names:
        try:
            out.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            log.warning("events socket user %s does not exist", name)
    return frozenset(out)


async def run(cfg, key: bytes) -> None:
    try:
        gid = grp.getgrnam(cfg.events.socket_group).gr_gid
    except KeyError:
        gid = None
    service = EventsService(cfg, key, resolve_secret, writer_uids=_uids(cfg.events.writer_users),
                            reader_uids=_uids(cfg.events.reader_users), group_gid=gid)
    await service.start()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    watchdog = asyncio.create_task(watchdog_loop())
    notify("READY=1")
    log.info("events service ready")
    await stop.wait()
    notify("STOPPING=1")
    watchdog.cancel()
    await service.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-events")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", action="store_true", help="verify database and audit chain, then exit")
    mode.add_argument("--acknowledge-tamper", metavar="NOTE", help="re-anchor after an investigated tamper alarm")
    opts = parser.parse_args(argv)
    try:
        cfg = load_config(opts.config)
        key = resolve_secret(cfg.events.hmac_key_ref)
    except (ConfigError, SecretError) as exc:
        print(f"usb-scan-events: startup failed: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.logging.level, station_id=cfg.station.station_id, console=True)
    try:
        if opts.verify or opts.acknowledge_tamper:
            store = open_store(cfg)
            try:
                if opts.acknowledge_tamper:
                    actor = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
                    seq = acknowledge_tamper(store, actor, opts.acknowledge_tamper)
                    print(f"verification re-anchored at seq {seq}")
                    return 0
                res = check_integrity(store, key)
                print(f"{'OK' if res.ok else 'FAILED'}: checked={res.checked} reason={res.reason or '-'} "
                      f"first_bad_seq={res.first_bad_seq}")
                return 0 if res.ok else 1
            finally:
                store.close()
        asyncio.run(run(cfg, key))
    except StoreCorrupt as exc:
        log.critical("event database failed its integrity check: %s", exc)
        return 1
    except StoreError as exc:
        log.critical("event store unusable: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
