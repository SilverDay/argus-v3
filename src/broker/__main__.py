"""Entry point: python -m src.broker [--config PATH]

Startup order matters:
  1. load config, set up logging and the audit log;
  2. recover from a previous crash: unmount and remove anything left under the
     mounts directory (no stale session may survive a restart, AC-R03);
  3. bind the socket;
  4. drop capabilities (before any thread exists — capability sets are per thread);
  5. serve; notify systemd READY=1 and ping the watchdog.
SIGTERM/SIGINT unmount every active session before exit.
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

from . import caps, mounts
from .audit import AuditLog
from .broker_server import BrokerServer
from .commands.unmount import unmount_session
from .context import BrokerContext
from .sysenv import SysEnv

log = logging.getLogger("usb-scan.broker")


async def recover_stale_mounts(ctx: BrokerContext) -> None:
    if not os.path.isdir(ctx.mounts_dir):
        return
    stale = mounts.mounts_under(ctx.env, ctx.mounts_dir)
    for entry in sorted(stale, key=lambda m: m.mountpoint.count("/"), reverse=True):
        if entry.mountpoint != ctx.mounts_dir:
            await ctx.env.runner(["umount", entry.mountpoint], mounts.COMMAND_TIMEOUT)
    for name in os.listdir(ctx.mounts_dir):
        if mounts.valid_session_id(name):
            mounts.remove_tree(os.path.join(ctx.mounts_dir, name))
    if stale:
        ctx.audit.write("crash_recovery", stale_mounts=len(stale))


async def serve(server: BrokerServer, ctx: BrokerContext) -> None:
    await server.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    watchdog = asyncio.create_task(watchdog_loop())
    notify("READY=1")
    ctx.audit.write("broker_started", pid=os.getpid())
    log.info("broker ready on %s", server.socket_path)
    await stop.wait()
    notify("STOPPING=1")
    watchdog.cancel()
    await server.close()
    if ctx.sessions.active is not None:
        await unmount_session(ctx, ctx.sessions.active.session_id)
    ctx.audit.write("broker_stopped")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-device-broker")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    parser.add_argument("--no-drop-caps", action="store_true", help="development only")
    opts = parser.parse_args(argv)

    try:
        cfg = load_config(opts.config)
        key = resolve_secret(cfg.broker.hmac_key_ref, env_override="USB_SCAN_HMAC_KEY")
        client_uid = pwd.getpwnam(cfg.broker.client_user).pw_uid
        socket_gid = grp.getgrnam(cfg.broker.socket_group).gr_gid
        read_gid = grp.getgrnam(cfg.broker.read_group).gr_gid
    except (ConfigError, SecretError, KeyError) as exc:
        print(f"usb-scan-device-broker: startup failed: {exc}", file=sys.stderr)
        return 2

    setup_logging(cfg.logging.level, station_id=cfg.station.station_id, console=True)
    ctx = BrokerContext(
        env=SysEnv(),
        audit=AuditLog(cfg.broker.audit_log),
        mounts_dir=cfg.broker.mounts_dir,
        read_gid=read_gid,
        ntfs_driver=cfg.broker.ntfs_driver.value,
        internal_prefixes=cfg.device.internal_device_sysfs_prefixes,
    )
    server = BrokerServer(ctx, socket_path=cfg.broker.socket_path, hmac_key=key,
                          client_uid=client_uid, socket_gid=socket_gid,
                          command_timeout=cfg.broker.command_timeout_seconds,
                          max_clock_skew=cfg.broker.max_clock_skew_seconds)

    mounts.ensure_private_dir(cfg.broker.mounts_dir, read_gid)
    asyncio.run(recover_stale_mounts(ctx))
    server.bind()
    if not opts.no_drop_caps:
        caps.drop_capabilities()
    try:
        asyncio.run(serve(server, ctx))
    finally:
        ctx.audit.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
