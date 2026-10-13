"""WSGI entry point: gunicorn 'src.web.wsgi:app' (user usbscan-web).

Config path from USB_SCAN_CONFIG (default /etc/usb-scan/scan_station.yaml). Refuses to
start when the admin web is not enabled in the configuration.
"""
from __future__ import annotations

import os

from src.shared.config import load_config
from src.shared.logging_setup import setup_logging

from .app import create_app

_cfg = load_config(os.environ.get("USB_SCAN_CONFIG", "/etc/usb-scan/scan_station.yaml"))
if not _cfg.admin_web.enabled:
    raise SystemExit("admin_web.enabled is false: refusing to start the admin web UI")
setup_logging(_cfg.logging.level, station_id=_cfg.station.station_id, console=True)
app = create_app(_cfg)
