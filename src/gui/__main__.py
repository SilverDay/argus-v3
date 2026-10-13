"""Entry point: python -m src.gui [--config PATH] [--windowed]  (runs as user usbscan-gui).

The GUI has no device rights and no scan logic; it only renders orchestrator events.
"""
from __future__ import annotations

import argparse
import signal
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from src.shared.config import ConfigError, load_config
from src.shared.logging_setup import setup_logging

from .app import build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-gui")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    parser.add_argument("--windowed", action="store_true", help="development: no fullscreen")
    opts, qt_args = parser.parse_known_args(argv)
    try:
        cfg = load_config(opts.config)
    except ConfigError as exc:
        print(f"usb-scan-gui: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.logging.level, station_id=cfg.station.station_id, console=True)
    app = QApplication([sys.argv[0], *qt_args])
    signal.signal(signal.SIGTERM, lambda *_: app.quit())
    # Python runs signal handlers only when it gets control; wake it periodically.
    sig_timer = QTimer(interval=500)
    sig_timer.timeout.connect(lambda: None)
    sig_timer.start()
    window, worker = build(cfg, app)
    worker.start()
    if cfg.gui.fullscreen and not opts.windowed:
        window.showFullScreen()
    else:
        window.resize(800, 480)
        window.show()
    try:
        return app.exec()
    finally:
        worker.stop()


if __name__ == "__main__":
    sys.exit(main())
