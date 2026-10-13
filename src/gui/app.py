"""Application setup: kiosk window, translations, IPC wiring (spec §4.1)."""
from __future__ import annotations

import os
import re

from PySide6.QtCore import QLocale, QTranslator, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from src.shared.config import Config

from .ipc_worker import IpcWorker
from .main_window import WINDOW_TITLE, MainWindow

_QM = re.compile(r"^usbscan_([a-z]{2}(?:_[A-Z]{2})?)\.qm$")


def available_languages(directory: str) -> list[tuple[str, str]]:
    """English (source strings) plus every usbscan_<locale>.qm found in ``directory``."""
    langs = [("en", "English")]
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        names = []
    for name in names:
        m = _QM.match(name)
        if m and m.group(1) != "en":
            code = m.group(1)
            langs.append((code, QLocale(code).nativeLanguageName() or code))
    return langs


class Translator:
    def __init__(self, app: QApplication, directory: str) -> None:
        self.app = app
        self.directory = directory
        self._current: QTranslator | None = None

    def set_language(self, code: str) -> bool:
        if self._current is not None:
            self.app.removeTranslator(self._current)
            self._current = None
        if code == "en":
            return True
        tr = QTranslator(self.app)
        if tr.load(os.path.join(self.directory, f"usbscan_{code}.qm")):
            self.app.installTranslator(tr)
            self._current = tr
            return True
        return False


def build(cfg: Config, app: QApplication) -> tuple[MainWindow, IpcWorker]:
    app.setApplicationName(WINDOW_TITLE)
    QGuiApplication.setDesktopFileName(WINDOW_TITLE)        # Wayland app_id / X11 WM_CLASS
    translator = Translator(app, cfg.gui.translations_dir)
    translator.set_language(cfg.gui.language)
    worker = IpcWorker(cfg.orchestrator.state_socket)
    window = MainWindow(cfg, worker.send, available_languages(cfg.gui.translations_dir),
                        on_language=translator.set_language)
    worker.event_received.connect(window.handle_event)       # queued: worker thread -> GUI thread
    window.setWindowFlag(Qt.FramelessWindowHint, True)
    if cfg.gui.hide_cursor:
        app.setOverrideCursor(Qt.BlankCursor)
    return window, worker
