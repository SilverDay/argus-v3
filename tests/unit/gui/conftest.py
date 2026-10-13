import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from src.gui.main_window import MainWindow  # noqa: E402
from src.shared.config import load_config_from_dict  # noqa: E402
from src.shared.models import EventType, ScanEvent  # noqa: E402


@pytest.fixture
def cfg():
    return load_config_from_dict({"gui": {"long_press_ms": 500, "ambient_after_seconds": 30},
                                  "station": {"station_id": "station-test"}})


@pytest.fixture
def sent():
    return []


@pytest.fixture
def window(qtbot, cfg, sent):
    w = MainWindow(cfg, sent.append)
    qtbot.addWidget(w)
    w.resize(800, 480)
    w.show()
    w.handle_event(ScanEvent(EventType.IPC_CONNECTED, None))
    return w


def ev(t, payload=None):
    return ScanEvent(t, None, payload or {})
