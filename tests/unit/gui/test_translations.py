"""Shipped GUI translations (owner decision 1.5.8: English source + German)."""
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

import pytest

from src.gui.app import Translator, available_languages
from src.gui.main_window import MainWindow
from src.shared.models import EventType, ScanEvent

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
TRANSLATIONS = os.path.join(REPO, "translations")
SHIPPED = ["de"]
PLACEHOLDER = re.compile(r"\{\w+\}")


def messages(locale):
    tree = ET.parse(os.path.join(TRANSLATIONS, f"usbscan_{locale}.ts"))
    return [(m.find("source").text, m.find("translation")) for m in tree.iter("message")]


@pytest.mark.parametrize("locale", SHIPPED)
def test_every_string_translated_with_the_same_placeholders(locale):
    msgs = messages(locale)
    assert msgs
    for source, tr in msgs:
        assert tr.get("type") is None and tr.text, f"untranslated: {source!r}"
        assert sorted(PLACEHOLDER.findall(source)) == sorted(PLACEHOLDER.findall(tr.text)), source


@pytest.mark.parametrize("locale", SHIPPED)
def test_ts_file_covers_every_gui_string(locale, tmp_path):
    lupdate = shutil.which("pyside6-lupdate")
    if lupdate is None:
        pytest.skip("pyside6-lupdate not installed")
    fresh = tmp_path / "fresh.ts"
    gui = os.path.join(REPO, "src", "gui")
    files = [os.path.join(d, f) for d, _, fs in os.walk(gui) for f in fs if f.endswith(".py")]
    subprocess.run([lupdate, *files, "-ts", str(fresh)], check=True, capture_output=True)
    current = {s for s, _ in messages(locale)}
    wanted = {m.find("source").text for m in ET.parse(fresh).iter("message")}
    assert wanted <= current, f"run scripts/update-translations.sh {locale}: missing {sorted(wanted - current)}"


@pytest.mark.parametrize("locale", SHIPPED)
def test_compiled_qm_shipped_and_offered(locale):
    assert os.path.exists(os.path.join(TRANSLATIONS, f"usbscan_{locale}.qm"))
    assert locale in [code for code, _ in available_languages(TRANSLATIONS)]


def test_german_texts_shown(qapp, cfg, qtbot):
    tr = Translator(qapp, TRANSLATIONS)
    assert tr.set_language("de")
    try:
        w = MainWindow(cfg, lambda event: None)
        qtbot.addWidget(w)
        w.show()
        w.handle_event(ScanEvent(EventType.IPC_CONNECTED, None))
        w.handle_event(ScanEvent(EventType.STATE_CHANGED, None, {"state": "IDLE"}))
        from tests.unit.gui.test_gui import all_text
        assert "USB-Gerät einstecken" in all_text(w)
    finally:
        tr.set_language("en")
