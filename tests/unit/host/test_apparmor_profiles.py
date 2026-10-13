import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
PROFILES = sorted((ROOT / "config" / "system" / "apparmor.d").glob("usb-scan-*"))
UNITS = {p.stem for p in (ROOT / "systemd").glob("usb-scan-*.service")}


def test_one_profile_per_service_and_complain_mode():
    names = {p.name for p in PROFILES}
    assert names == UNITS, (names ^ UNITS)              # every unit has a profile and vice versa
    for p in PROFILES:
        text = p.read_text()
        assert re.search(rf"^profile {re.escape(p.name)} flags=\(complain\) \{{", text, re.M), p.name


@pytest.mark.skipif(shutil.which("apparmor_parser") is None or not pathlib.Path("/etc/apparmor.d/tunables").is_dir(),
                    reason="apparmor_parser / abstractions not installed")
@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_profile_parses(profile):
    res = subprocess.run(["apparmor_parser", "-Q", "-K", "-I", "/etc/apparmor.d", str(profile)],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
