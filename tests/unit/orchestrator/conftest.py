from __future__ import annotations

import pytest

from src.orchestrator.event_sink import JsonlEventSink
from src.orchestrator.orchestrator import Orchestrator
from src.shared.config import load_config_from_dict
from tests.unit.orchestrator.fakes import FakeBroker, FakeClamd, make_sysfs


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    (data / "db").mkdir(parents=True)
    temp = tmp_path / "temp"
    temp.write_text("45000\n")
    part1 = tmp_path / "media" / "part1"
    part1.mkdir(parents=True)
    (part1 / "a.txt").write_text("hello")
    (part1 / "b.txt").write_text("world")
    sysfs = tmp_path / "sys"
    make_sysfs(str(sysfs))
    return {"tmp": tmp_path, "data": data, "temp": temp, "part1": part1, "sysfs": str(sysfs)}


def make_cfg(env, **overrides):
    raw = {
        "station": {"data_dir": str(env["data"])},
        "events": {"db_path": str(env["data"] / "db" / "events.db")},
        "device": {"insertion_debounce_ms": 0},
        "orchestrator": {"storage_wait_seconds": 1, "removed_result_display_seconds": 0,
                         "state_dir": str(env["data"] / "orchestrator"),
                         "result_display_seconds": 10, "thermal_zone_path": str(env["temp"])},
        "health": {"min_free_disk_mb": 1},
        "scan": {"progress_interval_ms": 100},
    }
    for section, values in overrides.items():
        raw.setdefault(section, {}).update(values)
    return load_config_from_dict(raw)


@pytest.fixture
def harness(env):
    def build(cfg_overrides=None, broker=None, clamd=None, auth=None, **modules):
        cfg = make_cfg(env, **(cfg_overrides or {}))
        broker = broker or FakeBroker({"part1": str(env["part1"])})
        clamd = clamd or FakeClamd()
        events = []
        orch_ref: list = []
        sink = JsonlEventSink(str(env["data"] / "db"))
        orch = Orchestrator(cfg, broker, clamd, sink, events.append, auth=auth,
                            sysfs_root=env["sysfs"], gui_uids=frozenset({4242}),
                            **{k: (v(cfg, orch_ref) if callable(v) else v) for k, v in modules.items()})
        orch_ref.append(orch)
        return orch, broker, clamd, events, sink
    return build
