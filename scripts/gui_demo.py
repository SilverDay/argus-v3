#!/usr/bin/env python3
"""Development tool: a mock orchestrator state socket that cycles through all GUI states.

    python3 scripts/gui_demo.py /tmp/state.sock &
    python3 -m src.gui --config dev.yaml --windowed      # dev.yaml: orchestrator.state_socket=/tmp/state.sock

Only the current user may connect (SO_PEERCRED). Not used in production.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.shared.ipc import INBOUND_OPERATOR_TYPES, IPCServer  # noqa: E402
from src.shared.models import EventType, ScanEvent  # noqa: E402

COV = {"files_scanned": 1240, "files_discovered": 1243, "partitions_scanned": 1, "partitions_discovered": 1,
       "files_skipped": 2, "files_failed": 0, "files_uninspectable": 1}

SEQUENCE = [
    (EventType.STATE_CHANGED, {"state": "STARTING"}),
    (EventType.STATE_CHANGED, {"state": "NOT_READY", "failures": ["signatures_stale"]}),
    (EventType.STATE_CHANGED, {"state": "IDLE"}),
    (EventType.STATE_CHANGED, {"state": "VALIDATING"}),
    (EventType.STATE_CHANGED, {"state": "MOUNTING"}),
    (EventType.STATE_CHANGED, {"state": "SCANNING"}),
    (EventType.SCAN_PROGRESS, {"files_scanned": 512, "files_discovered": 1243, "bytes_read": 734003200, "elapsed_s": 41}),
    (EventType.STATE_CHANGED, {"state": "EVALUATING"}),
    (EventType.VERDICT, {"verdict": "SUSPICIOUS", "coverage": COV, "reason_codes": [],
                         "threats": [{"engine": "yara", "signature": "hunting.odd_macro", "severity": "medium"}]}),
    (EventType.OPERATOR_HOLD_ENTERED, {"max_seconds": 10}),
    (EventType.STATE_CHANGED, {"state": "OPERATOR_HOLD", "remaining_s": 10}),
    (EventType.OPERATOR_HOLD_EXITED, {"reason": "timeout"}),
    (EventType.STATE_CHANGED, {"state": "EJECTING"}),
    (EventType.STATE_CHANGED, {"state": "RESULT", "verdict": "SUSPICIOUS", "safe_to_remove": True}),
    (EventType.STATE_CHANGED, {"state": "EJECT_FAILED", "safe_to_remove": False}),
    (EventType.STATE_CHANGED, {"state": "REJECTED", "reason": "hid_interface"}),
    (EventType.STATE_CHANGED, {"state": "ERROR", "reason": "broker_unavailable"}),
]


async def main(path: str, delay: float, loops: int) -> None:
    async def on_message(event: ScanEvent, creds) -> None:
        print("operator message:", event)            # repr redacts the PIN

    server = IPCServer(path, allowed_uids={os.getuid()}, inbound_types=INBOUND_OPERATOR_TYPES,
                       on_message=on_message)
    await server.start()
    try:
        for _ in range(loops):
            for etype, payload in SEQUENCE:
                server.broadcast(ScanEvent(etype, "demo", payload))
                await asyncio.sleep(delay)
    finally:
        await server.close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 2.0,
                     int(sys.argv[3]) if len(sys.argv) > 3 else 1_000_000))
