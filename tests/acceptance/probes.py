"""Probes run by run_acceptance.py in child processes as a service account.

    python -m tests.acceptance.probes connect SOCKET
    python -m tests.acceptance.probes broker-negative --config CFG --internal-sysfs PATH
    python -m tests.acceptance.probes lockout --config CFG query|fail N
    python -m tests.acceptance.probes pin-layout --config CFG N

Each prints one JSON object on the last stdout line. No secret, key or PIN is printed.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import socket
import sys
import uuid
from typing import Any

from src.shared import broker_protocol as bp
from src.shared.config import load_config
from src.shared.ipc import decode_event, encode_event
from src.shared.models import EventType, ScanEvent


def connect(path: str, timeout: float = 3.0) -> dict[str, Any]:
    """Accepted = the server answered anything; refused = connect failed or closed silently.

    The line sent is valid JSON but no valid request for any of the sockets; an authorised
    peer gets an error reply (broker/events) or the state snapshot (state.sock).
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            try:
                s.sendall(b'{"op":"ping"}\n')
                data = s.recv(4096)
            except (TimeoutError, ConnectionError):
                data = b""
    except FileNotFoundError:
        return {"result": "missing", "detail": "socket not found"}
    except PermissionError:
        return {"result": "refused", "detail": "EACCES on connect (file permissions)"}
    except OSError as exc:
        return {"result": "refused", "detail": f"{type(exc).__name__}: {exc.strerror}"}
    if data:
        return {"result": "accepted", "detail": f"{len(data)} bytes answered"}
    return {"result": "refused", "detail": "connection closed without reply (SO_PEERCRED)"}


def _broker_call(path: str, key: bytes, cmd: str, args: dict[str, Any], timeout: float = 30.0) -> str:
    """Return 'ok' or the broker's error code."""
    line, nonce = bp.build_request(key, cmd, args)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(line)
        buf = b""
        while not buf.endswith(b"\n"):
            data, fds, _flags, _addr = socket.recv_fds(s, bp.MAX_MESSAGE_BYTES, 4)
            for fd in fds:
                os.close(fd)
                return "fd_returned"      # a refused request must never hand out a descriptor
            if not data:
                break
            buf += data
    if not buf:
        return "closed"
    try:
        bp.parse_response(key, buf, nonce)
    except bp.ProtocolError as exc:
        return exc.code
    return "ok"


def broker_negative(config: str, internal_sysfs: str) -> dict[str, Any]:
    """AC-S04 as the orchestrator account: only allowlisted commands on USB identifiers."""
    from src.shared.secret_refs import resolve_secret
    cfg = load_config(config)
    return broker_cases(cfg.broker.socket_path, resolve_secret(cfg.broker.hmac_key_ref), internal_sysfs)


def broker_cases(path: str, key: bytes, internal_sysfs: str) -> dict[str, Any]:
    sid = str(uuid.uuid4())
    cases = [
        ("sanity: ping with the real key", "ping", {}, {"ok"}),
        ("unknown command", "exec", {"argv": ["/bin/sh", "-c", "id"]}, {bp.E_UNKNOWN_COMMAND}),
        ("raw /dev path instead of a sysfs identifier", "enumerate",
         {"sysfs_path": "/dev/mmcblk0", "session_id": sid}, {bp.E_INVALID_ARGUMENT, bp.E_NOT_FOUND}),
        ("internal system disk (sysfs)", "enumerate",
         {"sysfs_path": internal_sysfs, "session_id": sid}, {bp.E_INVALID_ARGUMENT, bp.E_NOT_FOUND}),
        ("sysfs traversal", "enumerate",
         {"sysfs_path": "/sys/devices/../../etc", "session_id": sid}, {bp.E_INVALID_ARGUMENT, bp.E_NOT_FOUND}),
        ("mount with an unknown session / path-like partition id", "mount",
         {"session_id": sid, "partition_id": "../../etc"}, {bp.E_INVALID_ARGUMENT, bp.E_NOT_FOUND}),
        ("confined open outside any session", "open",
         {"session_id": sid, "partition_id": "p1", "path_b64": base64.b64encode(b"../../etc/shadow").decode()},
         {bp.E_INVALID_ARGUMENT, bp.E_NOT_FOUND}),
        ("extra argument (host path)", "ping", {"path": "/etc"}, {bp.E_INVALID_ARGUMENT, bp.E_BAD_REQUEST}),
    ]
    out = []
    for name, cmd, args, expected in cases:
        try:
            got = _broker_call(path, key, cmd, args)
        except OSError as exc:
            got = f"oserror:{type(exc).__name__}"
        out.append({"case": name, "expected": sorted(expected), "got": got, "ok": got in expected})
    try:
        got = _broker_call(path, os.urandom(32), "ping", {})
    except OSError as exc:
        got = f"oserror:{type(exc).__name__}"
    # A forged request must not be executed; the reply then fails our MAC check or is an error.
    out.append({"case": "request signed with a wrong key", "expected": ["not ok"], "got": got, "ok": got != "ok"})
    return {"cases": out, "ok": all(c["ok"] for c in out)}


async def _lockout(config: str, action: str, count: int) -> dict[str, Any]:
    from src.shared.auth import load_deny_list, validate_pin_format
    cfg = load_config(config)
    reader, writer = await asyncio.open_unix_connection(cfg.orchestrator.state_socket, limit=1 << 16)

    async def next_of(types: set[EventType], timeout: float = 30.0) -> ScanEvent:
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                raise ConnectionError("state socket closed")
            ev = decode_event(line)
            if ev.event_type in types:
                return ev

    try:
        if action == "query":
            writer.write(encode_event(ScanEvent(EventType.LOCKOUT_QUERY, None)))
            await writer.drain()
            ev = await next_of({EventType.LOCKOUT_STATE})
            return {"locked_out": bool(ev.payload.get("locked_out"))}
        # A PIN that the PIN policy forbids (single repeated digit) can never be the
        # configured PIN when it was set with src.shared.pin_admin.
        wrong = "0" * cfg.pin.min_length
        deny = load_deny_list(cfg.pin.deny_list_path) if cfg.pin.deny_list_path else frozenset()
        if validate_pin_format(wrong, min_length=cfg.pin.min_length, max_length=cfg.pin.max_length,
                               deny_list=deny) is None:
            return {"error": "refusing: probe PIN would be a valid PIN under the policy"}
        results = []
        for _ in range(count):
            writer.write(encode_event(ScanEvent(EventType.OPERATOR_PIN_SUBMIT, None, {"pin": wrong})))
            await writer.drain()
            ev = await next_of({EventType.AUTH_RESULT})
            results.append({"success": ev.payload.get("success"), "locked_out": ev.payload.get("locked_out")})
        return {"attempts": results}
    finally:
        writer.close()


def pin_layouts(config: str, count: int) -> dict[str, Any]:
    """AC-S06 with the production GUI code (offscreen Qt): layout per presentation."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication
    from src.gui.main_window import MainWindow
    app = QApplication.instance() or QApplication([])
    window = MainWindow(load_config(config), lambda event: None)
    window.resize(800, 480)
    window.show()
    window.handle_event(ScanEvent(EventType.IPC_CONNECTED, None))
    layouts = []
    for _ in range(count):
        window.pin.open()
        app.processEvents()
        layouts.append("".join(window.pin.layout_digits()))
        window.pin.cancel()
    window.close()
    complete = all(sorted(x) == list("0123456789") for x in layouts)
    repeats_in_a_row = sum(a == b for a, b in zip(layouts, layouts[1:]))
    return {"presentations": count, "distinct": len(set(layouts)), "repeats_in_a_row": repeats_in_a_row,
            "all_digits_once": complete, "sample": layouts[:3]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="acceptance-probe")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("connect")
    c.add_argument("socket")
    b = sub.add_parser("broker-negative")
    b.add_argument("--config", required=True)
    b.add_argument("--internal-sysfs", required=True)
    lo = sub.add_parser("lockout")
    lo.add_argument("--config", required=True)
    lo.add_argument("action", choices=("query", "fail"))
    lo.add_argument("count", nargs="?", type=int, default=1)
    pl = sub.add_parser("pin-layout")
    pl.add_argument("--config", required=True)
    pl.add_argument("count", type=int)
    a = p.parse_args(argv)
    if a.cmd == "connect":
        out = connect(a.socket)
    elif a.cmd == "broker-negative":
        out = broker_negative(a.config, a.internal_sysfs)
    elif a.cmd == "pin-layout":
        out = pin_layouts(a.config, a.count)
    else:
        try:
            out = asyncio.run(_lockout(a.config, a.action, a.count))
        except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
            out = {"error": f"{type(exc).__name__}: {exc}"}
    out["uid"] = os.getuid()
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
