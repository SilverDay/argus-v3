"""Per-session YARA scanner process: python -m src.yara_worker.child --fd N ...

Started by the supervisor (yara_server) for one orchestrator connection. It is the only
code that runs libyara over hostile content, so it is disposable:
  * RLIMIT_AS (memory), RLIMIT_CPU (session budget backstop), RLIMIT_CORE=0, RLIMIT_NOFILE;
  * compiled rules arrive on stdin (no filesystem access needed);
  * file content arrives as read-only descriptors; the child never opens paths;
  * every file is read into memory with pread (no mmap: a vanished device must
    produce an I/O error, not SIGBUS) and matched with libyara's native timeout.
The supervisor SIGKILLs the child when the session budget is exhausted.
"""
from __future__ import annotations

import argparse
import io
import os
import resource
import socket
import stat
import sys
from typing import Any

import yara

from src.shared import yara_protocol as yp

READ_CHUNK = 4 * 1024 * 1024


def read_fd(fd: int, limit: int) -> bytes:
    chunks, offset = [], 0
    while True:
        chunk = os.pread(fd, min(READ_CHUNK, limit + 1 - offset), offset)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        offset += len(chunk)
        if offset > limit:
            raise OverflowError("file grew beyond the size limit")


def scan_fd(rules: yara.Rules, fd: int, *, timeout: int, max_bytes: int) -> dict[str, Any]:
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return {"status": "error", "reason": "not_regular"}
        if st.st_size > max_bytes:
            return {"status": "too_large"}
        try:
            data = read_fd(fd, max_bytes)
        except OverflowError:
            return {"status": "too_large"}
        except OSError:
            return {"status": "error", "reason": "io_error"}
        try:
            found = rules.match(data=data, timeout=timeout)
        except yara.TimeoutError:
            return {"status": "timeout"}
        except yara.Error as exc:
            return {"status": "error", "reason": str(exc)[:120]}
        if not found:
            return {"status": "clean"}
        return {"status": "match", "matches": [
            {"rule": m.rule[:128], "namespace": m.namespace[:128],
             "tags": [t[:64] for t in list(m.tags)[:16]],
             "severity": yp.severity_from_meta(m.meta)}
            for m in found[:yp.MAX_MATCHES]
        ]}
    finally:
        os.close(fd)


def serve(sock: socket.socket, rules: yara.Rules, version: str, *, timeout: int, max_bytes: int) -> None:
    buf = b""
    pending: list[int] = []
    try:
        while True:
            while b"\n" not in buf:
                data, fds, _flags, _addr = socket.recv_fds(sock, yp.MAX_LINE, 4)
                pending.extend(fds)
                if not data:
                    return
                buf += data
                if len(buf) > yp.MAX_LINE:
                    return
            line, buf = buf.split(b"\n", 1)
            try:
                req = yp.decode(line)
            except yp.YaraProtocolError:
                sock.sendall(yp.encode({"ok": False, "error": "bad_request"}))
                return
            op = req.get("op")
            if op == "hello":
                sock.sendall(yp.encode({"ok": True, "rules_version": version}))
            elif op == "scan":
                rid = req.get("id")
                if not pending or isinstance(rid, bool) or not isinstance(rid, int):
                    sock.sendall(yp.encode({"ok": False, "error": "bad_request"}))
                    return
                result = scan_fd(rules, pending.pop(0), timeout=timeout, max_bytes=max_bytes)
                sock.sendall(yp.encode({"id": rid, **result}))
            elif op == "bye":
                sock.sendall(yp.encode({"ok": True}))
                return
            else:
                sock.sendall(yp.encode({"ok": False, "error": "unknown_op"}))
                return
    finally:
        for fd in pending:
            os.close(fd)


def apply_limits(memory_mb: int, cpu_seconds: int) -> None:
    mem = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="yara-child")
    p.add_argument("--fd", type=int, required=True)
    p.add_argument("--rules-version", required=True)
    p.add_argument("--timeout", type=int, required=True)
    p.add_argument("--max-bytes", type=int, required=True)
    p.add_argument("--memory-mb", type=int, required=True)
    p.add_argument("--cpu-seconds", type=int, required=True)
    a = p.parse_args(argv)
    compiled = sys.stdin.buffer.read()
    apply_limits(a.memory_mb, a.cpu_seconds)
    rules = yara.load(file=io.BytesIO(compiled))
    del compiled
    sock = socket.socket(fileno=a.fd)
    try:
        serve(sock, rules, a.rules_version, timeout=a.timeout, max_bytes=a.max_bytes)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
