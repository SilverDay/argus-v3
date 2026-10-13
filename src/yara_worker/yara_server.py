"""YARA worker supervisor: socket server that runs one disposable child per session.

* Socket 0660 yarascan:<socket_group>; only the configured client uid is served (SO_PEERCRED).
* No verified ruleset -> the connection gets {"ok": false, "error": "ruleset_unavailable"}.
* Otherwise the connection fd is handed to a fresh child (src.yara_worker.child) together
  with the compiled rules on stdin; the supervisor keeps no copy of the connection.
* The supervisor SIGKILLs the child when ``global_budget_seconds`` is exhausted — the
  orchestrator runs as a different user and cannot do this itself (plan Phase 4 watchdog).
* At most ``max_sessions`` children run at once.
* Connections are accepted as raw sockets (``loop.sock_accept``), never wrapped in an
  asyncio stream: a stream transport starts reading at once and could swallow request
  bytes that belong to the child.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import os
import socket
import sys

from src.shared import yara_protocol as yp
from src.shared.config import YaraConfig
from src.shared.ipc import PeerCredentials, peer_credentials, remove_stale_socket

from .rules import RuleStore

log = logging.getLogger(__name__)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class YaraServer:
    def __init__(self, cfg: YaraConfig, store: RuleStore, *, client_uid: int, socket_gid: int | None = None,
                 max_sessions: int = 2, python: str = sys.executable) -> None:
        self.cfg = cfg
        self.store = store
        self._client_uid = client_uid
        self._socket_gid = socket_gid
        self._max_sessions = max_sessions
        self._python = python
        self._children: set[asyncio.subprocess.Process] = set()
        self._compiled: bytes | None = None
        self._compiled_for: str | None = None
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task | None = None
        self._tasks: set[asyncio.Task] = set()
        self.budget_kills = 0

    # --- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        remove_stale_socket(self.cfg.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            sock.bind(self.cfg.socket_path)
        finally:
            os.umask(old)
        if self._socket_gid is not None:
            os.chown(self.cfg.socket_path, -1, self._socket_gid)
        os.chmod(self.cfg.socket_path, 0o660)
        sock.listen(8)
        sock.setblocking(False)
        self._listener = sock
        self._accept_task = asyncio.create_task(self._accept_loop())

    async def _accept_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            conn, _ = await loop.sock_accept(self._listener)
            task = asyncio.create_task(self._handle(conn))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def close(self) -> None:
        if self._accept_task is not None:
            self._accept_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._accept_task
            self._accept_task = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        for proc in list(self._children):
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, 5)
        with contextlib.suppress(OSError):
            remove_stale_socket(self.cfg.socket_path)

    def reload(self) -> bool:
        ok = self.store.reload()
        if ok:
            log.info("yara ruleset %s active", self.store.active.version_id)
        else:
            log.error("yara ruleset reload failed, keeping previous: %s", self.store.last_error)
        return ok

    def _compiled_rules(self) -> bytes:
        active = self.store.active
        if self._compiled is None or self._compiled_for != active.version_id:
            buf = io.BytesIO()
            active.rules.save(file=buf)
            self._compiled, self._compiled_for = buf.getvalue(), active.version_id
        return self._compiled

    # --- sessions -----------------------------------------------------------

    @staticmethod
    async def _refuse(conn: socket.socket, error: str, detail: str = "") -> None:
        reply = {"ok": False, "error": error}
        if detail:
            reply["detail"] = detail[:200]
        with contextlib.suppress(ConnectionError, OSError):
            await asyncio.get_running_loop().sock_sendall(conn, yp.encode(reply))
        conn.close()

    async def _handle(self, conn: socket.socket) -> None:
        try:
            creds: PeerCredentials = peer_credentials(conn)
        except OSError:
            conn.close()
            return
        if creds.uid != self._client_uid:
            log.warning("yara: refused connection from uid=%d pid=%d", creds.uid, creds.pid)
            conn.close()
            return
        if self.store.active is None:
            await self._refuse(conn, "ruleset_unavailable", self.store.last_error or "")
            return
        if len(self._children) >= self._max_sessions:
            await self._refuse(conn, "busy")
            return

        conn.setblocking(True)          # the child uses blocking I/O on this descriptor
        conn_fd = conn.fileno()
        try:
            proc = await asyncio.create_subprocess_exec(
                self._python, "-m", "src.yara_worker.child",
                "--fd", str(conn_fd),
                "--rules-version", self.store.active.version_id,
                "--timeout", str(self.cfg.per_file_timeout_seconds),
                "--max-bytes", str(self.cfg.max_file_size_mb * 1024 * 1024),
                "--memory-mb", str(self.cfg.memory_limit_mb),
                "--cpu-seconds", str(self.cfg.global_budget_seconds),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE, pass_fds=(conn_fd,), cwd=PROJECT_ROOT,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            )
        finally:
            conn.close()            # the child owns the connection now
        self._children.add(proc)
        try:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                proc.stdin.write(self._compiled_rules())
                await proc.stdin.drain()
            proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), self.cfg.global_budget_seconds)
            except asyncio.TimeoutError:
                self.budget_kills += 1
                log.warning("yara: session budget %ss exhausted, killing child pid=%d",
                            self.cfg.global_budget_seconds, proc.pid)
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
            if proc.returncode not in (0, None) and proc.returncode != -9:
                err = (await proc.stderr.read(2000)).decode("utf-8", "replace").strip().splitlines()
                log.error("yara child exited with %s: %s", proc.returncode, err[-1] if err else "")
        finally:
            self._children.discard(proc)
