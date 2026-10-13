"""Host environment seam for the broker.

All filesystem roots and subprocess execution go through ``SysEnv`` so unit tests
can substitute a fake sysfs tree and a recording command runner.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], float], Awaitable[CommandResult]]


async def run_command(argv: Sequence[str], timeout: float) -> CommandResult:
    """Run argv (never via a shell) with a fixed environment and a hard timeout."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=SAFE_ENV,
        close_fds=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return CommandResult(-9, "", "timeout")
    return CommandResult(proc.returncode or 0, out.decode("utf-8", "replace")[:65536],
                         err.decode("utf-8", "replace")[:4096])


@dataclass
class SysEnv:
    sysfs_root: str = "/sys"
    dev_root: str = "/dev"
    proc_root: str = "/proc"
    runner: Runner = field(default=run_command)

    def sys(self, *parts: str) -> str:
        return os.path.join(self.sysfs_root, *parts)

    def dev(self, name: str) -> str:
        return os.path.join(self.dev_root, name)

    def proc(self, *parts: str) -> str:
        return os.path.join(self.proc_root, *parts)
