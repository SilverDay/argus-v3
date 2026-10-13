"""Set the local operator PIN (spec §10.1). Run as root on the device:

    /opt/usb-scan/.venv/bin/python -m src.shared.pin_admin [--config PATH]

* The PIN is read twice without echo (getpass), or as two lines from stdin when stdin is
  not a terminal (scripted provisioning). It is never accepted as a command-line argument
  (shell history, process list) and never printed or logged.
* Policy from ``pin.*``: digits only, length bounds, no single repeated digit, no sequential
  run, deny list. bcrypt with ``pin.bcrypt_cost`` (>= 12).
* The hash goes to the ``file:`` target of ``pin.hash_ref`` (never to scan_station.yaml):
  written atomically, mode 0640, owner root, group = the orchestrator group (``usbscan``).
There is no admin PIN: remote administration uses named OIDC/local accounts (spec §10.2).
"""
from __future__ import annotations

import argparse
import getpass
import grp
import os
import sys

from src.shared.auth import AuthError, hash_pin, load_deny_list, validate_pin_format
from src.shared.config import ConfigError, PinConfig, load_config

DEFAULT_GROUP = "usbscan"


class PinSetupError(Exception):
    pass


def hash_target(cfg: PinConfig) -> str:
    scheme, _, target = cfg.hash_ref.partition(":")
    if scheme != "file":
        raise PinSetupError("pin.hash_ref must be a file: reference for this tool")
    return target


def read_twice(stream=None) -> tuple[str, str]:
    stream = stream or sys.stdin
    if stream.isatty():
        return getpass.getpass("New operator code: "), getpass.getpass("Repeat operator code: ")
    first, second = stream.readline(), stream.readline()
    return first.rstrip("\n"), second.rstrip("\n")


def write_hash(path: str, hashed: str, gid: int | None) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o711, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, hashed.encode("ascii") + b"\n")
        os.fsync(fd)
        if gid is not None:
            os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def set_pin(cfg: PinConfig, first: str, second: str, *, gid: int | None) -> str:
    if first != second:
        raise PinSetupError("the two entries do not match")
    deny = load_deny_list(cfg.deny_list_path)
    problem = validate_pin_format(first, min_length=cfg.min_length, max_length=cfg.max_length, deny_list=deny)
    if problem:
        raise PinSetupError(problem)
    hashed = hash_pin(first, cost=cfg.bcrypt_cost, min_length=cfg.min_length, max_length=cfg.max_length,
                      deny_list=deny)
    path = hash_target(cfg)
    write_hash(path, hashed, gid)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-set-pin", description="Set the local operator PIN.")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    parser.add_argument("--group", default=DEFAULT_GROUP, help="group allowed to read the hash (orchestrator)")
    opts = parser.parse_args(argv)
    if os.geteuid() != 0:
        sys.stderr.write("usb-scan-set-pin: must run as root\n")
        return 2
    try:
        cfg = load_config(opts.config).pin
        gid = grp.getgrnam(opts.group).gr_gid
        first, second = read_twice()
        path = set_pin(cfg, first, second, gid=gid)
    except KeyError:
        sys.stderr.write(f"usb-scan-set-pin: group {opts.group} does not exist\n")
        return 2
    except (ConfigError, PinSetupError, AuthError, OSError) as exc:
        sys.stderr.write(f"usb-scan-set-pin: not changed: {exc}\n")
        return 1
    sys.stdout.write(f"Operator code updated ({path}). Restart usb-scan-orchestrator to apply.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
