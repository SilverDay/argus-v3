"""Manage local admin web accounts (spec §10.2; owner decision 1.5.10). Root only, on the station.

    python -m src.web.accounts_admin [--config CFG] list
    python -m src.web.accounts_admin add USER --role viewer|operator|admin
    python -m src.web.accounts_admin passwd USER
    python -m src.web.accounts_admin role USER ROLE
    python -m src.web.accounts_admin totp USER             # (re-)enrol the authenticator
    python -m src.web.accounts_admin disable|enable|remove USER

* Passphrases are typed twice without echo. They are never accepted as an argument and
  never printed. Policy: ``auth.web.local.min_passphrase_length`` characters up to 72 bytes
  (bcrypt), not containing the username, not a single repeated character. Stored as bcrypt
  cost 12.
* TOTP enrolment: a new 160-bit seed is shown once as an otpauth:// URI plus base32 text, for
  the authenticator app. It is saved only after the user proves it with a current code.
* Every change is first written to the audit chain (``web_auth``/``account_change``, as the
  admin web account). If the audit log is unavailable, nothing is changed (fail closed).
* The accounts file is replaced atomically (0640 root:<web group>). The web process picks up
  the change without a restart. Any change other than add/enable also ends the user's open
  local sessions (the web additionally re-checks status and role on every request).
"""
from __future__ import annotations

import argparse
import getpass
import grp
import os
import pwd
import sys
import tempfile

import bcrypt

from src.shared.config import ConfigError, load_config
from src.shared.models import EventType, ScanEvent

from . import totp
from .events_client import EventsClient
from .local_accounts import (
    MAX_PASSPHRASE_BYTES, MIN_COST, ROLES, _USER, Account, AccountsError, format_accounts, parse_accounts,
)


class AdminError(Exception):
    pass


def passphrase_problem(passphrase: str, username: str, min_length: int) -> str | None:
    if len(passphrase) < min_length:
        return f"at least {min_length} characters required"
    if len(passphrase.encode("utf-8")) > MAX_PASSPHRASE_BYTES:
        return f"at most {MAX_PASSPHRASE_BYTES} bytes (bcrypt limit)"
    if username and username in passphrase.lower():
        return "must not contain the username"
    if len(set(passphrase)) == 1:
        return "must not repeat a single character"
    return None


def hash_passphrase(passphrase: str) -> bytes:
    return bcrypt.hashpw(passphrase.encode("utf-8"), bcrypt.gensalt(MIN_COST))


def read_accounts(path: str) -> dict[str, Account]:
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_accounts(fh.read())
    except FileNotFoundError:
        return {}
    except (AccountsError, UnicodeDecodeError) as exc:
        raise AdminError(f"{path} is invalid ({exc}); fix or restore it before changing accounts") from None


def write_accounts(path: str, accounts: dict[str, Account], group: str) -> None:
    gid = grp.getgrnam(group).gr_gid
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".web-accounts.", dir=directory)
    try:
        os.fchmod(fd, 0o640)
        os.fchown(fd, 0, gid)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(format_accounts(accounts))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def audit_as(user: str, socket_path: str, event: ScanEvent) -> bool:
    """Append ``event`` with the identity of ``user`` (the admin web account, which holds the
    events service's web-audit role). Runs in a forked child that drops to that account."""
    pw = pwd.getpwnam(user)
    pid = os.fork()
    if pid == 0:                                               # child
        code = 1
        try:
            os.setgroups(os.getgrouplist(user, pw.pw_gid))
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            EventsClient(socket_path).audit(event)
            code = 0
        except BaseException:
            pass
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def end_sessions(state_dir: str, user: str) -> int:
    """Delete the user's local-account web sessions (after a credential, role or status change)."""
    import sqlite3
    path = os.path.join(state_dir, "web.db")
    if not os.path.exists(path):
        return 0
    db = sqlite3.connect(path, timeout=10)
    try:
        with db:
            return db.execute("DELETE FROM sessions WHERE user=? AND method LIKE 'local%'", (user,)).rowcount
    except sqlite3.OperationalError:          # no sessions table yet
        return 0
    finally:
        db.close()


def ask_passphrase(username: str, min_length: int) -> str:
    for _ in range(3):
        first = getpass.getpass(f"New passphrase for {username}: ")
        problem = passphrase_problem(first, username, min_length)
        if problem:
            print(f"rejected: {problem}", file=sys.stderr)
            continue
        if getpass.getpass("Repeat: ") != first:
            print("rejected: the entries differ", file=sys.stderr)
            continue
        return first
    raise AdminError("no acceptable passphrase entered")


def enrol_totp(username: str, issuer: str) -> str:
    seed = totp.new_seed()
    print("\nAdd this account to the authenticator app (scan or paste the URI, or type the key):")
    print(f"  URI: {totp.provisioning_uri(seed, username, issuer)}")
    print(f"  Key: {' '.join(seed[i:i + 4] for i in range(0, len(seed), 4))}")
    print("This key is shown only now. Clear the terminal afterwards.\n")
    for _ in range(3):
        code = input("Current 6-digit code from the app: ").strip()
        if totp.verify(seed, code) is not None:
            return seed
        print("code does not match (check the phone's clock)", file=sys.stderr)
    raise AdminError("authenticator not confirmed; nothing changed")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="usb-scan-web-accounts", description="Manage local admin web accounts.")
    p.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    p.add_argument("--group", default="usbscan-web", help="group that may read the accounts file (admin web)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    add = sub.add_parser("add")
    add.add_argument("user")
    add.add_argument("--role", required=True, choices=ROLES)
    for name in ("passwd", "totp", "disable", "enable", "remove"):
        sub.add_parser(name).add_argument("user")
    rl = sub.add_parser("role")
    rl.add_argument("user")
    rl.add_argument("role", choices=ROLES)
    a = p.parse_args(argv)

    try:
        if os.geteuid() != 0:
            raise AdminError("must run as root")
        cfg = load_config(a.config)
        lc = cfg.auth.web.local
        if not lc.accounts_ref.startswith("file:"):
            raise AdminError("auth.web.local.accounts_ref must be a file: reference")
        path = lc.accounts_ref.partition(":")[2]
        accounts = read_accounts(path)

        if a.cmd == "list":
            for acct in sorted(accounts.values(), key=lambda x: x.username):
                state = "disabled" if acct.disabled else "active"
                print(f"{acct.username:24} {acct.role:9} {state:9} totp={'yes' if acct.totp_seed else 'no'}")
            if not cfg.auth.web.local_enabled:
                print("note: auth.web.local_enabled is false; local sign-in is off", file=sys.stderr)
            return 0

        user = a.user.strip().lower()
        if not _USER.fullmatch(user):
            raise AdminError("username: lowercase letters, digits, '.', '_' or '-' (max 64)")
        acct = accounts.get(user)
        if a.cmd == "add":
            if acct is not None:
                raise AdminError(f"{user} exists")
            pw_hash = hash_passphrase(ask_passphrase(user, lc.min_passphrase_length))
            seed = enrol_totp(user, f"USB Scan {cfg.station.station_id}") if lc.require_totp else ""
            new = Account(user, a.role, pw_hash, seed)
        elif acct is None:
            raise AdminError(f"{user} does not exist")
        elif a.cmd == "passwd":
            new = Account(user, acct.role, hash_passphrase(ask_passphrase(user, lc.min_passphrase_length)),
                          acct.totp_seed, acct.disabled)
        elif a.cmd == "totp":
            new = Account(user, acct.role, acct.hash, enrol_totp(user, f"USB Scan {cfg.station.station_id}"),
                          acct.disabled)
        elif a.cmd == "role":
            new = Account(user, a.role, acct.hash, acct.totp_seed, acct.disabled)
        elif a.cmd in ("disable", "enable"):
            new = Account(user, acct.role, acct.hash, acct.totp_seed, a.cmd == "disable")
        else:
            new = None                                          # remove

        changed = dict(accounts)
        if new is None:
            del changed[user]
        else:
            changed[user] = new
        actor = os.environ.get("SUDO_USER") or "root"
        detail = {"result": "account_change", "action": a.cmd, "user": user[:128], "actor": actor[:64],
                  "role": new.role if new else acct.role, "method": "cli", "reason": ""}
        web_user = cfg.events.web_audit_users[0] if cfg.events.web_audit_users else "usbscan-web"
        if not audit_as(web_user, cfg.events.socket_path, ScanEvent(EventType.WEB_AUTH, None, detail)):
            raise AdminError("the audit log is unavailable; nothing changed (fail closed)")
        write_accounts(path, changed, a.group)
        ended = end_sessions(cfg.admin_web.state_dir, user) if a.cmd != "add" and a.cmd != "enable" else 0
        print(f"{a.cmd}: {user} done" + (f"; {ended} open session(s) ended" if ended else ""))
        if a.cmd == "add" and not cfg.auth.web.local_enabled:
            print("note: set auth.web.local_enabled: true to allow local sign-in", file=sys.stderr)
        return 0
    except (AdminError, ConfigError, KeyError, OSError) as exc:
        print(f"usb-scan-web-accounts: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\naborted; nothing changed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
