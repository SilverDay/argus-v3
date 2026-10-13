"""Secret reference resolution (spec §6.1, §8.3).

scan_station.yaml never contains secret values. Secret fields hold a reference:

    file:/etc/usb-scan/secrets/vt.key   root-controlled file
    credential:vt_key                   systemd credential ($CREDENTIALS_DIRECTORY/vt_key)
    env:USB_SCAN_VT_KEY                 environment variable — DEVELOPMENT ONLY

Environment variables are readable through /proc/<pid>/environ by the same user, so
``env:`` references and ``env_override`` are honoured only when USB_SCAN_DEV=1 is set
(owner decision). Production uses ``file:`` or systemd ``credential:`` references.

File-backed secrets are opened without following symlinks and are refused if
they are not regular files or are accessible by "other".
"""
from __future__ import annotations

import logging
import os
import re
import stat

SCHEMES = ("file", "credential", "env")
_CREDENTIAL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
MAX_SECRET_BYTES = 64 * 1024
DEV_MODE_VAR = "USB_SCAN_DEV"
log = logging.getLogger(__name__)


def dev_mode() -> bool:
    return os.environ.get(DEV_MODE_VAR) == "1"


class SecretError(Exception):
    """Raised when a secret reference is invalid or cannot be resolved safely."""


def validate_ref(ref: str) -> None:
    """Validate reference syntax without touching the filesystem."""
    scheme, sep, target = ref.partition(":")
    if not sep or scheme not in SCHEMES or not target:
        raise SecretError("secret reference must be 'file:<abs path>', 'credential:<name>' or 'env:<NAME>'")
    if scheme == "file" and (not os.path.isabs(target) or ".." in target.split("/")):
        raise SecretError("file: secret reference must be an absolute path without '..'")
    if scheme == "credential" and not _CREDENTIAL_NAME.match(target):
        raise SecretError("credential: secret reference has an invalid name")
    if scheme == "env" and not _ENV_NAME.match(target):
        raise SecretError("env: secret reference has an invalid variable name")


def _read_protected_file(path: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise SecretError(f"cannot open secret file {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecretError(f"secret file {path} is not a regular file")
        if st.st_mode & 0o007:
            raise SecretError(f"secret file {path} is accessible by other users (mode {stat.S_IMODE(st.st_mode):o})")
        if st.st_size > MAX_SECRET_BYTES:
            raise SecretError(f"secret file {path} is too large")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(MAX_SECRET_BYTES + 1)
    finally:
        os.close(fd)


def resolve_secret(ref: str, env_override: str | None = None, *, strip: bool = True) -> bytes:
    """Resolve ``ref`` to the secret bytes.

    ``env_override`` names an environment variable (USB_SCAN_VT_KEY, USB_SCAN_SMTP_PASS,
    USB_SCAN_HMAC_KEY) that takes precedence — in development mode only.
    """
    if env_override and os.environ.get(env_override):
        if dev_mode():
            log.warning("secret taken from environment variable %s (development mode)", env_override)
            return os.environ[env_override].encode()
        log.warning("ignoring %s: environment secrets require %s=1", env_override, DEV_MODE_VAR)
    validate_ref(ref)
    scheme, _, target = ref.partition(":")
    if scheme == "env":
        if not dev_mode():
            raise SecretError(f"env: secret references require {DEV_MODE_VAR}=1 (development only)")
        log.warning("secret taken from environment variable %s (development mode)", target)
        value = os.environ.get(target)
        if not value:
            raise SecretError(f"environment variable {target} is not set")
        data = value.encode()
    elif scheme == "credential":
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if not cred_dir:
            raise SecretError("CREDENTIALS_DIRECTORY is not set (systemd LoadCredential= missing?)")
        data = _read_protected_file(os.path.join(cred_dir, target))
    else:
        data = _read_protected_file(target)
    if strip:
        data = data.strip()
    if not data:
        raise SecretError("secret is empty")
    return data


def secret_path(ref: str) -> str:
    """Filesystem path behind a ``file:`` or ``credential:`` reference, for APIs that can only
    load a secret from a file (e.g. a TLS private key). The file is checked like any other
    secret file (regular, not a symlink, not accessible by "other")."""
    validate_ref(ref)
    scheme, _, target = ref.partition(":")
    if scheme == "env":
        raise SecretError("this secret must be a file: or credential: reference")
    if scheme == "credential":
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if not cred_dir:
            raise SecretError("CREDENTIALS_DIRECTORY is not set (systemd LoadCredential= missing?)")
        target = os.path.join(cred_dir, target)
    _read_protected_file(target)
    return target
