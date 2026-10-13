"""Signed YARA ruleset loading (spec §6.2, §7.3; owner decision: minisign).

Bundle layout (yara.rules_path):
    manifest.json          {"format": 1, "version": <int>, "files": {"<name>.yar": "<sha256>", ...}}
    manifest.json.minisig  minisign signature over manifest.json (yara.ruleset_signature_path)
    <name>.yar ...         rule files listed in the manifest

Activation steps — all must pass, otherwise the previous ruleset stays active:
  1. read manifest bytes once; verify *those bytes* with ``minisign -V`` against the
     trust anchor (copied to a private temp file, so the file cannot change in between);
  2. reject versions lower than the last accepted one (rollback guard, persisted);
  3. read each listed file once, check its SHA-256, compile from the in-memory source
     with ``includes=False`` (no rule may pull in other files);
  4. record the accepted version.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

import yara

from src.shared.config import YaraConfig

MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_RULE_FILE_BYTES = 16 * 1024 * 1024
MAX_RULE_FILES = 512
_RULE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(?:yar|yara)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RulesetError(Exception):
    """The bundle cannot be activated. The message is safe to log and report."""


@dataclass(frozen=True)
class Ruleset:
    rules: yara.Rules
    version: int
    digest: str            # SHA-256 of the signed manifest bytes
    rule_files: int

    @property
    def version_id(self) -> str:
        return f"{self.version}:{self.digest[:16]}"


def _read_limited(path: str, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise RulesetError(f"{os.path.basename(path)} exceeds {limit} bytes")
    return data


def verify_signature(cfg: YaraConfig, manifest: bytes, timeout: float = 30.0,
                     signature_path: str | None = None) -> None:
    """Verify ``manifest`` bytes with minisign; raise RulesetError on any failure."""
    try:
        signature = _read_limited(signature_path or cfg.ruleset_signature_path, 64 * 1024)
    except OSError as exc:
        raise RulesetError(f"signature unreadable: {exc.strerror}") from None
    with tempfile.TemporaryDirectory(prefix="yara-verify-") as tmp:
        m = os.path.join(tmp, MANIFEST_NAME)
        s = m + ".minisig"
        for path, data in ((m, manifest), (s, signature)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        try:
            result = subprocess.run(
                [cfg.minisign_path, "-V", "-q", "-p", cfg.trust_anchor_path, "-m", m, "-x", s],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RulesetError(f"minisign could not run: {type(exc).__name__}") from None
    if result.returncode != 0:
        raise RulesetError("ruleset signature verification failed")


def parse_manifest(data: bytes) -> tuple[int, dict[str, str]]:
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise RulesetError("manifest is not valid JSON") from None
    if not isinstance(obj, dict) or obj.get("format") != 1:
        raise RulesetError("unsupported manifest format")
    version, files = obj.get("version"), obj.get("files")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RulesetError("manifest version must be a positive integer")
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_RULE_FILES:
        raise RulesetError("manifest must list 1..512 rule files")
    for name, digest in files.items():
        if not isinstance(name, str) or not _RULE_FILE.match(name):
            raise RulesetError("manifest lists an invalid rule file name")
        if not isinstance(digest, str) or not _SHA256.match(digest):
            raise RulesetError(f"manifest has an invalid sha256 for {name}")
    return version, files


def _state_file(cfg: YaraConfig) -> str:
    return os.path.join(cfg.state_dir, "accepted_version")


def accepted_version(cfg: YaraConfig) -> int:
    try:
        return int(_read_limited(_state_file(cfg), 64).decode().strip())
    except (OSError, ValueError, RulesetError):
        return 0


def _store_accepted_version(cfg: YaraConfig, version: int) -> None:
    os.makedirs(cfg.state_dir, mode=0o700, exist_ok=True)
    tmp = _state_file(cfg) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"{version}\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, _state_file(cfg))


def verify_bundle(cfg: YaraConfig, rules_dir: str, signature_path: str) -> Ruleset:
    """Steps 1 and 3 for the bundle in ``rules_dir`` (signature, hashes, compile); no state is
    read or written. Used by the worker and by the bundle installer before activation."""
    try:
        manifest = _read_limited(os.path.join(rules_dir, MANIFEST_NAME), MAX_MANIFEST_BYTES)
    except OSError as exc:
        raise RulesetError(f"manifest unreadable: {exc.strerror}") from None
    verify_signature(cfg, manifest, signature_path=signature_path)
    version, files = parse_manifest(manifest)
    sources: dict[str, str] = {}
    for name, digest in sorted(files.items()):
        try:
            data = _read_limited(os.path.join(rules_dir, name), MAX_RULE_FILE_BYTES)
        except OSError as exc:
            raise RulesetError(f"rule file {name} unreadable: {exc.strerror}") from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise RulesetError(f"rule file {name} does not match the signed manifest")
        try:
            sources[name.rsplit(".", 1)[0]] = data.decode("utf-8")
        except UnicodeDecodeError:
            raise RulesetError(f"rule file {name} is not UTF-8") from None
    try:
        rules = yara.compile(sources=sources, includes=False)
    except yara.Error as exc:
        raise RulesetError(f"ruleset does not compile: {str(exc)[:200]}") from None
    return Ruleset(rules, version, hashlib.sha256(manifest).hexdigest(), len(sources))


def load_ruleset(cfg: YaraConfig) -> Ruleset:
    ruleset = verify_bundle(cfg, cfg.rules_path, cfg.ruleset_signature_path)
    floor = accepted_version(cfg)
    if ruleset.version < floor:
        raise RulesetError(f"ruleset version {ruleset.version} is older than accepted version {floor}")
    if ruleset.version > floor:
        _store_accepted_version(cfg, ruleset.version)
    return ruleset


class RuleStore:
    """Holds the active ruleset; a failed reload keeps the last known-good one."""

    def __init__(self, cfg: YaraConfig) -> None:
        self.cfg = cfg
        self.active: Ruleset | None = None
        self.last_error: str | None = None

    def reload(self) -> bool:
        try:
            self.active = load_ruleset(self.cfg)
            self.last_error = None
            return True
        except RulesetError as exc:
            self.last_error = str(exc)
            return False
