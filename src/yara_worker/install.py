"""Install a signed YARA ruleset bundle (owner decision, Phase 10: offline install AND
optional HTTPS pull).

    python -m src.yara_worker.install --config CFG BUNDLE.tar.gz     # offline (operator)
    python -m src.yara_worker.install --config CFG --pull            # timer, yara.update_url

Layout below ``dirname(yara.rules_path)``:
    versions/<version>/   manifest.json, manifest.json.minisig, *.yar   (read-only, 0755/0644)
    active -> versions/<version>                                       (= yara.rules_path)

Steps — any failure leaves the active ruleset untouched:
  1. read the archive without extracting it through tarfile: only regular files with plain
     names (manifest.json, manifest.json.minisig, *.yar/*.yara), size and count limits;
  2. write them into a fresh staging directory (O_EXCL, no symlinks);
  3. full verification in staging with the worker's own code (minisign signature over the
     manifest, per-file SHA-256, compile with includes disabled);
  4. refuse a version that is not newer than the active one (rollback guard; the worker
     keeps its own persisted guard as well);
  5. rename staging to versions/<version>, atomically replace the ``active`` symlink, keep the
     newest ``yara.keep_versions`` versions.
The worker picks the new target up by itself (it re-checks the ``active`` link) or on SIGHUP.
The bundle carries its own signature, so a pulled bundle is trusted only after step 3.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import re
import shutil
import ssl
import sys
import tarfile
import tempfile

import httpx

from src.shared.config import ConfigError, YaraConfig, load_config

from .rules import MANIFEST_NAME, MAX_MANIFEST_BYTES, MAX_RULE_FILE_BYTES, MAX_RULE_FILES, RulesetError, verify_bundle

log = logging.getLogger(__name__)
SIGNATURE_NAME = MANIFEST_NAME + ".minisig"
_RULE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(?:yar|yara)$")
MB = 1024 ** 2


class InstallError(Exception):
    pass


def layout(cfg: YaraConfig) -> tuple[str, str]:
    """(versions dir, active link). Requires the signature to live next to the manifest."""
    active = cfg.rules_path.rstrip("/")
    if cfg.ruleset_signature_path != os.path.join(active, SIGNATURE_NAME):
        raise InstallError("yara.ruleset_signature_path must be <rules_path>/manifest.json.minisig")
    return os.path.join(os.path.dirname(active), "versions"), active


def _read_member(tf: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size > limit:
        raise InstallError(f"{member.name}: larger than {limit} bytes")
    fh = tf.extractfile(member)
    if fh is None:
        raise InstallError(f"{member.name}: unreadable")
    data = fh.read(limit + 1)
    if len(data) > limit or len(data) != member.size:
        raise InstallError(f"{member.name}: size mismatch")
    return data


def read_bundle(path: str, max_bytes: int) -> dict[str, bytes]:
    """Return {name: content}. Nothing is written by tarfile; every member is checked."""
    if os.path.getsize(path) > max_bytes:
        raise InstallError("bundle exceeds yara.max_bundle_mb")
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(path, mode="r:*") as tf:
            for member in tf:
                name = member.name[2:] if member.name.startswith("./") else member.name
                if member.isdir() and name in ("", "."):
                    continue
                if not member.isreg():
                    raise InstallError(f"{member.name}: only regular files are allowed")
                if name not in (MANIFEST_NAME, SIGNATURE_NAME) and not _RULE_FILE.fullmatch(name):
                    raise InstallError(f"{member.name}: unexpected file name")
                if name in files:
                    raise InstallError(f"{name}: duplicate entry")
                limit = MAX_MANIFEST_BYTES if name in (MANIFEST_NAME, SIGNATURE_NAME) else MAX_RULE_FILE_BYTES
                files[name] = _read_member(tf, member, limit)
                total += len(files[name])
                if total > max_bytes or len(files) > MAX_RULE_FILES + 2:
                    raise InstallError("bundle content exceeds limits")
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise InstallError(f"unreadable bundle: {type(exc).__name__}") from None
    for required in (MANIFEST_NAME, SIGNATURE_NAME):
        if required not in files:
            raise InstallError(f"bundle lacks {required}")
    return files


def _manifest_version(path: str) -> int:
    try:
        with open(os.path.join(path, MANIFEST_NAME), "rb") as fh:
            v = json.loads(fh.read(MAX_MANIFEST_BYTES)).get("version")
        return v if isinstance(v, int) and not isinstance(v, bool) else 0
    except (OSError, ValueError, AttributeError):
        return 0


def install_bundle(cfg: YaraConfig, bundle_path: str) -> int:
    versions, active = layout(cfg)
    if os.path.isdir(active) and not os.path.islink(active):
        raise InstallError(f"{active} is a directory; it must be the symlink managed by this installer")
    os.makedirs(versions, mode=0o755, exist_ok=True)
    files = read_bundle(bundle_path, cfg.max_bundle_mb * MB)
    staging = tempfile.mkdtemp(prefix=".staging-", dir=versions)
    try:
        os.chmod(staging, 0o755)
        for name, data in files.items():
            fd = os.open(os.path.join(staging, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        try:
            ruleset = verify_bundle(cfg, staging, os.path.join(staging, SIGNATURE_NAME))
        except RulesetError as exc:
            raise InstallError(f"verification failed: {exc}") from None
        current = _manifest_version(active) if os.path.exists(active) else 0
        if ruleset.version <= current:
            raise InstallError(f"version {ruleset.version} is not newer than active version {current}")
        target = os.path.join(versions, str(ruleset.version))
        if os.path.lexists(target):
            shutil.rmtree(target)                         # leftover of an earlier failed activation
        os.rename(staging, target)
        staging = ""
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)
    tmp_link = active + ".new"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp_link)
    os.symlink(os.path.join("versions", str(ruleset.version)), tmp_link)
    os.replace(tmp_link, active)                          # atomic switch
    dfd = os.open(os.path.dirname(active), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    _prune(versions, cfg.keep_versions, keep=ruleset.version)
    log.info("YARA ruleset version %d activated (%d rule files)", ruleset.version, ruleset.rule_files)
    return ruleset.version


def _prune(versions: str, keep_count: int, keep: int) -> None:
    numbered = sorted((int(n) for n in os.listdir(versions) if n.isdigit()), reverse=True)
    for v in numbered[keep_count:]:
        if v != keep:
            shutil.rmtree(os.path.join(versions, str(v)), ignore_errors=True)


def pull_bundle(cfg: YaraConfig, dest: str, *, transport: httpx.BaseTransport | None = None) -> None:
    """Download yara.update_url to ``dest`` with TLS verification and a size cap."""
    if not cfg.update_url:
        raise InstallError("yara.update_url is not configured")
    if transport is not None:
        kwargs: dict = {"transport": transport}
    else:
        ctx = ssl.create_default_context()
        if cfg.update_ca_file:
            ctx.load_verify_locations(cafile=cfg.update_ca_file)
        kwargs = {"verify": ctx}
    limit = cfg.max_bundle_mb * MB
    try:
        with httpx.Client(timeout=60.0, follow_redirects=False, **kwargs) as client, \
                client.stream("GET", cfg.update_url) as resp:
            if resp.status_code != 200:
                raise InstallError(f"download failed: HTTP {resp.status_code}")
            size = 0
            with open(dest, "wb") as fh:
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > limit:
                        raise InstallError("download exceeds yara.max_bundle_mb")
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise InstallError(f"download failed: {type(exc).__name__}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="usb-scan-yara-install")
    parser.add_argument("--config", default="/etc/usb-scan/scan_station.yaml")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("bundle", nargs="?", help="signed bundle (.tar / .tar.gz)")
    mode.add_argument("--pull", action="store_true", help="download yara.update_url and install it")
    opts = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        cfg = load_config(opts.config).yara
        if opts.pull:
            with tempfile.TemporaryDirectory(prefix="yara-pull-") as tmp:
                path = os.path.join(tmp, "bundle")
                pull_bundle(cfg, path)
                version = install_bundle(cfg, path)
        else:
            version = install_bundle(cfg, opts.bundle)
    except (ConfigError, InstallError) as exc:
        if opts.pull and "not newer" in str(exc):
            print(f"no update: {exc}")
            return 0
        print(f"usb-scan-yara-install: {exc}", file=sys.stderr)
        return 1
    print(f"installed YARA ruleset version {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
