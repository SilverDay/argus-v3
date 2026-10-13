"""Helpers to build signed YARA rule bundles with real minisign keys (tests only)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess

from src.shared.config import load_config_from_dict

MINISIGN = shutil.which("minisign")


def make_keypair(directory: str, name: str = "key") -> tuple[str, str]:
    pub, sec = os.path.join(directory, f"{name}.pub"), os.path.join(directory, f"{name}.sec")
    subprocess.run([MINISIGN, "-G", "-W", "-p", pub, "-s", sec], check=True, capture_output=True)
    return pub, sec


def make_bundle(directory: str, sec_key: str, rules: dict[str, str], version: int = 1,
                manifest_files: dict[str, str] | None = None) -> str:
    os.makedirs(directory, exist_ok=True)
    files = {}
    for name, source in rules.items():
        with open(os.path.join(directory, name), "w") as fh:
            fh.write(source)
        files[name] = hashlib.sha256(source.encode()).hexdigest()
    manifest = os.path.join(directory, "manifest.json")
    with open(manifest, "w") as fh:
        json.dump({"format": 1, "version": version, "files": manifest_files or files}, fh)
    sig = manifest + ".minisig"
    if os.path.exists(sig):
        os.unlink(sig)
    subprocess.run([MINISIGN, "-S", "-s", sec_key, "-m", manifest, "-t", f"rules v{version}"],
                   check=True, capture_output=True)
    return directory


def yara_cfg(rules_dir: str, pub_key: str, state_dir: str, socket_path: str = "/tmp/unused.sock", **extra):
    raw = {"enabled": True, "rules_path": rules_dir,
           "ruleset_signature_path": os.path.join(rules_dir, "manifest.json.minisig"),
           "trust_anchor_path": pub_key, "minisign_path": MINISIGN, "state_dir": state_dir,
           "socket_path": socket_path}
    raw.update(extra)
    return load_config_from_dict({"yara": raw}).yara
