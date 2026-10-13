import os

import pytest

from src.shared.secret_refs import SecretError, resolve_secret, validate_ref


def _secret_file(tmp_path, content=b"s3cret\n", mode=0o600, name="k"):
    p = tmp_path / name
    p.write_bytes(content)
    os.chmod(p, mode)
    return p


def test_file_secret(tmp_path):
    p = _secret_file(tmp_path)
    assert resolve_secret(f"file:{p}") == b"s3cret"


def test_world_readable_file_refused(tmp_path):
    p = _secret_file(tmp_path, mode=0o644)
    with pytest.raises(SecretError, match="other users"):
        resolve_secret(f"file:{p}")


def test_symlink_refused(tmp_path):
    p = _secret_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(p)
    with pytest.raises(SecretError):
        resolve_secret(f"file:{link}")


def test_empty_secret_refused(tmp_path):
    p = _secret_file(tmp_path, content=b"\n")
    with pytest.raises(SecretError, match="empty"):
        resolve_secret(f"file:{p}")


def test_credential_directory(tmp_path, monkeypatch):
    _secret_file(tmp_path, name="vt_key", content=b"abc")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert resolve_secret("credential:vt_key") == b"abc"


def test_credential_directory_missing(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(SecretError, match="CREDENTIALS_DIRECTORY"):
        resolve_secret("credential:vt_key")


def test_env_ref_and_override(tmp_path, monkeypatch):
    monkeypatch.setenv("USB_SCAN_TEST_SECRET", "from-env")
    assert resolve_secret("env:USB_SCAN_TEST_SECRET") == b"from-env"
    p = _secret_file(tmp_path)
    monkeypatch.setenv("USB_SCAN_VT_KEY", "override")
    assert resolve_secret(f"file:{p}", env_override="USB_SCAN_VT_KEY") == b"override"
    monkeypatch.delenv("USB_SCAN_VT_KEY")
    assert resolve_secret(f"file:{p}", env_override="USB_SCAN_VT_KEY") == b"s3cret"


@pytest.mark.parametrize("ref", ["", "plain", "http://x", "file:rel", "file:/a/../b", "env:bad-name"])
def test_invalid_refs(ref):
    with pytest.raises(SecretError):
        validate_ref(ref)
