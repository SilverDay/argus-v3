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


def test_env_secrets_refused_outside_dev_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("USB_SCAN_DEV", raising=False)
    monkeypatch.setenv("USB_SCAN_TEST_SECRET", "from-env")
    with pytest.raises(SecretError, match="USB_SCAN_DEV"):
        resolve_secret("env:USB_SCAN_TEST_SECRET")
    p = _secret_file(tmp_path)
    monkeypatch.setenv("USB_SCAN_VT_KEY", "override")
    assert resolve_secret(f"file:{p}", env_override="USB_SCAN_VT_KEY") == b"s3cret"   # override ignored


def test_env_ref_and_override(tmp_path, monkeypatch):
    monkeypatch.setenv("USB_SCAN_DEV", "1")
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


def test_size_enforced_on_the_bytes_actually_read(tmp_path, monkeypatch):
    """The fstat size check alone is not enough: a file growing between fstat and read
    must still be refused, never returned oversized."""
    import os as _os
    from src.shared import secret_refs
    p = tmp_path / "grows"
    p.write_bytes(b"k" * 16)
    os.chmod(p, 0o600)
    real_fstat = _os.fstat

    def growing_fstat(fd):
        st = real_fstat(fd)
        with open(p, "ab") as fh:                      # grows right after the size check
            fh.write(b"k" * (secret_refs.MAX_SECRET_BYTES + 10))
        return st

    monkeypatch.setattr(secret_refs.os, "fstat", growing_fstat)
    with pytest.raises(secret_refs.SecretError, match="too large"):
        secret_refs.resolve_secret(f"file:{p}")
