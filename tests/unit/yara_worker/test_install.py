import asyncio
import io
import os
import tarfile

import httpx
import pytest

from src.yara_worker import install
from src.yara_worker.install import InstallError, install_bundle, pull_bundle, read_bundle
from src.yara_worker.rules import RuleStore
from tests.unit.yara_worker.bundle import make_bundle, make_keypair, yara_cfg

RULE = 'rule t_{v} {{ strings: $a = "MARK{v}" condition: $a }}'


def tar_of(directory: str, dest: str, extra: list[tarfile.TarInfo] | None = None, gz: bool = True) -> str:
    with tarfile.open(dest, "w:gz" if gz else "w") as tf:
        for name in sorted(os.listdir(directory)):
            tf.add(os.path.join(directory, name), arcname=name)
        for info in extra or []:
            tf.addfile(info, io.BytesIO(b"x" * info.size) if info.isreg() else None)
    return dest


@pytest.fixture
def env(tmp_path):
    pub, sec = make_keypair(str(tmp_path))
    rules_root = tmp_path / "rules"
    rules_root.mkdir()
    cfg = yara_cfg(str(rules_root / "active"), pub, str(tmp_path / "state"))

    def bundle(version: int, name: str | None = None, **kw) -> str:
        d = tmp_path / f"src{version}{name or ''}"
        make_bundle(str(d), sec, {"main.yar": RULE.format(v=version)}, version=version, **kw)
        return tar_of(str(d), str(tmp_path / f"b{version}{name or ''}.tar.gz"))
    return {"cfg": cfg, "bundle": bundle, "root": rules_root, "tmp": tmp_path, "sec": sec}


def test_install_activates_and_worker_loads(env):
    cfg = env["cfg"]
    assert install_bundle(cfg, env["bundle"](1)) == 1
    assert os.readlink(cfg.rules_path) == os.path.join("versions", "1")
    store = RuleStore(cfg)
    assert store.reload() and store.active.version == 1
    assert install_bundle(cfg, env["bundle"](2)) == 2
    assert store.reload() and store.active.version == 2
    assert oct(os.stat(env["root"] / "versions" / "2" / "main.yar").st_mode & 0o777) == "0o644"


def test_rollback_and_replay_refused(env):
    cfg = env["cfg"]
    old = env["bundle"](1)
    install_bundle(cfg, env["bundle"](2))
    for path in (old, env["bundle"](2, "again")):
        with pytest.raises(InstallError, match="not newer"):
            install_bundle(cfg, path)
    assert os.readlink(cfg.rules_path) == os.path.join("versions", "2")


def test_tampered_or_unsigned_bundle_refused(env, tmp_path):
    cfg = env["cfg"]
    install_bundle(cfg, env["bundle"](1))
    d = tmp_path / "evil"
    make_bundle(str(d), env["sec"], {"main.yar": RULE.format(v=3)}, version=3)
    (d / "main.yar").write_text(RULE.format(v=666))                  # changed after signing
    with pytest.raises(InstallError, match="verification failed"):
        install_bundle(cfg, tar_of(str(d), str(tmp_path / "evil.tar.gz")))
    other_pub, other_sec = make_keypair(str(tmp_path), "attacker")
    d2 = tmp_path / "forged"
    make_bundle(str(d2), other_sec, {"main.yar": RULE.format(v=4)}, version=4)
    with pytest.raises(InstallError, match="verification failed"):
        install_bundle(cfg, tar_of(str(d2), str(tmp_path / "forged.tar.gz")))
    assert os.readlink(cfg.rules_path) == os.path.join("versions", "1")
    assert sorted(os.listdir(env["root"] / "versions")) == ["1"]      # no staging leftovers


def _info(name: str, kind: bytes = tarfile.REGTYPE, size: int = 1, link: str = "") -> tarfile.TarInfo:
    i = tarfile.TarInfo(name)
    i.type, i.size, i.linkname = kind, size if kind == tarfile.REGTYPE else 0, link
    return i


@pytest.mark.parametrize("member,match", [
    (_info("../escape.yar"), "unexpected file name"),
    (_info("/etc/passwd"), "unexpected file name"),
    (_info("sub/x.yar"), "unexpected file name"),
    (_info("x.sh"), "unexpected file name"),
    (_info("evil.yar", tarfile.SYMTYPE, link="/etc/shadow"), "only regular files"),
    (_info("evil.yar", tarfile.LNKTYPE, link="manifest.json"), "only regular files"),
    (_info("dev.yar", tarfile.CHRTYPE), "only regular files"),
    (_info("manifest.json"), "duplicate"),
    (_info("big.yar", size=17 * 1024 * 1024), "larger than"),
])
def test_hostile_archives_rejected(env, tmp_path, member, match):
    d = tmp_path / "base"
    make_bundle(str(d), env["sec"], {"main.yar": RULE.format(v=1)}, version=1)
    path = tar_of(str(d), str(tmp_path / "hostile.tar.gz"), extra=[member])
    with pytest.raises(InstallError, match=match):
        read_bundle(path, 64 * 1024 * 1024)
    assert not os.path.exists(tmp_path / "escape.yar")


def test_bundle_size_limit_and_garbage(env, tmp_path):
    path = env["bundle"](1)
    with pytest.raises(InstallError, match="exceeds"):
        read_bundle(path, 10)
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"\x1f\x8b not really gzip")
    with pytest.raises(InstallError, match="unreadable bundle"):
        read_bundle(str(junk), 1024)


def test_legacy_directory_layout_refused(env):
    os.makedirs(env["cfg"].rules_path)
    with pytest.raises(InstallError, match="is a directory"):
        install_bundle(env["cfg"], env["bundle"](1))


def test_prune_keeps_newest(env):
    cfg = env["cfg"]
    for v in range(1, 6):
        install_bundle(cfg, env["bundle"](v))
    assert sorted(os.listdir(env["root"] / "versions")) == ["3", "4", "5"]   # keep_versions = 3


def test_pull_downloads_with_size_cap(env, tmp_path):
    from dataclasses import replace
    data = __import__("pathlib").Path(env["bundle"](1)).read_bytes()
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=data)

    cfg = replace(env["cfg"], update_url="https://rules.example.org/bundle.tar.gz")
    dest = str(tmp_path / "dl")
    pull_bundle(cfg, dest, transport=httpx.MockTransport(handler))
    assert __import__("pathlib").Path(dest).read_bytes() == data and seen[0].url.scheme == "https"
    assert install_bundle(cfg, dest) == 1
    with pytest.raises(InstallError, match="exceeds"):
        pull_bundle(replace(cfg, max_bundle_mb=1), dest,
                    transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * (2 * 1024 * 1024))))
    with pytest.raises(InstallError, match="HTTP 302"):
        pull_bundle(cfg, dest, transport=httpx.MockTransport(
            lambda r: httpx.Response(302, headers={"Location": "http://evil.example.org/b"})))
    with pytest.raises(InstallError, match="not configured"):
        pull_bundle(replace(cfg, update_url=""), dest)


def test_cli_offline_and_pull_noop(env, tmp_path, capsys, monkeypatch):
    cfgfile = tmp_path / "cfg.yaml"
    c = env["cfg"]
    cfgfile.write_text(f"""yara:
  enabled: true
  rules_path: {c.rules_path}
  ruleset_signature_path: {c.ruleset_signature_path}
  trust_anchor_path: {c.trust_anchor_path}
  minisign_path: {c.minisign_path}
  state_dir: {c.state_dir}
  update_url: https://rules.example.org/b.tar.gz
""")
    b1 = env["bundle"](1)
    assert install.main(["--config", str(cfgfile), b1]) == 0
    assert install.main(["--config", str(cfgfile), b1]) == 1                 # offline: older is an error
    monkeypatch.setattr(install, "pull_bundle", lambda cfg, dest: __import__("shutil").copy(b1, dest))
    assert install.main(["--config", str(cfgfile), "--pull"]) == 0           # pull: same version is a no-op
    assert "no update" in capsys.readouterr().out


async def test_worker_follows_active_link(env):
    from src.yara_worker.__main__ import watch_active_link
    cfg = env["cfg"]
    install_bundle(cfg, env["bundle"](1))
    store = RuleStore(cfg)
    store.reload()

    class Server:
        def reload(self):
            return store.reload()

    task = asyncio.create_task(watch_active_link(Server(), cfg.rules_path, interval=0.05))
    await asyncio.sleep(0.1)                          # watcher records the current target first
    install_bundle(cfg, env["bundle"](2))
    for _ in range(100):
        if store.active.version == 2:
            break
        await asyncio.sleep(0.05)
    task.cancel()
    assert store.active.version == 2
