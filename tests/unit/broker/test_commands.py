import json
import os

import pytest

from src.broker.audit import verify_chain
from src.broker.commands import COMMANDS
from src.shared.broker_protocol import ProtocolError

SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
SESSION2 = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
VFAT = (0, "TYPE=vfat\nUUID=1234-ABCD\nLABEL=STICK\n")
SYSFS = "/sys/bus/usb/devices/1-1"


async def call(ctx, cmd, **args):
    return await COMMANDS[cmd](ctx, args)


async def code_of(ctx, cmd, **args):
    with pytest.raises(ProtocolError) as exc:
        await call(ctx, cmd, **args)
    return exc.value.code


async def test_enumerate_lists_partitions_and_sets_readonly(host, ctx):
    host.build()
    host.blkid = {"/dev/sda": (0, "PTTYPE=dos\n"), "/dev/sda1": VFAT}
    res = await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    assert res["device"]["vendor_id"] == "0781" and res["device"]["serial"] == "ABC?123"
    assert res["device"]["capacity_bytes"] == 2048 * 512
    assert [(v["partition_id"], v["fs_type"], v["status"]) for v in res["volumes"]] == [
        ("part1", "vfat", "supported")]
    assert "/dev/" not in json.dumps(res)  # no raw device paths leave the broker
    setro = [c for c in host.calls if c[0] == "blockdev"]
    assert setro == [["blockdev", "--setro", "/dev/sda"], ["blockdev", "--setro", "/dev/sda1"]]
    assert host.calls.index(setro[-1]) < host.calls.index(next(c for c in host.calls if c[0] == "blkid"))


async def test_unpartitioned_disk_and_unsupported_volumes_reported(host, ctx):
    host.build(partitions=((1, "8:1"), (2, "8:2"), (3, "8:3")))
    host.blkid = {"/dev/sda": (0, "PTTYPE=gpt\n"), "/dev/sda1": (0, "TYPE=crypto_LUKS\n"),
                  "/dev/sda2": (0, "TYPE=hfsplus\n"), "/dev/sda3": (8, "")}
    res = await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    assert [v["status"] for v in res["volumes"]] == ["encrypted", "unsupported", "ambivalent"]
    assert await code_of(ctx, "mount", session_id=SESSION, partition_id="part1") == "unsupported_filesystem"


async def test_whole_disk_filesystem(host, ctx):
    host.build(partitions=())
    host.blkid = {"/dev/sda": VFAT}
    res = await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    assert res["volumes"][0]["partition_index"] == 0


@pytest.mark.parametrize("path", [
    "/dev/sda1", "/dev/disk/by-uuid/1234-ABCD", "/sys/bus/usb/devices/../../../dev/sda",
    "/sys/bus/usb/devices/1-1:1.0", "/sys/bus/usb/devices/usb1", "sda", "", 5, None,
])
async def test_raw_or_invalid_paths_rejected(host, ctx, path):
    host.build()
    assert await code_of(ctx, "enumerate", sysfs_path=path, session_id=SESSION) == "invalid_argument"
    assert not [c for c in host.calls if c[0] in ("blockdev", "mount")]


async def test_composite_hid_device_rejected(host, ctx):
    host.build(iface_classes=("08", "03"))
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION) == "invalid_argument"


async def test_unauthorized_device_rejected(host, ctx):
    host.build(authorized="0")
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION) == "invalid_argument"


async def test_device_mounted_elsewhere_is_refused(host, ctx):
    host.base_mountinfo += "30 22 8:1 / /media/stick rw - vfat /dev/sda1 rw\n"
    host.build()
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION) == "device_in_use"


async def test_device_held_by_device_mapper_is_refused(host, ctx):
    host.build()
    os.makedirs(os.path.join(host.sys, "class", "block", "sda1", "holders", "dm-0"))
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION) == "device_in_use"


async def test_internal_prefix_refused(host, ctx):
    host.build()
    ctx.internal_prefixes = ("/sys/devices/platform/axi",)
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION) == "device_in_use"


async def test_single_session_and_session_id_format(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id="../../etc") == "invalid_argument"
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION2) == "session_conflict"
    assert await code_of(ctx, "mount", session_id=SESSION2, partition_id="part1") == "not_found"


async def test_extra_arguments_rejected(host, ctx):
    host.build()
    assert await code_of(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION,
                         mount_options="rw") == "invalid_argument"


async def test_full_lifecycle_mount_unmount_eject(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    res = await call(ctx, "mount", session_id=SESSION, partition_id="part1")
    target = os.path.join(ctx.mounts_dir, SESSION, "part1")
    assert res == {"mount_path": target, "fs_type": "vfat"}
    mount_call = next(c for c in host.calls if c[0] == "mount")
    opts = mount_call[mount_call.index("-o") + 1].split(",")
    assert {"ro", "noexec", "nosuid", "nodev", "nosymfollow", "dmask=0027", "fmask=0137"} <= set(opts)
    assert "--options-source" in mount_call
    for d in (ctx.mounts_dir, os.path.dirname(target), target):
        assert os.stat(d).st_mode & 0o777 == 0o750

    assert await code_of(ctx, "eject", session_id=SESSION) == "session_conflict"  # still mounted
    await call(ctx, "unmount", session_id=SESSION)
    assert not os.path.exists(os.path.join(ctx.mounts_dir, SESSION))
    res = await call(ctx, "eject", session_id=SESSION)
    assert res == {"ejected": True, "method": "remove", "scsi_deleted": 1}
    with open(os.path.join(host.usb_dir, "remove")) as fh:
        assert fh.read() == "1"
    assert ctx.sessions.active is None
    with open(ctx.audit.path) as fh:
        lines = fh.read().splitlines()
    assert verify_chain(lines) is None
    assert [json.loads(l)["action"] for l in lines] == ["enumerate", "mount", "unmount", "eject"]


async def test_mount_detects_reinserted_device(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    with open(os.path.join(host.usb_dir, "devnum"), "w") as fh:
        fh.write("6\n")  # device re-enumerated on the same port
    assert await code_of(ctx, "mount", session_id=SESSION, partition_id="part1") == "device_changed"
    assert not [c for c in host.calls if c[0] == "mount"]


async def test_mount_detects_media_change(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    with open(os.path.join(host.sys, "class", "block", "sda", "diskseq"), "w") as fh:
        fh.write("8\n")
    assert await code_of(ctx, "mount", session_id=SESSION, partition_id="part1") == "device_changed"


async def test_post_mount_verification_wrong_device(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    host.mount_majmin = "179:2"  # something other than the enumerated partition got mounted
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    assert await code_of(ctx, "mount", session_id=SESSION, partition_id="part1") == "mount_failed"
    assert [c[0] for c in host.calls][-1] == "umount"


async def test_post_mount_verification_missing_flags(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    host.mount_flags = "ro,relatime"  # noexec/nosuid/nodev not applied
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    assert await code_of(ctx, "mount", session_id=SESSION, partition_id="part1") == "mount_failed"


async def test_unmount_busy_reports_failure(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    await call(ctx, "mount", session_id=SESSION, partition_id="part1")
    host.umount_busy = True
    assert await code_of(ctx, "unmount", session_id=SESSION) == "unmount_failed"
    assert not any(c[:2] == ["umount", "-l"] for c in host.calls)  # never lazy


async def test_eject_refuses_different_device(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    with open(os.path.join(host.usb_dir, "devnum"), "w") as fh:
        fh.write("9\n")
    assert await code_of(ctx, "eject", session_id=SESSION) == "device_changed"
    with open(os.path.join(host.usb_dir, "remove")) as fh:
        assert fh.read() == "\n"


async def test_release_closes_session(host, ctx):
    host.build()
    host.blkid = {"/dev/sda1": VFAT}
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    await call(ctx, "mount", session_id=SESSION, partition_id="part1")
    await call(ctx, "release", session_id=SESSION)
    assert ctx.sessions.active is None
    assert not os.path.exists(os.path.join(ctx.mounts_dir, SESSION))


async def test_ext4_gets_noload_and_ntfs_driver_choice(host, ctx):
    host.build(partitions=((1, "8:1"), (2, "8:2")))
    host.blkid = {"/dev/sda1": (0, "TYPE=ext4\n"), "/dev/sda2": (0, "TYPE=ntfs\n")}
    ctx.ntfs_driver = "ntfs3"
    await call(ctx, "enumerate", sysfs_path=SYSFS, session_id=SESSION)
    await call(ctx, "mount", session_id=SESSION, partition_id="part1")
    await call(ctx, "mount", session_id=SESSION, partition_id="part2")
    mounts = [c for c in host.calls if c[0] == "mount"]
    assert "noload" in mounts[0][mounts[0].index("-o") + 1]
    assert mounts[1][mounts[1].index("-t") + 1] == "ntfs3"


async def test_ping(ctx):
    assert await call(ctx, "ping") == {"pong": True}
