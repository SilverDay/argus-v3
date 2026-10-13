# Device Broker — Design Notes and Deviations (Phase 2)

These notes record where the implementation differs from spec v1.5 / implementation
plan v1.5, why, and what needs owner approval or validation on the Pi.

## 1. Mount namespace model (spec §3.2 step 3, plan Phase 2) — APPROVED by owner, spec 1.5.1 updated

**Spec/plan:** broker creates a per-session mount namespace; scanners get access via a
transient systemd drop-in adding `ReadOnlyPaths=/run/usb-scan/mounts/<session>/`.

**Problem (verified against systemd.exec(5), systemd `main`):**
- Namespace-creating options "disconnect propagation of mounts from the unit's processes
  to the host"; mounts created by the broker in its own namespace never reach clamd.
- Host mounts *do* propagate into service namespaces, and later submounts are not
  covered by `ReadOnlyPaths=` ("Restricting access with these options hence does not
  extend to submounts of a directory that are created later on").
- Unit settings take effect when the service starts, so a per-scan drop-in would
  require restarting clamd (signature reload) for every scan.

**Implemented:** mounts in the host namespace under
`/run/usb-scan/mounts/<session_id>/<partN>`, protected by
- mount flags themselves (`ro,noexec,nosuid,nodev,nosymfollow`) + BLKROSET on the device;
- `0750 root:usbscan-read` directories (only scanner identities are group members);
- `InaccessiblePaths=/run/usb-scan/mounts` for GUI, LED, web and events units (Phase 10,
  defence in depth);
- deterministic unmount with verification and crash recovery at broker start.

## 2. Writes despite `ro`

mount(8): "ext3 and ext4 will replay the journal if the filesystem is dirty". The broker
sets every block device and partition read-only (`blockdev --setro`) before probing and
adds `noload` for ext3/4. Verified on a loop device: a later `rw` mount is forced `ro`.

## 3. Socket mode

Plan: `0600 root:root`. A 0600 root socket cannot be connected to by the unprivileged
`usbscan` user. Implemented: `0660 root:usbscan` + SO_PEERCRED uid check + per-message HMAC.

## 4. Partition identifiers

Plan: callers pass filesystem UUIDs (resolved via `/dev/disk/by-uuid`). Filesystem UUIDs
are attacker-controlled (can be duplicated or set to the root filesystem's UUID).
Implemented: broker-issued per-session handles `partN`; UUIDs are returned for
information only. The orchestrator still never sees `/dev` paths.

## 5. Eject

Plan: write `0` to `authorized`. That de-authorises the device but does not flush or
detach the SCSI disk. Implemented: refuse while mounted → identity re-check → `1` to each
disk's SCSI `device/delete` → `1` to the USB device `remove` attribute (fallback
`authorized=0`). Eject is bound to the session, not to a caller-supplied sysfs path.
Whether VBUS is actually cut depends on the Pi 5 port hardware — validate on the Pi;
the GUI must never equate this with physical removal (spec §3.2 step 11).

## 6. Capabilities

Kept after bind: `CAP_SYS_ADMIN` (mount, BLKROSET), `CAP_CHOWN` (mount dir group).
`CAP_DAC_READ_SEARCH` (plan) is not needed: uid 0 owns the device nodes and sysfs files.
Capability sets are per thread; the drop runs before any thread exists and refuses otherwise.

## 7. Confined opens for permission-hidden content (owner decision)

The unprivileged scanner cannot read content the media's permissions hide (ext4's
0700 root `lost+found`, private directories, mode-000 files). Command `open`
{session_id, partition_id, path_b64} makes the broker open the path read-only with
`openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`
relative to an `O_PATH` handle on the verified mount root, and pass the descriptor back
with SCM_RIGHTS. Only regular files and directories are handed out; symlinks, special
files and anything outside the mount are refused. The orchestrator uses it only after
its own access fails, so normal media have no extra round-trips. Root handles are
closed before unmount; the number of opens per session is audited at unmount.

## 8. Validation still required on the Pi (Phase 10/12)

- systemd unit draft (`systemd/usb-scan-device-broker.service`): syscall filter, device
  policy, `MemoryDenyWriteExecute` with the venv interpreter.
- Real USB sysfs layout on Pi 5 (port naming, `remove` attribute, SCSI `delete`).
- NTFS/exFAT drivers (`ntfs3` vs `ntfs-3g`, kernel `exfat`) on the Trixie kernel (FR-USB-05).
- Throughput of confined opens on media with many permission-restricted files.
