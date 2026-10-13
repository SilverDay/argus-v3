---
name: device-broker
description: >-
  Custom privileged device broker architecture. Use when working on src/broker/,
  the orchestrator broker client, or any USB mount/unmount/eject logic.
  CRITICAL: replaces udisks2/dasbus entirely. No D-Bus.
---

# Device Broker (as implemented — see docs/broker-design-notes.md for rationale)

## Purpose
The broker is the ONLY component that mounts filesystems. Runs as root, keeps only
CAP_SYS_ADMIN + CAP_CHOWN after binding its socket, no_new_privs set.

## Socket & authentication
- /run/usb-scan/broker.sock, mode 0660 root:usbscan (connect(2) needs group write).
- SO_PEERCRED: only the configured client uid (usbscan) is served.
- Every request/response: HMAC-SHA256 (src/shared/broker_protocol.py), timestamp
  within max skew, single-use nonce. Key: broker.hmac_key_ref (≥32 bytes).

## Commands (strict allowlist; exact argument sets; anything else → unknown_command)
- ping {} → {"pong": true}
- enumerate {sysfs_path: "/sys/bus/usb/devices/<port>", session_id: uuid4}
  → opens the single session; sets every block device read-only (BLKROSET);
  returns device info + volumes [{partition_id "partN", status, fs_type, ...}]
- mount {session_id, partition_id} → {"mount_path", "fs_type"}
- unmount {session_id} → unmounts all, removes dirs, session stays open
- eject {session_id} → requires unmounted; SCSI delete + USB `remove`; closes session
- release {session_id} → unmount + close session without eject (device removed)
- open {session_id, partition_id, path_b64} → {"type","size"} + read-only fd via SCM_RIGHTS
  for file/dir; openat2 RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV from the
  mount-root O_PATH fd. Used only when the scanner's own open hits EACCES.

## Rules
- Never accept /dev paths. Partition handles are broker-issued (`partN`);
  filesystem UUIDs are attacker-controlled and informational only.
- Identity re-checked before mount and eject: sysfs realpath, busnum/devnum, diskseq.
- Devices mounted elsewhere, used as swap, held by dm/md, or under
  device.internal_device_sysfs_prefixes are refused (FR-USB-08).
- Composite devices with any non-08 interface and hubs are refused (also USBGuard).
- Mount flags: ro,noexec,nosuid,nodev,nosymfollow (+noload ext3/4;
  uid=0,gid=<read gid>,dmask=0027,fmask=0137 for FAT/exFAT/NTFS; uid/gid for ISO).
- Post-mount verification against /proc/self/mountinfo (device number + flags).
- Never lazy-unmount. Busy → unmount_failed (orchestrator shows EJECT_FAILED).
- Mounts are in the HOST namespace under /run/usb-scan/mounts/<session>/<partN>
  (0750 root:usbscan-read). The broker unit must not use namespace-creating
  sandboxing options (ProtectSystem, PrivateTmp, ...): they stop propagation.
- Every privileged action is written to the hash-chained audit log.

## Orchestrator side (Phase 3: src/orchestrator/broker_client.py)
Use broker_protocol.build_request / parse_response; one request per line;
raise BrokerError(code) on {"ok": false}.
