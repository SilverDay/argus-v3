---
name: device-broker
description: >-
  Custom privileged device broker architecture. Use when working on
  src/broker/, orchestrator mounter calls, or any USB mount/unmount/eject logic.
  CRITICAL: replaces udisks2/dasbus entirely. No D-Bus.
---

# Device Broker

## Purpose
The broker is the ONLY component that mounts filesystems. It runs as root with a
minimal allowlisted RPC interface. The orchestrator communicates with it via an
authenticated Unix socket — it never calls mount(8), udisks2, or D-Bus directly.

## Socket
Path: /run/usb-scan/broker.sock
Owner: root:root, mode 0600
Protocol: newline-delimited JSON with HMAC-SHA256 authentication per message.

## Allowed Commands (strict allowlist — all others return {"error": "unknown_command"})
- {"cmd": "enumerate", "sysfs_path": "..."}
  → Returns partition list with UUIDs and filesystem types.
- {"cmd": "mount", "partition_uuid": "...", "session_id": "..."}
  → Mounts read-only in a fresh mount namespace. Returns mount point path inside namespace.
- {"cmd": "unmount", "session_id": "..."}
  → Unmounts all partitions for session and destroys namespace.
- {"cmd": "eject", "sysfs_path": "..."}
  → Requests USB power-off via sysfs authorized attribute.
- {"cmd": "ping"}
  → Returns {"ok": true} for health check.

## Path Validation Rules
- Broker NEVER accepts raw /dev/sd* or /dev/disk/* paths from callers.
- Caller passes sysfs identifier (e.g. /sys/bus/usb/devices/1-1) or partition UUID.
- Broker resolves to block device internally; caller cannot influence resolution.
- Mount namespace is per-session (session_id from orchestrator). Destroyed on unmount.

## Mount Options (applied by broker, not caller)
FAT32/exFAT: ro,noexec,nosuid,nodev,uid=0,gid=<usbscan-read-gid>,dmask=0027,fmask=0137
NTFS (ntfs3): ro,noexec,nosuid,nodev,uid=0,gid=<usbscan-read-gid>,dmask=0027,fmask=0137
  → Validate kernel ntfs3 driver version before deployment; check CVE history.
  → Alternative: ntfs-3g with same options. Document which driver is used.
ext2/3/4: ro,noexec,nosuid,nodev
ISO 9660: ro,noexec,nosuid,nodev

## Mount Namespace Access for Scanners
ClamAV and YARA worker get ReadOnlyPaths=/run/usb-scan/mounts/<session_id>/ in their
systemd unit via a per-scan transient drop-in, not a persistent systemd unit change.
This avoids exposing previous sessions' mounts to current scanner processes.

## Orchestrator Side (src/orchestrator/broker_client.py)
broker_client = BrokerClient("/run/usb-scan/broker.sock", hmac_key=...)
partitions = await broker_client.enumerate(sysfs_path)
mount_result = await broker_client.mount(partition_uuid, session_id)
await broker_client.unmount(session_id)
await broker_client.eject(sysfs_path)
