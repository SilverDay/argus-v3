# YARA Worker — Design Notes (Phase 4)

Owner decisions (13 Oct 2026, spec 1.5.2): descriptor delivery, minisign-signed rules,
`yara.max_file_size_mb` default 256.

## Process model

```
orchestrator (usbscan) ──fd via SCM_RIGHTS──▶ /run/usb-scan/yara.sock (0660 yarascan:usbscan)
                                               │ supervisor (yarascan, asyncio)
                                               │   peer uid check, ruleset state, budget timer
                                               └──▶ child per session (python -m src.yara_worker.child)
                                                     RLIMIT_AS / CPU / NOFILE / CORE=0
                                                     compiled rules on stdin, libyara native timeout
```

* **No paths, no mounts.** The orchestrator sends the same read-only descriptor it gave
  clamd (including broker-confined opens of permission-hidden content). The worker unit can
  therefore use `InaccessiblePaths=/run/usb-scan/mounts` and `PrivateNetwork=yes`.
* **Disposable child.** libyara over hostile data runs only in the child. A crash, hang or
  memory blow-up ends that session only; the orchestrator records YARA as incomplete.
* **Budget kill.** The plan had the orchestrator SIGKILL the worker, but the orchestrator
  (`usbscan`) cannot signal a `yarascan` process. The supervisor (same uid as the child)
  kills the child after `yara.global_budget_seconds`; the orchestrator enforces the same
  budget on its side (`yara_budget_exceeded`). RLIMIT_CPU is a kernel backstop.
* **No mmap.** Files are read with `pread` into memory (≤ `max_file_size_mb`): a device
  that disappears mid-read yields an I/O error, not SIGBUS.
* **Raw accept.** The supervisor accepts connections with `loop.sock_accept`; an asyncio
  stream transport would start reading and swallow requests meant for the child
  (observed during development).

## Rules bundle (spec §7.3)

`manifest.json` = `{"format": 1, "version": N, "files": {"name.yar": "<sha256>"}}`,
signed with minisign (`manifest.json.minisig`), public key at `yara.trust_anchor_path`.
Activation: verify the exact manifest bytes → version ≥ last accepted (persisted in
`yara.state_dir`) → read + hash each listed file → compile from those bytes with
`includes=False` → record version. Any failure keeps the previous ruleset (SIGHUP reload).
Unlisted files in the directory are ignored. Required whenever YARA is enabled.

Severity: rule meta `severity = "high"|"critical"` → THREAT; `"low"` → low; otherwise
medium → SUSPICIOUS.

## Verdict effects

| Situation | mandatory | advisory |
|---|---|---|
| worker/ruleset unavailable at health check | NOT_READY (`yara_unavailable`) | warning |
| worker lost / timeout / too large / budget during scan | INCOMPLETE | reason code only |
| high-severity match | THREAT | THREAT |
| other match | SUSPICIOUS | SUSPICIOUS |

## Verified in CI (this container)

minisign 0.11 exit codes; yara-python 4.5.4 `match(data=…)`, `timeout=` → `TimeoutError`,
`save/load(file=…)`, `includes=False` rejects `include`. End-to-end test: signed bundle,
real supervisor and children, real clamd, ext4 loop mount, scanner as `nobody`, YARA match
in a 0700 directory via broker-confined descriptors.

## To validate on the Pi

* `minisign` package on Trixie (packaged in Ubuntu as 0.11; confirm Debian version).
* Memory limit vs. Python + libyara footprint on arm64 with large rulesets.
* Throughput with `clamav.concurrency` > 1 (YARA requests are serialised per session).
