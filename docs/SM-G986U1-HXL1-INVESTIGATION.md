# Galaxy S20+ Snapdragon (SM-G986U1) — 4.19 investigation

Status: **research only; NOT a supported payload and NOT tested on hardware**.

This document accompanies the app's read-only Investigation tab. It is deliberately
not represented in support/targets-v3.json: neither an exploit nor a KernelSU
late-load module has been verified for this target.

## Target reported by device owner

| Field | Reported value | Verification still needed |
|---|---|---|
| Handset | Galaxy S20+ SM-G986U1/DS | Android Build.MODEL (possibly SM-G986U1) |
| SoC | Qualcomm SM8250 / Snapdragon 865 | Build.DEVICE and product variant |
| Kernel | 4.19.113-27095354 | Exact uname -r and compiled kernel hash |
| Modem/baseband | G986U1UESCHXL1 | Actual AP/PDA and CSC build, not inferred from baseband |
| OS | Android 13 / One UI 5.1 | Fingerprint and security patch |
| Bootloader | Unconfirmed; US U1 generally locked | Device-reported state and recovery options |

The Exynos S20+ SM-G986B / codename y2s is a different port. The Snapdragon
variant is commonly known as y2q, but confirm the device identifier on hardware.
Do not reuse offsets, fingerprint tables, or modules from S20 Exynos / S23 / S24.

## Phase 1 — phone-side evidence (app-only + Shizuku)

In Ragnarok93/Root-My-Galaxy, select **Investigate** and run:

1. **App snapshot**: Android Build.MODEL, Build.DEVICE, fingerprint, uname,
   ABI, page size.
2. Pair and start Shizuku from Android's **Wireless debugging** settings,
   grant the app Shizuku permission, and **Collect via Shizuku**.
3. Export the resulting local JSON report and review it before sharing.

The collector intentionally does not enumerate personal identifiers such as IMEI
or phone serial, cannot modify the device, and does not upload the report.
It records missing permissions or inaccessible files as observations instead of
assuming access. UID 2000 means an authorized ADB-shell process, **not root**.

Shizuku started through wireless debugging does not grant read access to raw
boot/vendor partitions or other restricted block devices on a locked stock
handset. Download the exact Samsung AP firmware *offline*. Do not attempt
partition reads or flash images as part of these diagnostic steps.

## Phase 2 — obtain exact firmware artifacts

Ground identity in these report keys before deciding on a profile name:

- ro.product.model, ro.product.device, ro.product.name
- ro.build.display.id and ro.build.fingerprint
- ro.boot.bootloader, gsm.version.baseband and ro.build.version.security_patch
- kernel release from uname -a, kernel build string /proc/version
- the active slot and boot state (if exposed)

Download the **matching AP version**, not a package chosen solely from CP
(baseband). Extract boot.img.lz4 offline from AP; use lz4 to decompress and
a boot-image-aware unpacker (e.g., magiskboot) to recover the ARM64 kernel.
Keep SHA-256 for each stage. The app's SAF inspector can identify and hash a
user-selected boot.img or LZ4 file (up to 256 MiB); it neither unpacks an AP
archive nor reconstructs a symbolized kernel.

## Phase 3 — kernel analysis blockers

Verify the 4.19 Samsung tree against its binary, especially:

- Is the vulnerable CVE-2026-43499 rtmutex/futex path present and reachable?
- What are the exact target layouts for task_struct, rt_mutex_waiter,
  workqueue, pipe_buffer, file_operations, and other primitives?
- Can kallsyms or BTF be recovered from the actual kernel image? If not,
  is there an exact Samsung release and config suitable for disassembly?
- Are tracefs scheduler events accessible as an unprivileged shell? Do not
  reuse any event ID or caller address from another kernel.
- Which KASLR/physical-memory assumptions hold on Qualcomm SM8250?
- Which SELinux, KDP/RKP/DEFEX and kernel-module restrictions are enabled?

Read docs/PORTING.md for the analysis discipline, but do NOT reuse its
6.1/5.15 offsets or physical addresses. No exploit trigger should be attempted
until firmware, layouts and rollback safety gates have been independently
validated offline.

## Phase 4 — acceptance criteria before publishing support

- [ ] Hardware build and exact matching AP/boot image verified
- [ ] Kernel image SHA-256 and source/config provenance recorded
- [ ] Android 4.19-specific symbol/layout audit completed
- [ ] Confirmed native exploit path (not merely a reboot or crash)
- [ ] Clean recovery instructions and repeatable hardware logs
- [ ] Temporary UID 0 proven and reviewed independently
- [ ] Any KernelSU 4.19 module/loading method independently validated
- [ ] Firmware-locked manifest guard implemented and tested in the app
- [ ] Only then consider a production payload catalog entry

The current manifest schema matches model plus three-part kernel version.
That is **not precise enough** for an experimental 4.19 port. A future app
schema must require a matching firmware fingerprint/AP identity and explicitly
support root-only profiles before this device can appear as installable.

## Firmware analysis record template

Save a redacted local observation and fill the following, never guess:

- Device model / codename:
- AP, CP, CSC, bootloader, fingerprint, Android security patch:
- Kernel uname, config, page size:
- boot.img.lz4 SHA-256, boot.img SHA-256, extracted kernel SHA-256:
- Boot image header version, ARM64 kernel compression:
- Symbol recovery / BTF status:
- Vulnerable rtmutex code verified against binary:
- Available read-only tracefs event(s):
- Root status: **not tested**
