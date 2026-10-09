# Galaxy S20+ Snapdragon (SM-G986U1) — 4.19 investigation

Status: **research only; NOT a supported payload and NOT tested on hardware**.

This document accompanies the app's read-only Investigation tab. It is deliberately
not represented in support/targets-v3.json: neither an exploit nor a KernelSU
late-load module has been verified for this target.

## Findings from the October 9, 2026 device reports

Evidence: user-uploaded firmware inventory JSON, Shizuku investigation JSON,
and original gzip kernel configuration. SHA-256 of config.gz:
`1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd`

| Field | Observed |
|---|---|
| Model / codename | `SM-G986U1` / `y2q` |
| Android | 13 (SDK 33), ARM64, 4096-byte pages |
| Build | `TP1A.220624.014.G986U1UESCHXL1` |
| Fingerprint | `samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys` |
| Kernel | `4.19.113-27095354`, built Dec 27 2024 KST |
| Local firmware file | `SAMFW.COM_SM-G986U1_XAA_G986U1UESCHXL1_fac.zip` (6,869,850,700 bytes) |
| ZIP inventory | AP/BL/CP match `G986U1UESCHXL1`; CSC/HOME_CSC are `G986U1OYMCHXL1` |
| Boot/kernel image SHA-256 | Not yet available: nested AP TAR not inspected |
| Patch level, bootloader lock | Not captured: all shell diagnostic probes failed |

### Verified kernel-config flags

| Flag | Status | Implication |
|---|---|---|
| `CONFIG_ARCH_QCOM`, `CONFIG_ARCH_KONA` | enabled | Qualcomm Kona |
| `CONFIG_FUTEX_PI`, `CONFIG_RT_MUTEXES` | enabled | Relevant subsystems present; **no proof of vulnerability** |
| `CONFIG_KALLSYMS_ALL` | enabled | Symbol table compiled in; runtime addresses may be masked |
| `CONFIG_DEBUG_INFO` | enabled | Debug data requested at kernel build time, not guaranteed in deployed image |
| `CONFIG_KPROBES` | disabled | Kprobes unavailable |
| `CONFIG_MODULES`, `CONFIG_MODVERSIONS` | enabled | Module loading compiled in, ABI versioning enforced |
| `CONFIG_MODULE_SIG_FORCE`, `CONFIG_MODULE_SIG_SHA512` | enabled | Mandatory SHA-512 module signature verification |
| `CONFIG_RANDOMIZE_BASE` | enabled | KASLR |
| `CONFIG_UH_RKP` | enabled | Samsung RKP configured |
| `CONFIG_KDP_CRED`, `CONFIG_KDP_NS`, `CONFIG_KDP_DMAP` | enabled | Samsung KDP configured |
| `CONFIG_SECURITY_DEFEX` | enabled | Samsung DEFEX configured |
| `CONFIG_IKCONFIG_PROC` | enabled | Original `/proc/config.gz` was successfully exported |
| `CONFIG_DEBUG_INFO_BTF` | absent from config | BTF is not established |

### App-side Shizuku collector bug found

All 23 collected shell observations failed with
`IllegalArgumentException: process hasn't exited`. The Shizuku remote-process
adapter did not honor Java `Process.exitValue()` semantics during timed waits.
This is an app bug, **not evidence that Android denied all 23 probes**.
The separate kernel-config extraction succeeded. Re-run these diagnostics
with the corrected app to obtain security patch, SELinux, tracefs accessibility,
bootloader state and command UID.

### Next evidence gates

1. Re-run Shizuku probes on a fixed debug build, saving the new report.
2. Obtain `boot.img.lz4` from the exact AP TAR.MD5 and hash the compressed
   image, decompressed boot image, and extracted kernel. ZIP central-directory
   metadata does not expose embedded AP partitions.
3. Independently validate the exact 4.19 binary/source before drawing any
   conclusion about CVE-2026-43499.
4. Account for signature enforcement, Samsung KDP/RKP, DEFEX, KASLR, and
   target-specific structure offsets before researching a loader.

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
Keep SHA-256 for each stage. The app's SAF inspector can index a selected
AP/BL/CP/CSC TAR.MD5 directly without extraction; it also lists nested TAR
names in an outer ZIP. It does not inflate nested AP files or reconstruct
symbols. For large files the application explicitly skips full-file hashing.

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
