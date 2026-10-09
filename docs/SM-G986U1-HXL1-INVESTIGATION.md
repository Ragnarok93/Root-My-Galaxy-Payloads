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
| Boot/kernel image SHA-256 | Recovered offline from AP; see exact image hashes below. Installed partition hash unverified. |
| Security patch / bootloader lock | `2025-01-01` / `ro.boot.flash.locked=1`, vbmeta device state `locked` |

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

### Shizuku diagnostic validation — second report (2026-10-09T20:55:41Z)

The initial **23 FAILED** results were caused by the old adapter's
`IllegalArgumentException: process hasn't exited` bug. After the
Process-compatible timeout fix, **22 probes returned OK, 1 UNAVAILABLE,
and 0 FAILED**; Shizuku execution was confirmed as **UID 2000** (ADB shell,
not root).

| Probe | Observed result | Interpretation |
|---|---|---|
| `ro.product.name` | `y2quew` | Matches model/codename in fingerprint |
| `ro.build.version.security_patch` | `2025-01-01` | Android security patch |
| `ro.boot.bootloader` | `G986U1UESCHXL1` | Bootloader firmware identity |
| `gsm.version.baseband` | `G986U1UESCHXL1,G986U1UESCHXL1` | Dual-value baseband string |
| `ro.boot.flash.locked` | `1` | Locked flash/bootloader state |
| `ro.boot.vbmeta.device_state` | `locked` | Locked verified-boot device state |
| `security.selinux` | `Enforcing` | Mandatory access control enforced |
| `kernel.trace_event` | `72` | `sched_blocked_reason` event ID currently readable; per-build/boot value, **not** a kernel address |
| `kernel.kallsyms` | UNAVAILABLE | ADB shell cannot read `/proc/kallsyms` via probe; compiled-in kallsyms do not imply access |
| `kernel.modules` | exit 0, empty stdout | No modules listed by `/proc/modules` at capture time; modules are supported by config |
| `boot.slot` | exit 0, empty stdout | No slot suffix returned; does not alone prove partitioning layout |
| `storage.partitions` | block-device major/minor/size inventory | Physical `sd[a-d]`, removable `mmcblk0`, loop, zram and device-mapper entries enumerated; no partition labels or raw contents captured |

From `/proc/version`, the exact deployed kernel identifies
`clang version 10.0.6 for Android NDK`, Samsung build
`dpi@21DJ7C20`, and `#1 SMP PREEMPT Fri Dec 27 14:53:28 KST 2024`.

The original kernel config contains `CONFIG_TRACEPOINTS=y`,
`CONFIG_FTRACE=y` and `CONFIG_KALLSYMS_ALL=y`, but the shell
report demonstrates that trace event *metadata* is readable while
kernel symbol metadata is not. Do not infer unprivileged trace event
attachment, writable tracefs, a usable symbol leak, or root viability.

### Remaining research gates

1. Use the new bootloader/patch/fingerprint evidence to constrain the
   **SM-G986U1 / y2q / G986U1UESCHXL1 / 4.19.113-27095354** target.
2. **Completed offline:** extracted and hashed `boot.img.lz4`, decompressed `boot.img`, and ARM64 kernel from matching AP. A running-partition hash is not available.
3. Verify exact kernel binary/source and whether the proposed futex/rtmutex
   vulnerability is applicable **before** forming a payload.
4. Validate protection and rollback constraints, including locked AVB,
   SELinux enforcing, forced module signatures, Samsung RKP/KDP/DEFEX,
   KASLR, and inaccessible `/proc/kallsyms`.
5. Do not add this target to the supported payload manifest before
   firmware-locked identification and an independently validated method.

## Exact boot image recovered from selected AP firmware (2026-10-09)

Source: user-provided `boot.img.lz4` extracted from the
`SAMFW.COM_SM-G986U1_XAA_G986U1UESCHXL1_fac.zip` AP package. Binary and
hashes were analyzed offline; **no proprietary kernel/image content is
committed to the repository**.

| Artifact | Size (bytes) | SHA-256 |
|---|---:|---|
| Extracted `boot.img.lz4` | 25,597,493 | `02099ccbfb423292b631f228b8d3163b9a601f4a058360a4bca93f71f8e50a78` |
| Decompressed `boot.img` | 67,108,864 | `bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8` |
| Kernel `Image` | 51,957,772 | `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` |
| Gzip ramdisk | 724,388 | `86b00ab1f20206ceedcc574423ef11417927aa1f773408ec2c2af4a855ea7586` |
| Appended DTB image | 1,580,275 | `a6104cdba11e0cd3d6ddaba6819098ab01f0dc0e8e7fd333137c88ad07d9d0ce` |
| Kernel-embedded `config.gz` | 42,754 | `1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd` |

### Byte-exact cross-validation of kernel configuration

The ARM64 kernel Image contains the normal `IKCFG_ST` / `IKCFG_ED` embedded
kernel config sequence at offsets 26,785,408–26,828,170. The embedded 42,754
compressed bytes match the **previously exported live `/proc/config.gz`
byte-for-byte** (not merely a text-only configuration comparison), including
the SHA-256 shown above.

Its embedded Linux version string also exactly matches the running device:
`Linux version 4.19.113-27095354 (dpi@21DJ7C20) (clang version 10.0.6 for Android NDK) #1 SMP PREEMPT Fri Dec 27 14:53:28 KST 2024`.

This establishes strong firmware/kernel *build equivalence evidence*,
but a **live boot-partition byte-for-byte hash was not obtained**. The source
Image's hash must not be presented as a verified hash of the installed
partition.

### Android boot and ARM64 Image headers

| Field | Inspected value |
|---|---|
| LZ4 | Standard framed stream, 1 MiB independent blocks, content checksum, original size 64 MiB |
| Android boot magic | `ANDROID!` |
| Boot header version / header bytes | `2` / `1660` |
| Header page size | `4096` bytes |
| Kernel offset and length | `4096` / `51957772` |
| Ramdisk offset and length | `51965952` / `724388` |
| DTB offset and length | `52690944` / `1580275` |
| Header board name | `SRPSH29C012` |
| Kernel signature | `ARMd` (uncompressed AArch64 Image, not ELF) |
| ARM64 text_offset / image_size | `0x80000` / `0x433b000` |
| ARM64 Image flags | `0xA` |
| Boot-header OS version field | Android **11.0.0**, patch **2025-01** (the phone's *running* Android is **13**) |

The OS version discrepancy is **limited to the boot-header metadata** and
does not overturn the live-build and exact IKCONFIG match. Do not treat the
boot-header field as authoritative for running Android userspace.

The gzip ramdisk decompresses to a `cpio newc` archive of 1,565,952 bytes,
with 8 entries including `init`, `fstab.qcom` and `dpolicy`.
`fstab.qcom` references `first_stage_mount` and logical
`system` / `product` / `vendor` / `odm` partitions protected by AVB,
and `/data` with `fileencryption=ice`.

The DTB section contains **four sequential FDT v17 blobs**, of lengths
528,520 / 528,516 / 523,066 / 173 bytes. The first three identify Qualcomm
`kona` SoC variants **v2.1 / v2 / v1**. This does not establish which
board DTB was actually selected by the running bootloader.

### Research implications

- The extracted Image provides an exact byte artifact for further
  disassembly and comparison with Samsung's released 4.19 sources.
- `CONFIG_FUTEX_PI` and `CONFIG_RT_MUTEXES` are present in the *same*
  binary's embedded config. This remains **insufficient to establish that
  any exploit-relevant vulnerable code is present or reachable**.
- Module signatures, RKP, KDP, DEFEX, bootloader/AVB lock and SELinux
  enforcement remain meaningful constraints.
- `/proc/kallsyms` is unavailable through the current Shizuku shell;
  runtime addresses were **not** recovered.
- Keep all analysis read-only. No boot image modifications or
  flashing are justified by these findings.

## Target reported by device owner

| Field | Reported value | Verification still needed |
|---|---|---|
| Handset | Galaxy S20+ SM-G986U1/DS | Confirmed Android model `SM-G986U1`; `/DS` marketing suffix not surfaced in Build.MODEL |
| SoC | Qualcomm SM8250 / Snapdragon 865 | Build.DEVICE and product variant |
| Kernel | 4.19.113-27095354 | Exact uname -r and compiled kernel hash |
| Modem/baseband | G986U1UESCHXL1 | Actual AP/PDA and CSC build, not inferred from baseband |
| OS | Android 13 / One UI 5.1 | Build fingerprint confirmed; Android security patch `2025-01-01` |
| Bootloader | `G986U1UESCHXL1` | Device reports `ro.boot.flash.locked=1`, vbmeta state `locked`; recovery options still require investigation |

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
