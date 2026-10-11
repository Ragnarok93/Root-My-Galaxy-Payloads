# HXL1 — reuse Samsung production-kernel QEMU without importing another device's assumptions

**Owner target:** SM-G986U1, `G986U1UESCHXL1`, Qualcomm Snapdragon 865 (Kona), factory Linux 4.19.113. Exact original `kernel.bin` SHA-256: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.

## Owner checkpoint (2026-10-11 13:14 UTC)

- `gcc-aarch64-linux-gnu`, `qemu-user`, `qemu-system-arm`, `gdb-multiarch` installed in Ubuntu 24.04 WSL.
- `python3 tools/y2q_hxl1_original_cleanup_slice.py --require-arm64` output **PASS** and `[ARM64 USER] PASS` at `~/s20-artifacts/hxl1-research/original-cleanup-arm64.json`. This executes the **recompiled original C fragment with inert helpers** in AArch64 Linux user mode, not factory ARM64 kernel bytes.
- The user's first `qemu-system-aarch64 -machine virt,gic-version=3 -cpu cortex-a57 -smp 2 -m 2048 -kernel ~/s20-artifacts/kernel.bin ...` ran for 60 seconds **without console**, then GNU `timeout` exited `124`. No QEMU `-d` instruction trace, GDB PC, actual Linux banner or boot success was observed. **Timeout != crash, panic, or evidence that the kernel reached execution.**
- A transient `systemd-binfmt` installation-trigger failure on WSL did not prevent the direct AArch64 user-mode test from succeeding. Fixing binfmt system service is not required for explicit `qemu-aarch64` execution.

## Inspected third-party references (NOT pre-ported to HXL1)

1. [diabl0w/qemu-samsung-kernel](https://github.com/diabl0w/qemu-samsung-kernel), `README.md`, `build-qemu-samsung.sh`, `run.sh`, and `0001-samsung-qualcomm-kernel-emulation.patch`. The build script targets a private install of **QEMU 10.2.2** and the patch changes `hw/arm/boot.c`, `hw/arm/virt.c`, `target/arm/tcg/cpu64.c` and `target/arm/tcg/op_helper.c`. Its fork README reports booting Samsung 6.12 kernels. **The patch does not apply verbatim to Ubuntu's QEMU 8.2.2**.
2. [sarabpal-dev/qemu](https://github.com/sarabpal-dev/qemu), branch `samsung`, the fork cited by diabl0w. The QEMU 10.2.2 patch is described as a backport of its emulation work.
3. [polygraphene/qemu-galaxy-s26-kernel](https://github.com/polygraphene/qemu-galaxy-s26-kernel), `patch.py` and `README.md`. Its hard-coded ARM64 image base `0xffffffc080000000`, exact per-build patch addresses and newer Galaxy S26-only security transformations are **NOT valid** for HXL1, whose recovered text base is `0xffffff8008080000`. Do **not** run that patcher on HXL1.

### Fork feature adoption matrix

| Feature in third-party work | HXL1 treatment | Reason |
|---|---|---|
| Serial/TCG tracing, GDB workflow, isolated output | **REUSE NOW** | Generic, non-mutating diagnosis |
| Basic ARM64 Image header interpretation/DTB placement | **REVIEW/PORT IF BASELINE REQUIRES** | Fork changes kernel entry and load handling; HXL1 Image header and console must first be measured |
| Qualcomm `virt` RAM map and carveouts | **REDERIVE** | Fork hard-codes a different SoC's RAM holes, high memory, and RKP pool |
| MPIDR cluster/CPU topology and CPU feature mask | **REDERIVE** | Fork's 8-core arrangement/frequencies and A710 user config are not factory SD865 facts |
| Samsung uH HVC/SMC handlers (RKP/KDP) | **CONCEPTUALLY REUSABLE LATER** | Interfaces, struct expectations, EL transitions, and physical addresses differ; verify HXL1 original source and guest fault before introducing stubs |
| DEFEX `dpolicy` / initramfs construction | **INVESTIGATE ONLY IF REACHED** | Newer Android vendor_boot layout and DEFEX policy location may not match HXL1 boot-v2; no cross-version policy copies |
| Binary NOP patches to RKP/KDP/DEFEX, fixed addresses from S26 | **DO NOT REUSE** | Would alter protected kernel behaviors and invalidate original binary execution evidence |
| Wholesale fork patch / `build-qemu-samsung.sh` | **NOT YET** | Device-specific global `virt` map override, QEMU 10.2.2 build cost, and default `-j$(nproc)` may exceed WSL resources |

Do not assert 2026 S26 DEFEX policy/boot partition details for 2020 HXL1 without inspecting HXL1's actual boot-v2 artifacts. All third-party references are outside the project's original OEM source/binary provenance.

## New automated original-kernel first-failure probe

The committed `tools/y2q_hxl1_qemu_earlyboot_triage.py` refuses a kernel whose full SHA-256 differs from the pinned HXL1 original Image; validates the ARM64 Image header; defaults to dry-run; and on explicit `--execute` uses a 15-second bounded QEMU system-emu run. It records a separate serial log, QEMU `in_asm/int/guest_errors/unimp` instruction trace, and machine-readable status JSON. **It does not patch a kernel, manipulate DTBs, use a shell, contact ADB, or claim the original function executed from translated boot-stub trace alone.**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_earlyboot_triage

# Read-only plan and Image integrity gate:
python3 tools/y2q_hxl1_qemu_earlyboot_triage.py

# First original-image execution diagnostic:
python3 tools/y2q_hxl1_qemu_earlyboot_triage.py \
  --execute --seconds 15 \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-first-failure-20261011"
```

The output directory **must not already exist**. The script captures `serial-console.log`, `tcg-instructions.log`, and `report.json`; upload those three if console stays silent (logs may contain original unslid kernel addresses, not privileged real-device observations).

**Classify**:
- `TIMEOUT` + **no trace**: QEMU execution or logging setup unconfirmed; inspect version, process and `-d` output before making loader changes.
- `TIMEOUT` + trace blocks: QEMU translated boot ROM or ARM64 code; compare translated PCs and original Image load address before asserting Samsung kernel entry.
- First Linux boot banner: meaningful original-Image boot progress, but still not a successful source-faithful guest.
- Panic or exception logs: retain original stack/PC and check **which** HXL1 initialization dependency failed; only then consider porting one clearly identified fork emulation handler.

## Controlled comparison with a separately built fork (later, only if needed)

Use a separate directory for upstream source, not the user's HXL1 repo or kernel image. Avoid installing a patched emulator system-wide. The fork's `build-qemu-samsung.sh` builds private QEMU 10.2.2 and defaults to parallelism `nproc`, so first decide WSL resource limits and whether a *small, HXL1-gated subset* of the patch is necessary. After a verified fork build, use **the same** `tools/y2q_hxl1_qemu_earlyboot_triage.py` `--qemu /path/to/custom/qemu-system-aarch64` option to compare against system QEMU with a fresh output directory; never combine outcomes or re-use a prior report path.

## Gate decision

The original HXL1 **verbatim C cleanup** and AArch64 user-mode recompiled fragment are verified. Real original ARM64 `kernel.bin` execution, Samsung Linux boot, real futex/RT-mutex state, kernel code-loading route, bootloader unlock and KernelSU remain **NOT VERIFIED/BLOCKED**. Do not create an HXL1 root profile or run dangerous race probes on the physical phone based on this research-only simulation.
