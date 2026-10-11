# HXL1 — reuse Samsung production-kernel QEMU without importing another device's assumptions

**Owner target:** SM-G986U1, `G986U1UESCHXL1`, Qualcomm Snapdragon 865 (Kona), factory Linux 4.19.113. Exact original `kernel.bin` SHA-256: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.

## Owner checkpoint (2026-10-11 13:14 UTC)

- `gcc-aarch64-linux-gnu`, `qemu-user`, `qemu-system-arm`, `gdb-multiarch` installed in Ubuntu 24.04 WSL.
- `python3 tools/y2q_hxl1_original_cleanup_slice.py --require-arm64` output **PASS** and `[ARM64 USER] PASS` at `~/s20-artifacts/hxl1-research/original-cleanup-arm64.json`. This executes the **recompiled original C fragment with inert helpers** in AArch64 Linux user mode, not factory ARM64 kernel bytes.
- The user's first `qemu-system-aarch64 -machine virt,gic-version=3 -cpu cortex-a57 -smp 2 -m 2048 -kernel ~/s20-artifacts/kernel.bin ...` ran for 60 seconds **without console**, then GNU `timeout` exited `124`. No QEMU `-d` instruction trace, GDB PC, actual Linux banner or boot success was observed. **Timeout != crash, panic, or evidence that the kernel reached execution.**
- A transient `systemd-binfmt` installation-trigger failure on WSL did not prevent the direct AArch64 user-mode test from succeeding. Fixing binfmt system service is not required for explicit `qemu-aarch64` execution.

## Owner 13:28 UTC QEMU first-failure baseline

Owner pulled the repository and ran `python3 -m unittest -v tools.test_y2q_hxl1_qemu_earlyboot_triage`: **8/8 PASS**. The dry-run authenticated the **original HXL1 Image SHA256** `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` and reported **ARM64 Image text_offset=0x80000**. The 15-second explicit system emulation returned:

```text
[QEMU] TIMEOUT
[TRACE BLOCKS] True
[LINUX BANNER] False
[REPORT] /home/main/s20-artifacts/hxl1-research/qemu-first-failure-20261011/report.json
```

The owner has not uploaded the `report.json`, `serial-console.log`, or `tcg-instructions.log` bytes. We therefore know **QEMU translated at least one ARM64 basic block** (which may be QEMU's own bootloader stub). The captured summary alone does NOT identify the first factory-image PC, exception, kernel entry, real boot, or failed subsystem. A generic `virt` board's RAM starts at `0x40000000` (per QEMU docs); QEMU's ARM64 loader commonly uses a `0x80000` offset. Thus an expected candidate entry is **0x40080000**, but **that address is a hypothesis, not a verified translated PC**. Next step is **offline analysis of existing trace** before any more emulator launches or changing QEMU's RAM map.

The `timeout=124` from the owner's first 60-second GNU `timeout` is still interpreted as no boot observation; the second bounded `TIMEOUT` shows translated blocks but no Linux banner. Do not conflate the two.

---

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

## 15:22 UTC — exact HXL1 source and RKP bitmap symbol are corroborated

Owner pulled latest branch and ran two suites: `tools.test_y2q_hxl1_qemu_smc_register_capture` **5/5 PASS** (previous output-order test defect corrected), and `tools.test_y2q_hxl1_rkp_bitmap_abi_audit` **18/18 PASS**; overall **23/23 PASS**. Critically, the actual read-only **original retained HXL1 source ABI** and already captured guest GDB trace correlated:

```text
[HXL1 SOURCE] EXACT_LOCAL_SOURCE_DEFINITIONS_MATCH_CAPTURED_RKP_BITMAP_CALL
[APP] 0xc300c002 command 0x15
[GDB] X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000
[X2 SYMBOL] RECOVERED_SYMBOL_ADDRESS_CORRELATES 0xffffff800a4dd0b8
```

Saved `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-source-abi.json`. This is no longer a neighboring-tree hypothesis: the **exact source under `~/src/samsung-y2q-hxl1-stock` matches the secure monitor app/command**, and the recovered (non-factory-DWARF) `rkp_s_bitmap_buffer` symbol address equals guest X2. The original source file hashes are preserved by the owner's JSON report but **were not included in their console output**. Do not invent them in project docs. The prior `secure-monitor-gate.json` was produced *before* the later GDB capture and should not supersede it.

**New consequential platform-emulation requirement:** Review exact original `include/linux/rkp.h`, `arch/arm64/mm/mmu.c`, `init/main.c`, and `arch/arm64/mm/pgd.c` in addition to `uh.h`. A matching `X0/X1` proves call dispatch, **not** how the requested `sparse_bitmap_for_kernel_t` pointer and backing bitmap must be allocated, reserved, mapped or released. On public SM8250 source, `rkp_robuffer_init()` runs in `paging_init()` before `map_kernel` and `map_mem`, and the bitmap check indexes physical memory in `SPARSE_UNIT_BIT=30` chunks with per-page bits. Original HXL1 source agreement with these **additional semantics must be checked separately**.

**Implemented and committed:** `tools/y2q_hxl1_rkp_bitmap_preflight.py`, `tools/test_y2q_hxl1_rkp_bitmap_preflight.py` (14 new synthetic fixture tests, wired into HXL1 CI). The preflight refuses unchanged-source SHA mismatch relative to the prior verified ABI report; inspects command IDs 0x11–0x15, bitmap descriptor fields, 1 GiB sparse-unit calculations, early paging init order, follow-up RKP commands, protected-page allocator demands, and PAGE_SIZE from the owner's config. It writes a **fresh** `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-preflight.json`, marks guest descriptor pool/memory reservation as **UNIMPLEMENTED**, and explicitly reports that the fork is **not ready** even if source checks all pass. It performs **no QEMU launch or on-device operation**. Its WSL/Actions execution result is **NOT VERIFIED** yet.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rkp_bitmap_preflight
python3 tools/y2q_hxl1_rkp_bitmap_preflight.py
```

**Next QEMU implementation gate:** derive a reserved guest-physical memory pool and source-consistent sparse bitmap descriptor whose pages won't be reclaimed by Linux, with strict RKP command dispatch based on **HXL1 `rkp.h`**, not fork `KDP_SET_NS_FLAGS`. Only then build a separate QEMU 10.2.2 target (avoiding `-j$(nproc)` on WSL) and compare it with the already established original QEMU trace. The factory Image must remain immutable, unknown SMCs must not return unconditional success, and current lack of Android/Linux userspace boot or KernelSU must not be promoted into success.

---

## 15:04 UTC — GDB captured RKP-looking bitmap call; upstream KDP ID collision discovered

### Owner successful guest breakpoint (no source-fidelity assumptions)

The owner pulled through `d174944` and ran both SMC check suites: **17/18 tests passed, one test FAILED**. The lone failure was **test guard ordering**: `test_existing_output_is_preserved` constructed an empty temporary HOME with an existing output directory but no stock kernel; the shell script checked `kernel.bin` before checking the existing output directory, so it rejected the missing kernel rather than the already-existing output. This is a test/setup-order defect only; not a problem in the GDB capture. Shell checks were reordered (output preservation and stock image hash verification now precede optional QEMU/GDB binary requirements) and pushed to GitHub; revised suite execution remains unverified.

The stock `tools/y2q_hxl1_qemu_secure_monitor_gate.py` output verified the expected unchanged SMC/LDR/LDP opcodes and created `qemu-first-failure-20261011/secure-monitor-gate.json` (a **historical pre-GDB** report which rightly said X0–X6 unobserved at that time).

The bounded original-image QEMU+GDB execution reported **`HXL1_SMC_BREAKPOINT_HIT`**, with the **actual pre-instruction original HXL1 guest registers**:

```text
PC=0xffffff80080a5794   opcode=d4000003 (SMC #0)
X0=0xc300c002  X1=0x15  X2=0xffffff800a4dd0b8  X3=0x40000000
X4=0x0        X5=0x0   X6=0x3f
```

Full owner WSL report: `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/gdb-session.log`. This is a real guest CPU breakpoint at a factory kernel SMC, **not** proof of a functioning secure monitor, complete kernel boot, exploit or on-device unlock.

### Critical previously unrecognized fork ABI collision (DO NOT run fork handler)

**Public SM8250 kernel source directly pertinent to Samsung 4.19:**
- [nwrafael/android_kernel_samsung_sm8250: include/linux/uh.h](https://github.com/nwrafael/android_kernel_samsung_sm8250/blob/master/include/linux/uh.h) defines `APP_RKP=2`, `UH_PREFIX=0xc300c000`, hence **`UH_APP_RKP=0xc300c002`**. `uh_call` accepts app ID, command, and **four** explicit arguments: X0–X5; the observed `X6=0x3f` may be unrelated and cannot automatically be treated as argument.
- [nwrafael/android_kernel_samsung_sm8250: include/linux/rkp.h](https://github.com/nwrafael/android_kernel_samsung_sm8250/blob/master/include/linux/rkp.h) defines **`RKP_GET_RKP_GET_BUFFER_BITMAP=0x15`** and `rkp_robuffer_init()`, which issues `uh_call(UH_APP_RKP, RKP_GET_RKP_GET_BUFFER_BITMAP, (u64)&rkp_s_bitmap_buffer, (u64)memstart_addr, 0, 0)`. Thus the captured **X0/RKP, X1/bitmap, X2/plausible &rkp_s_bitmap_buffer, X3/QEMU DRAM 0x40000000** closely fit a real SM8250 RKP initialization. But **these are public adjacent-tree definitions**, NOT yet the owner's SHA-recorded exact HXL1 source.
- The inspected [diabl0w/qemu-samsung-kernel QEMU 10.2.2 patch](https://github.com/diabl0w/qemu-samsung-kernel/blob/master/0001-samsung-qualcomm-kernel-emulation.patch) maps **the same X0=0xc300c002 to KDP** and command `0x15` to **`KDP_SET_NS_FLAGS`**, which writes a guest `vfsmount.mnt_flags` int. That handler is **incompatible with** a true RKP bitmap-init call and must not be invoked in the HXL1 guest. The fork also maps `0xc300c001` to RKP, and its RKP command constants are `ROBUFFER_ALLOC=0x07`, `FREE=0x08`, `GET_RO_INFO=0x02`; the adjacent SM8250 `rkp.h` instead defines `ROBUFFER_ALLOC=0x11`, `FREE=0x12`, `GET_RO_BITMAP=0x13`, `GET_DBL_BITMAP=0x14`, `GET_BUFFER_BITMAP=0x15`. **Both application IDs AND command dispatch tables require rederivation for HXL1.** Even a simple app-ID swap is insufficient. The fork's RKP default path returns fake success for unknown commands, so it is not acceptable as an original-source-fidelity model.

### Exact HXL1 source audit now committed

`tools/y2q_hxl1_rkp_bitmap_abi_audit.py` reads `~/src/samsung-y2q-hxl1-stock/include/linux/{uh,rkp}.h` (not third-party source), hashes the two owner source files, validates original GDB `PC`, `d4000003`, `X0…X6`, compares source macro-expansion and `rkp_robuffer_init()` call shape, and independently checks whether the **recovered/approximate** `vmlinux-stock.nm` symbol for `rkp_s_bitmap_buffer` equals X2. If no exact symbol exists, it reports that separately rather than fabricating one. It writes a new (non-overwriting) `qemu-smc-registers-20261011/rkp-bitmap-source-abi.json`. Eighteen **synthetic** regressions committed, but their owner/CI pass and exact HXL1 source match are **not yet observed**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_qemu_smc_register_capture \
  tools.test_y2q_hxl1_rkp_bitmap_abi_audit
python3 tools/y2q_hxl1_rkp_bitmap_abi_audit.py
```

This **does not** start QEMU again. On ABI agreement, the next development step is a separately built, HXL1-gated QEMU secure-call handler that simulates the verified `RKP_GET_RKP_GET_BUFFER_BITMAP` side effects and its memory ownership, informed by original RKP sparse bitmap definitions. It should deliberately **refuse unknown commands** and avoid generic fake-success shortcuts, and never assume S26 physical address windows. We still need to understand expected bitmap lifetime, guest pointer representation and allocations before writing any handler; a matching GDB register capture does not establish those semantics.

---

## 14:48 UTC — original SMC #0 identified, Samsung-QEMU hypervisor handler selected for review

The owner successfully ran the stock-byte original Image ELR attribution tool and **13/13 tests PASS** on WSL. It validated the exact factory `kernel.bin` SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` and produced original-Image byte windows and disassembly for all three QEMU exceptions:

| QEMU exception | original HXL1 Image byte offset | original opcode | decoded instruction | candidate register fact |
|---|---:|---|---|---|
| Undefined Instruction `0xffffff80080a5794` | `0x25794` | `d4000003` | **`SMC #0`** | `X0` function/call ID remains *unobserved* |
| Data Abort FAR `0x58`, `0xffffff80082ac90c` | `0x22c90c` | `f9402eb8` | `LDR X24, [X21,#0x58]` | `X21=0` is consistent with reported FAR, but not independently captured |
| Data Abort FAR `0x10`, `0xffffff80086de39c` | `0x65e39c` | `a9412149` | `LDP X9,X8,[X10,#0x10]` | `X10=0` is consistent for the first load, but paired access and guest register state need confirmation |

**Significant revised conclusion:** The first exception is not an arbitrary unsupported AArch64 opcode. The decoded instruction is `SMC #0`, and the QEMU log gives syndrome EC=0x00 / UDEF, consistent with the generic `virt` setup lacking an appropriate secure-monitor handler for that invocation. It is **not yet proven** the SMC belonged to Samsung UH, RKP, or KDP specifically, because its application/cmd arguments reside in `X0…X6`, which were **not captured** by the previous `-d in_asm,int,guest_errors,unimp` trace. The recovered nearest symbol `back+0` is not a validated factory function identity. Similarly, the two data aborts were labeled `kmem_cache_alloc+0x110` and `dump_stack_minidump+0x80` using **recovered, unverified nearest-lower symbols**, not full original function membership.

### Upstream Samsung production-QEMU component now directly relevant

The [diabl0w/qemu-samsung-kernel patch](https://github.com/diabl0w/qemu-samsung-kernel/blob/master/0001-samsung-qualcomm-kernel-emulation.patch) implements `target/arm/tcg/op_helper.c:HELPER(pre_smc)` with a `handle_uh_call` dispatcher. The fork recognizes Qualcomm-style `X0=0xc300c001` (RKP) and `X0=0xc300c002` (KDP), with `X1` supplying command and `X2…` arguments, alongside another packed call-ID form. This is relevant **architecture to port**, **not** an authorized HXL1 patch yet. It also includes a generic success fallback for unrecognized SMCs and hard-codes another device's physical/virtual memory; copying those behaviors would invalidate research fidelity and may corrupt an emulated guest.

### Committed concrete next steps

1. `tools/y2q_hxl1_qemu_secure_monitor_gate.py` validates the SHA-pinned factory Image against `original-fault-sites.json`, decodes the three exact opcodes, derives conditional near-null register values and **explicitly refuses to identify the SMC call ID without actual guest register data**. Its thirteen offline regression tests are committed.
2. `tools/run_y2q_hxl1_qemu_smc_register_capture.sh` is a **bounded, local-host-only** GDB probe. It validates factory Image SHA, refuses overwriting evidence, launches **unchanged Ubuntu QEMU with the original unmodified Image**, `-S` and a localhost-bound debugger on port `12345`; it requests a hardware breakpoint at `0xffffff80080a5794`, and prints `X0…X6` if GDB actually stops there. It uses a 30-second limit and cleans up the QEMU child. Missed breakpoints are **INCONCLUSIVE**, not proof of a device restriction. Five unit tests (including Bash syntax and no-overwrite guard) are committed.
3. Both test suites are wired into the existing HXL1 isolated CI workflow; their WSL/CI outcome is still **not observed** as of this note.

To validate the offline report without starting QEMU:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_qemu_secure_monitor_gate \
  tools.test_y2q_hxl1_qemu_smc_register_capture
python3 tools/y2q_hxl1_qemu_secure_monitor_gate.py
```

To attempt actual guest-register measurement **after guard tests pass**, still off-device:

```bash
bash tools/run_y2q_hxl1_qemu_smc_register_capture.sh
```

Results are saved at `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/gdb-session.log` and `qemu-exceptions.log`, and the offline classification goes to `qemu-first-failure-20261011/secure-monitor-gate.json`. GDB output contains guest VM registers, not physical handset secrets. If its marker is `HXL1_SMC_BREAKPOINT_HIT`, inspect the captured `X0` and command arguments, then check **original HXL1 UH source** to establish the actual command ABI before attempting a separately built QEMU fork. If it is `INCONCLUSIVE`, inspect `gdb-session.log` for unsupported breakpoint/address semantics and maintain the original boot evidence as-is.

**Do not replace SMC with a NOP, return fake success for unknown secure calls, flash a device, or infer any real exploit/KernelSU route from this virtual-machine fault.** The user has a confirmed locked stock bootloader, and root/deployment remain unverified.

---

## 14:38 UTC owner QEMU exceptions — first evidence of concrete original-kernel faults

The owner ran `tools.test_y2q_hxl1_qemu_exception_summary` **9/9 PASS** and `python3 tools/y2q_hxl1_qemu_exception_summary.py` directly with **success**. It checked the entire retained QEMU log (`216857` bytes; `[PARTIAL] False`) and authenticated the earlier `270` distinct stock Image-offset opcode correlations at candidate QEMU PC `0x40080000`; `[MISMATCH COMPARISONS] 0`.

**Three actual exception entries** were present in the saved `-d int` log:

| Captured QEMU exception | ELR | ESR | FAR | Initial ARM64 syndrome interpretation |
|---|---|---|---|---|
| Undefined Instruction, EL1→EL1 | `0xffffff80080a5794` | `0x02000000` | not reported | EC=0x00, unknown/uncategorized; must inspect original opcode |
| Data Abort, EL1→EL1 | `0xffffff80082ac90c` | `0x96000005` | `0x58` | EC=0x25, DFSC=0x05 (level-1 translation fault), WnR=0 (read) |
| Data Abort, EL1→EL1 | `0xffffff80086de39c` | `0x96000005` | `0x10` | Same data-abort class at a different near-null virtual address |

The sample's **first translated PC** is `0x40000000` (QEMU loader region), and the **last translated PC** is `0xffffff8008146aec`. Neither is established as the last instruction actually executed. `[MATCHES END] 0x2580280…0x2580290` lists the greatest *offsets by numeric address* that matched the original binary, not the last execution stage or the first exception.

Using the prior `vmlinux-to-elf` **reconstructed/guessed** image VA base `0xffffff8008080000`, the ELRs map to possible raw Image offsets `0x25794`, `0x22c90c`, and `0x65e39c`. Treat these as **candidate** mappings until verified against original instruction bytes. The two FARs are compatible with null-related pointer dereferences, **but no actual pointer origin, function identity, or platform dependency has yet been demonstrated**. The Undefined Instruction may be a deliberate trap or unsupported instruction; its original word must be decoded before choosing an emulator CPU feature. The exceptions themselves demonstrate a guest encountered faults—not that an exploit or intended init completed.

**New committed offline original-opcode fault-site tool:** `tools/y2q_hxl1_qemu_fault_sites.py` and `tools/test_y2q_hxl1_qemu_fault_sites.py`. The tool validates the SHA-pinned `kernel.bin`, uses `exception-summary.json`, extracts a bounded byte window at each candidate ELR, optionally cross-references the earlier `vmlinux-stock.nm` (nearest-lower recovered symbol labeled explicitly unverified), decodes ESR/DFSC/WnR, and attempts `aarch64-linux-gnu-objdump` **on just the original instruction bytes**. It does not patch the kernel, rerun QEMU, access the handset or claim guest correctness. The thirteen new tests are wired into `.github/workflows/hxl1-cleanup-model.yml`, but full owner/CI success for those newly committed tests is **not yet verified**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fault_sites
python3 tools/y2q_hxl1_qemu_fault_sites.py
```

Fresh report location: `~/s20-artifacts/hxl1-research/qemu-first-failure-20261011/original-fault-sites.json`. It contains the original word windows and disassembly; use it to decide which **specific** guest CPU-instruction fault or null pointer access needs platform adaptation. **Do not rebuild the Samsung-QEMU fork or patch the original kernel until those faulting instructions are identified.** It is possible the three exceptions are recoverable boot-time probes, not the final reason for missing printk; do not assume any one exception is fatal without executed-block progression.

---

## 14:01 UTC — actual HXL1 factory-image translation verified

**Owner WSL result:** `python3 -m unittest -v tools.test_y2q_hxl1_qemu_trace_attest` reported **19/19 PASS** (zero skip/error). Running the corrected `OBJD-T:`-capable parser against the prior retained 15-second QEMU log produced:

```text
[EVIDENCE] FACTORY_IMAGE_INSTRUCTION_CORRELATION
[TRACE OPCODES] 11502
[BASE] 0x40080000 compared 288 matched 270 tail-matched 0 entry-word True
[BASE] 0x80080000 compared 0 matched 0 tail-matched 0 entry-word False
[REPORT] /home/main/s20-artifacts/hxl1-research/qemu-first-failure-20261011/offline-trace-format-v2.json
```

This establishes **strong original factory Image byte/code correlation at QEMU guest PC addresses beginning at 0x40080000**. The original Image hash was previously pinned and verified, 270 distinct offsets matched, and the entry instruction was included. QEMU produced an early Linux instruction *translation* for the original Image, **not a proven complete Linux initialization or source-faithful guest**. 288 compared opcode lines with 270 distinct matched offsets does not mean 18 different factory instructions mismatch: repeated PC translations are possible, and the JSON's `mismatchedWordComparisons` and `firstMismatch` must be reviewed independently. `tail-matched 0` means the final sampled file section had no distinct matches at that *same fixed candidate base*, not necessarily that execution never later continued in kernel virtual addresses after MMU activation.

**Critical QEMU semantics:** `-d in_asm` logs **translation blocks**, not every executed instruction. Guest PC disassembly is generally a guest virtual address once MMU mappings are enabled. QEMU `-d exec` logs before **executed** translation blocks. Without an exec trace, we **cannot** call the final logged `IN:` block the last executed location. Per QEMU `util/log.c` the `exec` category is separate from `in_asm`; do not infer a precise halt PC from translation order. This distinction must guide next instrumentation.

**Next constrained gate:** summarize the **existing** `offline-trace-format-v2.json` and the exception/guest-error contexts already in `tcg-instructions.log`, including first/last image matches, early exceptions and log-repetition patterns. No more source or opcode provenance steps, kernel flash, emulator fork build, or device probes. Only after reading those observations decide whether a short bounded `-d exec,int,cpu_reset` trace or a GDB halt is necessary.

---

## 13:43 UTC — no recognized opcode lines; trace-dialect fix

Owner pulled through `bc86ca1` and reran the **original existing trace analysis**, with **12/12 synthetic tests PASSED**. Actual saved trace result:

```text
[EVIDENCE] NO_FACTORY_IMAGE_INSTRUCTION_CORRELATION_IN_SAMPLED_TRACE
[TRACE OPCODES] 0
[BASE] 0x40080000 compared 0 matched 0 tail-matched 0 entry-word False
[BASE] 0x80080000 compared 0 matched 0 tail-matched 0 entry-word False
[REPORT] /home/main/s20-artifacts/hxl1-research/qemu-first-failure-20261011/offline-trace-attestation.json
```

**Interpretation corrected:** zero parsed opcode lines means **zero image comparisons attempted**; it is not evidence that the factory kernel did not execute or that all candidate load addresses mismatch. Prior QEMU tool already independently established `IN:` translation-block markers. An unrecognized QEMU logging dialect (e.g. bare PC plus `OBJD-T:` raw hexadecimal guest bytes, or disassembly-only without machine words) is one plausible cause; truncated sampling or logging anomalies remain possible until raw lines are inspected.

**Committed parsing and diagnostic improvements:** `tools/y2q_hxl1_qemu_trace_attest.py` now reports a distinct `PC_ADDRESSES_PRESENT_BUT_NO_PARSEABLE_OPCODE_WORDS` or `IN_ASM_SECTIONS_PRESENT_BUT_PC_FORMAT_UNKNOWN` status where appropriate, prints selected escaped log lines and PC-address samples on zero parsed words, and supports a second QEMU `-d in_asm` fallback format with bare `0xPC:` lines followed by `OBJD-T:` little-endian target instruction bytes. `OBJD-H:` host-JIT bytes are never treated as guest AArch64 words. Nineteen unit tests are committed (older 12 plus seven trace-format fixtures), but **the current 19-test suite and real original trace parsing have not yet been rerun on WSL**. A focused manual check of `OBJD-T` little-endian byte reconstruction passed in the assistant environment; this is not a substitute for WSL.

Use **the original existing QEMU trace**, not a new QEMU boot. Existing output `offline-trace-attestation.json` must be kept immutable. Choose a fresh report path:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_trace_attest
python3 tools/y2q_hxl1_qemu_trace_attest.py \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-first-failure-20261011/offline-trace-format-v2.json"
```

If this produces `[TRACE OPCODES] 0` again, the diagnostic will print first log lines and QEMU-PC samples, allowing us to extend the parser based on the **real format** rather than speculative addresses or guest patches. A matched opcode sequence is still only original-Image code correlation, not a complete Linux boot or root primitive.

---

## 13:37 UTC owner-run trace attestor failure and correction

The owner pulled through `da72394` and executed `tools.test_y2q_hxl1_qemu_trace_attest`, then the real offline trace analyzer. **4 of 10 tests passed and 6 errored** (not an assertion failure or stock kernel failure). The identical traceback in six tests and the real analyzer was:

```text
tools/y2q_hxl1_qemu_trace_attest.py:135
"factoryImageCorrelatedInTail": any(
    r["multiInstructionBinaryCorrelation"] for r in tail_results)
TypeError: string indices must be integers, not 'str'
```

**Cause:** In `analyze()`, `tail_results` initially held the `match_words` result list, then was reassigned to a dictionary keyed by `candidateImagePhysicalStart`; the final `for r in tail_results` loop iterated dictionary string keys. This occurred after the successful original Image SHA check and after reading the existing saved QEMU trace, preventing output report generation. It **does not** establish any success/failure of factory kernel boot or opcode correlation.

**Remediation already committed:** retain original tail list as `tail_records`, construct a separate dictionary for lookup, and evaluate the tail-correlation flag over `tail_records`. Two additional tests assert empty-head/empty-tail produces no false correlation and simultaneous head/tail matches remain independent, bringing the suite to **12** tests. No additional QEMU launch, extraction, or kernel source scan is needed. The new suite has **not yet been independently run on the owner's WSL**; no PASS is claimed. On owner WSL, run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_trace_attest
python3 tools/y2q_hxl1_qemu_trace_attest.py
```

This should consume the original **already retained** `qemu-first-failure-20261011/tcg-instructions.log` and `serial-console.log`. If it emits `[STOP] Refuse report overwrite...`, inspect whether an output file exists and specify a fresh `--output` path instead of deleting the original evidence. Share the resulting compact JSON, not the multi-megabyte TCG log unless the report is insufficient.

---

## 13:28 UTC follow-up — offline existing-trace image opcode attestation

New committed offline analyzer `tools/y2q_hxl1_qemu_trace_attest.py` and synthetic tests `tools/test_y2q_hxl1_qemu_trace_attest.py` consume the **already completed** `qemu-first-failure-20261011` trace, serial log and SHA-pinned unmodified `kernel.bin`. This process NEVER runs QEMU. It samples at most 12 MiB of trace head and 3 MiB of trace tail, compares actual ARM64 translated PC/opcode pairs to the bytes at matching offsets in the original factory Image, and reports any matches/mismatches under candidate Image physical start addresses.

Stock QEMU `virt` RAM starts at `0x40000000`, and standard QEMU ARM64 boot loading traditionally uses `KERNEL64_LOAD_ADDR=0x80000`. Coupled with the independently inspected HXL1 Image `text_offset=0x80000`, the **candidate Image physical start = 0x40080000**, but only an opcode-level match can corroborate it. An additional simple Samsung fork RAM-base candidate `0x80080000` is included for comparison; **actual patched fork boot.c overrides load offsets further**, so neither base is certified. Use `--physical-base 0xHEX` only when a separate observed PC motivates it.

To analyze without another emulation run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_trace_attest
python3 tools/y2q_hxl1_qemu_trace_attest.py
```

Fresh output: `~/s20-artifacts/hxl1-research/qemu-first-failure-20261011/offline-trace-attestation.json`. The JSON includes selected translated PCs and opcodes even **when no Image match is found**, trace size/sampling coverage, possible exception/banner signals, and all offset-compared opcode witnesses. The script and tests were committed, **but the owner has not yet executed them against the local trace**. Test outcome should not be claimed until CI or WSL actually runs.

**Acceptance:**
- `NO_FACTORY_IMAGE_INSTRUCTION_CORRELATION_IN_SAMPLED_TRACE`: original kernel entry not evidenced, *not proof it did not execute*; inspect earliest translated PCs and QEMU header loading before modifying QEMU.
- `FACTORY_IMAGE_INSTRUCTION_CORRELATION`: at least four distinct original Image offsets matched with at least three distinct instruction words under one hypothesized placement. This is byte-level execution-location evidence, **not Linux boot**, and not necessarily the boot entry since it could be another translated copy of Image words.
- `LinuxBootBannerSeen` is independent serial evidence. `TIMEOUT` is independent process-state evidence. Never infer Linux boot, privilege escalation, or a source-faithful guest solely from the translator output.

The Samsung production-kernel fork is now a **reference implementation for platform emulation only**. Do not run `build-qemu-samsung.sh` or copy its guest carveouts/security semantics until this original trace identifies a specific unsupported boot dependency.

---

## Controlled comparison with a separately built fork (later, only if needed)

Use a separate directory for upstream source, not the user's HXL1 repo or kernel image. Avoid installing a patched emulator system-wide. The fork's `build-qemu-samsung.sh` builds private QEMU 10.2.2 and defaults to parallelism `nproc`, so first decide WSL resource limits and whether a *small, HXL1-gated subset* of the patch is necessary. After a verified fork build, use **the same** `tools/y2q_hxl1_qemu_earlyboot_triage.py` `--qemu /path/to/custom/qemu-system-aarch64` option to compare against system QEMU with a fresh output directory; never combine outcomes or re-use a prior report path.

## Gate decision

The original HXL1 **verbatim C cleanup** and AArch64 user-mode recompiled fragment are verified. Real original ARM64 `kernel.bin` execution, Samsung Linux boot, real futex/RT-mutex state, kernel code-loading route, bootloader unlock and KernelSU remain **NOT VERIFIED/BLOCKED**. Do not create an HXL1 root profile or run dangerous race probes on the physical phone based on this research-only simulation.
