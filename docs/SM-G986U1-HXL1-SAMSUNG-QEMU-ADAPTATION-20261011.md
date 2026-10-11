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
