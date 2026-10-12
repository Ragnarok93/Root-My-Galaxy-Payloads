# Galaxy S20+ HXL1 — single-command porting automation

**Scope:** `SM-G986U1`, exact `G986U1UESCHXL1`, Linux `4.19.113-27095354`. This is a **host-only research evidence and diagnostic pipeline**, **not** a working Root-My-Galaxy exploit, a bootloader unlock, a KernelSU loader, or a production support profile.

## Why this exists

Earlier HXL1 work required executing dozens of small WSL commands and manually connecting results. Most of those commands were repeated source/ABI and factory firmware checks that could be orchestrated. **Stage 3 must not be kept open merely because nobody ran another audit.** But a genuine missing fact—e.g., the OEM's complete compiled `rt_mutex_waiter` layout—cannot be inferred from a different compiler's DWARF. The new pipeline runs all existing safe checks together and reports the remaining independently verifiable facts rather than calling tests successful exploitation.

## One WSL command

```bash
cd ~/src/Root-My-Galaxy-Payloads

# Fast-forward the current checkout, then execute all host-safe HXL1 stages.
# Each run creates a fresh, immutable evidence and status directory.
bash tools/run_y2q_hxl1_porting_automation.sh
```

Use `--mode plan` to enumerate the steps without running them or creating artifacts. If the Android NDK is installed, set `ANDROID_NDK_HOME` to its actual directory before running. Otherwise the non-root identity diagnostic build and bundle are explicitly **skipped**, without aborting the independent evidence tasks. Use `--output-dir <new-directory>` if a custom fresh report path is needed.

The tool SHA256-verifies **original factory** `~/s20-artifacts/kernel.bin` (`ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`) and stock `config.gz` (`1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd`) **before executing the pipeline**. If either fails, the whole run stops. It uses the original Samsung source tree at `~/src/samsung-y2q-hxl1-stock`; no kernel recompilation is attempted.

## What runs automatically

| Porting stage | Existing verification invoked | Output and significance |
|---|---|---|
| 1–2 / 7–9 | `y2q_porting_readiness.py` | Exact identity, source hashes and nine acceptance gates; never hides blocked stages |
| 3 | `y2q_stage3_layout_inventory.py` | OEM source declarations and recovered binary/debug inventory |
| 3 | `y2q_hxl1_kernel_proof_matrix.py` | Correlates stock sources, Clang18 exploratory objects and exact evidence; flags OEM ABI equivalence **unverified** |
| 3 | `y2q_export_table_audit.py` | Original ARM64 stock exported-symbol table candidates |
| 4 | `y2q_stock_boot_v2_audit.py` | Original Android boot v2/embedded component consistency; header addresses are not actual live physical addresses |
| 4 | `y2q_stock_fdt_semantic_audit.py` | Original four DTB semantic inventories |
| 5 | `y2q_ghostlock_static_audit.py` | Existing source/binary GhostLock review correlation, when original analysis artifacts are present |
| 5 | `y2q_research_toolchain.py scan` | Exact source + firmware-fingerprint-locked CVE research candidate, when original source-audit artifact is present |
| 6 | `y2q_research_toolchain.py build-probe` | Optional **unprivileged identity-only** AArch64 diagnostic, with NDK installed and source scan passed |
| 6 | `y2q_research_toolchain.py bundle` | Optional research/diagnostics-only bundle, never an exploit or active payload |

Every step gets a stored log, status `PASS`, `FAIL`, `SKIP_DEPENDENCY` or `SKIP_MISSING_PREREQUISITE`. Failures in one independent audit do not erase other verified evidence. The JSON/Markdown final report lists **all nine stages** and each exact proof still missing.

Reports are written under a new `~/s20-artifacts/hxl1-research/port-automation-<UTC timestamp>/` with:

- `port-automation.md`: single human-readable state/checklist
- `port-automation.json`: machine-readable gate and result data
- `logs/*.log`: bounded process output for each executed tool
- Individual **fresh** verification output files

**No `git push`, phone ADB/fastboot, flashing, guest memory patching, root operation, `qemu-system-aarch64`, KernelSU loading, or support feed publication is performed.** Only the optional NDK diagnostic is compiled, and it cannot root a phone.

## Non-automatable acceptance gates

1. Stage 3: source/compiled member layout *for the actual Samsung factory kernel* must be proved independently; Clang18 build outputs are only experimental. Do not put guessed pointers or offsets in production `target.h`.
2. Stage 4: the **physical-device** bootloader-selected kernel load and effective DTB/handoff are distinct from the already verified *QEMU virt* early-entry/FDT.
3. Stage 5: a repeatable GhostLock vulnerability primitive, real KASLR/trace prerequisites and controlled privilege transition must be demonstrated under HXL1; code-pattern matches alone do not establish device exploitability.
4. Stage 6: a native HXL1 executable **root** implementation and verified hardware behavior are not produced by a diagnostic .so.
5. Stage 7: stock `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_KPROBES=n`, UH/RKP/KDP/DEFEX constraints and a compatible KernelSU 4.19 hook/loader remain unresolved.
6. Stages 8–9: only publish an exact-match support profile after a reproducible on-device root and module-load proof, and a recovery/release plan.

This makes a **single repeatable request** sufficient to update the existing evidence state; it does not fabricate missing hardware, runtime exploits, or OEM debugging information. GitHub Actions runs automated fixtures and integration tests, but the real owner WSL firmware artifacts are not accessible to a hosted GitHub runner. The owner-host report is the authoritative full-input evidence result.

Relevant references: [PORTING.md](PORTING.md), [HXL1 readiness](SM-G986U1-G986U1UESCHXL1.md), [HXL1 research execution](SM-G986U1-HXL1-NEXT-STEPS.md), and [KernelSU Samsung module constraints](../kernelsu/README.md).
