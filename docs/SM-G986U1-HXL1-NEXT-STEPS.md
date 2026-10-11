# SM-G986U1 HXL1 — current porting execution guide

**Current October 11 REA FDT/boot-chain evidence:** [verified overlay composition, calculated FDT copy, boot/recovery component lookup, gzip classifier and remaining gates](SM-G986U1-HXL1-ABL-FDT-BOOTCHAIN-20261011.md). This research note supersedes earlier tentative names for `FUN_000228e0` and `FUN_00023a78`; root feasibility remains unproven.

## October 11, 13:14 UTC — AArch64 user PASS, silent stock QEMU timeout, Samsung QEMU adoption

**Owner-observed results:**
- `gcc-aarch64-linux-gnu`, `qemu-user`, `qemu-system-arm` and `gdb-multiarch` now installed on Ubuntu 24.04 WSL. Direct AArch64 user emulation of the SHA-pinned `remove_waiter` *recompiled C fragment* PASSED: `[ARM64 USER] PASS`. Report: `~/s20-artifacts/hxl1-research/original-cleanup-arm64.json`. A `systemd-binfmt` trigger warning did not prevent direct `qemu-aarch64` execution.
- First `qemu-system-aarch64` stock original `kernel.bin` attempt (generic `virt,gic-version=3`, Cortex-A57, SMP2, 2 GiB) printed nothing for 60 seconds; GNU timeout exit `124`. There was **no TCG trace/GDB PC/early console**, so this is **no observable boot**, not a proven kernel crash or known entry point.
- The user explicitly requested reuse of existing public Samsung production-kernel QEMU work wherever beneficial. [Specific fork analysis, reuse matrix, and next bounded probe](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md) inspect the actual `diabl0w/qemu-samsung-kernel` QEMU 10.2.2 patch and S26 references. Key warning: fork hard-codes a *different* SoC's high/low memory carveouts, UH/KDP semantics and AArch64 kernel load/physical assumptions. Do NOT blindly patch HXL1 or substitute its DEFEX policy. Do NOT simply execute `build-qemu-samsung.sh` at `-j$(nproc)` on resource-limited WSL.
- **New executable research tool committed:** `tools/y2q_hxl1_qemu_earlyboot_triage.py` and `tools/test_y2q_hxl1_qemu_earlyboot_triage.py`. It accepts only the original pinned HXL1 kernel SHA and ARM64 Image header, defaults to read-only plan, and on explicit `--execute` logs QEMU serial plus bounded TCG instruction/exception traces for a 15-second window. The tool and its synthetic fake-QEMU tests were added to `.github/workflows/hxl1-cleanup-model.yml`; **remote Actions pass has not been verified**.
- On receiving `qemu-first-failure-20261011/{report.json,serial-console.log,tcg-instructions.log}`, classify actual boot entry or the first guest exception. Port **only** a proven necessary, separately audited fork component with HXL1-specific address/memory/hypercall provenance.

**Readiness:** AArch64 user-space original source-fragment execution COMPLETE. Factory original ARM64 kernel boot, source-faithful guest, RT-mutex runtime reproduction, bootloader unlock and KernelSU remain unverified/blocked. Avoid re-running completed source/REA/instruction-window investigations.

---

## October 11, 12:50 UTC — OEM C fragment passed; original opcode store path additionally bounded

The owner's WSL source-fragment run PASSED the exact original Samsung RT-mutex SHA-gated native harness; **five unit tests passed, one optional ARM64 QEMU user test skipped** due to unavailable emulator/toolchain. Report: `~/s20-artifacts/hxl1-research/original-source-fragment-regression.json`. This fulfills the native verbatim-C fragment subgate only.

The assistant independently used owner-uploaded stock-Image-derived code-slice and REA ZIPs to authenticate the full `remove_waiter` slice and interpret a **15-original-instruction bounded path** to `str xzr,[x20,#0x8f8]`. Both synthetic task-identity cases and **6/6 tests** passed, including byte tamper rejection. [Detailed constrained original ARM64 trace](SM-G986U1-HXL1-BOUNDED-ORIGINAL-BINARY-TRACE-20261011.md). The reusable script/tests/report were delivered separately in `HXL1-bounded-original-ARM64-trace.zip` and are **not yet checked into this GitHub repo**. This interpretation does not execute OEM code in a real ARM64 CPU or faithful guest, and it does not verify any kernel exploitation path.

**Do not repeat these passing user-space/static tasks.** The consequential next feasibility decision is whether Samsung Linux 4.19.113 can be genuinely booted or otherwise safely executed in a source-faithful isolated guest, or whether an authorized live kernel-code-loading route exists. The installed upstream Linux 4.19.325 QEMU control is insufficient, and the locked stock build has forced module signatures and kprobes disabled. Stage 3 remains PARTIAL, KernelSU/deployment BLOCKED.

---

## October 11, 12:35 UTC — original Samsung C function fragment execution preparation

The owner executed the existing model on WSL at 12:30 UTC, with original Samsung C source SHA checks and ten compiled user-space scenarios `PASS`; report `~/s20-artifacts/hxl1-research/cleanup-model.json`. That model-only milestone is COMPLETE.

**New committed next step:** `tools/y2q_hxl1_original_cleanup_slice.py`, `tools/test_y2q_hxl1_original_cleanup_slice.py`, and CI additions to `.github/workflows/hxl1-cleanup-model.yml`. The tool extracts the **actual unedited `remove_waiter()` C function-definition text** from the SHA-pinned original Samsung RT-mutex source and compiles it in a disposable harness with mocked kernel helpers and a controlled no-owner early-return. Cases `current == waiter->task` and `current != waiter->task` check which synthetic task's blocked-on state gets cleared. Five isolated tests, including real C compilation and false-source SHA/modified behavior rejection, PASSED on a representative Linux 4.19-shaped fixture. Optional `aarch64-linux-gnu-gcc`/`qemu-aarch64` allows cross-compiled **ARM64 USER-MODE** execution; this is **not a kernel guest boot** and must not be described as one.

Owner-specific original Samsung C execution has **not yet been run**; [one-shot instructions and limits](SM-G986U1-HXL1-VERBATIM-CLEANUP-GUEST-SLICE-20261011.md). The exact Samsung RT-mutex C file SHA is enforced before compilation. A compiler error due to unmocked OEM dependencies is a **real harness compatibility block** to correct rather than an excuse to mark a PASS.

**No kernel-runtime gate is promoted by this source fragment.** Authentic Samsung `kernel.bin` execution in a source-faithful AArch64 Linux QEMU guest, real PI state corruption, a kernel arbitrary memory primitive, physical loader/KASLR verification, bootloader unlock and KernelSU code injection remain NOT VERIFIED/BLOCKED. Existing upstream 4.19.325 guest cannot substitute for HXL1; actual Samsung 4.19.113 has SoC/Kconfig constraints on the generic QEMU `virt` machine.

---

## October 11, 12:08 UTC — deterministic cleanup ownership regression (user-space only)

**Committed implementation:** `tools/y2q_hxl1_cleanup_regression.py` is a pinned-source-gated, ten-scenario **compiled user-space C state model**. `tools/test_y2q_hxl1_cleanup_regression.py` provides 8 isolated positive and negative regression tests. All eight passed in the assistant's host environment; the compiled C model also produced the expected ownership divergence for `waiter_task != current` and negative rollback return. An isolated GitHub Actions workflow `.github/workflows/hxl1-cleanup-model.yml` was committed to run these mock/source-independent unit tests on push and PR (remote Actions result **not yet independently confirmed**). [Execution instructions](SM-G986U1-HXL1-USERSPACE-CLEANUP-REGRESSION-20261011.md).

The model checks the same **two pinned Samsung source hashes** and **six source indicators** already defined by `tools/y2q_rtmutex_fix_audit.py` when run against the user's HXL1 WSL checkout. It compares a stock `ret != 0; selected_task = current` cleanup with a corrected `ret < 0; selected_task = waiter.task` and non-enqueued guard. It never invokes kernel futex calls, syscalls, races, device interfaces or kernel modules.

**Observed in compiled *simulation* (not an OEM execution):** on negative return, with different current/waiter task identities, the stock model clears current's PI-blocked flag while the corrected model clears the waiter's. On a zero return neither model cleans up; on a positive return the original nonzero branch still invokes modeled cleanup but corrected negative-only branch does not.

**Critical non-promotion:** passing model tests **does not** demonstrate that the HXL1 kernel executes the mismatched path under real Android scheduling, that the source is faithful in a disposable guest, that any arbitrary read/write primitive exists, or that KernelSU can load on the locked SM-G986U1. `sourceExactKernelGuestReproduced`, `hxl1RuntimeReachabilityProven`, `rootPrimitiveVerified`, `kernelSuInstallable` remain **false**. Original kernel assembly and source correlation documented previously is a separate proof category. Next necessary engineering gate is **actual HXL1-source-faithful guest execution**, not repetition of the model; if such a guest cannot be built/reproduced, the correct status remains `NOT_TESTED`.

---

## October 11, 11:43 UTC — authenticated subset of original RT-mutex and waiter displacements

A new offline pass reused the owner's previous original REA/ELF ZIP evidence and **independently reverified 723/723 Ghidra instructions against LLVM plus 31 specific additional byte-identical compiled RT-mutex/waiter instruction witnesses**. Eight focused full LLVM/subset tests and seven separately committed pinned-byte/source-header attestor tests passed locally (15 in total). Findings: `rt_mutex` candidate waiters.rb_root at `+0x10`, waiters.rb_leftmost at `+0x18`, owner at `+0x20`; `rt_mutex_waiter` candidate `tree_entry +0x00`, `pi_tree_entry +0x18`, `task +0x30`, `lock +0x38`, `prio +0x40`, `deadline +0x48`. The waiter priority and deadline each have **direct and nested PI-tree instruction pathways** that agree algebraically. See [the focused RT-mutex analysis](SM-G986U1-HXL1-STAGE3-RTMUTEX-LAYOUT-20261011.md).

**New runnable GitHub code** now committed: `tools/y2q_hxl1_rtmutex_displacement_attest.py` and `tools/test_y2q_hxl1_rtmutex_displacement_attest.py`. The attestor independently re-verifies the 31 pinned machine words and their ELF SHA digests, and has optional `--source` support to validate the **actual owner's exact Samsung HXL1 source** by pre-known RT-mutex/futex C SHA pins. It then records SHA digests, declaration order and conditional-member presence for `include/linux/rtmutex.h` and `kernel/locking/rtmutex_common.h`. See the [single-pass source checking instructions](SM-G986U1-HXL1-RTMUTEX-ATTEST-RUN.md). The full more general LLVM analyzer and frozen report are delivered as `HXL1-Stage3-v6-rtmutex-layout-subset.zip`, not yet in GitHub. Avoid repeated REA/bootchain/stock firmware inventory commands.

**Gate unchanged:** despite this meaningful compiled type subset, original factory DWARF/BTF and complete type sizes/conditional fields are not established; Stage 3 stays PARTIAL. No runtime read/write primitive, root or KernelSU demonstrated.

---

## October 11, 11:33 UTC — compiled member attribution and proxy-cleanup control flow

Verified **new Stage-3 subset** offline from the owner's two previously exported archives, without repeating REA or accessing a phone. The independent AArch64 decoder agreed on **723/723** REA-reported instructions; 38 annotated, exact code witnesses and 12 negative/positive opcode-and-attribution tests passed. See [the focused evidence report](SM-G986U1-HXL1-STAGE3-MEMBER-CORRELATION-20261011.md).

- `task_struct.pi_lock` candidate compiled displacement `0x8c8` relative to current (from `mrs sp_el0`) and relative to a separate masked owner pointer.
- `task_struct.pi_waiters` candidate `0x8e0` owner-relative; `task_struct.pi_blocked_on` candidate `0x8f8`, independently used with distinct current and owner registers.
- `task_struct.pi_state_cache` candidate `0x9f8` from futex cache load/store, **provisional** pending local exact-source behavior mapping.
- `rt_mutex_start_proxy_lock+0x34` takes cleanup on a nonzero return path, and `+0x44` directly calls `remove_waiter`. `remove_waiter+0x68` performs current-relative PI field clear. `remove_waiter+0x19c` passes current in `x5` to the next call. This matches the general source-level ownership bug review, not a demonstrated exploit.
- The assistant produced `HXL1-Stage3-v5-correlation.zip` (offline audit, original pinned-source optional checks, report, tests). The scripts are **delivered as an archive, not yet committed to GitHub**. Tests were executed in the assistant's container with the supplied archives; the exact local Samsung C file bytes were **not** uploaded. Prior owner-executed SHA checks attest those files, but this pass cannot independently compile full factory type layouts.

**Readiness unchanged:** Stage 3 PARTIAL pending independently authenticated full OEM type layout and runtime evidence. Stages 4–6 OPEN, KernelSU BLOCKED. No bootloader unlock, root, code execution on handset or flash.

---

## October 11, 11:24 UTC — independent complete slice bytes/LLVM crosscheck

The owner uploaded `HXL1-Stage3-Code-Slices.zip` containing three synthetic ELF64 AArch64 files from the already validated v4.2 run. This independent offline pass consumed the **three original REA JSON reports and manifest plus these three ELF files**, verified each entire ELF SHA-256 against the manifest, verified each `.text` SHA-256 against the manifest's saved stock-byte digest, and used a **separate LLVM AArch64 instruction decoder** (not Ghidra) to cover each four-byte location. This is a re-verification of the owner's saved exact-stock snapshot, **not direct access to the complete 52-MB factory Image or original factory DWARF**. No phone access or new REA was necessary.

| Original function | Slice bytes | REA reported/LLVM matching | LLVM-decoded slice slots | All 4-byte slots |
|---|---:|---:|---:|---:|
| `remove_waiter` `0xffffff8008147db4` | 568 | 140 / 140 | 141 | 142 |
| `rt_mutex_start_proxy_lock` `0xffffff8008147d14` | 160 | 38 / 38 | 39 | 40 |
| `futex_lock_pi` `0xffffff8008191984` | 2216 | 545 / 545 | 553 | 554 |
| **Total** | **2944** | **723 / 723** | **733** | **736** |

**New verification level:** zero mnemonic/operand differences for **all 723 reported REA instructions**, after explicitly normalizing only equivalent assembler notation (e.g. `b.cs` vs `b.hs`, hex vs decimal immediates, signed/wrapped ARM64 constants, register-index shift 0). Prior v4.2 had checked the independent objdump prefix of **16 instructions per function**; this separate pass extends comparison to the **entire reported instruction sets**. Test coverage: six isolated automated tests, including tampered ELF, tampered REA operand, and altered stock-manifest rejection, all PASS.

**All 13 REA-omitted words classified, not assumed to be gaps in OEM bytes:**
- `remove_waiter`: `+0x230` = `nop`; `+0x234` = undecodable `0x00be7bad`.
- `rt_mutex_start_proxy_lock`: `+0x98` = `nop`; `+0x9c` = undecodable `0x00be7bad`.
- `futex_lock_pi`: `+0x530` = `b +0x540`; `+0x538`=`ldr x26,[sp]`; `+0x53c`=`mov x27,x21`; `+0x540`=`mov w28,#0xbeff`; `+0x544`=`adrp x19,...`; `+0x548`=`movk w28,#0xdead,lsl #16`; `+0x828`=`b +0x804`; `+0x848`=`b +0x578`; `+0x8a4`=undecodable `0x00be7bad`.
The `mov/movk` pair would construct `0xdeadbeff` in `w28` if executed; **the runtime execution/reachability of these omitted instructions is not established**. The identical `0x00be7bad` final word in all slices is genuinely in the uploaded, manifest-pinned original bytes; its compiler/toolchain purpose is **unknown**. Six of the ten valid omitted instructions are clustered in `futex_lock_pi+0x538...+0x548`, outside Ghidra's non-contiguous function-body ranges; don't silently treat absent REA lines as undecodable instructions.

**Binary-derived ownership path, corroborated by independent decoder:**
- `remove_waiter+0x34` `mrs x20,sp_el0`; `+0x38` `add x21,x20,#0x8c8`; `+0x68` `str xzr,[x20,#0x8f8]` (current-task-relative store).
- At `remove_waiter+0x78`, `and x21,x24,#-0x2` **redefines** `x21`; subsequent `[x21,#0x8e0]` and `[x21,#0x8f8]` are relative to a *different* pointer. Conflating those displacements with current-task fields is invalid.
- `rt_mutex_start_proxy_lock+0x44` has a direct `bl` targeting the stock `remove_waiter` address when rebased out of synthetic ELF coordinates.
- `futex_lock_pi+0x30` obtains the task pointer from `sp_el0`, then `+0x78` and `+0xf8` load/store `[x20,#0x9f8]`, but **member identity remains unverified**.

**Proof gate remains PARTIAL:** These are independently verified **compiled displacement and static call-edge observations**, not a complete original `task_struct`/`rt_mutex_waiter` factory layout or proof of GhostLock execution, exploitability, physical memory access, bootloader unlock or KernelSU. Next productive work is source-level field/member attribution with an independent factory ABI provenance check; no more kernel-wide Ghidra imports or repeated firmware-provenance commands required.

---

## October 11, 11:15 UTC — uploaded Stage-3 REA archive analyzed offline

Owner submitted four files from successful v4.2 cache: `rea-slice-remove_waiter-ffffff8008147db4.json`, `rea-slice-rt_mutex_start_proxy_lock-ffffff8008147d14.json`, `rea-slice-futex_lock_pi-ffffff8008191984.json`, and `stage3-rea-correlation.json`. Independently checked JSON identity, instruction addresses, evidence IDs and isolated ELF SHA-256 links to the manifest; **the archive contains no original raw Image bytes or sliced ELF bytes**, so it does not itself support a second opcode-level re-disassembly. Source and stock bytes were checked on WSL by prior v4.2 pipeline; its independent disassembler comparison covered the **first 16 instructions per function**, not the whole recovered extent.

| Reconstructed stock function VA | Reported REA instructions | Total 4-byte positions in original slice | Not shown by REA | Coverage |
|---|---:|---:|---:|---:|
| `remove_waiter` `0xffffff8008147db4` | 140 | 142 | 2 | 98.59% |
| `rt_mutex_start_proxy_lock` `0xffffff8008147d14` | 38 | 40 | 2 | 95.00% |
| `futex_lock_pi` `0xffffff8008191984` | 545 | 554 | 9 | 98.38% |
| **Total** | **723** | **736** | **13** | **98.23%** |

Absent four-byte addresses, calculated from cached Ghidra coverage: `remove_waiter`: last 2 words at `0xffffff8008147fe4` and `0xffffff8008147fe8`; `rt_mutex_start_proxy_lock`: last 2 words at `0xffffff8008147dac` and `0xffffff8008147db0`; `futex_lock_pi`: nine positions (see locally generated archive audit). These may be padding, data or missing decoded code; classification **requires original bytes**, not assumption.

**Compiled source/ownership-path witnesses in `remove_waiter` (stock addresses are static recovered VAs, not runtime physical addresses):**
- At `0xffffff8008147de8` (function +0x34), `mrs x20, sp_el0`. Under this Samsung ARM64 current-task convention, it obtains the current-task pointer.
- At `0xffffff8008147dec` (+0x38), `add x21, x20, #0x8c8` uses a current-relative `0x8c8` displacement, consistent with the source `pi_lock` operation.
- At `0xffffff8008147e1c` (+0x68), `str xzr, [x20, #0x8f8]` explicitly zeros a **current-relative** field, consistent with source `current->pi_blocked_on`.
- At `0xffffff8008147e2c` (+0x78), `and x21, x24, #-0x2` overwrites `x21` with a different pointer. Therefore subsequent `[x21,#0x8e0]` and `[x21,#0x8f8]` references at `+0xc4` and `+0x150` **must not** be misclassified as current-relative; they are consistent with accessing PI state on a different task.
- At `rt_mutex_start_proxy_lock+0x44`, `bl 0x000100a0` in the slice resolves to `0xffffff8008147db4` in the original symbol map, the **direct call to `remove_waiter`**. Synthetic ELF branches reuse original AArch64 relative encodings; resolve with `original_function_VA + (synthetic_target - 0x10000)` rather than interpreting Ghidra display targets as real loaded addresses.

This establishes concrete reported *stock instruction-level displacement* candidates and the compiled cleanup call edge, strengthening the prior source-only ownership-path review. **It does not authenticate a complete `task_struct`/`rt_mutex_waiter` factory ABI**: source-level member attribution, adjacent register/control-flow propagation, absent words and the complete independent binary decoder check must be distinguished. `futex_lock_pi` also reads current-task-relative `+0x9f8` after `mrs x20,sp_el0`; the member identity is unverified.

**Next meaningful offline gate:** independently disassemble the 3 tiny preserved `isolated-*.elf` slices or the exact original byte ranges, compare 736 word positions and inspect the 13 missing REA addresses. Owner has already created these ELFs in the v4.2 cache. Do not rerun REA/Ghidra, rebuilt firmware provenance tests or compile the kernel. Stage 3 remains PARTIAL, Stage 4–6 OPEN, KernelSU BLOCKED. No root or phone action.

---

## October 11, 11:02 UTC — bounded-slice Stage-3 REA validated on owner WSL

The owner installed local v4.2 bounded-slice REA code and ran `python3 tools/y2q_hxl1_porting_pipeline.py --steps factory_abi` at 2026-10-11 11:00 UTC. Exact saved run: `~/s20-artifacts/hxl1-research/pipeline/run-20261011T110041993854Z`. The `factory_abi` script **PASSED** and generated `stage3-rea-factory-abi/stage3-rea-correlation.md`, showing all three symbols `remove_waiter`, `rt_mutex_start_proxy_lock`, `futex_lock_pi` in `INSTRUCTION_CORRELATED` / `MATCH` status. Stock kernel SHA256: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`; independently reconstructed analysis ELF SHA256: `e15f67e8253396d9e6463e5dfd78d67e324a7149842a7fbccb973ec0fd36ecdb`. The earlier 330000-ms whole-ELF REA import timeout was resolved by isolating bounded function ELF slices, rather than changing original firmware.

**Precise boundary:** v4.2's independent disassembler check compares the first 16 original instructions and source/image provenance. This verified milestone is not a full-function behavioral equivalence proof and does not authenticate `rt_mutex`/`rt_mutex_waiter` factory member offsets. A new *local-only*, separately packaged v4.3 cached-evidence audit scans **all REA-reported instruction addresses** in the existing v4.2 cache with an independent GNU AArch64 decoder; counts missing instructions and potential opcode/register/memory-operand discrepancies without rerunning REA or touching the phone. Its **nine isolated unit tests passed**, but the v4.3 full original-cache comparison has **not yet been run by the owner**, and the local code is **not committed** to this GitHub branch. Do not promote this to Stage-3 COMPLETE until independent compiled-layout/source-to-binary proof is available.

**Next engineering decision:** Evaluate v4.3 whole-slice coverage, then trace verified binary/source control-flow and operand provenance for the relevant existing functions only. Maintain strict separation of instruction encoding correlation, independently established factory field layouts, runtime address proof, exploitability, and KernelSU compatibility. No root/bootloader unlock/flash achieved.

---

## October 11, 10:49 UTC — REA provider timeout on reconstructed stock kernel ELF

Owner ran the v4 Stage-3 `factory_abi` pipeline; REA returned structured stdout JSON with `code=provider_timeout`, `operation=read_function_instructions`, `timeout_ms=330000`, and **empty stderr** for `remove_waiter` at recovered static `0xffffff8008147db4`. Saved as `~/s20-artifacts/hxl1-research/pipeline/run-20261011T103543343199Z/stage3-rea-factory-abi/rea-remove_waiter-ffffff8008147db4.partial.json`. This is a **whole-kernel import/analysis timeout**, not disproof of original source or proof of factory ABI.

A locally packaged (not yet committed to GitHub) v4.2 Stage-3 replacement eliminates automatic import of the entire recovered ~52-MB ELF for REA. It constructs each small ELF64 AArch64 function slice from SHA-256-pinned stock `kernel.bin`, cross-checks the entire slice with the recovered analysis ELF's executable segment, uses the next recovered symbol as a conservative boundary, caps the synthetic ELF code at 8192 bytes, and places the isolated function at `0x10000`. It then requires REA's evidence digest to match the synthetic ELF, translates REA addresses back to the authenticated original image-relative coordinates, and compares to GNU objdump. All 12 isolated unit tests passed, including real `readelf` validation, tamper checks and failure JSON diagnostics. This is **not yet an owner-executed v4.2 REA result**; wait for the actual WSL run before claiming it solved the provider timeout.

Old `rea-remove_waiter-*.partial.json` evidence is retained. New slices and reports use `isolated-*` and `rea-slice-*` names. Because ABI offsets cannot be inferred from truncated code and provenance-by-reconstructed-kallsyms alone, Stage 3 remains PARTIAL regardless of instruction matching. No kernel exploit, root, KernelSU or deployment supported.

---

## October 11, 10:21 UTC — offline HXL1 Pipeline v3 executed successfully

**Latest owner-executed WSL run:** `~/s20-artifacts/hxl1-research/pipeline/run-20261011T101520426839Z`. The previous **Pipeline v2** run reported all **10 underlying verification steps PASS** (stock firmware, boot v2, DTB inventory, FDT semantics, Stage-3 source layout, kernel proof matrix, ABL static handoff, RAM-partition protocol, pinned EFI/REA boot-chain evidence, and readiness). The subsequent **Pipeline v3** test suite completed **14 of 14 passing**, then independently generated `proof-ledger.md` from that saved successful run. Its output explicitly reports `OFFLINE CHECKS PASS=True` and `UNRESOLVED STAGES=[3,4,5,6,7,8,9]`.

**Distinguish success levels:** successful execution of all verifiers means tool integrity and pinned **static inputs**, **not** an installable payload. The official nine-stage readiness remains: stages 1–2 COMPLETE; stage 3 PARTIAL; stages 4–6 OPEN; stages 7–8 BLOCKED; stage 9 DEFERRED. The independent Stage-3 proof matrix inspected 85 retained **experimental Clang18** objects, finding **zero** complete `rt_mutex` and `rt_mutex_waiter` DWARF type definitions. This is a lack of verified factory layouts, not evidence those structures are absent from the kernel.

**Local implementation status:** The v1/v2/v3 pipeline scripts and proof-ledger modules were delivered to the owner as ZIP files, extracted into their local repository, and tested there. **They are not present on this GitHub branch**; `git pull` alone will not install or reproduce the runner until source is committed through an authorized workflow. Only these documentary observations are being synchronized here. Preserve `~/s20-artifacts` evidence and avoid cleaning original firmware while readiness is incomplete.

**Next actionable Stage-3 focus:** (1) inventory the original compiled ARM64 code and retained factory symbol/correlation evidence for the precise `rt_mutex` and `rt_mutex_waiter` members needed by any proposed target; (2) distinguish observed factory instruction offsets from source-only or experimental Clang18 DWARF declarations; (3) if factory ABI cannot be independently authenticated, record a specific `NO_VERIFIED_FACTORY_LAYOUT` blocker rather than using a guessed offset. Original runtime addresses, slide values and root-execution permission are separate later gates. Do not repeat DTB/protocol identification as a substitute for closing this gate.

**Hardware safety:** No bootloader unlock, root, KernelSU installation, phone modification, or kernel exploit was demonstrated by this run.

---

## Current priority — proven shared REA DTB/DTBO cmdline function (October 11, 2026)

**New, owner-executed REA/Ghidra findings on the SHA256-pinned original
`LinuxLoader-HXL1.efi`**:

| Stock string | Exact REA string xref source | Ghidra owning function |
|---|---|---|
| `androidboot.dtb_idx=` at `0xbfd99` | `0x2c350` | `FUN_0002bdf8`, entry `0x2bdf8` |
| `androidboot.dtbo_idx=` at `0xbfd82` | `0x2c308` | **the same** `FUN_0002bdf8` |

The previously verified source xrefs have REA evidence
`ev_b31e5021edd1b1d5db9ff58336bb5e0f0abc3ff1d8e2189e6ce93363a5c796db`
and
`ev_14dae88115f0805e73bc32804d89232d6212f4d3e65c777c335cd9ff09557a1b`.
The independent function reports have distinct evidence IDs
`ev_c2fd2200127d2a4bfef7b18a6ae80d09abcc09fe8d78e996af33dd3a635f51c4`
and
`ev_14f1e57b01fe90c2b5f6a15871dcf09b86d465d44550a7b7fcff5d97a393b81f`.
Both contain the source instruction within Ghidra's
`0x2bdf8–0x2cae3` function body and report available
HighFunction p-code.

**What this establishes:** the original binary's two
`androidboot` index strings are referenced by the **same**
cmdline builder. It does **not** establish whether it computes
the indices itself, reads globals or receives values from
the caller. The booted property values `dtb_idx=0` and
`dtbo_idx=2` are separate selection domains and do not
authenticate any particular offline base-FDT candidate or
DTBO overlay entry. No original standalone DTBO image was
found in the owner's filename-limited local artifact scan.

### Immediate next REA pass — reuse cached functions, trace once

Do **not** rerun `xrefs` or `function`. Both existing JSON
function reports reside in
`~/s20-artifacts/hxl1-research/abl-linuxloader/rea-dt-index-LBaPQ6`.
First display only the index-constructing pseudocode lines,
then invoke **the REA fork's native high-p-code value tracer
once** on the already proven shared function. Preserve output
and do not silently reuse incomplete traces:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

bash -euo pipefail <<'BASH'
OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
RUN="$OUT/rea-dt-index-LBaPQ6"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003

test -d "$RUN" && test -f "$REA" && test -f "$EFI" && test ! -L "$EFI"
printf '%s  %s\n' "$PIN" "$EFI" | sha256sum -c

python3 - "$RUN" <<'PY'
import re, sys
from pathlib import Path
from tools.y2q_linuxloader_rea_stage4_xrefs import parse_xrefs
from tools.y2q_linuxloader_rea_stage4_functions import validated

folder=Path(sys.argv[1])
specs=[
    ("dtb-index","0xbfd99","0x2c350"),
    ("dtbo-index","0xbfd82","0x2c308"),
]
reports=[]
for label,string_addr,source in specs:
    x=parse_xrefs(folder/(label+"-xrefs.json"),string_addr)
    assert x["sourceAddresses"]==[source],(label,x["sourceAddresses"])
    f=validated(folder,label,source)
    assert f["entry"]=="0x2bdf8" and f["pcodeAvailable"] is True
    reports.append(f)
    print("[VERIFIED]",label,f["entry"],f["evidenceId"])
assert reports[0]["body"]==reports[1]["body"]

lines=reports[0]["pseudocode"].splitlines()
hits=[n for n,line in enumerate(lines) if
      re.search(r"androidboot\.(?:dtb|dtbo)_idx",line)]
print("[CMDLINE INDEX LITERAL MATCHES]",len(hits))
shown=set()
for n in hits:
    for i in range(max(0,n-12),min(len(lines),n+17)):
        if i not in shown:
            print(f"{i+1:4}: {lines[i][:240]}")
            shown.add(i)
if not hits:
    print("[LIMIT] Pseudocode does not expose either literal; use saved raw evidence")
print("[LIMIT] Static cmdline formatting is not boot-time DTB selection")
PY

if test -s "$HOME/.nvm/nvm.sh"; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
fi
if test -s "$OUT/rea-ghidra-env.sh"; then
  . "$OUT/rea-ghidra-env.sh"
fi

TRACE="$RUN/rea-shared-dtb-dtbo-native-values.json"
if test -e "$TRACE"; then
  echo "[PRESERVED EXISTING TRACE] $TRACE"
else
  PARTIAL="$RUN/rea-shared-dtb-dtbo-native-values.partial.json"
  ERR="$RUN/rea-shared-dtb-dtbo-native-values.stderr.txt"
  test ! -e "$PARTIAL" && test ! -e "$ERR" || {
    echo "[STOP] Prior incomplete native trace exists; review it first"
    exit 2
  }
  if node "$REA" trace-native-values "$EFI" 0x2bdf8 \
      --provider ghidra --json > "$PARTIAL" 2> "$ERR"; then
    mv "$PARTIAL" "$TRACE"
    echo "[REA TRACE SAVED] $TRACE"
  else
    echo "[REA TRACE FAILED; PARTIAL PRESERVED] $PARTIAL"
    sed -n '1,24p' "$ERR"
    exit 2
  fi
fi

python3 - "$TRACE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
d=json.loads(p.read_text())
print("[TRACE FILE]",p)
print("[OPERATION]",d.get("operation"))
print("[PROVIDER]",d.get("provider"))
print("[EVIDENCE]",d.get("evidence_id"))
print("[ERROR]",d.get("error"))
n=d.get("normalized_result",{})
print("[RESULT KEYS]",sorted(n) if isinstance(n,dict) else type(n).__name__)
print("[LIMIT] A bounded p-code trace does not measure physical runtime state")
PY
BASH
```

REA's [native investigation contract](https://github.com/Ragnarok93/rea/blob/main/docs/native-investigation.md)
explains that `trace-native-values` follows HighFunction
def-use and statically resolved call arguments. Its built-in
budgets, pagination and omitted counts matter: absence from
one page is not proof of absent dataflow. Missing memory alias,
unresolved indirect calls, persistent-state updates and
boot-time inputs remain unknown.

**Next analysis decision:** inspect whichever operands feed the
two actual command-line value formatting calls in the decompile.
If they originate in a caller argument/global, follow the
authenticated producer with a *targeted* REA query. Do not
treat `FUN_0002bdf8` itself as the selector until the
dataflow proves it. Avoid unrelated kernel-debug/root
investigations while this narrow DT-index gate is open.

**Device safety boundary:** no Android device access, partition
write, exploit test, kernel load, privilege escalation or
KernelSU here. Symbol/structure work is still partial;
physical handoff and per-boot slide remain open and
KernelSU native integration remains blocked.

---

## Exact gate state, as of October 11, 2026

| PORTING.md | State | Verified already | What *actually* remains |
|---|---|---|---|
| 1. Exact firmware | COMPLETE | Owner ADB / Shizuku model, fingerprint, HXL1 kernel, locked bootloader, SELinux enforcing, shell UID 2000 | Recheck only after a firmware change |
| 2. Extract stock inputs | COMPLETE (offline originals) | Hash-pinned boot v2, ARM64 kernel Image, config, vendor source from 11 overlays, matching BL archive and parsed DTB streams | Only running-kernel/selected DTB identity is unproven; do not restart downloads |
| 3. Kernel symbols/layouts | PARTIAL, **active gate** | Recovered original Image ELF/NM, source fix review, 11 raw Image code windows; two Clang18 rtmutex/futex objects and internally consistent DWARF | Prove source-to-factory-instruction semantics and **independent factory-compiled** layouts; no original BTF/DWARF established |
| 4. Physical BL handoff | OPEN | Original ABL/XBL/XBL_CONFIG and Android boot-v2 fields; DTB candidates; some original EFI static flow | *Actually selected* boot chain/device tree and physical Linux load remain unknown |
| 5. Per-boot runtime metadata | OPEN | Device-specific non-root identity and some tracefs metadata | Device runtime slide, trace/worker and physical fingerprint details, where accessible; never import another device's constants |
| 6. Native target | OPEN | Firmware-locked inert Android diagnostic | Runnable HXL1 privilege chain, not just source code or Clang18 objects |
| 7. KernelSU | BLOCKED | Stock CONFIG_MODULE_SIG_FORCE=y, CONFIG_KPROBES=n, Samsung RKP/KDP/DEFEX | Proven code loading, kernel 4.19 hooking and OEM-specific compatibility |
| 8. App/feed | BLOCKED | Research-only identity gating | Actual hardware-verified secure integration; no HXL1 in `support/targets-v3.json` |
| 9. Recovery/release | DEFERRED | Original evidence retained | Repeatable owned-device recovery/testing before any risky execution |

**Treat the evidence source as immutable.** Original extracted
`~/s20-artifacts/kernel.bin` SHA256:
`ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
The Clang18 two-object agreement is **experimental only**, *not*
a Samsung factory Clang10 ABI match. Even factory code-window hashes do
not themselves provide verified member offsets or runtime addresses.

## Do this next — one gate at a time

### A. Reconcile the documented nine-stage gates (run now)

In WSL2:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m unittest -q tools/test_y2q_porting_readiness.py
python3 tools/y2q_porting_readiness.py \
  --output "$HOME/s20-artifacts/hxl1-research/port-readiness-20261011.json"

cat "$HOME/s20-artifacts/hxl1-research/port-readiness-20261011.md"
```

**Pass:** tests pass; Stage 1 and Stage 2 COMPLETE; Stage 3
PARTIAL; Stage 4–5 OPEN; Stage 6 OPEN; Stage 7–8 BLOCKED;
Stage 9 DEFERRED; `payloadPortCompleted=false`.
If anything disagrees, investigate the *specific input*; **do not
mark a gate complete by editing the evidence manifest alone**. The
readiness utility is the status authority for the nine gates, not
how many auxiliary analyzers or Clang18 tests have passed.

### B. Review original compiled kernel vs original source (next active step)

Use the **already implemented** code-review tool, not another kernel
build, BTF extractor or new symbolic-analysis framework:

```bash
bash tools/run_y2q_hxl1_stock_rtmutex_source_code_review.sh
```

**Input:** the already created original
`~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows-v2.json`,
hash-pinned original `kernel.bin`, `vmlinux-stock.nm`,
and original Samsung `kernel/locking/rtmutex.c` and
`kernel/futex.c`.

**Pass:** all 11 original code windows independently match actual
Image instruction words; original source hashes match; source
functions `remove_waiter`, `rt_mutex_start_proxy_lock` and
`futex_lock_pi` can be reviewed side-by-side. Save the write-once
`hxl1-stock-rtmutex-source-code-01.md`/JSON (or the next unused numbered
pair: `-02`, `-03`, etc. if a prior run already produced files).
The runner preserves existing reports rather than overwriting them.
An explicit `--out /path/to/report.json` is never auto-renamed and will
fail with the occupied filename if either JSON or Markdown exists.
**No source-level
operation has yet been proven to map to a specific factory structure
offset by this name-based report.** Review it before any new tools
or code are justified.

**Actual owner result (October 11, 2026):** The readiness tool passed
9/9 checks and classified stages 1–2 COMPLETE, 3 PARTIAL, 4–6 OPEN,
7–8 BLOCKED and 9 DEFERRED. The 11 original full-symbol-bounded
windows passed the source review (67/67 local tests); three
name-associated source definitions were found at original
`rtmutex.c:1068–1119`, `rtmutex.c:1797–1810`, and
`futex.c:2817–2998`. Their 192-byte code limits truncate
`remove_waiter` and `futex_lock_pi`.

The first report was already present, so the tool successfully wrote
`hxl1-stock-rtmutex-source-code-02.md` and JSON, but **then**
crashed while printing the terminal review because a summary-loop
variable overwrote the parsed `--show-review` arguments. The CLI
shadowing has been corrected with regression tests. **The existing
`-02.md` report is valid and need not be regenerated.** Use:

```bash
cat "$HOME/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-source-code-02.md"
```

Share this already-generated report for review before taking further
action; do not create a third redundant report merely for terminal
printing. Neither the report nor its disassembly proves factory member
offsets, exact full function semantics, boot relocation or root.

### C. Samsung FUS metadata check — optional, *not a new prerequisite*

The reference [`PORTING.md`](PORTING.md) uses
[`samloader-rs`](https://github.com/topjohnwu/samloader-rs)
to retrieve the **S721N/LUC** sample firmware. Those model/region and
four-part version values **must not** be copied for the S20+.

The original HXL1 kernel/boot/BL is already present and hash verified.
`samloader-rs` can query *currently available* official Samsung FUS
metadata, but `check-update --all` may not return an archived
HXL1 version, and a different currently offered build must not
replace the audited source or change the profile identity.

If `samloader` is already installed, **first determine the owner's
actual active sales/CSC code** from existing device metadata, then run:

```bash
samloader --version
samloader check-update --model SM-G986U1 --region ACTUAL_CSC --all --verbose
```

Replace `ACTUAL_CSC` **only** with independently observed CSC/sales
region (e.g. do not assume `XAA` simply because the model ends
in `U1`). This is a network firmware listing only. Do **not** run
`samloader download`, `flash`, `detect`, `reboot-download`,
or PIT/partition commands as part of this audit.
If the binary is absent or FUS omits HXL1, record
`FUS_HISTORICAL_LOOKUP_UNAVAILABLE` and continue:
existing original hash provenance remains intact.

### D. After B passes: identify the *specific* unresolved factory gate

Use the **already installed** tools for the actual gap:

- `llvm-objdump` / `aarch64-linux-gnu-objdump`, `llvm-nm`,
  recovered original `vmlinux-stock.elf` and source for
  static source-to-code examination. Use Ghidra *only if* bounded
  CLI disassembly is ambiguous and an address/branch-flow question
  requires it.
- `vmlinux-to-elf` has **already** been used. Its symbol recovery
  is not factory DWARF. `pahole` worked for our **Clang18-built
  objects**; their fields are not original layout evidence.
- Original `kernel.bin` had **no valid bounded raw BTF candidate**
  in the existing scan, and the reconstructed ELF exposes no
  original verified DWARF/BTF. `bpftool` is useful only if an
  **actual original BTF blob** is found; installing it alone cannot
  create original type information.
- Use existing HXL1 ABL/XBL, boot header and FDT reports for Stage 4,
  **after defining a specific physical-handoff proof question**.
  Static EFI RAM-region fields are not kernel load addresses.
- Use existing **read-only ADB/Shizuku** capability/identity probes
  for Stage 5 only when a concrete runtime question remains. Clearly
  distinguish `uid=2000` shell privileges from an ordinary app.
  Do not perform unsafe futex stress, kernel writes, or blind
  memory probing.

### E. Explicit stop/go policy

**Stop:** If factory field association or the kernel-loading chain
cannot be independently authenticated, record `UNVERIFIED`.
No more full Samsung kernel Image compilations, repeat Clang18 layout
extractions, speculative offset guessing, or redundant report
generators solely to inflate the completed-test count.

**Go:** Native device-specific implementation/KernelSU/app work can
only proceed after independent, reproducible evidence exists
for the exact shipping build and security constraints; do not
publish a support feed entry from stock source resemblance or
experimental DWARF alone.

## How we collaborate

Send the **Stage A readiness summary first**. If the nine states
are as expected, run **Stage B** and send the original source/code
excerpts (the runner prints them to the terminal). Review those
specific instructions, decide what they prove, then choose exactly
one next missing evidence gate. Do **not** execute all later stages
in advance.


## Current owner checkpoint — October 11, 2026

**Stage A passed**: 9/9 readiness tests and the exact expected
nine-stage statuses. **Stage B passed**: 69/69 source-code review
regressions; all eleven original disassembly windows and source SHA256
identities reverified. The owner preserved report
`hxl1-stock-rtmutex-source-code-03.md`.

A subsequent **direct original 568-byte** `remove_waiter` disassembly
captured all the major normal and exceptional branches through the
next recovered text-symbol boundary. Original stock instructions now
provide strong, source-consistent candidate associations for the
current-task PI lock, PI-blocked-on state, tagged lock owner,
and owner blocked-on-lock followup. The relevant original code SHA256
and precise provenance cautions are recorded in
[`ROOT_PAYLOAD_RESEARCH.md`](../research/y2q-G986U1UESCHXL1/ROOT_PAYLOAD_RESEARCH.md).
No original BTF/DWARF or factory debug member declarations have been
recovered; Stage 3 remains **PARTIAL**.

**Do not rerun Stage A/B, compile new Clang18 objects, or run a broad
script suite.** The next single check is a read-only lookup of
the **already-recovered** `vmlinux-stock.nm` for the actual branch/call
target symbol names, alongside original header declarations:

```bash
cd ~/src/Root-My-Galaxy-Payloads
NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"
grep -iE '^(ffffff8008146ca4|ffffff80080fafb4|ffffff800996d544|ffffff800996d774|ffffff800996d664|ffffff800996d83c)[[:space:]]' "$NM" || true

STOCK="$HOME/src/samsung-y2q-hxl1-stock"
grep -nE -C 4 'struct rt_mutex_waiter|struct rt_mutex \{|pi_lock|pi_waiters|pi_blocked_on' \
  "$STOCK/include/linux/rtmutex.h" \
  "$STOCK/include/linux/sched.h" | head -n 120
```

If all or some target names are missing, record the omission;
do **not** manufacture or import a substitute from a different
device. Inspect those precise branch destinations using the existing
recovered Image and disassembler only when essential. Distinguish
original machine-code member-location candidates from independently
established complete factory layouts. Continue only after evaluating
this output, then select one remaining proof gap.


### Owner checkpoint: stock `remove_waiter` call graph verified

The owner's next read-only WSL check resolved **all six** selected
original stock static-call destinations in
`vmlinux-stock.nm`: `rt_mutex_adjust_prio_chain`,
`rt_mutex_setprio`, `_raw_spin_lock`,
`_raw_spin_lock_irq`, `_raw_spin_unlock`,
and `_raw_spin_unlock_irq`. Original headers also confirm the
presence and ordering of `rt_mutex.wait_lock/waiters/owner`
and `task_struct.pi_lock/pi_waiters/pi_top_task/pi_blocked_on`.

This completes the **targeted original call-identity check**; do
not rerun it. It strengthens source-to-factory-instruction evidence,
**not** complete factory field-layout provenance or root feasibility.

**Next one evidence gate — original nested RT-mutex/waiter declarations:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
STOCK="$HOME/src/samsung-y2q-hxl1-stock"
for src in \
  "$STOCK/kernel/locking/rtmutex.c" \
  "$STOCK/kernel/locking/rtmutex_common.h" \
  "$STOCK/include/linux/rtmutex.h"; do
  if [ -f "$src" ]; then
    echo "===== $src ====="
    grep -nE -C 10 \
      'struct rt_mutex_waiter[[:space:]]*\{|rt_mutex_top_waiter\(|rt_mutex_owner\(|task_blocked_on_lock\(' \
      "$src" | head -n 175
  fi
done
```

Review only which original structures, inline helpers and pointer
relationships the stock `remove_waiter` accesses can corroborate.
A source-level nested definition, even with these corroborating
machine instructions, does not authenticate *every* packed/aligned
member in the OEM compiled binary. Retain Stage 3 **PARTIAL**
and continue to Stage 4–5 runtime-evidence prerequisites as
independent gates only when there is a specific remaining proof
question. Nothing here authorizes kernel memory writes or a
KernelSU support-feed entry.


### Completed: Original waiter/helper correlation (owner WSL verification)

Owner confirmed the exact original `rtmutex_common.h` source
defines `struct rt_mutex_waiter`, the `rt_mutex_top_waiter()`
cached-first-node and `BUG_ON(w->lock != lock)` path, the
tagged `rt_mutex_owner()` accessor, and
`task_blocked_on_lock() -> p->pi_blocked_on->lock`.
These source relationships fit the original stock `remove_waiter`
load/branch chain: `lock+24` top cached waiter,
`waiter+56` lock pointer, `lock+32` owner pointer,
and owner/current task PI accesses near
`+0x8c8`/`+0x8e0`/`+0x8f8`.
Conditional `CONFIG_DEBUG_RT_MUTEXES` layout changes remain
a separate verification requirement for any field after the
optional debug members, such as `prio`.

**Stop looping on RT-mutex structure scans.** The selected
source-to-binary operation correlations are now sufficiently
documented as observations, but the **complete OEM ABI remains
PARTIAL**. They do not provide arbitrary kernel read/write,
a runtime kernel pointer or a valid KernelSU loading path.

### Next gate: review *existing* Stage 4/5 evidence, not a new sweep

The exact original ABL LinuxLoader static handoff was already
documented, and the prior device-side, read-only ADB evidence
did not measure the actual UEFI `KernelBaseAddr`/base-memory
branch, KASLR value, physical kernel entry or confirmed
booted DTB. Rather than rerun that denied/restricted probe,
read the retained results and identify whether the device
exposes a new legitimate source of runtime evidence:

```bash
cd ~/src/Root-My-Galaxy-Payloads
BASE="$HOME/s20-artifacts/hxl1-research"

echo "=== Existing Stage 4 static handoff ==="
sed -n '1,115p' "$BASE/abl-linuxloader/rea-stage4-handoff-static.md"

echo "=== Already retained live ADB reports (do not re-probe) ==="
find "$BASE/live-adb" -type f -name live-boot-evidence.md -print 2>/dev/null |
  sort | tail -n 5

echo "=== Exact HXL1 signed-module/kernel-probe gates ==="
gzip -dc "$HOME/s20-artifacts/config.gz" |
  grep -E '^(CONFIG_MODULES=|CONFIG_MODULE_SIG_FORCE=|CONFIG_KPROBES=|# CONFIG_KPROBES is not set|CONFIG_RT_MUTEXES=|CONFIG_FUTEX_PI=|CONFIG_DEBUG_RT_MUTEXES=|# CONFIG_DEBUG_RT_MUTEXES is not set)' || true
```

**Decision:** With no new independent runtime evidence,
do **not** claim a physical load/KASLR number, GhostLock
exploitation, root or KernelSU. Existing forced module-signature
checks and `CONFIG_KPROBES=n` must be treated as real design
obstacles. The next engineering milestone is *feasibility of
an authorized runtime privilege/code-loading primitive on the
exact locked HXL1 build*, not another Clang18 object or
truncated disassembly. Stage 7 stays BLOCKED.


## October 11 owner checkpoint — verified exact kernel config; runtime-feasibility decision

Owner ran the existing host-only review at commit `d820195`.
The original authenticated static LinuxLoader handoff showed:
`KernelEntry = KernelBaseAddr + imageFormatBias + (KASLRState << 15)`
or `KernelEntry = (BaseMemory | OEMImageFormatOffset) +
(KASLRState << 15)`. The `0x40` KASLR initializer is a **sentinel**,
not a measured runtime displacement. Neither the selected branch,
per-boot RAM base, actual DTB nor physical target was observed.

There are already TWO local, retained, read-only ADB reports:
`live-adb/20261010T130008Z/live-boot-evidence.md`
and `live-adb/20261010T130021Z/live-boot-evidence.md`.
**Read them, but do not reissue blocked/restricted device probes.**

Owner's current exact `config.gz` confirms:

| Option | Owner observed | Gate |
|---|---|---|
| `CONFIG_FUTEX_PI` | `y` | Subsystem built in; exploitability **not** proved |
| `CONFIG_RT_MUTEXES` | `y` | Source/code consistency |
| `CONFIG_DEBUG_RT_MUTEXES` | **not set** | Non-debug waiter struct selected; conditional debug fields absent |
| `CONFIG_MODULES` | `y` | Module framework built |
| `CONFIG_MODULE_SIG_FORCE` | `y` | Normal untrusted module insertion denied |
| `CONFIG_KPROBES` | **not set** | Existing KernelSU kprobe/kretprobe path unavailable |

The non-debug waiter priority candidate at offset `0x40`
in original `remove_waiter` is now additionally supported by the
configuration: two `struct rb_node` fields, task and lock pointers,
then `prio`. This **does not** establish a complete factory ABI.

**Focused next host-only action: summarize only *existing*
runtime observation statuses** without dumping private bootargs,
addresses or repeating ADB requests:

```bash
cd ~/src/Root-My-Galaxy-Payloads
python3 - <<'PY'
import json
from pathlib import Path
base=Path.home()/"s20-artifacts/hxl1-research/live-adb"
for path in sorted(base.glob("*/live-boot-evidence.json")):
    report=json.loads(path.read_text())
    print("REPORT",path.parent.name)
    print("  iomem:",report.get("iomem",{}).get("status","UNAVAILABLE"))
    props=report.get("bootProperties",{})
    for field in ("ro.boot.dtb_idx","ro.boot.dtbo_idx"):
        print(" ",field+":",props.get(field,"[UNAVAILABLE]"))
    for field in ("proc_cmdline","proc_bootconfig","proc_iomem",
                  "proc_dt_bootargs","sys_dt_bootargs","proc_dt_model",
                  "sys_dt_model"):
        print(" ",field+":",
              report.get("fileObservations",{}).get(field,{}).get("status",
              "NOT_COLLECTED"))
    for flag in ("physicalKernelEntryVerified",
                 "runtimeKaslrMeasured",
                 "runningDtbMatchedToBootloaderSelection"):
        print(" ",flag+":",report.get(flag,"NOT_COLLECTED"))
PY
```

**Acceptance criteria:** If the past device observations contain a
grounded DTB index, check against existing FDT candidate records;
otherwise document that specific limitation. An absent/restricted
IOMEM or bootargs never licenses guessing the physical address or
forcing access. ADB unprivileged shell cannot establish UEFI
KernelBaseAddr/KASLR independently on this evidence alone.

**Primary go/no-go:** With the locked bootloader, forced module
signatures and no kernel probes, the exact-device native/KernelSU
path is **BLOCKED** until a demonstrable authorized kernel-code
execution mechanism and compatible hook backend are available.
No stock source resemblance, linker symbol or futex-PI smoke test
alone satisfies this. Do not produce/flash an HXL1 module or
declare the profile supported.

**Engineering priority:** Obtain *new evidence* of an authorized
privileged loading route or a safely demonstrated HXL1-specific
runtime bug in an isolated reproduction. Until then preserve
the research profile and do not run another broad static scan.


## October 11 checkpoint — exact reported DTB/DTBO indices

The owner inspected *two already-retained* HXL1 device ADB records
(`20261010T130008Z` and `20261010T130021Z`, just 13 seconds apart).
Both give:

- `ro.boot.dtb_idx=0` and `ro.boot.dtbo_idx=2`;
- `/proc/cmdline`, `/proc/iomem`, both device-tree root
  `model` and `chosen/bootargs` interfaces: **PERMISSION_DENIED**;
- `/proc/bootconfig`: **NOT_PRESENT**;
- no verified physical Linux kernel load/entry, runtime
  KASLR or effective DTB hash.

These are two observations, **not independent boot measurements**.

The *offline* embedded stock boot-v2 region has four validated
contiguous FDTs in **one-based report order**:
candidate 1 Kona v2.1 at offset `0x0`,
candidate 2 Kona v2 at `0x81088`,
candidate 3 Kona v1 at `0x10210c`,
candidate 4 minimal 173-byte tree at `0x181c46`.
Its first bytes are FDT magic, **not** Android DT-table magic.
The selector's index base and its mapping to these four bytes
are **not independently established**. Therefore the observed
`dtb_idx=0` does NOT certify that first candidate is running.
The observed `dtbo_idx=2` is in a distinct *overlay* selection
domain, **not** candidate 3 of the four embedded base FDTs.

**Completed (owner WSL2):** No `dtbo.img`, `dtbo.img.lz4`
or `dtbo.bin` was found within five subdirectory levels under
`~/s20-artifacts`. The four original base FDT identities remain
unchanged. Record
`HXL1_ORIGINAL_DTBO_TABLE_NOT_IN_LOCAL_EVIDENCE`, not
`NO_DTBO_PARTITION_EXISTS`.
The `dtb_idx=0` and `dtbo_idx=2` properties are preserved
as bootloader selection hints only. No DTBO index or effective
tree hash is independently proven.

**Stop repeating the firmware/DTB and restricted ADB loops.**
A separate DTBO extraction or older Samsung FUS metadata lookup
should be reopened only if a concrete implementation or recovery
gate actually requires that evidence.

### Next consequential engineering milestone — isolated runtime feasibility

The original HXL1 `remove_waiter` bug-pattern, its stock
compiled access paths, selected struct member candidates and
six call destinations are documented. The pre-existing ARM64
QEMU lab booted **upstream** Linux 4.19.325 with debugging,
but did **not** reproduce the OEM HXL1 proxy-lock rollback
behavior, and did **not** match the device's complete Samsung
kernel or security policy. The target kernel is
`4.19.113-27095354`, not upstream 4.19.325.

Any further work must use a **safe, isolated, source-exact
regression** that distinguishes the potentially incorrect
`current`/waiter task cleanup branch from its patched
counterpart. It should measure only bounded state/lock
integrity in a disposable instrumented guest, not induce
unstable futex races on the real phone. First verify the
lab's actual source and configuration fidelity; if
HXL1 code cannot run there faithfully, treat reproduction
as `NOT_TESTED` rather than transferring upstream
results to the stock handset.

A demonstrated **cleanup bug is not automatically an exploitable
kernel read/write primitive**. A demonstrated primitive would
still not give KernelSU installation automatically.
The live `SM-G986U1` remains verified-boot locked with
`CONFIG_MODULE_SIG_FORCE=y` and
`CONFIG_KPROBES=n`; an independently verified
privileged code-loading route and a compatible Linux 4.19
hook/backend design remain absent. No root/profile release
until these are established.

**Current readiness:** Stages 1–2 COMPLETE, Stage 3 PARTIAL,
Stages 4–6 OPEN, Stages 7–8 BLOCKED, Stage 9 DEFERRED.
