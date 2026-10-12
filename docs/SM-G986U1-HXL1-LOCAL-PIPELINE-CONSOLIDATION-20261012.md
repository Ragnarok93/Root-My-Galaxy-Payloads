# SM-G986U1 HXL1 — owner WSL local-pipeline review and consolidation (2026-10-12)

**Target:** SM-G986U1 / `G986U1UESCHXL1` / Snapdragon 865 / Linux `4.19.113-27095354`. **Source:** owner-uploaded `hxl1-local-pipeline-review.tar.gz` (17 members, including `Run.py`, provisional `target.h`, two READMEs, four additional Markdown reports, four research modules and five tests). These are owner-local, **untracked** files; they are not automatically authoritative GitHub repository code or authenticated vendor binary evidence. Preserve original owner evidence.

**Conclusion:** owner-local research extends the GitHub porting evidence, particularly via a Clang 10 comparison build, static factory displacement comparison, bounded REA function slices and authenticated static LinuxLoader analysis. **Do not replace the existing GitHub nine-stage runner with the second overlapping runner.** Reuse useful independent evidence, but do not promote a successful static test, a Clang 10 *comparison* build, or the generated `target.h` to a working CVE payload or factory ABI. The existing root/KernelSU/flash gates remain unchanged.

## New local results worth preserving and independently accepting

| Owner-local source | Reported evidence | What it does **not** establish |
|---|---|---|
| `docs/HXL1-CLANG10-ABI-COMPARISON.md` | Independent Clang r377782d / version 10.0.6 RT-mutex and futex object builds, original `config.gz` baseline; `rt_mutex` and `rt_mutex_waiter` DWARF present in both objects and same reported direct layout; config common enabled differences reported zero | Shipped factory compiler provenance, complete factory ABI, full OEM kernel rebuild, device exploitation |
| Same document, factory displacement follow-up | Reported 31 original ARM64 instruction words matched stock Image and 13 existing RT-mutex/waiter/task-struct displacement candidates agreed with comparison DWARF, including nested cached-rbtree fields | Each instruction bound independently to a **specific source field** in the factory control-flow path, all required fields and runtime state |
| `tools/y2q_hxl1_rea_factory_abi.py` + `test_y2q_hxl1_rea_slices.py` | Implements three separate 8-KiB-max AArch64 ELF function slices from source-pinned Image and reconstructed executable ELF, each relocated to `0x10000` for faster Ghidra/REA; maps reported instruction addresses back to stock symbols; explicit timeout/incomplete cache handling | Dynamic execution, complete factory debug type offsets, proof that symbolic source names are original ELF debug names; no actual owner run of v4.2 supplied in this archive |
| `tools/y2q_hxl1_bootchain_attest.py` | Source-pinned LinuxLoader PE `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`; RAM partition and SCM GUIDs, wrapper and layout constants, six cached Ghidra native dossiers checked by address and mnemonic | Booted physical address, selected real FDT, secure-world state/authorization, actual unsigned firmware acceptance |
| `tools/y2q_hxl1_proof_ledger.py` | Combines nine-stage readiness, kernel matrix, static bootchain and REA status without claiming root | Independent evidence rehash of every accepted JSON: current `_json_if_verified` trusts step PASS and file presence rather than recorded per-file digests. Must harden before promoting accepted reports. |
| `tools/y2q_hxl1_porting_pipeline.py` | Second, owner-local 11-step WSL pipeline with independent bootchain and REA static analysis | It duplicates the tracked `tools/y2q_hxl1_porting_automation.py` and its report contract. Do **not** add a second competing production entrypoint. Fold guarded extra checks into existing runner only after provenance and tests. |
| `Run.py` + `targets/y2q-G986U1UESCHXL1/target.h` | 145,433 recovered kallsyms, 256/256 P0 fingerprint words checked, partial static offsets. Generated target remains expressly provisional | ABL step hardcodes AArch64 for an **ELF32 EM_ARM** outer `abl.elf`, logs 'No boot string found', and writes `PARTIAL` definitions into its separate `~/src/targets/` tree. These must not enter production root target. |

## Concrete new local artifacts cited by the owner's report

Retained original sources on the owner WSL system, **not uploaded in the review archive**:

- `~/s20-artifacts/hxl1-research/clang10-abi-comparison/`: original config diff, Clang10 objects/pahole reports/build logs, `factory-displacement-comparison.json`.
- `~/s20-artifacts/hxl1-research/vmlinux-stock.elf` and `vmlinux-stock.nm`: reconstructed analysis ELF and recovered symbol listing, not OEM DWARF.
- `~/s20-artifacts/hxl1-research/abl-linuxloader/LinuxLoader-HXL1.efi`, original REA cache `rea-dt-index-LBaPQ6/`.
- `~/src/samsung-y2q-hxl1-clang10-abi-comparison/`: separate source/build workspace.
- `~/src/targets/y2q-G986U1UESCHXL1/target.h`: provisional generated target kept **outside** tracked repository support feed.

The uploaded archive contains summary Markdown and source implementations, **not the Clang10 comparison object binaries, factory displacement JSON, complete REA cache, signed factory firmware, or original Ghidra outputs**. We cannot independently rehash and validate those objects from this archive alone. The 31/13 agreement is therefore a **reported local result**, not yet an independently re-executed or reviewed factory offset attestation in GitHub CI.

## Exact integration strategy

1. **Preserve and checkpoint the local untracked files.** `git status --short` showed only `??` entries, not modifications to tracked code. Never run `git clean -fd`, `git add -A`, overwrite local `Run.py`, or push production `target.h`. Review files individually before version control.
2. **One canonical host runner:** keep `tools/run_y2q_hxl1_porting_automation.sh` and `tools/y2q_hxl1_porting_automation.py` as the single project entrypoint; its original factory hashes and official nine gates are already tested. Do not automatically run untracked local scripts from that runner.
3. **Highest-value Stage 3 proof:** independently re-attest the owner Clang10 comparison report and `factory-displacement-comparison.json`, then review source-to-original-stock code def-use for **all exploit-required** `rt_mutex`, `rt_mutex_waiter`, and `task_struct` fields. Existing 31 matching instruction words, by themselves, do not prove field ownership or complete ABI.
4. **Reuse bounded REA:** the local v4.2 slice design addresses the observed whole-52MB-ELF REA `provider_timeout` by cutting small stock-byte-exact slices; store a fresh, SHA-bound report and classify missing/failing Ghidra evidence honestly. Do not reuse partial timeout JSON as proof.
5. **Stage 4 bootchain:** reuse the already well-documented LinuxLoader-handoff path and original six cached dossiers; do not re-run `Run.py`'s outer-ABL AArch64 string search. Real loader handoff, selected physical kernel base and FDT remain separate measurements.
6. **Hardening before promoting local modules:** require per-report content digest in proof ledger; verify source-bound REP/procedure; avoid trusting stale output if child tool fails; enforce isolated output folder and forbid executable payload/feed operations.
7. **Runtime/KernelSU gates:** source pattern matching is not a reproduced CVE primitive; on locked HXL1, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_UH_LKM_BLOCK=y`, `CONFIG_KPROBES=n`, RKP/KDP/DEFEX require a distinct authorized loader/integration proof. The local `docs/HXL1-SU-ROUTE-ASSESSMENT.md` identifies KernelSU Next legacy manual built-in hooks as a candidate, **not** an available flash or installed module.

## Mandatory reporting boundary

A bounded REA correlation, exact factory displacement agreement, static RAM-partition GUID proof or Clang10 comparison can move an **evidence subcheck** forward. None by itself marks Stage 3 factory ABI, Stage 4 live handoff, Stage 5 controlled exploit, Stage 6 root profile, Stage 7 KernelSU, Stage 8 support feed, or Stage 9 release complete. Keep stage states from the canonical `y2q_porting_readiness.py` until independently validated prerequisites exist.

**Current:** Stage 1 COMPLETE; Stage 2 COMPLETE; Stage 3 PARTIAL; stages 4–6 OPEN; stages 7–8 BLOCKED; Stage 9 DEFERRED. Do not claim physical device modified.
