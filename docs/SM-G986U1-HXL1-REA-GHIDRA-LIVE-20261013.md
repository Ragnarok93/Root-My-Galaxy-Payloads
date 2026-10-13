# Original HXL1 Stage 3 — owner live REA/Ghidra evidence review (2026-10-13 UTC)

**Target:** SM-G986U1, original Samsung `G986U1UESCHXL1` Linux 4.19 kernel, Snapdragon 865.  
**Scope:** static original-code structure/field identification, not an executed bug, a root exploit, or an OEM-factory compiler attestation.

## Exact reviewed owner evidence

Owner supplied the archive `hxl1-stage3-live-ghidra-evidence.tar.gz` after running `tools/run_y2q_hxl1_stage3_rea_live_review.sh`. It contains the saved live review report, all six native/function Ghidra JSON outputs, and the original October 12 Stage 3 report.

- SHA-256 of uploaded review archive: `bc10e853aff4e76f4c05cb9095cbd235dd535f56e83f37ec6ed43eaa4be804e6`.
- Live review JSON SHA-256: `cbe2a4c917d65ebb4b404c8ff61c52cf00a28c08f021cd8da312f895eebbbda1`.
- Original source Image SHA *recorded by the user's prior factory attestation*: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`. The 52 MB original `kernel.bin` was **not** part of this archive; this review validates Ghidra output contents, not an independent rehash of that absent original.
- Saved live native instruction comparison: `remove_waiter` 140/140, `rt_mutex_start_proxy_lock` 38/38, `futex_lock_pi` 545/545 **exactly identical** to factory-attested saved slices. The Ghidra provider identifies itself as **12.1.4**, architecture `arm64`.
- Ghidra HighFunction P-code retained: `remove_waiter` 214 operations (no reported truncation/omitted edges), `rt_mutex_start_proxy_lock` 21 (no reported truncation/omitted edges), `futex_lock_pi` **3,000 with `truncated=true`, at least one omitted operation and 52 known omitted def-use edges**. Do not describe the futex P-code as complete.
- Two separate Clang10 **comparison** ET_REL object files in the saved Stage 3 report have matching `pahole` output for `struct rt_mutex` and `struct rt_mutex_waiter`. They are **rebuilt comparison objects**, not original Samsung factory `.o`/DWARF.
- Original live review: `memberCandidateRegisterFlow.matchedStaticChains=9/13`; `factoryMemberOffsetsVerified=0`; Stage 3 still **PARTIAL**. The absence of `rt_mutex_waiter` `task`, `lock`, `prio`, and `deadline` from the nine static *predefined* chains does not mean those displacements do not occur in the original kernel.

## Verified original-code pointer traces: additional evidence for waiter fields

All `0x100xx` addresses below refer to the source-bound isolated `remove_waiter` ELF relocated to `0x10000`, **not original static virtual addresses**. The factory static function entry was `0xffffff8008147db4`.

**Candidate `rt_mutex_waiter.lock` at `0x38`:**

- `0x10018: ldr x22, [x0, #0x18]` loads the pointer at the lock's `waiters.rb_leftmost` comparison displacement. In Ghidra High P-code this is `0x10018#26 INT_ADD(parameter0, 0x18)` and `0x10018#27 LOAD`.
- `0x10028: ldr x8, [x22, #0x38]` reads from the pointer returned by that load; `0x10028#1398 PTRADD` has a def-use edge to `0x10018#27`, and `0x10028#33 LOAD` consumes the pointer expression. The result is compared against the original lock argument at `0x1002c`.
- `0x100b0: ldr x0, [x19, #0x18]` then `0x100b8: ldr x8, [x0, #0x38]` provides another code route from the same lock-leftmost displacement to `+0x38`.

**Candidate `rt_mutex_waiter.prio` at `0x40`:**

- `0x100b0` loads `x0` from lock `+0x18`; `0x100d0: ldr w10, [x0, #0x40]` uses the pointer as a priority-like signed comparison value. Ghidra High P-code `0x100d0#169 LOAD` has a def-use path through `0x100d0#168 INT_ADD` to the `0x100b0#141 LOAD`.
- In the rb-tree comparison path `0x100e8: ldr w12, [x12, #0x28]` references an embedded node. The comparison DWARF places `pi_tree_entry` at `+0x18`, and `prio` at `+0x40`, yielding node-relative `0x40-0x18=0x28`. This is a **second consistent address relation**, not an original C field name recovered from the factory binary.

**Candidate `rt_mutex_waiter.deadline` at `0x48`:**

- `0x101e0: ldr x12, [x0, #0x48]` uses the leftmost-waiter pointer originating at `0x100b0` in Ghidra's High P-code chain (`0x101e0#414 LOAD` through `0x101e0#413 INT_ADD`).
- `0x101e4: ldr x13, [x9, #0x30]` is part of a comparison against an embedded rb-tree node, not proof of `waiter.task`. With the rebuilt comparison's `pi_tree_entry` at `+0x18`, node-relative `+0x30` corresponds to waiter-relative `+0x48`, consistent with `deadline`.
- **Do not misclassify `[x9,#0x30]` as `waiter.task@0x30`.** The untyped base register points to a different object/subobject in the comparison path.

**Candidate `rt_mutex_waiter.task` at `0x30` remains missing an original direct waiter-argument load in the `remove_waiter` native instruction list.** The saved Clang10 comparison DWARF independently lays it out at `+0x30` (48 bytes); that does **not** itself prove the OEM binary accesses this field at runtime. The complete 140-instruction `remove_waiter` listing has no `ldr [... x23, #0x30]` from its saved waiter argument. An untyped `+0x30` access elsewhere is not enough to close this gap.

## A key GhostLock source-to-binary review lead, **not exploit proof**

`remove_waiter` preserves the candidate original waiter argument in `x23` (`0x10020: mov x23,x1`), but also reads `sp_el0` into `x20` at `0x10034`, constructs `x20+0x8c8` at `0x10038`, and performs `0x10068: str xzr,[x20,#0x8f8]`. The latter code sequence is consistent with manipulating the **current task's PI lock/blocked-on state**, rather than dereferencing a `waiter->task` field. This observation is an original native-code fact plus comparison-offset interpretation.

To determine whether it represents the proposed wrong-task proxy-lock cleanup behavior, review the *exact* Samsung `remove_waiter` source expression, its enclosing conditions, and callers of `remove_waiter`/`rt_mutex_start_proxy_lock` together. A failure to load `waiter.task` inside one function does not prove that the live call's `current` differs from the intended waiter task. **No device runtime identity mismatch, controlled corruption, arbitrary kernel access, or privilege escalation has been demonstrated.**

## Remaining 13 candidate field inventory

| Comparison object / member | Clang10 comparison offset | Factory Ghidra read/source lead | Current disposition |
|---|---:|---|---|
| `rt_mutex.waiters.rb_root.rb_node` | 0x10 | `remove_waiter +0x100a8` lock argument | static mapped candidate |
| `rt_mutex.waiters.rb_leftmost` | 0x18 | `remove_waiter +0x10018`, `+0x100b0` | static mapped candidate |
| `rt_mutex.owner` | 0x20 | `remove_waiter +0x1003c`; proxy-lock `+0x10084` | static mapped candidate |
| `rt_mutex_waiter.tree_entry` | 0x00 | `remove_waiter +0x10048` waiter argument | static mapped candidate |
| `rt_mutex_waiter.pi_tree_entry` | 0x18 | `remove_waiter +0x1008c` waiter argument | static mapped candidate |
| `rt_mutex_waiter.task` | 0x30 | no independently identified direct waiter pointer load | **still unmapped** |
| `rt_mutex_waiter.lock` | 0x38 | `+0x10028`, `+0x100b8` from lock-leftmost pointer | **new P-code pointer trace** |
| `rt_mutex_waiter.prio` | 0x40 | `+0x100d0` plus nested-node `+0x28` | **new P-code pointer trace** |
| `rt_mutex_waiter.deadline` | 0x48 | `+0x101e0` plus nested-node `+0x30` | **new P-code pointer trace** |
| `task_struct.pi_lock` | 0x8c8 | `remove_waiter +0x10034` `sp_el0`; `+0x10038` add | static mapped candidate |
| `task_struct.pi_waiters.rb_root.rb_node` | 0x8e0 | `remove_waiter +0x100c4`, `+0x10130` | static mapped candidate |
| `task_struct.pi_waiters.rb_leftmost` | 0x8e8 | `remove_waiter +0x10138` | static mapped candidate |
| `task_struct.pi_blocked_on` | 0x8f8 | `remove_waiter +0x10068`, `+0x10150` | static mapped candidate |

The original `liveNativeMemberDisplacementWorklist` includes stack spills such as `[sp,#0x20]` alongside object references like `[x22,#0x38]`, and the `futex_lock_pi` function includes accesses to objects with *other* layouts. None may be counted as a typed waiter field until the base is authenticated. The source runner now separately counts stack-frame false positives and records P-code truncation.

## Required next substantive proofs

1. **Original source expression review:** bind `remove_waiter` `lock->waiters.rb_leftmost` and its nested `rt_mutex_waiter` accesses to exactly pinned Samsung declarations and all branch paths; trace `current` versus `waiter->task` in the proxy-lock cleanup call path.
2. **Factory compilation equivalence:** Clang10 reconstructed DWARF and independently recovered ARM64 displacements corroborate likely offsets but are not shipped OEM compiled type-debug records. Do not convert these to production `target.h` entries based on these traces alone.
3. **Full futex P-code, only if necessary:** current `futex_lock_pi` HighFunction has 3,000 retained operations, 52 omitted edges and a truncation flag. Do not treat a partial graph as a proof of non-use of `waiter.task`. Prefer bounded analysis of the exact relevant callees or window over re-running the already completed six whole-slice Ghidra queries.
4. **Separate on-device gates:** factory offset confidence is not runtime bug triggering; a root-capable payload, KernelSU backend, permitted bootloader path, and physical-device proof remain unestablished.

**Readiness:** Stage 1–2 COMPLETE, Stage 3 PARTIAL, Stage 4–6 OPEN, Stage 7–8 BLOCKED, Stage 9 DEFERRED. Nothing here touched the Galaxy S20+.
