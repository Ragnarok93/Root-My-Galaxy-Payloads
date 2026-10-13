# HXL1 GhostLock and Root-My-Galaxy offset requirements — source-scoped inventory

**Device:** Samsung Galaxy S20+ SM-G986U1, exact build `G986U1UESCHXL1`, ARM64 Linux `4.19.113-27095354`.

**Evidence available:** original `kernel.bin` pinned SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`; the owner's October 12 Stage 3 report; October 13 live REA/Ghidra 3-function dossier (140+38+545 original instruction matches, 9 predefined static chains); owner-uploaded SHA-pinned `kernel/locking/rtmutex.c` and `kernel/futex.c`; separate Clang10 comparison object files. Source file SHA pins are `36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9` and `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`.

**Do not mix the two registries below.** The 13 GhostLock ABI hypotheses and the *additional* app payload's tracing/placement/P0 parameters serve different purposes. Some latter parameters describe a specific proof-of-concept implementation rather than a compiler-derived kernel type field. No HXL1 root payload/authorized KernelSU loader/physical bootloader unlock is yet proven.

## A. Original 13 RT-mutex/futex C-structure members

| Type/member | Clang10 comparison value | Original ARM64 Ghidra observation | Evidence grade |
|---|---:|---|---|
| rt_mutex.waiters.rb_root.rb_node | 0x10 | Typed source-order + static register chain | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| rt_mutex.waiters.rb_leftmost | 0x18 | Static chain; leftmost pointer loaded at isolated `0x10018` | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| rt_mutex.owner | 0x20 | Static chain; owner load at isolated `0x1003c` | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| rt_mutex_waiter.tree_entry | 0x00 | Waiter-argument register chain | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| rt_mutex_waiter.pi_tree_entry | 0x18 | Waiter-argument register chain | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| rt_mutex_waiter.task | 0x30 | No established direct waiter-argument load in saved `remove_waiter` instructions | UNMAPPED_SOURCE_FIELD |
| rt_mutex_waiter.lock | 0x38 | Source-bound load via lock-leftmost waiter pointer at `0x10028`, `0x100b8` | GHIDRA_POINTER_FLOW_LEAD |
| rt_mutex_waiter.prio | 0x40 | Source-bound load at `0x100d0`; embedded node-relative `0x28` corroboration | GHIDRA_POINTER_FLOW_LEAD |
| rt_mutex_waiter.deadline | 0x48 | Source-bound load at `0x101e0`; embedded node-relative `0x30` corroboration | GHIDRA_POINTER_FLOW_LEAD |
| task_struct.pi_lock | 0x8c8 | `sp_el0`-based current task + displacement | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| task_struct.pi_waiters.rb_root.rb_node | 0x8e0 | Static original owner-pointer chain | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| task_struct.pi_waiters.rb_leftmost | 0x8e8 | Static original owner-pointer chain | SOURCE_AND_DISPLACEMENT_CANDIDATE |
| task_struct.pi_blocked_on | 0x8f8 | Original `str xzr,[x20,#0x8f8]`; `x20` from `sp_el0` | SOURCE_AND_DISPLACEMENT_CANDIDATE |

*All 13 are candidate offsets; **0/13 factory C-member identities were certified** by the existing tool. An assembly immediate does not uniquely identify its C object.* The three Ghidra-pointer-flow leads are an additional class of evidence and do not mean 12 fields are factory certified. The saved `futex_lock_pi` High P-code trace is truncated at 3,000 operations with 52 known omitted edges, so absence-of-use claims from that function are unsafe.

## B. Payload-specific values absent from the uploaded generic `Run.py` target generator

| Macro/group | Current HXL1 evidence | Required proof / rule |
|---|---|---|
| `P0_PAGE_OFFSET` | **Missing** | Match original 4.19 ARM64 virtual-memory configuration and compiled address translation; **not** interchangeable with physical RAM base. |
| `P0_PHYS_OFFSET` | **UNVERIFIED on handset** | Original physical RAM start/effective boot handoff, trusted device/bootloader evidence; never copy `0x80000000` from a different model. |
| `P0_KERNEL_PHYS_LOAD` | **UNVERIFIED on handset** | Actual ABL/LinuxLoader-selected load and decompression/handoff; QEMU virt's `0x40080000` does not establish it. |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | **NOT DERIVED** | Target-compiled `worker_thread` code and the precise `schedule` return site, minus independently pinned `KIMAGE_TEXT_BASE`; qualify tracefs feature availability. |
| `SLIDE_TRACEFS_EVENT_ID` | **NOT DERIVED** | Confirm `sched:sched_blocked_reason` exists/active in Samsung 4.19 configuration; derive event ID from this *exact* kernel's registration order or observe trusted device `events/.../id`. Android 6.1 example `106` cannot be copied. |
| `SLIDE_PSELECT_WORD_SHIFT` | **NOT DERIVED** | Validate the HXL1-compatible userspace `pselect6`/fdset implementation and payload overlap; this is an index of 64-bit words in a particular memory layout, not a Ghidra member offset. |
| `FAKE_WAITER_*` | **NOT DERIVED** | Separate *native* `rt_mutex_waiter` member identities from the synthetic waiter placement, embedded rb-node-relative offsets, and memory bounds required by a specific payload. |
| `FAKE_TASK_*` | **NOT DERIVED** | Prove HXL1 `task_struct` member offsets and only then derive any synthetic task layout for an isolated regression. BTF of a different kernel is not a substitute. |
| `LOCK_OFF`, `SLIDE_BANK_LOCK_OFF`, `FAKE_TASK_OFF` | **NOT DERIVED** | Payload placement/overlap geometry, not standalone OEM factory C-struct member offsets. |
| P0 256-qword fingerprint table | **ORIGINAL INPUT VERIFIED** | Existing owner script verified 32 candidate slides × 8 source words; this does **not** establish physical RAM mapping or slide-observation capability. |

Source examples: `docs/PORTING.md` and the upstream `src/targets/essi-S721NKSSCDZF3/target.h`. The upstream file includes macros above for its own Android 6.1 device. Those values, including `SLIDE_TRACEFS_EVENT_ID=106`, `SLIDE_TRACEFS_WORKER_CALLER_OFF=0x000dbd9c`, `SLIDE_PSELECT_WORD_SHIFT=0`, and `P0_PAGE_OFFSET=0xffffff8000000000`, are **not established for HXL1**.

The owner's `Run.py` currently enumerates 24 symbol-derived/Ghidra-assisted target definitions and only two physical headers; it omits all tracefs/pselect, synthetic-task/waiter/lock, and page-offset categories. Those omissions affect compatibility with the upstream payload, but do not imply such an exploit will operate on this phone.

## C. New exact-Samsung-source cleanup finding (not runtime root)

The original Samsung `kernel/locking/rtmutex.c` has:

- Lines **1068–1079**: `remove_waiter(lock, waiter)` obtains `owner`, locks `current->pi_lock`, dequeues `waiter`, then writes `current->pi_blocked_on = NULL`.
- Lines **1797–1807**: `rt_mutex_start_proxy_lock(lock, waiter, task)` calls `__rt_mutex_start_proxy_lock(lock, waiter, task)`; on a nonzero result it calls `remove_waiter(lock, waiter)` without passing the explicit `task`.
- Original Ghidra native `remove_waiter` shows `mov x23,x1` preserving waiter, `mrs x20,sp_el0` obtaining current task, `add x21,x20,#0x8c8`, and `str xzr,[x20,#0x8f8]`.

This **correlates** original Samsung source with original function instructions and identifies a precise `current` vs `task` review question. It does **not** establish that nonzero result can be reached with `task != current` at a real caller, a broken invariant, a kernel primitive, or device root. Next action: correlate the exact `futex_lock_pi` call sites and control-flow/return-code conditions to identify whether the relevant path is reachable *without* treating a truncated HighFunction as complete. Use isolated host-only regression for any task state changes.

## D. Defects in the separately supplied generic Python provenance script

The October 13 uploaded `Run.py` source is **not** our factory-proof gate and should not publish a production payload.

1. Step 6 takes the first available `abl.elf` (original **ELF32 EM_ARM**) before `LinuxLoader-HXL1.efi`, then forces global `AARCH64:LE:64:v8A` on that input. Correct the binary selection and header validation; prefer existing SHA-pinned nested LinuxLoader research rather than repeating the `Starting kernel` string-only approach.
2. Step 5b's `ResolveStructOffsets.java` searches pointer values and static strings but does not recover dynamic RT-mutex C field identity; it marks all results PARTIAL. `logger_array` must remain a symbol-offset vs field-offset distinction. Ghidra `-noanalysis` is especially weak for function ownership and dataflow.
3. Step 8 **allows make release with `PARTIAL` offsets** (warning only), and Step 10 can write a support-feed entry even if the device/runtime/authorization/KernelSU checks are unresolved. These two actions must be fail-closed in any HXL1 build or release automation.
4. Step 7 verifies only source-fingerprint construction (256 qwords), not the usable runtime slide oracle, virtual mapping, or physical base.
5. The root payload macro names/required definitions should be extracted from the *currently selected payload variant* in its own source rather than copied wholesale from a different supported device.

## E. Recommended sequence

1. **Keep completed HXL1 factory REA/Ghidra evidence**; no repeated extraction, no repeated six provider calls, no more 13-member displacement inventories.
2. Review exact original `rt_mutex_start_proxy_lock` error-return path and `futex_lock_pi` call conditions against saved native/decompiler data, then verify source-function provenance for `waiter->task` and `current` before accepting a cleanup mismatch.
3. Independently inventory exact HXL1 `worker_thread` and tracer configuration, only if the selected payload uses that oracle; categorize runtime event ID as unavailable when the feature is absent instead of copying `106`.
4. Treat `P0_PAGE_OFFSET` as a separate source/config proof. Keep physical and synthetic object placement variables unproved until an HXL1-specific legitimate test is available.
5. Never build a purported root payload or publish a support feed from partial-only values. Original HXL1 root and KernelSU integration remain blocked.

**Readiness:** Stages 1–2 COMPLETE, 3 PARTIAL, 4–6 OPEN, 7–8 BLOCKED, 9 DEFERRED.
