## October 14, 12:22 UTC — NEW factory function report: actionable store; initial negative CFG findings invalid

The owner executed the narrow, newly added original-stock compiled function extractor and uploaded `hxl1-task-blocks-original-compiled-20261014.json`. The original ELF and NM SHA pins were checked by the extractor, and it recovered the **208-instruction** `task_blocks_on_rt_mutex` function from `0xffffff80081479d4` to `0xffffff8008147d14`. Original instruction `+0xf0` (`0xffffff8008147ac4`, word `f9047e95`) is `str x21, [x20, #2296]`, a candidate publication into the target task's `pi_blocked_on` field (displacement 2296 / 0x8f8). The common return is `+0x2d4`. Original task register origin remains a **hypothesis**, not a dataflow proof.

**Critical extraction bug fixed, not a negative lifetime result:** GNU AArch64 objdump emits targets such as `ffffff8008146ca4` without a `0x` prefix. The initial extractor handed that text directly to `y2q_hxl1_static_cfg_audit.edges_for()` (expects `0x...`) and to the recovered-symbol resolver (also requires a hex literal with `0x`). Thus the original report's `possibleReturnReachableAfterStore=false`, `possibleEarlyReturnAvoidingThisStore=false`, and **0 recovered chain-walk calls** are invalid **analysis-output false negatives**, not evidence that the paths are absent. It did correctly capture the original store word, function bounds and raw BL destination strings.

The same targeted extractor now normalizes **only control-transfer operands** (`b`, `b.*`, `bl`, `cbz`, `cbnz`, `tbz`, `tbnz`), preserving unrelated immediate values. It lists exact stock recovered BL symbols, conservative entry/store/return graph relations, and whether a recovered `rt_mutex_adjust_prio_chain` call can be reached after publication and may reach the return. The output explicitly keeps **nonzero error feasibility, x20→target-task provenance, stale reference, and live root unverified**. A new three-test regression targets this exact parsing defect and conservative reachability; it is CI-integrated. The corrected extractor **has not yet been run on owner original ELF**.

Single focused rerun of only the one new function (NOT the old 47-case stack suites):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 tools/y2q_hxl1_task_blocks_original_compiled_gap.py \
  --elf "$HOME/s20-artifacts/ghostlock-419/stock-kernel/stock-vmlinux.elf" \
  --nm "$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm" \
  --output "$HOME/s20-artifacts/hxl1-research/hxl1-task-blocks-original-compiled-corrected-20261014.json"
```

Even if corrected conservative reachability is positive, the missing independent guarantee is **post-publication nonzero chain-walk error return under jointly feasible predicates**, then target-task cleanup state on the compiled proxy rollback. No exploitability or KernelSU status is promoted by one CFG result.

---
## Targeted remaining compiled-code gap — task_blocks_on_rt_mutex (12:05 UTC)

Do **not** repeat the original stock `remove_waiter` current-vs-target task mismatch: it is **already** source/binary-correlated in `SM-G986U1-HXL1-RTMUTEX-SOURCE-REA-TASK-IDENTITY-20261013.md` (including the early return and post-publication error distinction, plus nonzero 1 return consideration). The preceding broad waiter/stack regression cycles do not establish the post-publication, failing chain-walk *factory compiled path*.

The as-yet-uncorroborated function is `task_blocks_on_rt_mutex` at **original static VA 0xffffff80081479d4**, which the pinned HXL1 `rt_mutex_start_proxy_lock` disassembly reaches by BL. The Linux v4.19 reference implementation sets `task->pi_blocked_on = waiter` **after** the early owner==task branch, and subsequently can call `rt_mutex_adjust_prio_chain` and return its status. Treat that as **upstream/source correspondence only** until its factory HXL1 compiled function is inspected. The official CVE advisory explicitly describes the wrong-task rollback defect but does not prove a particular live Samsung error-path interleaving.

A single-purpose new offline extractor `tools/y2q_hxl1_task_blocks_original_compiled_gap.py` was added for the **previously unanalyzed** stock function only. It requires the **already existing** HXL1 reconstructed stock-vmlinux ELF (SHA-256 `e15f67e8253396d9e6463e5dfd78d67e324a7149842a7fbccb973ec0fd36ecdb`) and exact recovered NM (SHA-256 `c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f`); disassembles only `task_blocks_on_rt_mutex` within the next recorded recovered text-symbol boundary; lists candidate `task_struct.pi_blocked_on` displacement stores, intervening chain-walk calls, conservative early/post-store return reachability, and bounded machine-code context. No generic code window reruns, kernel compilation, source patches, device actions, exploit attempts or previous stage regression rechecks.

**Trust limit:** a literal `[xN,#2296]` write is only a candidate PI-blocked-on store. Without tracking xN to the queued task argument, return-value propagation, and all control-flow predicates, the original function does **not** yet establish a factory-reachable late failure leaving a stale reference. Even a compiler-reachable condition is not a live device observation or authorization to promote root or KernelSU stages.

Single missing-function extraction on WSL:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 tools/y2q_hxl1_task_blocks_original_compiled_gap.py \
  --elf "$HOME/s20-artifacts/ghostlock-419/stock-kernel/stock-vmlinux.elf" \
  --nm "$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm" \
  --output "$HOME/s20-artifacts/hxl1-research/hxl1-task-blocks-original-compiled-20261014.json"
```

The output is a new report for the missing compiled function, not another summary of known `remove_waiter` instructions.

---
# HXL1 — NEW research: futex_q candidate field layout and concurrent waiter-pointer writer (2026-10-14)

**Purpose:** Resolve two previously OPEN questions, without reiterating earlier call counts, hashes, unit tests, or GhostLock readiness checks. Target factory HXL1 SM-G986U1 Linux 4.19 / Samsung original source and Image-derived disassembly.

## 1. Three-field original ABI constraint narrows the q.rt_waiter mapping

The Samsung original kernel/futex.c declaration at source lines 244–254 orders:
- struct plist_node list;
- task, lock_ptr;
- union futex_key key;
- pi_state, rt_waiter, requeue_pi_key;
- u32 bitset;
and annotates the struct with __randomize_layout.

A standalone Clang 17 64-bit-layout calculation using *upstream Linux v4.19* struct plist_node and union futex_key definitions plus this **original Samsung futex_q field declaration** produces the following **SOURCE ABI CANDIDATE** (not OEM DWARF):
- sizeof(plist_node) = 0x28 (40 bytes)
- sizeof(futex_key) = 0x18 (24 bytes)
- sizeof(futex_q) = 0x70 (112 bytes)
- offsetof(futex_q, task)=0x28; lock_ptr=0x30; key=0x38; pi_state=0x50
- offsetof(futex_q, rt_waiter)=**0x58**; requeue_pi_key=**0x60**; bitset=**0x68**

The original HXL1 do_futex machine code at the compiled call consistent with futex_wait_setup(uaddr, val, flags, &q, &hb) builds **x3=SP+0x48** and **x4=SP+0xb8**. On AArch64 x3 and x4 are fourth and fifth arguments. Identifying x3 as &q yields these **THREE INDEPENDENT ORIGINAL INSTRUCTION MATCHES**:

| Original HXL1 machine instruction | Original stack slot | Derived futex_q field from q base SP+0x48 |
| --- | --- | --- |
| str w26, [sp,#176] at do_futex+0x11cc | SP+0xb0 | q.bitset: q + 0x68 |
| stp x25,x27, [sp,#160] at +0x11d0 (first element) | SP+0xa0 | q.rt_waiter: q + 0x58 |
| stp x25,x27, [sp,#160] at +0x11d0 (second element) | SP+0xa8 | q.requeue_pi_key: q + 0x60 |
| ldp x8,x9, [sp,#152] at +0x12ec (second element) | SP+0xa0 | candidate reload of q.rt_waiter, then cbz x9 at +0x12f0 |

This is much stronger than a one-slot coincidence: the **base address, bitset, two distinct pointer fields, and later null-check** are mutually consistent with the original Samsung source, arm64 ABI and the upstream v4.19 C data types.

### Randstruct status — avoid an obsolete blocker

The supplied HXL1 stock.config explicitly indicates **CONFIG_CC_IS_CLANG=y, CONFIG_CLANG_VERSION=100006, CONFIG_GCC_VERSION=0**. There is no enabled CONFIG_GCC_PLUGINS or CONFIG_GCC_PLUGIN_RANDSTRUCT entry in that file. Upstream Linux v4.19 include/linux/compiler_types.h lines 122–124 define __randomize_layout as __designated_init in the absence of an overriding compiler implementation, not as automatic field permutation. Upstream v4.19 scripts/gcc-plugins/Kconfig describes the GCC-specific randstruct plugin. These facts, plus three matching compiled slots, make shuffled q fields **unlikely** for HXL1.

**Remaining qualification:** The recovered NM has not yet been applied to this first argument-bearing callee in this new analysis. The model uses upstream v4.19 plist/key declarations rather than a separately rehashed Samsung include-tree. Do not describe the q field layout as OEM DWARF-certified or infer other fields outside these observed offsets without further source.

Upstream reference definitions:
- https://github.com/torvalds/linux/blob/v4.19/include/linux/plist.h
- https://github.com/torvalds/linux/blob/v4.19/include/linux/futex.h
- https://github.com/torvalds/linux/blob/v4.19/include/linux/compiler_types.h
- https://github.com/torvalds/linux/blob/v4.19/scripts/gcc-plugins/Kconfig

## 2. Original source directly identifies a competing writer, not just unknown called-function effects

Crucial Samsung original source **kernel/futex.c lines 1816–1845**:

- requeue_pi_wake_futex(q, key, hb) is invoked when the requeue code acquires the target PI lock (original source call around line 1910).
- It updates q->key and unqueues q (line 1837).
- It explicitly checks and then executes **q->rt_waiter = NULL** (line 1840).
- It adjusts q->lock_ptr, then wakes q->task (lines 1842–1844).
- The source comment requires both hash-bucket locks to be held and explains that nulling rt_waiter tells the waiting thread about atomic lock acquisition.

The original waiter path declares rt_waiter on its stack (line 3238), passes &rt_waiter to rt_mutex_init_waiter (3267), copies &rt_waiter to q.rt_waiter (3274), may block in futex_wait_queue_me (3296), and branches on **!q.rt_waiter** (3314). The queue function may call freezable_schedule() (line 2636), during which the *sleeping thread's kernel stack remains its own*; an unrelated concurrent syscall does not simply execute on that suspended frame.

**Consequences for the previously OPEN lifetime gate:**
1. A changed q.rt_waiter value can be an **intentional synchronized requeue action**, not evidence of corruption.
2. The four direct callees on the previous 31-instruction witness are not the sole potential memory writers; another thread executing futex_requeue can intentionally change the shared q state while the waiter sleeps.
3. Proving **cross-syscall reuse** requires demonstrating a genuine escape beyond valid waiter teardown / cleanup, or a specific unintended race; observing stack object construction and a blocked task is insufficient.
4. The correct outstanding study is **inter-thread handoff plus all return/cleanup paths**, especially whether a waiter address can remain referenced after the waiter function returns. Do not claim such an escape exists without direct evidence.

## 3. Actual cross-thread handoff and return-path obligation (new source-flow analysis)

The original HXL1 source contains a concrete handoff, not merely speculative changes by unknown BL targets:

1. **Waiter publishes stack-local state:** futex_wait_requeue_pi initializes local rt_waiter (3267), sets q.rt_waiter and q.requeue_pi_key (3274–3275), and enters futex_wait_queue_me (3296), which can call freezable_schedule (2636).
2. **Other task can operate under futex hash-bucket locking:** futex_requeue (1934 onward) checks that this->rt_waiter exists and this->pi_state is absent (2121–2123), validates the requeue key (2139), sets this->pi_state (2155), and calls **rt_mutex_start_proxy_lock(&pi_state->pi_mutex, this->rt_waiter, this->task)** (2156–2158). This publishes the pointer to the RT-mutex machinery when it queues a waiter.
3. **Atomic acquisition case:** if rt_mutex_start_proxy_lock returns 1, requeue_pi_wake_futex (2168) unqueues the q, clears **q->rt_waiter = NULL** (1840), adjusts lock_ptr and wakes the original task (1842–1844).
4. **Contended case:** after wakeup, the original waiter checks q.rt_waiter (3314); if non-NULL it may execute rt_mutex_wait_proxy_lock (3343), conditional rt_mutex_cleanup_proxy_lock (3346), debug_rt_mutex_free_waiter (3349), fixup_owner (3354) and unqueue_me_pi (3373). The return is only at 3402, after the documented cleanup control flow.
5. **Error case in the requeue task:** a nonzero/error return from rt_mutex_start_proxy_lock causes this->pi_state to be cleared and the pi-state reference released (2171–2185), not an unconditional deletion of the stack waiter.

**Security-relevant missing proof:** A dangling stack pointer requires showing that a reference survives the thread's logical waiter lifetime / function return or a failing inter-thread handoff ordering. The source outlines the expected synchronization/cleanup on ordinary paths and **does not alone demonstrate a dangling reference**. The existing shortest CFG store/load witness is not a post-return witness; it is inside an active do_futex frame. Do not claim the original return path leaves a stale waiter pointer.

This is the next *unique* research question: can any **factory-reachable** interaction of the atomic-acquired, contended, and abort/error paths leave rt_waiter reachable by RT-mutex machinery after all intended cleanup? Only original stock compiled CFG/concurrency evidence supporting such a path would justify a GhostLock-use-after-return claim.

## Decision: stop duplicate verification, change research focus

The factory q.rt_waiter placement is now a **high-confidence ABI-consistent mapping** supported by multiple real Image instructions and Clang config. Keep the exact OEM compiler identity qualifier rather than relabeling old Stage-3 facts as new discoveries.

**Next needed facts, not another regression cycle:** (a) original source/compiled function edges by which futex_requeue publishes, clears or detaches waiter references; (b) whether *any* reachable return can leave a pointer to the expired stack-local waiter; (c) if one exists, whether the target firmware retains that edge under its real concurrency rules. An original source-only counterexample is insufficient without the compiled target-path evidence.

No working GhostLock primitive, root, KernelSU, or bootloader deployment is established. Existing readiness stages remain unchanged.
