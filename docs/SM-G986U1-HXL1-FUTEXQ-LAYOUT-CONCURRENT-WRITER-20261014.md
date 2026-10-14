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

## Decision: stop duplicate verification, change research focus

The factory q.rt_waiter placement is now a **high-confidence ABI-consistent mapping** supported by multiple real Image instructions and Clang config. Keep the exact OEM compiler identity qualifier rather than relabeling old Stage-3 facts as new discoveries.

**Next needed facts, not another regression cycle:** (a) original source/compiled function edges by which futex_requeue publishes, clears or detaches waiter references; (b) whether *any* reachable return can leave a pointer to the expired stack-local waiter; (c) if one exists, whether the target firmware retains that edge under its real concurrency rules. An original source-only counterexample is insufficient without the compiled target-path evidence.

No working GhostLock primitive, root, KernelSU, or bootloader deployment is established. Existing readiness stages remain unchanged.
