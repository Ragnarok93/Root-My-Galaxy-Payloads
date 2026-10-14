# HXL1 — NEW inter-thread ownership and post-error lifetime audit (2026-10-14)

**Question now studied (not previously resolved by the two original -EDEADLK origin audits):** what becomes of the **waiting task's** RT-mutex waiter reference when a different task is executing FUTEX_CMP_REQUEUE_PI and the **late** PI-chain error path causes proxy-lock rollback? This is a source/binary **conditional path audit**, not an exploit recipe, runnable trigger, device trace, or KernelSU deployment.

## New cross-task invariant

Let **T** be the sleeping task owning `rt_waiter` on its kernel stack, and **R** be the task presently executing `futex_requeue()`. They are *different tasks*. Let `Q` be T's stack-local `futex_q`.

| Stage | Original HXL1 source and binary observation | What is known / conditional |
| --- | --- | --- |
| Waiter preparation | `kernel/futex.c:3238,3264–3275`: T owns local `rt_waiter`; `Q.rt_waiter = &rt_waiter`; `Q.requeue_pi_key = &key2`. | The stack object is live for the active wait call. |
| Waiter publication by R | `kernel/futex.c:2154–2158` invokes `rt_mutex_start_proxy_lock(&pi_state->pi_mutex, this->rt_waiter, this->task)`; original `task_blocks_on_rt_mutex+0xf0` stores the candidate waiter pointer through the target task's `pi_blocked_on` field (`str x21,[x20,#2296]`). | Publication into **T**, not R, is source-correlated and consistent with the stock compiled pointer store. |
| Late PI-chain error | Original compiled `rt_mutex_adjust_prio_chain+0x750` (cycle) and `+0x79c` (depth) each assign signed -35 to W20. Common `+0x7a0` copies W20 to W0 before RET. Original `task_blocks_on_rt_mutex` preserves the returned error in W20 and later copies it to W0. | These branches exist, but the joint live runtime predicates have NOT been established. |
| Proxy rollback | Source `proxy-lock-source.c`: `rt_mutex_start_proxy_lock()` calls `remove_waiter(lock,waiter)` when ret is nonzero; original compiled caller `0xffffff8008147d90..0xffffff8008147da8` has an **additional lock-owner guard** that zeros error if owner is missing. | Removal occurs on the late-error path **only if** the relevant lock still has an owner. |
| Wrong-task PI clearing | Source `remove_waiter-source.c`: `raw_spin_lock(&current->pi_lock); rt_mutex_dequeue(lock,waiter); current->pi_blocked_on=NULL;`. Original compiled `remove_waiter+0x34: mrs x20,sp_el0`; `+0x68: str xzr,[x20,#2296]`. | This explicitly targets **R->pi_blocked_on**, whereas the earlier waiter publication targeted **T->pi_blocked_on**. Thus this rollback's visible PI-field clearing does **not** undo that target-task publication. This is the previously documented CVE logic; the **new result** is its connection to the complete HXL1 waiter return paths. |
| Requeue caller's error case | `kernel/futex.c:2171–2186`: on nonzero proxy return, `this->pi_state=NULL;` and `put_pi_state(pi_state)`; break before `requeue_futex()` at 2189. | This clears **Q.pi_state**, but not the **T.pi_blocked_on** field. Q is not relocated by this call in the error case. |
| Original-key early wake | `kernel/futex.c:3160–3189`: if Q.key is not target key2, `handle_early_requeue_pi_wakeup()` unqueues `Q` from original hash bucket; possible result timeout/signal/spurious return. `futex_wait_requeue_pi():3298–3302` goes to `out_put_keys` on nonzero ret, skipping `rt_mutex_wait_proxy_lock`, `rt_mutex_cleanup_proxy_lock` and `unqueue_me_pi` at 3343–3373. | The visible early-wake cleanup does not update **T.pi_blocked_on**, despite its impending stack-local waiter lifetime ending. Whether this specific early-wake occurs after the late-error rollback on a live device is not proven. |
| Wait function returns | `kernel/futex.c:3392–3402` releases keys/timer then returns from T's `futex_wait_requeue_pi` frame. | If **T.pi_blocked_on** still points to local `rt_waiter` at return, its pointee's stack object lifetime has ended. This is a **conditional dangling-reference** inference; no actual stale-pointer dereference is observed. |

## Single new conditional implication (not a demonstrated runtime trace)

Under **all** of these explicit conditions:

1. An original HXL1 **post-publication** PI-chain error returns nonzero (`-EDEADLK`), rather than an early pre-publication rejection.
2. The proxy lock's owner remains non-NULL when the compiled rollback guard is evaluated; otherwise the caller zeros the result and does not take this rollback.
3. The failed requeue exits before moving Q to the PI futex, leaving Q on its original hash bucket.
4. T subsequently takes the original-key early-wakeup/return path, and no *other* concurrent kernel operation clears T's `pi_blocked_on` between publication and T's function return.

the visible source/compiled transitions are consistent with **T.pi_blocked_on retaining a pointer to a no-longer-live stack-local `rt_waiter`**. This is **stronger and more precise** than earlier discussion of an unspecified 'stale waiter': the relevant retained reference is **in the target task_struct**; the proxy's RT-mutex wait-tree node is separately dequeued during rollback.

### What this does NOT establish

- No currently observed execution satisfies the **conjunction** of post-publication chain error, continued lock ownership, and early wake/return.
- No proof that source branch predicates are simultaneously satisfiable on the factory phone, nor of all other concurrently executing cleanup effects.
- No measured post-return dereference, memory reuse, arbitrary write, user-controllable primitive, root, KernelSU or bootloader unlock.
- The already-documented `remove_waiter` wrong-task clearing remains the **same old CVE bug**, not a new distinct vulnerability.

### New practical direction (no repeated extraction)

The genuine remaining readiness gate is **factory-credible joint-state reachability and exclusion of intervening repair**. Existing stock function disassembly is sufficient to state the conditional invariant; continuing to count BL targets or rehash old text sections adds nothing. A defensible next analysis should test the above state assumptions with a **bounded, non-device source-level concurrency model or upstream/factory patch correspondence**, and clearly distinguish abstract model satisfiability from real HXL1 behavior.

**Suggested mitigation audit:** establish which task's `pi_blocked_on` the *corrected* rollback should clear under the correct task PI lock and whether the target's original-key wakeup path can then return with no retained reference. Do not modify factory images or claim compatibility without build/test validation.

**Source provenance:** Samsung original `kernel/futex.c` from user-provided `hxl1-source-dispatch-review.tar.gz`; original rt-mutex source excerpts and stock disassembly from `rtmutex-stock-evidence.zip`; original 534-instruction target chainwalk ledger from owner-uploaded `hxl1-chainwalk-complete-20261014.json`; preexisting `task_blocks_on_rt_mutex` W20 register evidence.

