## October 14, 15:29 UTC — NEW factory source negative gates: rollback does not wake affected PI waiter

This follow-up reuses the **original pinned Samsung** `kernel/futex.c` from the previously supplied archive (SHA-256 `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`) and reviews only wakeup/refusal conditions that were **not covered by the earlier conditional lifetime model**. This is an original-source control-flow exclusion, not a new user-trigger recipe or a successful hardware race.

- **The failed `FUTEX_CMP_REQUEUE_PI` does not directly wake this waiter.** `futex_requeue` marks normal wake-queue entries at lines 2133–2135 **only** with `!requeue_pi`. The alternative PI atomic-acquire wake `requeue_pi_wake_futex` at line 2168 belongs to the **successful `ret == 1`** branch. In the `ret < 0` branch, lines 2171–2186 clear `this->pi_state`, drop a reference and `break` before `requeue_futex` at 2189; `wake_up_q(&wake_q)` at 2202 has not had **this failed PI waiter** appended by this loop.
- **Ordinary futex wake operations refuse the still-PI-marked queue entry:** `futex_wake` checks `this->pi_state || this->rt_waiter` and returns `-EINVAL` at lines 1622–1624. Both queues in `futex_wake_op` repeat that rejection at lines 1752–1754 and 1766–1768. Non-PI `futex_requeue` rejects a `this->rt_waiter` entry at lines 2121–2125. No conclusion about unrelated queue entries is intended.
- **The waiting stack remains live until wait completion, not until requeue failure.** `futex_wait_queue_me` sets `TASK_INTERRUPTIBLE` at line 2618, arms an optional timer at 2622–2623, and conditionally enters `freezable_schedule` at 2635–2636. After it resumes, `futex_wait_requeue_pi` checks original-key early wake at 3299 and exits if that returns nonzero at 3301–3302. That helper distinguishes timeout, signal, and possible spurious rescheduling at lines 3182–3187. Therefore the retained `T.pi_blocked_on` pointer, if any, does **not become dangling merely because R's error rollback finished**.

**New exclusion for the previously modeled conditional stale-reference state:** the rollback path **alone** does not provide a source-level mechanism for ending T's waiter-stack lifetime. A further, independently established completion transition is necessary, along with proof that no legitimate repair clears T's PI field. The prior abstract model's `original_key_waiter_returns` should be treated as an **assumed** event, not as something established by proxy failure. Ordinary `FUTEX_WAKE`, `FUTEX_WAKE_OP`, and ordinary requeue are excluded as straightforward wake/relocation mechanisms for this still-marked PI waiter. This does **not** exclude timeout, signal, other scheduler activity or a later PI-aware operation.

**Open guide gate unchanged:** the original HXL1 joint-state possibility (late chain-walk error, owner-present rollback, independently completed wait and no intervening repair), any post-return invalid dereference, kernel privilege escalation, KernelSU and firmware deployment remain unverified. Do not repeat RT-mutex instruction, symbol or stack audits; future analysis must account for concrete legitimate state repair as well as task completion. No physical device or exploit work was performed.

---

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


## New official correction crosswalk and bounded source-transition model

The official Linux CVE advisory explicitly enumerates three consequences of the **same** wrong-task rollback: holding the wrong task's `pi_lock` during dequeue, leaving the target task's `pi_blocked_on` uncleared, and adjusting the priority-inheritance chain using the wrong task. The upstream fix is Linux commit [3bfdc63936dd4773109b7b8c280c0f3b5ae7d349](https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349); official announcement: [CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7).

The upstream diff applies **three identity-sensitive corrections**: obtains the task from `waiter->task`, takes that task's `pi_lock` while dequeuing and clearing its PI state, and passes that task as the top task in `rt_mutex_adjust_prio_chain()`. This supports the HXL1 cross-task ownership diagnosis but does **not** make an upstream v7.x patch a mechanically safe drop-in for Samsung's 4.19 tree: the modern diff uses `scoped_guard`, and backport locking conventions differ.

New offline model: [`tools/y2q_hxl1_pi_lifetime_state_model.py`](../tools/y2q_hxl1_pi_lifetime_state_model.py), with [nine regression invariants](../tools/test_y2q_hxl1_pi_lifetime_state_model.py) and [isolated CI](../.github/workflows/hxl1-pi-lifetime-model-ci.yml). Nine equivalent local tests passed on 2026-10-14; CI execution is not yet confirmed.

The model distinguishes four conditional states rather than inferring a live exploit:

| Abstract source assumptions | Modeled target `pi_blocked_on` after original-key return |
| --- | --- |
| Published waiter, late nonzero error, lock owner still present, stock rollback, no other repair | **Retained reference to expired stack-local waiter** |
| Same assumptions, corrected rollback uses `waiter->task` | **Cleared** |
| Same assumptions, but another legitimate operation clears target PI field first | **Cleared** |
| Lock owner disappears before proxy rollback guard | **This particular nonzero-error rollback is suppressed; other continuation not modeled** |

These are **logical implications under stated assumptions**, not real HXL1 scheduling witnesses. In particular, the model does not claim that a cycle/depth error, owner-present guard and later original-key wake can be made true simultaneously. It does not create a syscall trigger, runtime UAF, privilege escalation or deployable firmware.

The next substantive research must assess joint-state feasibility and all legitimate intervening cleanup paths, **not** redisassemble or rehash the now completed 534-instruction PI-chain function.

