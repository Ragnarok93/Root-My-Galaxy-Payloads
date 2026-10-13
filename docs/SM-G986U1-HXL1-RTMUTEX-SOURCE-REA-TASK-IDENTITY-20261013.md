# HXL1 task-identity review: Samsung source and original live REA/Ghidra (October 13, 2026)

**Device/firmware scope:** Galaxy S20+ SM-G986U1, Samsung G986U1UESCHXL1, Linux 4.19. **Result: GO for a source/binary-corroborated conditional task-identity defect; NO-GO for claiming runtime exploitability or a production root profile.** No handset was accessed.

## Evidence independently read

User supplied **two** exact uploaded archives:
- `hxl1-rtmutex-source-review.tar.gz` SHA-256 `2da244efa88cc9e8a486f5fa90603cd9e2def3df947083306163c4811c01acf4`, containing four original Samsung source/header files. The two core source files independently hash to the existing `tools/y2q_hxl1_rtmutex_displacement_attest.py` pins:
  - `kernel/locking/rtmutex.c`: `36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9`
  - `kernel/futex.c`: `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`
  - `include/linux/rtmutex.h`: `020228c4d90e4266517334e93ab2f6a22f97ce59a8a4bd712910b54995ee7979`
  - `include/linux/sched.h`: `0d8cfa0da4736e87c61cdf8969426dd20cd1ad602474526d3310b8373b24db3b`
- `hxl1-stage3-live-ghidra-evidence.tar.gz`, SHA-256 `bc10e853aff4e76f4c05cb9095cbd235dd535f56e83f37ec6ed43eaa4be804e6`. Its three original-function native instruction records match archived factory-bound REA opcode records: 140/140 `remove_waiter`, 38/38 `rt_mutex_start_proxy_lock`, 545/545 `futex_lock_pi`. The source SHA matches the repository pins; the original 52 MB stock `kernel.bin` is **not present in either archive**, so re-hashing it during this independent review was not possible. The owner's October 12 Stage 3 verifier separately attested its exact SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.

## Definitive source-to-original-code correspondence

**Proxy lock operates on a supplied task**:
- `kernel/locking/rtmutex.c:929–966` `task_blocks_on_rt_mutex(lock,waiter,task,...)` sets `waiter->task = task` (line 954) and `task->pi_blocked_on = waiter` (line 964) after the early `owner == task` check at lines 950–951.
- `kernel/locking/rtmutex.c:1748–1775` `__rt_mutex_start_proxy_lock` calls `task_blocks_on_rt_mutex(...,task,RT_MUTEX_FULL_CHAINWALK)` and can return nonzero, including `-EDEADLK` from the chain checker (`rtmutex.c:474–489` or `:597–604`) or `1` on lock acquisition (`:1756–1757`).
- `kernel/locking/rtmutex.c:1797–1809` `rt_mutex_start_proxy_lock` invokes `remove_waiter(lock,waiter)` for **any nonzero** return from the preceding call (line 1805), irrespective of whether `current` is the passed `task`.
- Factory-bound Ghidra original `rt_mutex_start_proxy_lock` entry `0xffffff8008147d14` observes success path `0xffffff8008147d48: cbz w0, ...`, setting return `1`, then invokes `remove_waiter` at `0xffffff8008147d58: bl 0x000100a0` in the relocated slice. The chain/error branch also leads to that call when its owner check retains nonzero result. The call target is `remove_waiter` entry `0xffffff8008147db4`; in its relocated slice it is labeled `0x100a0`.

**Cleanup operates on current task, not on the passed waiter's task**:
- `kernel/locking/rtmutex.c:1068–1080` `remove_waiter(lock,waiter)` locks `current->pi_lock` then removes `waiter`, sets `current->pi_blocked_on=NULL` and unlocks **current**.
- Factory-bound original `remove_waiter` (entry `0xffffff8008147db4`) preserves the `waiter` argument at `0xffffff8008147dd4: mov x23,x1`, retrieves `sp_el0` at `0xffffff8008147de8: mrs x20,sp_el0`, forms the current-task lock address at `0xffffff8008147dec: add x21,x20,#0x8c8`, and stores zero to `0xffffff8008147e1c: str xzr,[x20,#0x8f8]`. The offsets `0x8c8` and `0x8f8` are **source/Clang10-comparison field hypotheses corroborated by stock native code**, not independently authenticated original OEM debug types.
- Other `remove_waiter` calls from ordinary slowlock are entered with the caller itself as the waiter; `current` is not universally incorrect. The **proxy path** is where a different task pointer matters.

**The cross-task proxy caller exists in pinned Samsung source**:
- `kernel/futex.c:2254–2278` `__queue_me` sets `q->task=current` when the original waiter joins the futex queue (line 2277).
- A separate execution of `futex_requeue` iterates queued waiters and invokes `rt_mutex_start_proxy_lock(&pi_state->pi_mutex,this->rt_waiter,this->task)` at `kernel/futex.c:2107–2158`. The queued waiter task is not generally the requeue caller's `current`; it can be a different thread.
- An error from the proxy start enters the error-handling branch `kernel/futex.c:2171–2186`.
- **Conditional inconsistency**: when `task_blocks_on_rt_mutex()` has first set `task->pi_blocked_on=waiter` and subsequently reports an error for that queued target, `rt_mutex_start_proxy_lock()` calls `remove_waiter()`, which clears `current->pi_blocked_on` instead of `task->pi_blocked_on`. This is a source-level mismatched cleanup target, supported by factory `sp_el0` instructions. A particular hardware interleaving and actual state difference have **not** been observed on the phone.

## Separate return-value concern

`rt_mutex_start_proxy_lock` at `rtmutex.c:1804–1806` uses `if (unlikely(ret)) remove_waiter(...)`. But the documented return contract at `:1790–1793` declares `1` a successful proxy acquisition, not an error. The original Ghidra assembly likewise routes the acquisition-success `ret=1` branch through `remove_waiter` (`...7d48` -> `...7d58`). This is **not limited to the negative-error case**. It warrants independent invariant testing because the waiter may not have been enqueued on this fast-success path. Do not conclude that a successful return necessarily caused memory corruption; determine the state of the initialized waiter's tree nodes and caller PI state.

## Go / no-go matrix

| Claim | Assessment | Reason |
|---|---|---|
| Original Samsung source provenance of `rtmutex.c` and `futex.c` | **YES** | Both match previously pinned SHA-256 |
| Original Ghidra `current` PI cleanup and proxy caller branch | **YES** | Exact factory-derived native instructions plus source lines |
| Cross-task proxy caller possible in Samsung source | **YES** | `futex_requeue` passes queued `this->task`, distinct from the requeue executor |
| Conditional wrong-task cleanup on a nonzero proxy start | **SOURCE-CONFIRMED** | Target PI blocked-on state set in one function, current PI cleared in another; some early error paths set no target PI state |
| Triggered on a physical S20+ | **NOT PROVEN** | No runtime `current`/target comparison or demonstrated unsafe interleaving |
| Kernel arbitrary-read/write/privilege escalation | **NOT PROVEN** | A source-level state invariant issue is not an exploitation primitive |
| All 13 original OEM structure-member offsets | **NOT PROVEN** | Clang10 comparison and matched displacements do not substitute for original OEM debug type attribution |
| Bootloader unlock / KernelSU deployability | **NOT PROVEN** | No verified loader/authorization route |

## Next safe research gate

Create an **isolated, harmless state-invariant regression** with distinct `caller`, `target`, `owner`, and `waiter` identities using source-exact control flow. Exercise simulated `ret=-EDEADLK`, `ret=0`, `ret=1`, and owner-disappeared behavior; confirm whether current PI state changes and whether the target's blocked-on value is left stale under each case. Do not induce racy futex calls on the real locked phone or write firmware. Distinguish a source-level invariant result from hardware reachability.

One more useful factory static check, if warranted, is to correlate the *separate* `futex_requeue` compiled function from the SHA-pinned original Image with a fresh bounded REA/Ghidra source slice. It was **not** one of the three analyzed function bodies; current correspondence of `futex_requeue` is source-level only.

**Readiness unchanged:** Stages 1–2 COMPLETE, Stage 3 PARTIAL, 4–6 OPEN, 7–8 BLOCKED, 9 DEFERRED. No root or device modifications.
