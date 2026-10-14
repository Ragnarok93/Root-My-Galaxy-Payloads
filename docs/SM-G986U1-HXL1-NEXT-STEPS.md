## October 14 — Defensive 4.19 cleanup-backport candidate staged (NEW)

The outstanding source defect is independently covered by the existing [cross-task lifetime audit](SM-G986U1-HXL1-CROSS-TASK-LIFETIME-AUDIT-20261014.md) and nine-test abstract model. **Do not duplicate that work.** A separate [defensive backport review](SM-G986U1-HXL1-RTMUTEX-DEFENSIVE-419-BACKPORT-20261014.md) now stages a source-only Linux 4.19 `remove_waiter()` task-identity fix, adapted from the upstream CVE-2026-43499 correction. The patch applies cleanly to the exact archived original function excerpt (including when embedded after dummy preceding lines); the complete Samsung source tree has **not** been checked or built here. Nothing was flashed. No root/KernelSU stage change.

**Only safe next action:** run the one `git apply --check` command documented in the remediation review against the owner's full stock source checkout. A passing dry-run is source-context evidence, not factory compatibility or a deployable image.

---

## October 14 — post-error cross-task ownership gate (NEW; old instruction audits closed)

The **new** cross-function evidence is [HXL1 cross-task lifetime audit](SM-G986U1-HXL1-CROSS-TASK-LIFETIME-AUDIT-20261014.md). Original stock source correlates an already published target-task PI waiter, wrong-task `remove_waiter` rollback, `futex_requeue` error exit before moving the futex_q, original-key early-wakeup handling, and eventual waiter stack return. If (and only if) a **late** chain-walk error returns while the proxy lock still has an owner, and no other operation clears the target PI state, the source-level state transitions permit a retained target-task pointer after waiter lifetime ends. The **official upstream fix** `3bfdc63936dd` confirms that the rollback must operate on `waiter->task`, including PI locking and chain top-task identity. A small [abstract-only source state model](../tools/y2q_hxl1_pi_lifetime_state_model.py) and nine new tests are committed; no runtime trigger.

**Only unresolved gate:** original HXL1 joint-state feasibility of the post-publication error, continued ownership, and legitimate waiter exit, accounting for all intervening state repair. **Do not** repeat earlier source hashes, ELF disassembly, BL crosswalk, register-return, negative-literal or branch-guard audits. Source-level conditional UAF risk is not a demonstrated runtime stale dereference, temporary root, KernelSU or unlocked bootloader.

---

## October 14 — NEW targeted gap analysis: candidate futex_q field ABI and cross-thread reference handoff

**Stop duplicated archival verifications and symptom-free regression additions.** The user specifically wants only the remaining unproven relationships investigated. A new original ABI/source analysis, without another full audit cycle, narrows the former `q.rt_waiter` *field-placement* ambiguity: reconstructed upstream 4.19 64-bit `struct futex_q` gives `rt_waiter` at +0x58, `requeue_pi_key` at +0x60 and `bitset` at +0x68. The original HXL1 compiled call consistent with `futex_wait_setup(...,&q,&hb)` passes `x3=SP+0x48` as the fourth argument and stores all three fields at matching original SP slots: `SP+0xa0`, `SP+0xa8`, `SP+0xb0`. The supplied HXL1 Clang10 config has no GCC randstruct plugin enabled; the source `__randomize_layout` annotation alone is not proof of actual randomization. This yields a high-confidence original field map without claiming full OEM DWARF or changed readiness.

More important, original Samsung `kernel/futex.c` has a specific **other-thread writer**: `requeue_pi_wake_futex` deliberately clears `q->rt_waiter` (1840) after successful atomic PI acquisition. `futex_requeue` passes the address stored in `this->rt_waiter` to `rt_mutex_start_proxy_lock` (2156–2158) and distinguishes successful, queued, and error cases. The original sleeper may block in `freezable_schedule` (2636), then checks `q.rt_waiter` (3314), conditionally waits/cleans (3343–3349), unqueues (3373) and returns (3402). The reported null-check is expected protocol behavior; it is not evidence of memory corruption or a dangling pointer.

**Only next substantive blocker:** prove or disprove a factory-reachable inter-thread ordering that leaves an RT-mutex reference to the *expired* stack waiter after intended cleanup or the original do_futex return. A live blocked task retains its own kernel stack; matching SP offsets across unrelated syscalls do not demonstrate overlapping live objects. Intervening call names and existing static path witnesses are insufficient. Prioritize genuine source/compiled concurrency-state analysis, not more SHA runs, symbol counting or historical checkpoints.

See [new field-layout and inter-thread ownership analysis](SM-G986U1-HXL1-FUTEXQ-LAYOUT-CONCURRENT-WRITER-20261014.md). Stage 3 remains PARTIAL and root/KernelSU NOT demonstrated.

---

## October 14, 11:38 UTC — 47/47 owner tests confirmed; four-call witness NM crosswalk automated

The owner uploaded a complete WSL console transcript with fast-forward through ac4cd4a and **all 47 current tests passing** (25 waiter/frame, 15 static store/load CFG, 7 witness). The three original-archive audits completed and rehashed recovered vmlinux-stock.nm. The original frame is 480 bytes, with two SP writes in 1,766 instructions; the candidate SP+0xa0 stack pointer store/load/null-test remains linked by a conservative 31-instruction CFG witness with four calls and five conditional branches. The full runtime lifetime, memory side effects, factory q.rt_waiter layout and root **are not established**.

The confirmed [47-test owner checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-owner-waiter-47-tests-20261014T1138.json) and [brief audit guide](SM-G986U1-HXL1-GHOSTLOCK-WAITER-47-TESTS-20261014.md) are committed. Rather than repeating code extraction or asking for a standalone NM upload, the existing `tools/y2q_hxl1_waiter_store_load_witness.py` now accepts `--nm` and uses the strict original recovered-NM SHA to **name the four intervening direct BL destinations**, with alias/interior ambiguity and unknown memory effects retained. The existing WSL runner passes the already available NM automatically.

Six new synthetic regressions bring the witness suite to **13 cases written**, beyond the **7/7** owner-confirmed baseline. Execution of these six newest tests and the new NM-enhanced report is **not yet observed**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

No readiness changes: stages 1–2 complete, 3 partial, 4–6 open, 7–8 blocked, 9 deferred. The four called helpers' memory effects remain a substantive static-analysis uncertainty, not solved by the act of labeling them.

---
## October 14, 11:26 UTC — uploaded original waiter reports and conservative call-effects witness

The owner uploaded two completed SHA-pinned read-only outputs: original waiter source/compiled audit (6,461 bytes, SHA-256 440c7fa2426b5e620eb6b28c1d7ad1ac20057767a4e6b0b56f8574f8d2407da3), and original store/load static CFG audit (2,363 bytes, SHA-256 5e7defd15144f2d792ae63c8f9caf244e1f3f247300078671f80d5a74acff024). They affirm 12 C source landmarks, 3 stack-derived helper arguments, 158 original SP uses with only 2 explicit SP writes (480-byte do_futex frame), an SP+0xa0 pointer store and matching later reload into x9, and a 31-instruction conservative CFG path. The owner-side recovered NM was independently rehashed. There is no claim of OEM struct field identity, full pointer lifetime, cross-syscall alias or root; no current unittest console transcript was uploaded.

A further bounded read-only inspection of the **actual original archived disassembly** enumerated that same shortest 31-instruction store-to-load path in full. It contains **four direct BL callsites** at do_futex +0x11d4, +0x12a4, +0x12b0, +0x12e8, and **five conditional branch sites** at +0x11dc (taken), +0x1230 (taken), +0x12c0 (fall-through), +0x12d0 (fall-through), +0x12e0 (fall-through). The only syntactic explicit store instruction on that shortest path is the first at +0x11d0. **This is not complete memory-alias analysis:** the four called functions may affect reachable memory, the conditions are not proved jointly satisfiable, and other paths have not been analyzed. No C-local factory field or live waiter overlap can be inferred.

New tools/y2q_hxl1_waiter_store_load_witness.py, seven locally passing synthetic tests, CI integration, and extension of tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh are committed. The next owner run tests and rechecks all existing original source+compiled and new static witness evidence without reflashing or phone access:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

New [machine-readable research checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-waiter-store-load-witness-20261014.json). New suite owner/CI pass not observed yet. No readiness promotion: Stage 3 PARTIAL, Stages 4–6 OPEN, 7–8 BLOCKED, 9 DEFERRED. Runtime exploitation and KernelSU unverified.

---

## October 14, 11:07 UTC — original HXL1 waiter stack-slot store/load and null-test linked conservatively

Owner uploaded the completed extended waiter report, SHA-256 440c7fa2426b5e620eb6b28c1d7ad1ac20057767a4e6b0b56f8574f8d2407da3 (6461 bytes). The tool independently rehashed recovered NM and confirmed 12 original source landmarks, 3 compiled waiter helper arguments, 158 original SP references/2 writes in a 480-byte frame, and conditional x25 store. This upload **does not contain a 25-test console transcript**.

Further independent analysis of the exact SHA-pinned original source and disassembly archives identified a machine-code store at do_futex+0x11d0, first value to SP+0xa0, and a later load at +0x12ec, second LDP register x9 from **the same SP+0xa0**. The next original instruction +0x12f0 tests x9 for null. The bounded conservative CFG finds a **31-instruction static path** from the store to the reload. The original C source assigns q.rt_waiter=&rt_waiter (3274) and checks if (!q.rt_waiter) (3314); source struct futex_q is marked __randomize_layout, and actual OEM field layout, branch-path feasibility, and indirect memory aliasing remain **UNPROVEN**.

New tools/y2q_hxl1_waiter_store_load_cfg.py, 15 synthetic tests, GhostLock CI integration and the extended existing waiter-lifetime owner runner are committed. Local independently authored equivalent tests passed 15/15; **owner/hosted new suite run unconfirmed**. The exact [research evidence](../research/y2q-G986U1UESCHXL1/ghostlock-owner-waiter-store-load-cfg-20261014.json) and [complete store/load CFG notes](SM-G986U1-HXL1-GHOSTLOCK-WAITER-STORE-LOAD-CFG-20261014.md) distinguish actual binary memory addresses from source-field hypotheses.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

This is read-only, uses the existing original archives and recovered NM, and does not run a payload or modify a phone. Stage 3 PARTIAL, 4–6 OPEN, 7–8 BLOCKED, 9 DEFERRED; no GhostLock primitive/root/KernelSU established.

---

## October 14, 10:53 UTC — owner NM pin passed; original do_futex frame SP invariant and conditional waiter-pointer stack store

Owner's uploaded full report `hxl1-waiter-source-compiled-20261014T105255123936007Z.json` (SHA-256 `f90df3db38e68e246fda6052896f72607b8dfd8a950e19c8a45d70c7500f3a40`) confirms 12 source markers, all three compiled waiter-helper arguments and **independent recovered NM rehash**. The upload does not include console test output, so 12 prior tests can be described only as earlier local test work.

The original archived **1,766-instruction `do_futex`** was independently checked again: **158 SP-referencing instructions, exactly two SP writes**—`+0x0: sub sp,sp,#0x1e0` and `+0xb78: add sp,sp,#0x1e0`—followed immediately by `ret` at `+0xb7c`. There are no SP memory-writeback forms or unexpected SP opcodes. On ordinary ABI-compliant paths, this supports a stable relative frame base for `SP+0xc0` within the 480-byte function frame, not all-path waiter execution or cross-syscall reuse.

A new bounded original pointer-transfer check further finds `+0x1194: add x25,sp,#0xc0`, two subsequent BLs (waiter init `+0x1198`, futex-key acquisition `+0x11b0`), `+0x11b4: cbnz w0, ...` (skip when the key operation fails), and `+0x11d0: stp x25,x27,[sp,#160]` on fall-through. No intervening `x25/w25` references were present in this original straight-line region. With the normal ARM64 callee-preserved-register assumption, `x25` carries the original stack-derived value `SP+0xc0` to a stack store at `SP+0xa0`. **The destination C object and `q.rt_waiter` field identity remain unverified**.

These checks were integrated into the same `tools/y2q_hxl1_waiter_argument_lifetime_audit.py` (no new archive extraction). Its regression suite now contains **25 written cases** and the existing WSL runner prints the frame and pointer-store results; the current **25-test suite has not yet been observed passing on owner WSL or CI**. [Full research write-up](SM-G986U1-HXL1-GHOSTLOCK-WAITER-THREE-ARGUMENTS-20261014.md), [frame census](../research/y2q-G986U1UESCHXL1/ghostlock-dofutex-sp-frame-census-20261014.json), and [conditional store checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-waiter-sp-invariant-and-store-20261014.json).

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

**No stage promotion:** compiler C-local bounds, path-sensitive waiter lifetime, cross-syscall stack overlap, GhostLock primitive/root, and KernelSU remain unverified. Porting readiness stays COMPLETE, COMPLETE, PARTIAL, OPEN, OPEN, OPEN, BLOCKED, BLOCKED, DEFERRED.

---

## October 14, 10:23 UTC — three original waiter callsite arguments independently corroborated

Independently rehashed both original user-provided Samsung archives. The original `kernel/futex.c` source's source-local `rt_waiter` and `q.rt_waiter` lifetime sequence has **12 ordered markers** (declaration 3238 through return 3402), including **conditional**, not unconditional, proxy cleanup. Separately, the archived **1,766-instruction original `do_futex` machine code** has three exact static stack-relative argument constructions: `x0 = sp + 0xc0` before `rt_mutex_init_waiter` (`+0x1198`), `x2 = sp + 0xc0` before `rt_mutex_wait_proxy_lock` (`+0x1308`), and `x1 = sp + 0xc0` before `rt_mutex_cleanup_proxy_lock` (`+0x1328`). The tool hashes and checks machine words and complete intervening straight-line argument instructions, not just their proximity.

New [single offline verifier and 12 locally passing regressions](SM-G986U1-HXL1-GHOSTLOCK-WAITER-THREE-ARGUMENTS-20261014.md) are committed to `tools/y2q_hxl1_waiter_argument_lifetime_audit.py`, `tools/test_y2q_hxl1_waiter_argument_lifetime_audit.py`, and `tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh`, with GhostLock CI integration. Original static/source evidence checkpoint: [three waiter argument sites](../research/y2q-G986U1UESCHXL1/ghostlock-waiter-three-argument-sites-20261014.json).

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

This refines evidence of the source/compiler waiter path but **does not** prove all-path stack-pointer stability, exact C-local byte bounds, pointer-lifetime under a block, cross-syscall stack reuse, exploitability, root or KernelSU. No readiness stage was promoted. **Owner/hosted CI tests of the new commit remain unconfirmed.**

---

## October 14, 09:27 UTC — original futex waiter initializer receives stack-derived pointer

The newly uploaded two-hop `do_futex` report (SHA-256 `9ea5655068fa39ecb0387bb9fa3b566d4463f613a585d977282056364e057321`) and independently rehashed original `do_futex.disasm.txt` establish the consecutive compiled machine instructions `do_futex+0x1190: add x0, sp, #0xc0`, `+0x1194: add x25, sp, #0xc0`, `+0x1198: bl rt_mutex_init_waiter`. Thus the original stock kernel **passes a stack-derived first argument (`x0`) to the recovered waiter-initialization function**, not merely a nearby stack address. The separate `x25` copy is also observed.

The original uploaded Samsung source archive `kernel/futex.c`, independently SHA-verified, declares `struct rt_mutex_waiter rt_waiter` (archived source line 3238), explicitly describes its stack allocation (3263–3265), calls `rt_mutex_init_waiter(&rt_waiter)` (3267), and sets `q.rt_waiter = &rt_waiter` (3274). This is **strong source-to-machine consistency**, but neither archive nor static code alone certifies full compiler C-local attribution, bounds and lifetime, runtime reuse of the same stack storage, GhostLock exploitability or root.

The existing operation-11 verifier was updated in place to fail closed if the exact `x0/x25` sequence or direct `rt_mutex_init_waiter` callee changes; four new synthetic tests bring that suite to **30 written cases**, pending WSL/CI execution. The new [read-only evidence checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-op11-stack-derived-argument-20261014.json) and [detailed reconciliation](SM-G986U1-HXL1-GHOSTLOCK-OP11-COMPILED-BLOCK-20261014.md) record the original SHA pins, distinct source-vs-machine facts, and unproven conclusions.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

**Next substantive evidence gate:** compile/source object lifetime and all relevant cleanup and queue-pointer uses under a conservative CFG, with no assumptions about overlap with `sendmsg`. The case-11 direct pointer evidence does not promote Stage 3 or unlock KernelSU. Readiness stays COMPLETE, COMPLETE, PARTIAL, OPEN, OPEN, OPEN, BLOCKED, BLOCKED, DEFERRED.

---

## October 14, 09:12 UTC — five original HXL1 futex case-11 call targets recovered

Owner supplied and we parsed the updated original static `do_futex` operation-11 report, SHA-256 `82735ba24c2b14b652e0f965cdc9939918d812985153fa1a98548be59731de75` (14,815 bytes). All **five of five** direct BL addresses across the existing depth-two alternatives now have exact recovered symbol labels from the pinned HXL1 NM: `hrtimer_init`, `hrtimer_init_sleeper`, `ktime_add_safe`, **`rt_mutex_init_waiter`**, and `get_futex_key`. The first block remains `do_futex+0xbd0`, 24 instructions, zero direct calls; the later bounded alternative blocks contain all five.

This is a meaningful original compiler-code corroboration of the futex waiter/timer setup function families; it is **not evidence that C-local stack object identity, lifetime, interprocedural dataflow, cross-syscall stack alias or exploitability was established**. There was no physical phone exploit test. The input report explicitly marks original compiler-local mapping, root and KernelSU false.

[Versioned 09:12 owner checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-op11-owner-twohop-20261014T091255Z.json) and [detailed five-call reconciliation](SM-G986U1-HXL1-GHOSTLOCK-OP11-COMPILED-BLOCK-20261014.md) are committed. The original `tools/y2q_hxl1_ghostlock_futex_op11_block.py` now labels the report accurately as two-hop static analysis, rejects drift in all five exact named callees, and adds four tests (suite: **26**, pending execution). The existing CI workflow already tracks both edited tool and tests.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

**Next evidence gate:** independently reconcile the compiled source-object identity and lifetime to the pinned Samsung `kernel/futex.c` source, with explicit uncertainty until OEM compiler-local metadata or stronger original machine-code attribution exists. Merely counting further helper calls cannot prove reuse or root. Do not advance production or KernelSU deployment gates.

Readiness unchanged: stages 1–2 COMPLETE, stage 3 PARTIAL, stages 4–6 OPEN, 7–8 BLOCKED, stage 9 DEFERRED.

---

## October 14 — independent uploaded-archive verification: op11 two-hop callsites

Independently rehashed the original uploaded five-function `hxl1-disassembly-review.tar.gz` (SHA-256 `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997`) and its original `do_futex.disasm.txt` (`56286516ae9e6a873beab22b16af3ab330a768dc1b02f901854eb96f193789a5`). Analyzed the **actual static instruction text** without QEMU, a new build or device operation.

The original case-11 block at `do_futex+0xbd0` has 24 instructions and no BL calls. Its immediate static alternatives are `+0xc30` (1 instruction, terminates in `cbz`) and `+0x117c` (2 instructions, terminates in `b`). Their successor alternatives, reached through the next static branch edge, are `+0xc34` (16 instructions; BL at `+0xc48`, `+0xc58`, `+0xc68`), `+0x118c` (11 instructions; BL at `+0x1198`, `+0x11b0`) and `+0x128c` (2 instructions; zero BL). There are **five original literal BL sites in these depth-two alternatives**, not zero throughout case 11.

A versioned [machine-readable two-hop checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-op11-original-twohop-20261014.json) and the [updated full forensic guide](SM-G986U1-HXL1-GHOSTLOCK-OP11-COMPILED-BLOCK-20261014.md) contain the exact addresses, bounds and provenance limitations. The existing `tools/y2q_hxl1_ghostlock_futex_op11_block.py` now checks the exact original six block/count triples and produces two-hop branches and exact recovered-NM labels. Four extra synthetic tests increase that suite to **22**, and the existing runner now prints all bounded successor calls:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

**New 22-test suite execution on owner/CI still unconfirmed**; the original archive itself *was* independently examined in this turn. The absolute kernel Image was not freshly rehashed in this archive-only pass. Five branch calls do not establish specific C-local objects, actual runtime path feasibility, waiter lifetime, stack reuse, exploitable corruption, temporary root or KernelSU. Stage 3 still PARTIAL; no downstream deployment gate is promoted.

---

## October 14, 08:35 UTC — original HXL1 futex operation-11 first block established

Owner ran `bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh` on original SHA-pinned five-function code archive after `b37bf5d`. All **13/13** original synthetic tests passed. Exact cached compiled `do_futex` operation-11 dispatch enters a **24-instruction first basic block at `do_futex+0xbd0`**, with **zero direct `bl` calls before the first explicit control transfer**. The full JSON lives on owner WSL as `ghostlock-original-futex-op11-20261014T083539553990891Z.json`; the terminal paste does **not** include the terminating branch opcode or its target.

To avoid repeating source-based searches, the same SHA-bound offline tool is now extended to capture that ending control transfer, plus at most two one-hop successor blocks capped at 64 contiguous instructions each. It preserves literal opcodes/operands and recovered static call-target labels, does not recursively traverse branches or claim dynamic feasibility. Five added synthetic tests bring the suite to **18**, but only the earlier **13/13** run is owner-confirmed so far. See [the updated original operation-11 guide and owner evidence](SM-G986U1-HXL1-GHOSTLOCK-OP11-COMPILED-BLOCK-20261014.md), and [research checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-owner-futex-op11-firstblock-20261014T083539Z.json).

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

A block without immediate BL calls does not prove that the source helper is absent/inlined, that subsequent blocks have no calls, or that an `rt_mutex_waiter` can overlap `sendmsg` storage. All readiness stages, root and KernelSU gates remain unchanged.

---

## October 14, 08:18 UTC — helper-class audit passed; pivot to factory futex case-11 code

Owner executed the HXL1 static helper ledger after pulling `b76bfb3`: **10/10 tests PASS**. All 41 original `sendmsg`/iovec BL sites classify into nine source-agnostic classes, and the three `jopp_springboard_blr_x8` sites are now fixed in the report at `__sys_sendto:0xffffff800966eb70` and `___sys_sendmsg:0xffffff800966f498/0xffffff800966f4e0`. Their effective x8 call destinations and C pointer arguments remain **unproven**. The exact owner crosswalk SHA in the new report is `94be240898b54c51ef428e2813b3ed143117de37d2a1098c0238db076d15badd`. This classification does not upgrade GhostLock applicability.

No further helper-label counting is needed. The stronger remaining proof target is **the original compiled futex operation-11 path** and its relationship to the source-local `rt_mutex_waiter`, whose 30 pinned source lifetime landmarks and conservative original `do_futex` case-11 reachability were already documented.

New bounded `tools/y2q_hxl1_ghostlock_futex_op11_block.py`, 13 synthetic tests, and one-command `tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh` reuse only the existing exact-SHA `hxl1-disassembly-review.tar.gz` (5 function disassemblies, 4,102 machine-instruction slots) and original `vmlinux-stock.nm`. They isolate **just the original compiled case-11 branch's first basic block**, label any literal calls, and stop at a branch or 128 instructions. They do not attribute compiler locals, assume helper inlining, prove runtime waiter reuse, generate an exploit or access ADB.

See [details, evidence pins and automatic existing-archive discovery](SM-G986U1-HXL1-GHOSTLOCK-OP11-COMPILED-BLOCK-20261014.md) and [owner 10/10 evidence checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-owner-helper-classes-20261014T081755Z.json). **New suite 13/13 and real archive run remain pending**, so please execute only:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

Readiness unchanged: stages 1–2 COMPLETE, stage 3 PARTIAL, 4–6 OPEN, 7–8 BLOCKED, 9 DEFERRED. No live GhostLock primitive, physical handoff, temporary root or KernelSU demonstrated.

---

## October 14, 08:06 UTC — GhostLock original sendmsg labels all 21/21 resolved

Owner WSL completed **12/12** `tools.test_y2q_hxl1_ghostlock_call_target_crosswalk` tests, then resolved **all 21 immediate BL branch destinations** among 41 original sendmsg/iovec callsites to the existing SHA-pinned HXL1 recovered symbol labels. This includes three direct calls to `jopp_springboard_blr_x8`. The springboard label is authentic as a recovered immediate target; the *actual* x8-mediated destination beyond the trampoline is **NOT** known. No CFG or C-local pointer lifetime was inferred from an exact label.

Other original static destinations include `___sys_sendmsg` (3), `copy_msghdr_from_user` (1), allocator/free helpers `__kmalloc`, `kfree`, `sock_kmalloc`, `sock_kfree_s` (one branch each), `security_socket_sendmsg` (2), and compiler failure handler `__stack_chk_fail` (5). These are branch *sites*, not measured runtime hit counts or proof of matching allocated objects.

The source reports are already sufficient to build a compact family ledger, so new `tools/y2q_hxl1_ghostlock_helper_classes.py` and 10 synthetic tests (CI-wired) classify all 41 branch sites and preserve unverified JOP effective callees and memory object lifetimes. No live GhostLock test was attempted. See [21-symbol reconciliation and single no-device command](SM-G986U1-HXL1-GHOSTLOCK-21-SYMBOLS-20261014.md), plus [versioned owner observation](../research/y2q-G986U1UESCHXL1/ghostlock-sendmsg-21-exact-symbols-20261014.json). New checker owner/CI run still pending.

Next **substantive** evidence is actual original Samsung futex waiter local/object-lifetime source-to-machine attribution, and separate proof a sendmsg buffer remains resident on the intended stack under a real blocked call. Additional call-label grouping cannot establish either. KernelSU, exploitation and deployment gates are unchanged.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_helper_classes

EVIDENCE="$HOME/s20-artifacts/hxl1-research"
OUT="$EVIDENCE/ghostlock-helper-classes-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 -m tools.y2q_hxl1_ghostlock_helper_classes \
  --crosswalk "$EVIDENCE/ghostlock-call-targets-20261014T080638Z.json" \
  --output "$OUT"
cat "$OUT"
```

---

## October 14, 07:51 UTC — GhostLock 41 stock sendmsg callsites, 21 unique targets

Owner reran the previous fail-closed, original-HXL1 instruction callsite audit: **13/13 tests passed**, 746 original Image instruction slots confirmed, and 41 direct BL calls over the six bounded original sendmsg/iovec code windows. There are 21 distinct static destinations. Exactly 19 of the calls have textual SP-address constructions in the preceding 12 instruction slots; **40 of 41** also have a prior branch or other call in that linear interval, which does not prove dataflow or dynamic control flow.

The original code-call edges already match known recovered HXL1 entries: `__sys_sendmsg -> ___sys_sendmsg` once, `__sys_sendmmsg -> ___sys_sendmsg` twice, and `___sys_sendmsg -> copy_msghdr_from_user` once. This narrows static review without establishing any `rt_mutex_waiter` C-local, pointer lifetime or GhostLock stack alias.

New `tools/y2q_hxl1_ghostlock_call_target_crosswalk.py` plus 12 synthetic tests (wired to GhostLock CI) will resolve the 21 destinations against SHA-pinned original recovered `vmlinux-stock.nm`; exact labels and ambiguous interior intervals are **separate classifications**. Owner/CI run of the new 12-test suite is still pending.

See [the 41-call owner evidence, original SHA notes and one WSL command](SM-G986U1-HXL1-GHOSTLOCK-SENDMSG-CALLTARGETS-20261014.md) and [machine-readable accepted owner summary](../research/y2q-G986U1UESCHXL1/ghostlock-sendmsg-41-calls-owner-20261014.json). Next: symbolize the unique original call destinations **once**, not another kernel extraction or broad REA trace. No Stage 3/5 upgrade, root or KernelSU claim.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_call_target_crosswalk
EVIDENCE="$HOME/s20-artifacts/hxl1-research"
OUT="$EVIDENCE/ghostlock-call-targets-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 -m tools.y2q_hxl1_ghostlock_call_target_crosswalk \
  --report "$EVIDENCE/ghostlock-sendmsg-calls-20261014T075055Z.json" \
  --nm "$EVIDENCE/vmlinux-stock.nm" --output "$OUT"
cat "$OUT"
```

---

## October 14, 07:13 UTC — six factory sendmsg ARM64 entry frames attested

Owner supplied the full HXL1 `ghostlock-sendmsg-frame-20261014T071250203042958Z.json` report, independently hashed as `a0426c036e614611c368338c9f80e298f13b23bc238e1b3dc67aa1a3c20dcc10`. The owner-side tool rehashed the exact original Image, Nm, six code slices and saved disassemblies, checking **746 native instruction slots** against original Image machine words.

Original compiler-generated static entry allocations are now observed for `__sys_sendmsg` (144 bytes), `___sys_sendmsg` (400), `__sys_sendto` (320), `__sys_sendmmsg` (352), `rw_copy_check_uvector` (80), and `copy_msghdr_from_user` (112). Each has an equal-size textual restoration. **Do not** infer all-path stack-frame behavior, specific C locals or a reused `rt_mutex_waiter`. Recovered names `____sys_sendmsg` and `futex_wait_requeue_pi` remain absent; no compiled-function absence is proven.

A new offline, fail-closed `tools/y2q_hxl1_ghostlock_sendmsg_callsite_audit.py` and 13 synthetic tests analyze verified original code-window disassemblies for **literal** BL/BLR calls and nearby SP-relative constructions, preserving a strict lexical-proximity-only conclusion. The static result does not prove pointer argument identities, object lifetimes, a blocking sendmsg carrier, exploit success, or KernelSU. The new suite is in GhostLock CI, but a passing owner/hosted run has **not yet been observed**. See [the exact frame ledger and one-shot command](SM-G986U1-HXL1-GHOSTLOCK-SENDMSG-STATIC-FRAMES-20261014.md) and [machine-readable result](../research/y2q-G986U1UESCHXL1/ghostlock-original-sendmsg-frame-owner-20261014.json).

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_sendmsg_callsite_audit

EVIDENCE="$HOME/s20-artifacts/hxl1-research"
OUT="$EVIDENCE/ghostlock-sendmsg-calls-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 -m tools.y2q_hxl1_ghostlock_sendmsg_callsite_audit --evidence-dir "$EVIDENCE" --output "$OUT"
cat "$OUT"
```

No firmware re-extraction, new kernel build, ADB, REA, exploit invocation or source change is necessary. Stage 3 PARTIAL, Stage 5 OPEN, KernelSU BLOCKED.

---

## October 14, 06:49 UTC — original HXL1 sendmsg windows accepted; byte-level audit next

Owner uploaded original-sendmsg-windows.json (SHA-256 8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8): six of eight requested original Samsung code windows found, all capped=false, each with saved disassembly metadata. Recovered `____sys_sendmsg` and `futex_wait_requeue_pi` names were absent, but **compiled absence/inlining is not proved**. No original disassembly text was uploaded in this message; the actual saved .bin/disasm files remain on owner WSL. The manifest verifies original kernel SHA on the owner's side, but those kernel bytes were not rehashed here.

New `tools/y2q_hxl1_ghostlock_sendmsg_frame_attest.py` checks every original kernel Image byte, recovered nm entry and next-symbol bound, saved binary and disassembly SHA, and machine instruction word for each of the six windows. It uses the existing frame-footprint parser only to report conservative static SP instructions. `tools/run_y2q_hxl1_ghostlock_sendmsg_frame_attest.sh` finds the **exact uploaded manifest** by hash and runs the verifier plus its 15 synthetic tests in one command, without another original extraction or device operation. The files are added to GhostLock CI; owner/CI success **not confirmed yet**.

See [the owner result and runner guide](SM-G986U1-HXL1-GHOSTLOCK-SENDMSG-ORIGINAL-WINDOWS-20261014.md) and the exact [machine-readable report transcription](../research/y2q-G986U1UESCHXL1/ghostlock-original-sendmsg-owner-result-20261014.json). Run only:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_sendmsg_frame_attest.sh
```

No original compiled-local alias, ghostlock runtime primitive, root, kernel physical handoff or KernelSU verified. Stage 3 PARTIAL, Stage 5 OPEN, Stage 7 BLOCKED.

---

## October 14 — GhostLock 4.19 investigation resumed (current priority)

User requested a return to HXL1 GhostLock kernel research rather than continued Stage 4 LinuxLoader index-tracing. Source path, select arithmetic, compact CFG and five original disassembly windows have already been analyzed; **do not repeat earlier source-bug checks or borrow K40 offsets**.

Current independent 4.19 reference `ccp-p/ghostlock-cve-2026-43499-4.19-k40` at `68f191029f20162de3c402935c2f0213210e2de6` has a root-chain milestone still blocked and a K40 sendmsg-carrier premature-return trial. Its later read-only/offline placement redesign is **not Samsung compiled-stack proof**. Prior HXL1 source analysis still corroborates the original CVE-2026-43499 `remove_waiter()` task mismatch, but actual waiter frame geometry/overlap, per-boot runtime primitive and module loading are unverified.

New pinned offline checker `tools/y2q_hxl1_ghostlock_crossfork_419_gate.py`, with ten fail-closed regression tests and GhostLock CI wiring, authenticates the exact Samsung `rtmutex.c`/`futex.c` SHA pins and three K40 documentation blob IDs, and records optional Samsung `net/socket.c`/`fs/read_write.c` source evidence without claiming compiled placement. See [full assessment and WSL one-command check](SM-G986U1-HXL1-GHOSTLOCK-419-FORK-DELTA-20261014.md) and [machine-readable checkpoint](../research/y2q-G986U1UESCHXL1/ghostlock-k40-fork-delta-20261014.json). New tests/real owner audit **not yet confirmed**.

**Next research gate:** independent HXL1 original compiled waiter and native `sendmsg` frame/lifetime attribution versus K40's nonportable carrier hypothesis. Do not generate an executable y2q target or import K40 geometry before this gate. KernelSU SIG_FORCE / disabled KPROBES / RKP-KDP-DEFEX remains a separate blocker; nine-stage status unchanged.

---

## October 14, 05:28 UTC — original LinuxLoader two index getters isolated

The owner completed the previously added no-provider cached analysis against SHA-pinned original `LinuxLoader-HXL1.efi`: all **12/12** tests passed, original `FUN_0002bdf8` decompile consistent across both reports, and exactly two index literals in its 398-line pseudocode. The original Ghidra pseudocode at line 252 calls `FUN_00023b00()`, guards its return against `-1`, and formats `androidboot.dtbo_idx=` at line 254. At line 261 it calls `FUN_00023b40()`, guards `-1`, and formats `androidboot.dtb_idx=` at line 263. Both branches are under the observed `FUN_000235b0()==0` condition. These are the **immediate formatter value getters**, not independently proved index computation/selector algorithms.

The original completed native REA value trace remains **absent**, and HighFunction p-code is marked truncated. Do **not** restart the prior full formatter value trace. Instead see [two getter callsite evidence and bounded capture commands](SM-G986U1-HXL1-LINUXLOADER-GETTERS-20261014.md), with new fail-closed static checker and two explicit per-getter REA `function` requests only if warranted. The tested prior cached auditor was deliberately preserved/restored unchanged. New owner/CI verification of the added getter tests and targeted capture runner is pending.

The indices observed from the handset are still hints, not a proven mapping from `dtb_idx=0` to base FDT candidate 1 or `dtbo_idx=2` to an overlay. Stage 4 physical handoff remains **OPEN**, and no KernelSU/root readiness is claimed.

---

## October 14 — REA DTB/DTBO native trace was cancelled; do NOT repeat unbounded analysis

**Owner tests:** corrected Stage 4 live-device DTB identity suite **25/25 PASS**. The existing no-root ADB probe established both root-property paths as inaccessible and captured existing dtb_idx=0 and dtbo_idx=2 *hints* (already recorded in October 10 observations). No original selected DTB or physical Linux handoff established.

**New uploaded trace evidence:** the file rea-shared-dtb-dtbo-native-values.partial.json has SHA-256 0bd68713838b2536f67ff683b284d35008b5fcdcc05cfac608dee9c0b1a5e847. It contains only error=Analysis failed, code/category=cancelled, details.operation=analyze_function, cleanup=complete. The successful native result file is missing; **no native producer dataflow was obtained**. Its retryable flag is not evidence that another attempt would complete. The reason for cancellation is unknown.

Do not repeat the old trace-native-values invocation shown in the historic October 11 section below. **Use the new read-only, offline cached-function verifier** in docs/SM-G986U1-HXL1-REA-INDEX-TRACE-CANCELLED-20261014.md and tools/y2q_hxl1_linuxloader_cached_index_audit.py to reuse existing SHA-authenticated EFI, dtb-index and dtbo-index xrefs and cached Ghidra function dossiers without restarting the provider. It outputs only bounded pseudocode snippets and an explicit failed-trace status; it cannot certify selector-value origins, applied DTB/DTBO or physical kernel load. The prior instructions remain below only as historical record of the already attempted trace.

**Status unchanged:** Stage 3 PARTIAL, Stage 4–6 OPEN, Stage 7–8 BLOCKED, Stage 9 DEFERRED. No root, KernelSU or feed support.

---

## October 13, 14:34 UTC — original compiled HXL1 control-flow gate

**No new device or firmware extraction run.** Reused the owner's previously supplied `hxl1-disassembly-review.tar.gz` (SHA256 `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997`), retaining exact 5/5 archived disassembly text digest validation and 4,102 contiguous ARM64 instruction slots. The checked file-relative function windows and the approximate direct-control-flow result are:

| Window | Instructions | Direct branches | Unresolved direct targets | Indirect branches | May be reached from entry |
|---|---:|---:|---:|---:|---:|
| `core_sys_select` | 266 | 37 | 0 | 0 | 266 |
| `do_select` | 420 | 65 | 0 | 0 | 420 |
| `futex_requeue` | 1,096 | 226 | 0 | 0 | 1,078 |
| `do_futex` | 1,766 | 355 | 0 | 0 | 1,742 |
| `futex_lock_pi` | 554 | 81 | 0 | 0 | 546 |

The previously verified case-11 compare and in-window branch are present. A bounded intraprocedural graph, in which both sides of conditional branches are possible and direct function calls may return, reaches the case-11 block from `do_futex`'s entry; from the case-11 block it can reach the common dispatcher return. Exactly **335 possible instruction nodes** are reachable from that block under this conservative model. The only literal `sp` adjustments in the complete `do_futex` window are its original **480-byte entry allocation and matching restoration**. This supports an in-frame dispatch relationship, not exact source-helper inlining nor source object lifetime/aliasing.

The graph leaves 24 `do_futex` instruction slots and 26 combined `futex_requeue`/`futex_lock_pi` slots unvisited under direct-edge reachability. These are not certified dead instructions; trap paths, error handling, data/text layout, or model incompleteness may explain them. No paths outside the five named windows were inferred from decoded direct branches, but cross-function BLs were modeled only as potentially returning; their side effects are not proven.

**Test results:** A self-contained local control-flow archive verifier ran against the owner's real archive, and **8/8 local synthetic tests passed**. Committed the reusable GitHub-side static CFG tool, five synthetic CI tests, and workflow integration. GitHub CI execution and the owner's HXL1 run of the newly committed implementation have not yet been observed; do not misstate CI as PASS.

**Acceptance boundary:** archival text hashes match the saved collector manifest, but the original `kernel.bin` bytes were not independently supplied in this archive for fresh comparison. This confirms **intra-function static reachability only**. It does not prove the C helper's exact compiled boundary, C local-variable layout, runtime cross-syscall stack reclamation, GhostLock exploitability, temporary root, or KernelSU. Future work needs source-to-assembly attribution with the hash-pinned original Samsung `kernel/futex.c`, not another offset or frame-size loop.

---

## October 13, 14:19 UTC — original five-function frame footprints independently audited

Using the owner's existing `hxl1-disassembly-review.tar.gz`, an independent local offline script verified **5/5 disassembly text SHA-256s**, instruction counts, contiguous original-image-relative addresses and the operation-11 branch target. Then it extracted *only* literal AArch64 stack-pointer adjustment and restoration instructions from each verified function window:

| Stock recovered function window | Observed entry stack allocation | Corresponding restoration instructions observed |
|---|---:|---|
| `core_sys_select` | 448 bytes (`sub sp, sp, #0x1c0`) | YES |
| `do_select` | 880 bytes (preindexed save 96 + `sub sp, sp, #0x310`) | YES |
| `do_futex` | 480 bytes (`sub sp, sp, #0x1e0`) | YES |
| `futex_requeue` | 288 bytes (`sub sp, sp, #0x120`) | YES |
| `futex_lock_pi` | 384 bytes (`sub sp, sp, #0x180`) | YES |

The compiled opcode-11 branch continues into instructions *within the same next-symbol-bounded `do_futex` window*. That is stronger evidence than source presence alone; it is **not** certified DWARF evidence of a specific C helper's inlining, nor proof of a cross-syscall stack-object relationship. The five sizes are per-function static entry prologue allocations, **not live relative stack locations**; matching restore instructions do not prove all control-flow paths were validated. Those original code windows were initially extracted by the owner from SHA-pinned `kernel.bin` and then text-digest checked here; this archive lacks the raw Image for an independent second factory-byte check.

A standalone offline frame-footprint analyzer ran against this archive, and **7/7 synthetic tests passed locally** (normal/preindexed frame accounting, non-entry adjustment caution, missing instruction slot, altered disassembly, unsafe tar symlink, no-root claim). All stages related to exploitability and KernelSU are unchanged: source-helper attribution OPEN, stack alias/lifetime OPEN, transient root UNPROVEN, and KernelSU BLOCKED.

Stop treating numeric layout parity or a fixed frame size as an exploitability proof. Advance only if independent original factory C-to-assembly mapping can establish the relevant function boundaries and object lifetimes without extrapolating Redmi offsets.

---

## October 13, 14:06 UTC — compiled HXL1 futex dispatcher addresses missing-name ambiguity

**Input independently reviewed:** user-supplied `hxl1-disassembly-review.tar.gz`, including five disassembly texts and `stack-gate.json`. All five text digests match the manifest, and the windows contain **4,102 contiguous four-byte instructions**.

**New original HXL1 compiled-code finding:** the `do_futex` dispatcher contains a distinct comparison and internal branch for command **11** (`FUTEX_WAIT_REQUEUE_PI`) and a distinct case **12** (`FUTEX_CMP_REQUEUE_PI`) routed to the separately extracted `futex_requeue` function. The three previously established direct calls among the extracted functions were reverified.

**Interpretation:** A missing recovered text-symbol name for `futex_wait_requeue_pi` is no longer a credible argument that the entire operation-11 dispatch path is absent. The source function was independently verified in pinned Samsung `kernel/futex.c` at line 3232. However, the archive does **not** prove the exact compiler inlining/renaming decision, source object placement, a cross-function stack overlap, exploit applicability, or root access.

**Evidence boundary:** this is an original-image-relative disassembly review. The archive lacks raw original `kernel.bin` and does not verify physical bootloader handoff, current KASLR, live addresses, kernel privileges, or KernelSU. No phone writes or exploit runs were performed. Mainline Linux v4.19 futex switch semantics corroborate the command names but are not substituted for the Samsung source.

**Decision:** No more searches for that exact symbol name are warranted merely to determine whether operation 11 has code. Investigations must center on independent source-to-compiled-code attribution and actual compatibility constraints, not guessed function boundaries.

---

## October 13, 14:00 UTC — original compiled select/futex archive independently reviewed

The owner supplied `hxl1-disassembly-review.tar.gz` with `stack-gate.json` and five disassembly text files, each corresponding to its exact recovered HXL1 original-code window. Independent review confirmed **5/5 matching disassembly text SHA-256 hashes**, **4,102 contiguous AArch64 instruction slots**, and **241 direct-call instructions** across the five windows. The archive did not contain raw `kernel.bin` or each original `*.bin`, so text-to-manifest hash verification was independently performed, while the original factory-byte hash assertion remains the prior owner's pinned collector result.

The verified callgraph *inside the five archived windows* includes:
- `core_sys_select` directly calls `do_select`.
- `do_futex` directly calls `futex_requeue`.
- `do_futex` directly calls `futex_lock_pi`.

The following function windows are accounted for: `core_sys_select` 1,064 bytes, `do_select` 1,680, `do_futex` 7,064, `futex_requeue` 4,384 and `futex_lock_pi` 2,216. **These represent next-symbol-bounded windows, not certified compiler function extents.** Unmapped direct-call destinations remain outside the five supplied windows.

`futex_wait_requeue_pi` remains **ABSENT AS A RECOVERED SYMBOL NAME** despite its existing `static int` declaration at line 3232 in hash-verified Samsung `kernel/futex.c` and `CONFIG_FUTEX=y`, `CONFIG_FUTEX_PI=y`. Do not infer that the compiled implementation is present, removed, inlined, or at a particular address from this evidence alone. Its exact code emission remains unresolved.

This compilation review does **not** demonstrate a cross-function stack-object relationship, original runtime function base, an exploitation prerequisite, temporary root, or KernelSU. No new device experiment is justified by these five windows alone. Retain these distinctions in all downstream readiness reporting.

---

## October 13, 13:45 UTC — original futex symbol provenance verified

User-uploaded `stack-gate.md` established five original ARM64 HXL1 code windows with disassembly: `core_sys_select` 1,064 bytes, `do_select` 1,680, `futex_requeue` 4,384, `do_futex` 7,064, and `futex_lock_pi` 2,216. `futex_wait_requeue_pi` was not found by **exact name** in the recovered text-symbol table. This is **5/6 extraction success, not a verified cross-function stack relationship**.

The subsequent uploaded `futex-symbol-provenance.md` verified exact stock `kernel/futex.c` and `config.gz` hashes. The source declares `static int futex_wait_requeue_pi` at line 3232; `CONFIG_FUTEX=y`, `CONFIG_FUTEX_PI=y`, `CONFIG_KALLSYMS=y`, `CONFIG_KALLSYMS_ALL=y`. There is no exact recovered text-symbol name and no name-containing variants. `CONFIG_LTO*` values were **NOT_RECORDED**, not proven disabled.

**Interpretation:** Function source/config presence is established; factory code emission, location, inlining, and symbol recovery completeness are not established. The absence of a recovered name does not by itself disprove compilation, and it cannot be substituted with a guessed address. Do not promote the existing five function windows or source declaration to an active GhostLock payload.

**Most useful next owner artifact:** the five `*.disasm.txt` files and `stack-gate.json` already present in the `ghostlock-stack-gate-*` directory. Reviewing the authentic `do_futex` and related compiled dispatch/call sites, alongside exact original source, is more useful than repeating source-name checks. Only the Markdown summaries were uploaded for this checkpoint; the native disassembly itself has not been made available for independent review.

No root, KernelSU, physical bootloader handoff, or exploit-ready geometry proven.

---

## October 12 — owner local Clang10 ABI comparison and bounded REA pipeline reviewed

The owner supplied a 17-file `hxl1-local-pipeline-review.tar.gz` containing `Run.py`, generated provisional `target.h`, new untracked offline research tools and six README/documents. The [source review](SM-G986U1-HXL1-LOCAL-PIPELINE-CONSOLIDATION-20261012.md) records the exact scope and safety checks. **These modules are owner-local and were not blindly copied over tracked GitHub code**.

Newly documented owner result: a **Clang r377782d 10.0.6 comparison**, with successful `kernel/locking/rtmutex.o` and `kernel/futex.o` builds and matching direct DWARF type layouts across both translation units; a follow-up claims all **31 previously selected** stock Image ARM64 instruction words were independently authenticated and **13 pre-existing candidate field displacements** agreed with the comparison DWARF. Neither the actual comparison JSON, compiled `.o` files nor original full build logs were in the uploaded archive. Therefore **do not claim independently re-accepted factory offsets** until these exact owner files are parsed and each required original instruction's source-field def/use is grounded. Matching compiler version alone does not prove the OEM toolchain.

Tracked canonical automation now includes an **optional** `03_clang10_checkpoint` step (`tools/y2q_hxl1_clang10_checkpoint.py`), which records exact original `kernel.bin`/`config.gz` pins, original comparison JSON SHA256 and retained AArch64 ELF object SHA256s, **without repeating Clang10 build, REA or Stage3 field-offset derivation**. It explicitly marks `factoryAbiAuthenticated=false` and does not promote Stage 3. Regression suite **509/509 passed** in [GitHub Actions run #38263532533](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38263532533).

Owner local v4.2 `y2q_hxl1_rea_factory_abi.py` provides bounded file-backed ELF function slices to avoid the earlier 330s full reconstructed-ELF REA provider timeout. It is a possible targeted integration after the owner-local implementation and source/tool identity are authenticated, not a reason to run the whole bootchain research again. The local static bootchain tool overlaps already documented LinuxLoader source evidence; actual physical kernel handoff remains **OPEN**. `Run.py` still analyzes ELF32 ARM `abl.elf` as AArch64 and writes PARTIAL values into a **separate owner** `~/src/targets` tree. Never copy that `target.h` into production `support`.

**Next real technical gate:** independently check the Clang10 comparison report, all required nested RT-mutex/waiter/task type members and each factory access path; verify measured runtime behavior separately. Keep Stage 1–2 complete, Stage 3 partial, Stage 4–6 open, Stage 7–8 blocked, Stage 9 deferred.

---

## October 12, 03:16 UTC — actual owner automated port run 9/10, Stage 6 ZIP contract repaired

**Real HXL1 owner WSL run** `port-automation-20261012T031554640552Z`: 10 scheduled steps, **nine passed** on the owner's exact original firmware, including firmware readiness, layout inventory, Stage 3 proof matrix and export table, boot v2 and FDT semantic checks, static GhostLock source/binary research, complete scan and successful Android NDK inert identity diagnostic shared-object build. **Only `06_bundle_identity_only` failed.** This is a diagnostic ZIP packaging failure, not a new factory code/root security blocker, and it does not change Stage 3's independent compiled OEM ABI proof requirement. Nine-stage results: `COMPLETE,COMPLETE,PARTIAL,OPEN,OPEN,OPEN,BLOCKED,BLOCKED,DEFERRED`. No root, KernelSU, flash or production target feed.

**Bundler contract regression identified by code review:** initial automation created `06-hxl1-identity-diagnostic.so` and an accurate `manifest.payload.file` of that name, while the bundler required the canonical `y2q-G986U1UESCHXL1-identity-diagnostic.so`. The exact owner's `logs/06_bundle_identity_only.log` was not provided, so do not claim an exhaustive diagnosis beyond this reproducible contract mismatch. Production automation now uses the canonical filename. The bundler allows exactly that or the prior known safe legacy name, with exact manifest basename, SHA256, original device identity, inert read-only flags and ELF64/AArch64 checks all enforced. The separate Python `SyntaxWarning` escape defects in Markdown output were corrected.

**Repair just the previous failed ZIP without repeating Stage 1–5/NDK work or editing original records:**

```bash
cd ~/src/Root-My-Galaxy-Payloads && git pull --ff-only && \
python3 tools/y2q_hxl1_porting_bundle_repair.py \
  --run-dir "$HOME/s20-artifacts/hxl1-research/port-automation-20261012T031554640552Z"
```

Creates only `06-hxl1-diagnostics-only-recovered.zip` and `06-hxl1-bundle-repair.json` in that existing run if all original scan/build/pinned factory SHA evidence still verifies. The original `port-automation.json` stays unchanged and accurately documents the initial failed step. The ZIP contains an **identity-only diagnostic**, not an active root payload.

The new toolchain and recovery fixture tests passed **487/487** HXL1 CI tests in [GitHub Actions run #38199458175](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38199458175) (that run has original synthetic CI inputs only). The owner's real repair execution and any fresh full owner run are still pending. Full details: [automated porting guide](SM-G986U1-HXL1-AUTOMATED-PORTING.md).

---

## October 12, 02:51 UTC — single-command automated nine-stage HXL1 porting evidence pipeline

**Workflow correction:** stop requiring repeated manual one-audit-per-turn instructions. The owner now has a [single-command Stage 1–9 host-only porting pipeline](SM-G986U1-HXL1-AUTOMATED-PORTING.md), implemented at `tools/y2q_hxl1_porting_automation.py`, with convenience wrapper `tools/run_y2q_hxl1_porting_automation.sh` that fast-forwards the current Git branch. This reuses the actual pinned factory source and kernel evidence plus existing stage 3 proof matrix, stage 4 stock boot/FDT, stage 5 GhostLock research checks, and optional stage 6 NDK identity-only diagnostic/bundle. It outputs a **new immutable** Markdown/JSON step log and precise nine-stage blockers every run; it continues independent checks on one failed step and skips unavailable optional inputs explicitly.

```bash
cd ~/src/Root-My-Galaxy-Payloads
bash tools/run_y2q_hxl1_porting_automation.sh
```

**CI:** the 20 new local-input-free regression tests and the full HXL1 suite passed **465/465** in [GitHub Actions run #38198179809](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38198179809). The separate CI task also executed `--mode plan` and validated actual script wiring; **the owner's original WSL-only factory files are not available in the hosted GitHub runner**. An actual owner host run is therefore still required before its new readiness report can be interpreted.

**No false gate promotions:** nine-stage readiness remains Stage 1–2 COMPLETE, Stage 3 PARTIAL, Stage 4–6 OPEN, Stage 7–8 BLOCKED, Stage 9 DEFERRED until independently authenticated evidence changes. The Clang18 DWARF and verified original instruction offsets are valuable, but do **not** automatically establish a complete factory Clang10 compiled structure ABI. The GhostLock source bug-pattern is confirmed in reconstructed vendor source, yet controlled runtime exploitation/root, authorized Linux 4.19 KernelSU loading, actual physical OEM unlocking and production feed integration remain unverified. The automation does not launch an exploit, alter physical firmware, contact ADB, or fabricate guest RKP services. Focus subsequent development on **the exact missing factory ABI and runtime CVE primitive**, not endless manual standalone reports.

---

## October 12, 02:36 UTC — X21 stack-restore candidate not executed in capture; X10 field-load observed

**Owner actual WSL evidence, two separate original stock-HXL1 compact QEMU guest runs:** `tools.test_y2q_hxl1_qemu_compact_register_provenance` passed **18/18** locally. Factory Image SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`, compact guest input DTB SHA `1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd`, and previously independently captured complete **35,168-byte** guest FDT were all verified.

**X21 first null-base load:**
```text
[REGISTER PRODUCER] 0xffffff80082ac8f4 a94457f6
[FAULT LOAD] 0xffffff80082ac90c f9402eb8
[PROVENANCE STATUS] FAULT_CAPTURED_PRODUCER_NOT_OBSERVED
[PRODUCER HIT] False
[FAULT HIT] True
[FAULT BASE] 0x0
[FULL DATA FLOW PROVEN] NO
```
At the original stock `LDR x24,[x21,#0x58]` the real fault-load breakpoint was hit with X21=0, but the candidate earlier `LDP x22,x21,[sp,#64]` at `...8f4` **was not hit in this bounded run**. Do **not** attribute the live X21 zero to a stack-restored zero, or claim that the faulting cache argument was null, on this evidence. A bypass/branch into the load path is possible and must be mapped from verified original instruction edges/real PC observation. The recovered nearest symbol is `kmem_cache_alloc`, but symbol range/function boundary is reconstructed, not independently debug-info proven.

**X10 second null-base load:**
```text
[REGISTER PRODUCER] 0xffffff80086de394 f9458f0a
[FAULT LOAD] 0xffffff80086de39c a9412149
[PROVENANCE STATUS] PRODUCER_THEN_FAULT_OBSERVED_NO_FULL_DEF_USE_PROOF
[PRODUCER HIT] True
[FAULT HIT] True
[PRODUCER EFFECTIVE ADDRESS] 0xffffff800ac304d8
[FAULT BASE] 0x0
[FULL DATA FLOW PROVEN] NO
```
This distinct compact original Image guest run stopped **before** the stock `LDR x10,[x24,#0xb18]` and later before `LDP x9,x8,[x10,#0x10]`, with live X10=0 at the paired-load breakpoint. The first breakpoint gave concrete candidate guest pointer-field address `0xffffff800ac304d8`. **The stdout does not say whether the read-only GDB attempt to inspect 8 bytes at that address succeeded, nor what those bytes were.** It is premature to claim `memory[X24+0xB18] = 0` until the original log supplies a matching 64-bit source value. The recovered nearest `dump_stack_minidump` and saved LR near `panic` continue to support a *possible* secondary panic diagnostic abort, but a full executed return/call path has not been traced.

Neither run independently proves the Samsung UH/RKP bitmap SMC service succeeded, that a protected carveout exists, or that the two base-register failures are consequences of a specific SMC response. Missing `SMC+4` breakpoint hits in earlier separate probes are not proof the SMC never returned.

**New strictly offline, original-source-backed check:** `tools/y2q_hxl1_compact_regorigin_route_audit.py` recomputes both owner real reports **from their original saved raw GDB text**, verifies original factory opcode bytes for both producer and load and original compact-FDT provenance, emits the x10 source memory value **only when independently attested at the exact GDB-read address**, and scans a bounded local original Image region around the first fault for direct `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ` static incoming branches. Every source edge is explicitly marked *not proven executed*. CI fixture tests cover malformed GDB, wrong source pointer, changed opcode/provenance and AArch64 positive/negative branch encodings; unlike the owner's real saved data, they do not attest the physical Samsung UH service or actual fault path. The **17 new isolated tests passed** in [GitHub Actions run #38196749922](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38196749922), with **445/445 HXL1 regression tests PASS**. The owner has not run the new offline audit yet.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_compact_regorigin_route_audit
python3 tools/y2q_hxl1_compact_regorigin_route_audit.py
```

After reading the actual original-source branch candidates and X10 field read, select the earliest **runtime** predecessor breakpoint for X21, or observe the *actual kernel SLUB call's X0* using a controlled call-instance capture. Avoid re-running FDT experiments or patching the stock kernel to mask null-base faults. OEM bootloader unlock and KernelSU remain unverified.

---

## October 12, 02:20 UTC — SLUB_DEBUG confirmed; X21 restored from stack and X10 loaded from memory before separate zero-base reads

**Owner real WSL output:** after branch pull through `a3e066f`, original factory SHA-pinned `tools.test_y2q_hxl1_compact_fault_function_windows` **16/16 PASS**, and the real `tools/y2q_hxl1_compact_fault_function_windows.py` succeeded, attesting both earlier GDB measurements X21=0 and X10=0 against source Image bytes and the 35,168-byte compact guest FDT evidence. Stock `config.gz` reports `CONFIG_SLUB=y` and `CONFIG_SLUB_DEBUG=y`; neither `CONFIG_SLAB` nor `CONFIG_SLOB` is enabled/recorded. `CONFIG_KASAN`, `CONFIG_SLAB_FREELIST_HARDENED` and `CONFIG_SLAB_FREELIST_RANDOM` were not enabled/recorded. Slab allocator variant is now **actual config**, not inferred from kernel age.

**Important source-register-provenance caveat** near original Image `LDR x24,[x21,#0x58]`, ELR `0xffffff80082ac90c`, recovered closest symbol `kmem_cache_alloc +0x110`:
```asm
ffffff80082ac814: stp x22, x21, [sp, #64]
ffffff80082ac828: mov x21, x0
ffffff80082ac84c: ldp w21, w23, [x21, #24]     // W21 write zero-extends X21
ffffff80082ac8f4: ldp x22, x21, [sp, #64]      // X21 restored from stack; second word at SP+72
ffffff80082ac90c: ldr x24, [x21, #88]         // owner observed X21=0, separate FAR=0x58
```
**Do NOT claim the original `kmem_cache_alloc` X0 argument was null based only on the later X21=0.** Multiple original source writes precede that load, and restored X21 may reflect the caller's callee-saved state, a later epilogue or even a distinct code path/function if reconstructed function boundaries are inaccurate. The original source window confirms possible producers but does not show which branch executed. The first fault is now a confirmed zero-base read, **not yet a proven slab-cache initialization failure**.

The later source `LDP x9,x8,[x10,#0x10]` site `0xffffff80086de39c` is within nearest recovered `dump_stack_minidump +0x80`, live X10=0, earlier separate FAR=0x10. Directly preceding factory code:
```asm
ffffff80086de394: ldr x10, [x24, #2840]    // candidate source = memory[X24+0xB18]
ffffff80086de39c: ldp x9, x8, [x10, #16]
```
The previously measured LR for this fault is near recovered `panic`. Thus a **secondary panic/minidump diagnostic failure is plausible**, but actual panic-entry chronology and the origin of X24's field are not proven. Neither failure should be automatically attributed to the RKP bitmap `SMC #0` request, for which the 0xc300c002/0x15 input is source validated but no successful UH response/bitmap pool was observed. The SMC+4 breakpoint was not observed in either fault-register capture, and that is not proof the SMC failed.

**New bounded same-run source-producer diagnostic:** `tools/y2q_hxl1_qemu_compact_register_provenance.py` starts isolated original SHA-pinned stock HXL1 QEMU virt only on explicit invocation and revalidates the earlier 35,168-byte complete guest FDT, exact compact source and original factory opcode words. It stops at original kernel entry and the exact HXL1 RKP SMC, then arms two **temporary** read-only GDB breakpoints at the source candidate and the known fault instruction:
- `--target x21`: producer `0xffffff80082ac8f4` (original `a94457f6`, `LDP x22,x21,[sp,#64]`), saves SP and reads stack word `[SP+72]`; fault `0xffffff80082ac90c` (original `f9402eb8`), captures X21.
- `--target x10`: producer `0xffffff80086de394` (original `f9458f0a`, `LDR x10,[x24,#2840]`), saves X24 and attempts read-only 64-bit load `[X24+2840]`; fault `0xffffff80086de39c` (original `a9412149`), captures X10.

The tool preserves whether the producer was **actually observed before the fault in the same run**, and records optional source-memory bytes only if independently read at the exact effective address. If the source breakpoint is skipped, the producer remains unknown; if GDB cannot read memory, the value remains unknown. Even both breakpoints firing does **not** establish a complete def-use chain or causal relation to a Samsung UH return, and neither guest/kernel memory nor the physical phone is written. The 18 new isolated host-only tests passed in [GitHub Actions run #38195789729](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38195789729), with **428/428 total HXL1 regressions PASS**. The owner's real GDB producer-to-fault capture is pending, and CI cannot substitute for it.

Owner next commands after pulling:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_compact_register_provenance
python3 tools/y2q_hxl1_qemu_compact_register_provenance.py \
  --target x21 --preflight-only \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-regorigin-x21-v1-20261012"
python3 tools/y2q_hxl1_qemu_compact_register_provenance.py \
  --target x21 \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-regorigin-x21-v1-20261012"
```

Once that observation is understood, optionally sample X10 in its **own fresh output directory** with `--target x10`. The *owner's real original guest producer-to-load result is still pending*. Do not add any fictional UH/RKP pool mapping or attempt KernelSU deployment.

---

## October 12, 02:11 UTC — both faulting bases observed as zero; panic/minidump likely secondary

**Owner WSL completed the next original-stock-image evidence gate:** after `git pull --ff-only` through `d39087c`, all **15/15** host source-correlator tests passed. The read-only offline `tools/y2q_hxl1_compact_fault_live_attribution.py --target x21` independently rechecked the previous actual compact-original-QEMU GDB register report and raw GDB log, exact original `kernel.bin` SHA-256, original live `LDR` opcode, 35,168-byte original guest FDT source and earlier QEMU exception FAR:
```text
[LIVE FAULT BASE] X21 0x0
[STOCK INSTRUCTION] 0xffffff80082ac90c f9402eb8
[RECOVERED FUNCTION] kmem_cache_alloc
[LINK REGISTER] 0xffffff80082ac83c nearest kmem_cache_alloc
[SEPARATE QEMU FAR] 0x58 matches candidate address True
[SMC+4 CAPTURED] False
```
The owner then independently launched a **fresh bounded original factory Image QEMU/GDB capture with exact compact FDT** using `--target x10`. It stopped before original live `LDP x9,x8,[x10,#0x10]`, `PC=0xffffff80086de39c`, verified original opcode `a9412149` and **actually read X10=0**. The independent offline source audit returned:
```text
[LIVE FAULT BASE] X10 0x0
[STOCK INSTRUCTION] 0xffffff80086de39c a9412149
[RECOVERED FUNCTION] dump_stack_minidump
[LINK REGISTER] 0xffffff80080b8d1c nearest panic
[SEPARATE QEMU FAR] 0x10 matches candidate address True
[SMC+4 CAPTURED] False
```
These are **two separately repeated compact QEMU guest runs**. Each live null-base value and original opcode is directly observed by GDB before executing its respective instruction. QEMU's earlier original compact-FDT exception log **independently** reported Data Abort FARs `0x58` and `0x10`, respectively. This cross-run corroboration is stronger than an opcode-only theory, but does **not** prove both aborts occurred in either newly halted GDB run. The `LDP` pair has two candidate addresses (`0x10` and `0x18`) for X10=0, with the **separate earlier FAR=0x10** supporting the first transfer. The original `kmem_cache_alloc`, `dump_stack_minidump` and `panic` labels come from **reconstructed** symbols; source/liveness requires independent tracing, not just nearest-label matching.

**Working, unproven prioritization:** the first failed read is within the recovered slab allocator `kmem_cache_alloc` path, while the second is within recovered `dump_stack_minidump` and its saved LR is nearest `panic`; the second abort may be **secondary to diagnostic/panic handling**, not an independently failing RKP bitmap request. However, neither the actual allocator-cache-object passed to `kmem_cache_alloc`, the earlier cause of an erroneous X21=0, nor the actual first panic invocation has been captured. The `SMC+4` breakpoint is **not observed** in either fault capture, but cannot by itself prove the RKP SMC didn't return, that it failed, or that it caused any slab issue. Do not manufacture a secure monitor response, edit kernel fault handlers or allocate an unauthenticated RKP pool based on these findings.

**New narrowly scoped offline source-attribution tool:** `tools/y2q_hxl1_compact_fault_function_windows.py` cross-checks **both real GDB and FDT records** against original factory Image bytes, checks nearest recovered text-symbol boundaries, extracts a bounded original-AArch64 instruction window preceding both faulting sites, lists textual uses of X21/X10 plus nearby calls/branches, and reads the exact source stock `config.gz` keys to identify the allocator variant (SLAB, SLUB or SLOB) without assuming upstream source equals OEM code. It does **not** claim a register writer or path was executed just because its instruction appears in factory bytes. The 16 host-only source-window/config regressions passed in [GitHub Actions run #38195071185](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38195071185); **410/410 total isolated HXL1 tests PASS**. The owner's real factory source-window output remains pending, and synthetic CI does not establish any original kernel register producer.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_compact_fault_function_windows
python3 tools/y2q_hxl1_compact_fault_function_windows.py
```

After the owner produces the code-window output, determine the actual X21 source/register assignment and the failing slab-cache pointer from original code (and, only if needed, new bounded original register/stack capture). Independently determine whether the second fault occurs only after a `panic` transition. FDT delivery/size is closed; UH/RKP function, allocator memblock carveout, hardware bootloader unlock and KernelSU installation remain **unverified**.

---

## October 12, 02:02 UTC — first HXL1 compact-QEMU fault live X21=0; original RKP source ABI independently rechecked

**Owner's real WSL, no handset touched:** After pulling feature branch through `8b79be3`, the owner ran **27/27 tests PASS** for `tools.test_y2q_hxl1_compact_bitmap_call_audit` and `tools.test_y2q_hxl1_qemu_compact_fault_regs`. The independently rechecked original HXL1 `uh.h/rkp.h` ABI confirmed **`0xc300c002 / 0x15 = UH_APP_RKP / RKP_GET_RKP_GET_BUFFER_BITMAP`**, with X2 matching the recovered `rkp_s_bitmap_buffer` address and X3 QEMU guest RAM start `0x40000000`. X6=0x3f was captured but **is not an original `uh_call` explicit source argument**. No UH response, RKP pool, kernel `memblock` reservation or root verified.

The owner's independent compact original-kernel GDB test **revalidated original factory SHA, original compact DTB SHA `1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd`, and earlier 35,168-byte complete runtime FDT evidence**. It hit the original `SMC #0` service request in the same guest run and then stopped **before** the original factory instruction `LDR x24,[x21,#0x58]` at `0xffffff80082ac90c`. It independently checked the runtime instruction word `0xf9402eb8`, measured **X21=0x0** and returned **`LIVE_ORIGINAL_FAULT_BASE_REGISTER_CAPTURED`**. Thus the first faulting load would compute **address `0x58`** with that captured base. A different, earlier compact-QEMU run actually logged a Data Abort at that same stock ELR with **FAR `0x58`**, providing strong **cross-run agreement**, not an additional abort in this halted GDB run.

The same-session **`SMC+4` breakpoint was not observed** (`smcNextPcObserved=false`), even though the subsequent fault-load breakpoint was reached. This does **not** prove the SMC failed, returned an error or skipped a particular AArch64 instruction; exception returns and GDB breakpoint behavior require their own trace. The X21 null-base condition is now measured; its upstream initialization/provenance and causal relationship to the Samsung SMC remain unproven. The *other* original compact-QEMU fault `LDP x9,x8,[x10,#0x10]` at `0xffffff80086de39c` had FAR `0x10`; no **actual** X10 register capture has been performed yet.

**Next offline proof tool committed:** `tools/y2q_hxl1_compact_fault_live_attribution.py` revalidates the exact owner X21 GDB report against the saved raw GDB log, original factory Image/source opcode, reconstructed nearest stock symbol, and earlier independent QEMU exception report, while retaining that **the FAR came from a separate run**. It emits a small source disassembly window and source-nearest candidate for both the fault ELR and captured LR; it cannot establish the true writer of X21 or a secure-monitor response. The 15 synthetic tests check null-base interpretation, altered GDB/source, prior FAR mismatch, guest FDT origin and X10 paired-load address alternatives. They passed in [GitHub Actions run #38194489007](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38194489007), with **394/394 isolated HXL1 tests PASS**. Owner's actual new offline source-attribution and X10 guest run are pending. The companion independent X10 debugger probe **already exists** in `tools/y2q_hxl1_qemu_compact_fault_regs.py`; it must use a *fresh* output folder.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_compact_fault_live_attribution
python3 tools/y2q_hxl1_compact_fault_live_attribution.py --target x21

# After reviewing the original X21 source window, separately test X10
python3 tools/y2q_hxl1_qemu_compact_fault_regs.py \
  --target x10 \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-fault-x10-v1-20261012"
```

The explicit **no-fake-UH/no-kernel-patch** stance remains. Establish source-level X21 initialization and both fault-time bases before deciding what, if anything, a source-faithful QEMU secure-monitor adapter must do. Original HXL1 FDT delivery and full guest `fdt_totalsize=35168` are proved and do not require rework.

---

## October 12, 01:50 UTC — compact guest's original RKP bitmap SMC request independently captured; next fault-time register gate

**Owner direct WSL result:** the original SHA-pinned factory HXL1 Image, SHA-pinned compact `-dtb` and 35,168-byte guest runtime FDT revalidated. Both `tools.test_y2q_hxl1_compact_fault_dependencies` and `tools.test_y2q_hxl1_qemu_compact_smc_registers` passed **24/24**. The prior original compact-run exception audit was independently reproduced. The newest bounded GDB run stopped **before** original `SMC #0` at `0xffffff80080a5794`, with original live `0xd4000003` opcode and registers `X0=0xc300c002,X1=0x15,X2=0xffffff800a4dd0b8,X3=0x40000000,X4=X5=0,X6=0x3f`. It classified `STOCK_SMC_0_LIVE_ARGUMENTS_CAPTURED`. **No original HXL1 SMC response, pointer write, protected bitmap/pool, memblock exclusion or KernelSU was observed.**

**Original source resolves the meaning:** `include/linux/uh.h` + `include/linux/rkp.h` and the earlier source-ABI audit identify `UH_APP_RKP`, `RKP_GET_RKP_GET_BUFFER_BITMAP`, and original `rkp_s_bitmap_buffer` pointer at the recorded X2. `0xc300c002/0x15` is **HXL1 RKP bitmap protocol**, not the identically numbered *KDP_SET_NS_FLAGS* command from a different QEMU patch fork. X3 is original `memstart_addr`. X6=0x3f is an observed volatile register without a proven source-level argument role. **Do not infer or dispatch based on X6.**

The old QEMU compact exception log had `SMC #0`, then reads `LDR x24,[x21,#0x58]` at `0xffffff80082ac90c,FAR=0x58` and `LDP x9,x8,[x10,#0x10]` at `0xffffff80086de39c,FAR=0x10`. Those fault addresses are *compatible* with null bases but do not establish the actual live X21/X10 values or causality between faults and UH SMC return.

**New engineering work committed and tested:**
- `tools/y2q_hxl1_compact_bitmap_call_audit.py` validates **the new compact GDB report** against original GDB opcode/args, original Image and 35,168-byte FDT provenance, HXL1 `uh.h/rkp.h` source, and the exact recovered `rkp_s_bitmap_buffer` symbol. Its 13 host-fixture tests guard mismatched sources/registers, X6 ambiguity, fork ID collision and unsafe optimistic conclusions.
- `tools/y2q_hxl1_qemu_compact_fault_regs.py` provides a separately bounded, read-only original QEMU/GDB run. It verifies the already proven stock kernel and exact compact source, checks entry and SMC instruction and X0-X3, optionally records raw X0 at `SMC+4`, and stops before either **X21-based LDR** or **X10-based LDP** to capture actual base/SP/LR and the live opcode; it does not execute the faulting instruction or claim an abort in that capture. Failure to hit a breakpoint is inconclusive. Its 14 host-only tests verify both load offsets, raw SMC return uncertainty, and failure guards. [GitHub Actions run #38193740839](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38193740839) passed **379/379 total HXL1 isolated tests**. **The owner's real new fault-register captures remain pending.**

Owner next WSL commands:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_compact_bitmap_call_audit \
  tools.test_y2q_hxl1_qemu_compact_fault_regs

# No emulator: independently recheck original compact guest's RKP bitmap command.
python3 tools/y2q_hxl1_compact_bitmap_call_audit.py

# Preflight only; safe to repeat without creating an output.
python3 tools/y2q_hxl1_qemu_compact_fault_regs.py --target x21 \
  --preflight-only \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-fault-x21-v1-20261012"

# New, isolated QEMU run. Never overwrite earlier source/guest evidence.
python3 tools/y2q_hxl1_qemu_compact_fault_regs.py --target x21 \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-fault-x21-v1-20261012"
```

If this yields a verified X21 and original live opcode, study the first fault's base register before scheduling a second `--target x10` run in a new directory. Do not interpret X0 after SMC as success without OEM return contract and a verifiable bitmap pointer write. **No physical-phone bootloader unlock or KernelSU deployment is established.**

---

## October 12, 01:41 UTC — original compact SMC argument and faulting base-register proof gates

**Verified owner evidence:** A real factory-image/offline compact exception audit ran on WSL successfully after **13/13 owner tests passed**. The exact compact input SHA `1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd`, **35,168-byte actual guest FDT**, the original stock factory Image and saved QEMU exception log were linked. The compact-mode run retained exactly **three QEMU exception records**, with source ELRs `0xffffff80080a5794` (Samsung SMC), `0xffffff80082ac90c` (read abort FAR `0x58`) and `0xffffff80086de39c` (read abort FAR `0x10`).

**Existing exact factory opcode gate, reused rather than reinvented:** `tools/y2q_hxl1_qemu_secure_monitor_gate.py` previously pinned `d4000003` to `SMC #0`, `f9402eb8` to `LDR x24,[x21,#0x58]` and `a9412149` to `LDP x9,x8,[x10,#0x10]`. The two FARs are consistent with zero base-register values under ordinary address calculations, **not proof** that X21 or X10 equaled zero at the fault. For `LDP` an abort may concern either element at base+0x10 or base+0x18; a FAR `0x10` supports more than one possible base and cannot alone establish a null-pointer failure. No SMC response or causal connection from the SMC to the data aborts has been established.

**New offline tool** `tools/y2q_hxl1_compact_fault_dependencies.py` independently checks that exact source opcode and address correlation against the verified compact input/FDT SHA and *unchanged original exception log*, requiring three unique ELRs and matching ESR/FAR details. It prints specific source base registers and conservative candidate base values; never invents guest register contents, UH command results or RKP memory. The host-only dependencies regression tests were **13/13 PASS in [Actions run #38193078807](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38193078807), 341/341 total isolated tests**.

**New next actual runtime proof tool, isolated original-image guest** `tools/y2q_hxl1_qemu_compact_smc_registers.py` verifies the **owner's 35,168-byte guest FDT capture and compact source before QEMU**. When explicitly run (without `--preflight-only`) it starts the original SHA-pinned HXL1 factory Image under QEMU virt with the exact verified compact `-dtb`, no NIC and no guest writes. It first stops on kernel entry `0x40080000` and verifies `X0=0x48000000,X1=X2=X3=0`; only then it arms a second GDB breakpoint at **`0xffffff80080a5794`**, records actual X0-X6 before executing `SMC #0`, and reads the guest opcode to compare against original `0xd4000003`. Execution is bounded to 30 seconds by default; timeouts preserve the GDB/QEMU log and do not claim success. The script captures **no SMC return**, does not implement Samsung UH, and makes no claim that an RKP allocator is available. This requires a **fresh output directory**, so existing original/compact evidence remains untouched.

**All 11 new compact-SMC GDB fixture tests and the full isolated [GitHub Actions run #38193282707](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38193282707) passed: 352/352 tests.** This is host-only CI; the owner's actual new GDB SMC argument run remains **pending**.

Owner procedure (validated host suite; live run not yet executed by owner):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_compact_fault_dependencies \
  tools.test_y2q_hxl1_qemu_compact_smc_registers

# No QEMU run: source-attested original compact run's three exception instructions
python3 tools/y2q_hxl1_compact_fault_dependencies.py

# Read-only original factory QEMU configuration/source preflight
python3 tools/y2q_hxl1_qemu_compact_smc_registers.py --preflight-only

# Bounded original stock-image QEMU guest: real X0-X6 immediately before SMC
python3 tools/y2q_hxl1_qemu_compact_smc_registers.py \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-smc-registers-v1-20261012"
```

The proof that **this compact guest** uses the same Samsung SMC ID/argument convention as the earlier noncompact/independent GDB capture is still pending; do not copy historical X0 values into the new report. Also, the SMC capture will not itself prove the memory-access bases X21/X10; they require a separate fault-instruction breakpoint/exception-state register trace after the SMC ABI is better understood. **Physical bootloader unlock and KernelSU remain blocked.**

---

## October 12, 01:41 UTC — compact original-image SMC plus two source-verified data aborts

**Owner WSL audit succeeded:** After `git pull --ff-only`, `tools.test_y2q_hxl1_compact_exception_audit` passed **13/13**; the actual SHA-pinned factory HXL1 kernel, source DTB/manifest, 35,168-byte guest runtime FDT, input hash `1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd`, and saved compact-mode QEMU trace revalidated. The real report `qemu-pc-compact-fdt-20261012/compact-original-exception-audit.json` establishes **three QEMU exceptions**, including the previously observed `SMC #0` instruction site `0xffffff80080a5794` and data-abort ELRs `0xffffff80082ac90c` and `0xffffff80086de39c`. A present SMC exception **does not prove a functioning Samsung secure monitor**, a successful return, or that it caused a later abort. Linux `memblock.reserved`, UH/RKP pool, userspace boot, hardware unlock and KernelSU remain unverified.

**Next precise original-opcode dependency gate, committed for offline run:** The previously independently developed `tools/y2q_hxl1_qemu_secure_monitor_gate.py` encoded exact factory opcodes `d4000003` (`SMC #0`), `f9402eb8` (64-bit `LDR x24,[x21,#0x58]`) and `a9412149` (`LDP x9,x8,[x10,#0x10]`). The corresponding original compact QEMU abort FARs were `0x58` and `0x10`. Therefore a zero base register is **compatible with both effective fault addresses**, but cannot be established from QEMU ELR/FAR alone. On `LDP`, FAR may refer to either 64-bit element, so the address calculation may use offset `0x10` or `0x18`. This observation does **not** establish actual `X21` or `X10` contents, nor a causal relationship to the SMC.

New `tools/y2q_hxl1_compact_fault_dependencies.py` revalidates the saved original Image SHA and linked 35,168-byte guest FDT source, hashes and parses the original compact QEMU exception log, requires three unique matching records, and independently compares exact original machine opcodes at each ELR. It fails closed on wrong opcode, FAR, ESR class, altered source or unrelated DTB capture. It prints the exact register and effective offsets, distinguishes *compatible with zero base* from *captured zero base*, and marks **SMC service X0, return X0, fault-time base registers and causality** unobserved. Host fixture tests have been committed for CI, but owner factory audit is still **pending**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_compact_fault_dependencies
python3 tools/y2q_hxl1_compact_fault_dependencies.py
```

Expected independent output is `~/s20-artifacts/hxl1-research/qemu-pc-compact-fdt-20261012/compact-fault-dependencies-v2.json`. This uses existing original Image and exception files only; no new QEMU run, canary generation, kernel patch, handset action or service response emulation. Once source register dependencies are verified, a separate stock-image, compact-DTB, bounded **live GDB X0-X6 at SMC and X21/X10 at the relevant fault instruction** can establish missing runtime facts. Do not reuse the previous unmodified/default-QEMU SMC argument values as if they were captured in this specific compact boot.

---

## October 12, 01:34 UTC — original HXL1 compact guest FDT 35,168 bytes verified; begin secure-monitor exceptions

**Actual owner WSL:** The new original factory-kernel, GDB-at-entry, input-SHA-pinned compact-FDT capture passed all 15/15 local tests, delivered the exact compact diagnostic self-reservation, and read the **complete 35,168-byte runtime FDT** from original kernel `PC=0x40080000`, `X0=0x48000000`, with `X1=X2=X3=0`. The strict verifier returned:

```text
[GUEST RUNTIME FDT BYTES] 35168
[ARM64 EARLY 2MiB] True
[CANARY FDT DELIVERY] DELIVERED_COMPACT_OVERRIDE_RUNTIME_FDT_WITHIN_2M
[RKP PROTECTED POOL VERIFIED] NO
[REPORT] /home/main/s20-artifacts/hxl1-research/qemu-compact-entry-fdt-20261012/compact-fdt-audit.json
```

**FDT transport, source compaction, alignment, full guest length and early-size limit gates are now proved PASS.** The guest FDT is 2,061,984 bytes below Linux ARM64's 2,097,152-byte early ceiling. The old `setup_arch` original kernel panic/stop diagnostic (source: `printk` invalid DTB, `yield; B yield`) was circumvented by **correcting the input DTB**, not by editing the kernel. The owner subsequently observed the source-matched Samsung `SMC` ELR `0xffffff80080a5794` and the known faults `0xffffff80082ac90c`, FAR `0x58`, and `0xffffff80086de39c`, FAR `0x10` under the smaller guest input. These are **separate unresolved platform/secure-call execution boundaries**; not a kernel boot, RKP pool, KernelSU, or physical bootloader unlock.

**Committed next target, no new QEMU execution:** `tools/y2q_hxl1_compact_exception_audit.py` checks source/manifest SHA, the **new fully captured original guest FDT and its provenance**, and the existing compact-mode QMP input hash, then parses the already stored bounded `qemu-pc-compact-fdt-20261012/qemu-exceptions.log`. It decodes exception `ELR/ESR/FAR` and maps exact known Samsung SMC and both data-abort ELRs to original factory Image opcodes, AArch64 disassembly when available and the nearest *recovered* symbols. Long logs retain examples of the critical known sites even if the first events are repetitive. It never claims the vendor UH secure monitor is present, that a guest memory pool exists or that Linux booted successfully. The 13 new synthetic exception-correlation tests passed in [GitHub Actions run #38192724982](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38192724982), **328/328 isolated HXL1 tests PASS**. Source/test CI does **not** substitute for the still-**pending owner offline audit**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_compact_exception_audit
python3 tools/y2q_hxl1_compact_exception_audit.py
```

**Next actual engineering decision:** use recovered exact instructions at the two abort ELRs and the Samsung `SMC` callsite to determine missing emulated secure monitor services, null/invalid address dereferences or allocation-state dependencies. Read-only evidence first. No guessing RKP allocator fields, patching around faults, repeating FDT canaries, or handset flashing.

---

## October 12, 01:17 UTC — 7,584-byte compact FDT gets past original setup_arch stop and reaches known HXL1 SMC/fault sites

**Owner WSL real output** after `git pull --ff-only`: **41/41** local host regressions passed. The SHA-pinned original HXL1 Image bytes at static `printk` pointer `0xffffff800a17415c` now decode definitively to `KERN_SOH` log-level 2 plus:

```text
Error: invalid device tree blob at physical address %pa (virtual address 0x%p)
The dtb must be 8-byte aligned and must not exceed 2 MB in size

Please check your bootloader.
```

This original-source string and original `yield; b -4` loop establish the intended **kernel invalid DTB error path**. It is not a physical Samsung bootloader unlock state or exploitation primitive.

**Source fixed without touching factory firmware:** Original QEMU-generated `qemu-virt.dtb` 1,048,576 bytes consisted of 7,568 bytes of retained structural/header information and **1,041,008 trailing verified-zero padding bytes**. The builder preserved sections/strings, then added exactly one diagnostic memreserve, yielding **7,584 bytes** at SHA-256 `1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd` (manifest reconstruction verified). It declares `[0x48000000,0x48200000)` as **FDT self-reservation only**; no protected RKP pool.

**Actual compact-DTB original kernel QMP run moved beyond early stop.** The 4 observed PC samples alternated between `0xffffff8008146ad4` and `0xffffff8008146ae4` rather than the old fatal `setup_arch` PC `0xffffff800a60514c`. QEMU exception trace recorded **Samsung SMC at `0xffffff80080a5794`** and previously observed data-abort sites `ELR=0xffffff80082ac90c,FAR=0x58` and `ELR=0xffffff80086de39c,FAR=0x10`. This validates **progress into the existing next HXL1 secure-monitor/exception boundary**, not successful kernel boot, working UH/RKP services, allocation exclusion, a handset unlock or KernelSU deployment. The two alternating new PCs may themselves be another failure loop, so don't call this a successful boot.

**Next unclosed proof:** the smaller *input* DTB does not prove the exact **runtime** FDT size; QEMU previously doubled it through direct-boot handoff. New `tools/y2q_hxl1_qemu_compact_fdt_capture.py` reconstructs and SHA-pins the compact source, starts a fresh bounded, host-only QEMU guest, and halts at original `PC=0x40080000` with verified `X0=0x48000000`. It reads the full dynamic `fdt_totalsize` from the guest, checks the exact GDB dump marker/guest header, RAM profile, diagnostic self-reservation and **ARM64 <=2,097,152** entry-size gate. A capture where the FDT remains >2MiB will be reported as such, not falsely labeled valid. **15 new no-guest fixture tests passed** with **315/315 total isolated tests PASS** in [GitHub Actions run #38191506521](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38191506521). The owner's actual new kernel-entry compact-FDT capture is **pending**.

Owner's next shortest test (unique output; preserves all earlier evidence):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_compact_fdt_capture
python3 tools/y2q_hxl1_qemu_compact_fdt_capture.py \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-entry-fdt-20261012"
```

Once the actual guest FDT <2MiB is measured, return to exact Samsung `UH_APP_RKP` SMC operation and those two original abort sites, with guest allocator state verification still separate. No live device is touched. Detailed [original FDT source, fix and QEMU evidence](SM-G986U1-HXL1-QEMU-FDT-2M-STOP-20261012.md).

---

## October 12, 01:07 UTC — QEMU v3 FDT exceeds ARM64 2MiB; setup_arch yield-loop cause narrowed

Owner WSL ran `tools.test_y2q_hxl1_setup_arch_loop_audit`: **15/15 PASS**, SHA-pinned original Image with `printk` recovered at `0xffffff800814f350`, static format pointer `0xffffff800a17415c`, and original source `YIELD; B -4` loop at `0xffffff800a605148/14c` in the nearest recovered `setup_arch`. A plain-ASCII check returned `NO_PLAUSIBLE_PRINTABLE_STRING` for the static format; original Linux printk strings can begin with `KERN_SOH` log level or line breaks, and that check was overly strict. The source `X13/X14` fragments `heck you`/`r bootlo` are consistent with, but do not alone prove, the upstream text mentioning the bootloader.

**Strong externally verified upstream source match:** ARM64 `setup_machine_fdt()` prints an invalid-device-tree message and executes a deliberate `while(true) cpu_relax()` stop loop if `fixmap_remap_fdt()` or `early_init_dt_scan()` rejects the early blob. Its diagnostic states an **FDT maximum of 2MiB**. The owner's v3 actual original-kernel guest FDT declared `2,117,184 (0x204e40)` bytes, exceeding `2,097,152` by **20,032 bytes**. This explains how QEMU's `-dtb` input may have a valid FDT reserve record at guest entry and still fail earlier in the kernel than `memblock_reserve` or UH SMC. The message's reference to a *bootloader* is **about supplying a valid DTB**, not evidence of a physical Samsung OEM unlock check. The exact factory-original conditional path is not independently live-traced, but the source, string fragments, PC and measured size agree. Source references: https://android.googlesource.com/kernel/common/+/19b68814b1cd60c40546f31f7cc5b7895c0b013b/arch/arm64/kernel/setup.c and https://gbmc.googlesource.com/linux/+/777747f634ba765085373f851e9c48dccb12ad52/arch/arm64/kernel/setup.c . Distinguish upstream reference from the OEM Image's measured bytes.

**Implementation committed:** `tools/y2q_hxl1_qemu_fdt_size_recovery.py` exactly pins original `dumpdtb` hash and its 2GiB RAM profile; bounds every FDT section/reservation; trims **only provable trailing zero padding** outside all sections; refuses nonzero tail, changed structure/strings, changed memory semantic inventory or absent removable slack; and writes a separate diagnostic custom `-dtb` copy with a 2MiB **FDT self-reservation only** (not an RKP pool). It does not patch or boot the OEM kernel. Existing bounded QMP sampler gained `--mode compact-canary` which reconstructs and verifies the exact compact DTB and manifest before starting QEMU. Its PC snapshots cannot independently prove guest FDT size or allocator state. Separately, the original loop audit now recognizes bounded factory `printk` formats with optional `KERN_SOH` log level and newlines, without guessing nonprintable content. **12 new FDT-size recovery tests + 2 new printk-format tests** passed; the isolated HXL1 run [#38191018246](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38191018246) was **300/300 PASS**.

Next user run, all on WSL; existing v3 artifacts are not overwritten:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_setup_arch_loop_audit \
  tools.test_y2q_hxl1_qemu_fdt_size_recovery \
  tools.test_y2q_hxl1_qemu_memblock_pc_sampler

python3 tools/y2q_hxl1_setup_arch_loop_audit.py \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-memblock-pc-samples-v3-20261012/setup-arch-loop-printk-v2.json"

python3 tools/y2q_hxl1_qemu_fdt_size_recovery.py
python3 tools/y2q_hxl1_qemu_fdt_size_recovery.py \
  --verify-dir "$HOME/s20-artifacts/hxl1-research/qemu-fdt-under-2m-20261012"

python3 tools/y2q_hxl1_qemu_memblock_pc_sampler.py \
  --mode compact-canary \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-pc-compact-fdt-20261012"
```

This is a **hypothesis-guided size correction**, not a successful guest boot or memblock proof. If the original generated FDT contains no removable padding, it stops and reports the evidence; do not blindly modify its original node structure. If new QMP still sees the source fatal loop, first directly verify the new guest FDT's `totalsize` and original conditional path. If QMP progresses, independently verify the full *runtime* FDT is within 2MiB before resuming allocator probes. Full procedure: [HXL1 early FDT >2MiB stop study](SM-G986U1-HXL1-QEMU-FDT-2M-STOP-20261012.md).

No KernelSU, RKP protected pool, hardware bootloader unlock or device root is established.

---

## October 12, 00:58 UTC — original HXL1 setup_arch yield/backward-branch loop located

**Owner WSL source-grounded breakthrough:** `tools.test_y2q_hxl1_qemu_pc_attribution` **17/17 PASS** on the owner's WSL. The exact factory `kernel.bin` SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` was validated. Its reconstructed `VM_BASE=0xffffff8008080000` mapped four identical QMP PC samples at `0xffffff800a60514c` to factory Image offset `0x258514c`. The original Image opcode at PC is **`0x17ffffff`**, an unconditional ARM64 `B` to `0xffffff800a605148`. The word at the target is **`0xd503203f`**, `YIELD`. Original-Image disassembly:

```asm
0xffffff800a60512c: sub x0, x9, x8
0xffffff800a605130: b   0xffffff800a605160   // an edge skipping the loop block
0xffffff800a605134: adrp x0, 0xffffff800a174000
0xffffff800a605138: add x1, sp, #0x18
0xffffff800a60513c: add x0, x0, #0x15c
0xffffff800a605140: mov x2, x19
0xffffff800a605144: bl  0xffffff800814f350   // callee not yet source identified
0xffffff800a605148: yield
0xffffff800a60514c: b   0xffffff800a605148
0xffffff800a605150: adrp x8, 0xffffff800a4c7000
0xffffff800a605160: bl  0xffffff80080abf88
```

The **original factory source contains a demonstrable two-instruction `yield; b yield` loop**, and the owner's four running-CPU samples were all within that loop at the branch instruction, with `X16=X30=0xffffff800a605148`. The nearest lower-or-equal *reconstructed* `vmlinux-stock.nm` symbol is `setup_arch` at `0xffffff800a604f88`, **offset `+0x1c4`**, but reconstructed name/extent must not be treated as independently validated live runtime symbols. The loop source bytes and PC samples together **strongly support** stalling in that branch rather than a simple inability to hit `memblock_reserve`; nonetheless the original live guest opcode bytes have not yet been read to independently exclude changed code mapping or other execution artifacts.

The preceding `BL` targets `0xffffff800814f350`, factory Image offset `0xcf350`. The `ADRP x0` at `0xffffff800a605134` followed by `ADD x0,#0x15c` at `...513c` constructs a candidate static data pointer `0xffffff800a17415c` (factory Image offset `0x20f415c`). **Do not guess the callee type, message text or condition** until these original bytes are independently decoded. `X13/X14` only held ASCII fragments `"heck you"` and `"r bootlo"`, which are not proof of a complete message or bootloader defect. An unconditional skip edge at `0xffffff800a605130` reaches `0xffffff800a605160` *without entering the loop*; the predecessor condition selecting the block remains unresolved.

**Implementation committed:** `tools/y2q_hxl1_setup_arch_loop_audit.py` performs a strictly host-only original SHA-pinned factory-Image check, decodes the YIELD/B loop, preceding BL target, ADRP+ADD static pointer, nearby branch to skip the block, original code bytes and closest recovered symbol; if the original file does not contain that exact loop, the CLI refuses a positive result. It saves a new `setup-arch-loop-callee-audit.json` without overwriting owner evidence or running QEMU. `tools/test_y2q_hxl1_setup_arch_loop_audit.py` contains 15 new regression cases and is wired into the isolated HXL1 workflow. The 15 new host-only tests **passed in [GitHub Actions run #38190236648](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38190236648)**, with **285/285 isolated HXL1 tests PASS**. The owner's real offline callee/message report is still pending; successful CI fixtures are not factory data evidence.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_setup_arch_loop_audit
python3 tools/y2q_hxl1_setup_arch_loop_audit.py
```

**Next concrete decision:** identify exact call target and static message from the original Image/symbols. Compare the condition selecting the fatal block against verified early boot state, rather than creating another RKP memory model or changing the guest instructions prematurely. Existing FDT canary delivery remains proven; Linux memblock exclusion, UH RKP secure memory, physical bootloader unlock and KernelSU are not established.

---

## October 12 00:46 UTC — QMP guest PC snapshots reveal a repeatable original-Image address

Owner WSL pulled through `2e2a56d`, ran `tools.test_y2q_hxl1_qemu_memblock_pc_sampler` **11/11 PASS**, verified stock factory Image SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` and v3 `DELIVERED_AND_FULLY_COVERED` canary, then ran the **actual** bounded v3 QMP CPU-state sampler. Four snapshots taken at approximately 2.4, 4.8, 7.2 and 9.6 s all returned:

```text
[PC OBSERVATION] SAME_PC_IN_MULTIPLE_SNAPSHOTS
[PC SERIES] 0xffffff800a60514c repeated four times
[CPU STATE] EL1h, PSTATE=600001c5, reported running
[X16] 0xffffff800a605148
[X30] 0xffffff800a605148
[X20] 0x48000000 (previously measured FDT physical pointer)
[QEMU EXCEPTIONS] empty (0 bytes in this particular run)
[samplingError] null
```

Other saved register details include `X00=0xcb`, `X01=0xffffff800b234335`, `X02=0xffffffffffffffc5`, `X06=0xffffff800b237463`, `X13=0x756f79206b636568` and `X14=0x6f6c746f6f622072`. The latter two decode to little-endian ASCII **fragments** `"heck you"` and `"r bootlo"`; those fragments alone do **not** identify a complete string, a panic, or any bootloader condition. The reproduced register context is promising, but a repeatable PC on samples alone cannot establish whether a loop, wait, repeated reset, unsupported platform or other control flow is responsible. The QMP sampler did not independently attest kernel entry, although separate original GDB v2 evidence did. No guest ESR/FAR/ELR were exposed by `info registers` in this run.

The sample PC `0xffffff800a60514c` maps under the **reconstructed, unverified live-VA** `VM_BASE=0xffffff8008080000` to *candidate original factory Image offset* **`0x258514c`**. `X16` and `X30` are each **4 bytes before** PC. Source pointer candidates `X01` and `X06` also lie inside the previous original Image length; their actual OEM bytes must be inspected before quoting strings. These observations do **not** prove a bootloader check or rootability.

**New SHA-pinned, read-only next tool:** `tools/y2q_hxl1_qemu_pc_attribution.py` validates the retained QMP raw registers against saved PC sequence, rechecks exact factory `kernel.bin` SHA, correlates the address to original bytes and the nearest *reconstructed* `vmlinux-stock.nm` text symbol, disassembles local AArch64 instructions with `aarch64-linux-gnu-objdump` when installed, and cautiously extracts only printable **NUL-terminated** strings from original Image offsets held in selected registers. It also prints `X13/X14` as byte fragments without guessing missing bytes. No guest execution is needed, no firmware is written, and neither candidate symbols nor factory bytes alone prove the live guest instruction at PC. The new 17 host fixture tests are now **PASS**, with the entire isolated HXL1 [GitHub Actions run #38189615887](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38189615887) **270/270 PASS**; the owner's real Image-source attribution report is pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_pc_attribution
python3 tools/y2q_hxl1_qemu_pc_attribution.py
cat "$HOME/s20-artifacts/hxl1-research/qemu-memblock-pc-samples-v3-20261012/original-pc-attribution.json"
```

The report must preserve the original **candidate vs runtime** uncertainty. A future, narrowly bounded GDB live-opcode read or comparative baseline PC sample may be justified *after* inspecting actual OEM function bytes. Do **not** modify RKP RAM, reinterpret `memblock_reserve` as proven, or return to the completed FDT canary experiment.

---

## October 12, 00:34 UTC — stock kernel entered; post-entry timeout and below-RAM read

The owner ran **16/16** updated memblock-probe host tests PASS and the offline v1 audit:
```json
{"status":"OFFLINE_DIAGNOSTICS_ONLY","gdbExitCode":"124","gdbLogLines":6,
 "timeoutObserved":true,"kernelEntryProof":false,
 "qemuExceptionLogBytes":0,"linuxMemblockAllocatorExclusionVerified":false}
```
The old v1 GDB log had exactly the hardware breakpoints at `0xffffff80082a0844` and `0xffffff80080a5794` followed by timeout. It contained no proven kernel-entry state and no retained QEMU exception log.

The owner then actually ran the corrected two-stage GDB v2 capture, **preserving the original factory Image and verified v3 canary**. This time GDB independently proved kernel entry `PC=0x40080000` with the expected `X0=0x48000000`, but **neither** the candidate `memblock_reserve` call nor the earlier known Samsung UH SMC breakpoint fired before the 30-second timeout. The exact report was:

```text
[MEMBLOCK PROBE] POST_ENTRY_EXECUTION_TIMEOUT
[entryFdtPointerValidated] true
[memblockReserveCallObserved] false
[statusCode] 124
[QEMU] Invalid read at addr 0x3FFFFFFC, size 4, region '(null)', reason: rejected
```

**Interpretation:** Kernel entry is independently confirmed *in this v2 session*; the failure occurs **after entry, before any instrumented later breakpoint**. An invalid read at `0x3FFFFFFC` is exactly four bytes below QEMU virt's guest RAM base `0x40000000`. Without an actual guest `PC/ELR/FAR/ESR` snapshot at that time, the warning neither identifies the responsible original kernel instruction nor proves a stuck instruction loop, memblock exclusion failure, or FDT corruption. The recovered `memblock_reserve` remains anchored to an original opcode `0xd10103ff`, but is a recovered candidate, not an independent original runtime symbol. Do **not** diagnose this as Linux rejecting the reservation or conclude that secure UH is bypassed.

**New focused diagnostic implementation:** `tools/y2q_hxl1_qemu_memblock_pc_sampler.py` starts the same SHA-pinned original Image under the local `virt,gic-version=3` QEMU machine and revalidates prior v3 guest-canary evidence. It adds an isolated local UNIX QMP monitor and takes a bounded set of CPU snapshots using `human-monitor-command: info registers`, plus QMP `query-status`, while recording QEMU exception tails. It **does not** depend on the recovered memblock breakpoint, install firmware hooks, modify guest memory, or touch the physical S20+. It emits live `PC/ELR/FAR/ESR` where exposed by the QEMU monitor; missing register fields remain **unknown**, never fabricated. A frozen-looking `PC` at multiple sample times is **not itself proof of a loop**. The monitor uses a maximum 24-second sampling window, an exception-log size guard and automatic emulator shutdown. It supports `--mode v3-canary` and `--mode baseline`, the latter omitting the custom `-dtb` for a controlled comparison. Eleven additional host-only regressions **passed** in successful isolated HXL1 [Actions run #38188768267](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38188768267), **253/253 total tests PASS**. The **owner-run** CPU/exception snapshot evidence is still pending.

Run the read-only preflight, then the v3 comparison. The output directory is fresh and does not replace any earlier GDB capture:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_memblock_pc_sampler
python3 tools/y2q_hxl1_qemu_memblock_pc_sampler.py --preflight-only

python3 tools/y2q_hxl1_qemu_memblock_pc_sampler.py \
  --mode v3-canary \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-memblock-pc-samples-v3-20261012"

cat "$HOME/s20-artifacts/hxl1-research/qemu-memblock-pc-samples-v3-20261012/pc-sample-report.json"
```

If the snapshot shows an identifiable guest failure PC or repeated synchronous exception, correlate it against **original stock Image bytes/source** before changing any guest memory. If QMP cannot return registers or the outcome is still inconclusive, check `samplingError`, `qemuStdout`, `exceptionLog`, and keep the original output. The optional unmodified baseline is only justified if needed to isolate `-dtb` effects.

---

## October 12 — first memblock probe timed out before any attested breakpoint

**Owner-run, original firmware SHA-pinned and guest v3 preflight VERIFIED.** The owner's WSL ran **11/11** original `tools.test_y2q_hxl1_memblock_trace_gate` host fixture tests successfully and independently confirmed `memblock_reserve` at recovered `0xffffff80082a0844`, with original Image first opcode `0xd10103ff`. Existing v3 FDT remained `DELIVERED_AND_FULLY_COVERED`.

The first isolated guest attempt at `qemu-memblock-callsite-v1-20261011` returned **`NO_BOUND_TARGET_BREAKPOINT_OBSERVED`, statusCode=124**, `memblockReserveCallObserved=false`. **No evidence exists from that output of even having reached the stock kernel entry**. The previous GDB script placed a conditional recovered-VA memblock breakpoint and SMC breakpoint, then ran from reset. It did not attest entry `PC=0x40080000` and discarded GDB timeout stderr, while not retaining QEMU exception traces. Therefore the timeout cannot distinguish failure to enter the original kernel, inability to install a virtual breakpoint, an early guest exception loop, or no matching FDT reservation call. It is **NOT** a negative `memblock_reserve` result.

**Implementation correction, committed:** Revised `tools/y2q_hxl1_memblock_trace_gate.py` now performs a two-stage GDB test. Stage A breaks on the already verified original kernel entry `PC=0x40080000` and records live `X0=0x48000000` before declaring guest entry. Stage B *only after entry* installs a conditional recovered `memblock_reserve` GDB breakpoint and a breakpoint at original HXL1 `SMC #0` `PC=0xffffff80080a5794`. A guest opcode at the candidate memblock function must match original Image bytes. The tool also records GDB error/timeout stderr and QEMU `int,guest_errors` traces. It offers `--audit-dir` for a read-only, **no-QEMU** retrospective diagnosis of the old `gdb.log`, `qemu.log` and exit status. An unobserved entry remains **INCONCLUSIVE**, as does a matched entry without either later breakpoint.

**First investigate preserved old logs without rerunning QEMU:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_memblock_trace_gate
python3 tools/y2q_hxl1_memblock_trace_gate.py \
  --audit-dir "$HOME/s20-artifacts/hxl1-research/qemu-memblock-callsite-v1-20261011"
```

If the old error report is insufficient, the next **optional** run should use new, non-overwriting `qemu-memblock-callsite-v2-20261012` output. The full evidence is in `gdb.log`, `qemu-exceptions.log` and `memblock-probe-report.json`; the status distinguishes entry-not-seen versus entry-confirmed without memblock/SMC. This is *not* a proof of allocator exclusion even if a function call is observed. Do not repeat the FDT canary or trigger a real device exploit.

---

## Owner v3 verified — memreserve canary fully covers original QEMU guest FDT

**Owner WSL exact output, October 11:** 31/31 `tools.test_y2q_hxl1_qemu_fdt_canary` unit tests passed, existing v3 canary SHA `630d405830964399e3be63a2c685442e42d5512d62ba394da3d9eef248f5c575` was accepted by independent prelaunch verification, QEMU/GDB read complete guest FDT of **2,117,184 bytes** at `X0=0x48000000`, and the strict offline verifier returned `[MEMRESERVE REACHED KERNEL ENTRY] YES`, `DELIVERED_AND_FULLY_COVERED` and `SELF RESERVATION COVERS RUNTIME FDT True`.

The single canary reservation covers **2,117,632 bytes** at `[0x48000000,0x48205000)`. The owner's earlier builder printed `[STOP] Canary output directory already exists` simply because v3 had been created; the subsequent SHA-pinned verifier explicitly passed the saved v3 content. **The original-image QEMU FDT transport and complete self-coverage gates are now CLOSED/PASS.** Preserve the v3 report `qemu-fdt-canary-delivery-v3-20261011/canary-delivery-audit.json` and cease repetitive canary construction.

**New limited guest instrumentation:** `tools/y2q_hxl1_memblock_trace_gate.py` checks the original factory Image hash, anchored recovered `memblock_reserve` function entry and the existing guest-confirmed v3 canary. It prepares a host-only plan without execution by default. With `--execute`, it runs bounded original-image QEMU with `-nic none` and GDB conditional breakpoints to *observe whether the candidate stock function receives X0 equal to the FDT start*. It compares the live opcode to original Image bytes and records X1 length. This is only a **function-call argument observation**, never allocator exclusion proof: no source-verified `struct memblock` layout, successful return observation or reserved-region state is established.

Owner can run **only after isolated tests pass**:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_memblock_trace_gate
python3 tools/y2q_hxl1_memblock_trace_gate.py
python3 tools/y2q_hxl1_memblock_trace_gate.py --execute \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-memblock-callsite-v1-20261011"
```

If the symbol is absent/ambiguous or original Image bytes fail, the tool stops before guest startup. If no matching GDB call is hit, classify **inconclusive**, not Linux ignoring the reservation. The next valid state gate is to observe the fully initialized `memblock.reserved` table (with independently validated exact factory ABI) before page allocator startup. Physical-phone bootloader unlock, RKP protected pool, root and KernelSU remain separate blocked gates.

---

# SM-G986U1 HXL1 — current porting execution guide

**Current October 11 REA FDT/boot-chain evidence:** [verified overlay composition, calculated FDT copy, boot/recovery component lookup, gzip classifier and remaining gates](SM-G986U1-HXL1-ABL-FDT-BOOTCHAIN-20261011.md). This research note supersedes earlier tentative names for `FUN_000228e0` and `FUN_00023a78`; root feasibility remains unproven.

## October 12, 00:06 UTC — owner v2 delivery audited; v3 prelaunch validator corrected

Owner WSL confirmed `tools.test_y2q_hxl1_qemu_fdt_canary` **27/27 PASS** and actually replayed retained v2 complete guest-FDT evidence using `--audit-delivery-only`:

```text
[MEMRESERVE REACHED KERNEL ENTRY] YES
[DIAGNOSTIC CLASSIFICATION] DELIVERED_BUT_SELF_RESERVATION_UNDERSIZED
[SELF RESERVATION COVERS RUNTIME FDT] False
[MIN PAGE-ROUNDED SELF RESERVE BYTES] 2117632
[RUNTIME FDT BYTES] 2117184
[SECURE RKP MEMORY RESERVED] NO
[LINUX MEMBLOCK VERIFIED] NO
```

This independently attests the diagnostic `-dtb` canary **reached original guest entry** at X0=`0x48000000` in the saved v2 guest binary. It does NOT prove that Linux memblock excluded any pages, that a protected UH/RKP pool was created or that the Samsung handset bootloader is unlocked.

Owner also built a new v3 canary override (SHA `630d405830964399e3be63a2c685442e42d5512d62ba394da3d9eef248f5c575`) with exact measured `memreserve` `[0x48000000,0x48205000)`, **2,117,632 bytes**. But its `run_y2q_hxl1_qemu_fdt_canary_capture.sh` rejected the valid manifest **before launching QEMU**, printing `[STOP] Canary FDT manifest/content mismatch`. A subsequent run of the offline verifier naturally failed with missing `delivered-fdt.dtb`. This was a bug in the old shell's inline check: it required the reserve size to equal `align_up(original override header totalsize, 4096)` instead of honoring the already-validated *explicitly measured guest runtime* size. **No v3 guest boot/FDT result exists yet**. The v3 canary directory is valid and must not be re-created or overwritten.

**Fixes committed through GitHub:** removed the hardcoded minimum-size shell check, replaced it with `y2q_hxl1_qemu_fdt_canary.py --verify-dir`, which independently SHA-pins and reconstructs the **exact** override and entire manifest, including a legitimate explicit reserve size; it refuses tampering, wrong source SHA, malformed measured reserve fields and unexpected bytes. Four new synthetic regression tests cover owner's actual v3 manifest acceptance, mutation refusal, offline CLI pinning, and verify-before-QEMU ordering. [GitHub Actions isolated HXL1 run #38186873252](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38186873252) completed **SUCCESS with 226/226 tests PASS, including 31 canary regressions**. Real v3 guest delivery/coverage remains owner pending.

**Resume using existing v3 canary; do not rerun its builder:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

CAN="$HOME/s20-artifacts/hxl1-research/qemu-memreserve-canary-v3-20261011"
CAP="$HOME/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-v3-20261011"

python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary
python3 tools/y2q_hxl1_qemu_fdt_canary.py --verify-dir "$CAN"

bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh "$CAN" "$CAP" &&
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py \
  --canary-dir "$CAN" --delivery-dir "$CAP"
```

The failed v3 attempt aborted before creating `CAP` in the original script, so its name can normally be reused **if it does not already exist**. If the directory exists for any reason, pass a new capture directory and the matching `--delivery-dir`. Even after guest FDT self-coverage passes, actual memblock/page allocation exclusion remains the next *unverified* requirement.

---


## October 11, 23:57 UTC — QEMU -dtb canary delivered, guest FDT expanded beyond self-reservation

Owner WSL pulled through `50b2b65` and ran `tools.test_y2q_hxl1_qemu_fdt_canary`: **23/23 PASS**. V2 source FDT generated a diagnostic canary SHA `622103a0167457c0493dadc30979b3cc5aa630111df3970ab9ceb6eb1caae0b2` reserving the then-predicted FDT pages `[0x48000000,0x48101000)` (`1,052,672` bytes). **GDB then read the complete guest FDT, whose actual `totalsize` was 2,117,184 bytes**, not the 1,048,592-byte override file. The source-length assumptions failed again, but *not because of a truncated dump*: the new capture passed its exact-length GDB and header validation. The offline verifier then stopped only at:

```text
[GUEST DECLARED FDT BYTES] 2117184
[CAPTURE] Complete guest-declared FDT read at original entry via custom -dtb
[STOP] Canary does not cover the complete page-rounded FDT
```

Review of exact verifier control flow establishes the following **limited but real new fact**: the final error occurs **after** it successfully parsed the 2,117,184-byte guest DTB, verified the original stock image PC/X0/GDB full-read marker, checked the original generated and runtime FDT hashes, reconstructed the single canary, and required `guest["memoryReservationEntries"]==[expected_canary_reservation]`. Thus the custom `-dtb` canary entry **DID reach the guest**; the FDT self-reservation was merely **too small** to cover QEMU's expanded runtime FDT. Delivery has been proven; Linux's memblock allocator exclusion has **not**. This is **not** a kernel boot failure.

Actual guest FDT span is `[0x48000000,0x48204e40)`; it requires a 4 KiB-aligned diagnostic self-reservation of **2,117,632 bytes**, `[0x48000000,0x48205000)`. This is derived from **actual owner GDB data**, not a pool-selection guess. Neither address marks newly available RKP RAM; the whole interval is already occupied by the guest's FDT as declared in its header. No live Linux memblock/protected-pool observation exists.

**Committed follow-up:** `tools/y2q_hxl1_qemu_fdt_canary_verify.py` now has an explicit `--audit-delivery-only` mode that checks *all original proof gates* and writes `classification=DELIVERED_BUT_SELF_RESERVATION_UNDERSIZED` rather than suppressing the delivery finding. The default verifier remains strict on complete FDT self-coverage. `tools/y2q_hxl1_qemu_fdt_canary.py` now optionally takes `--self-reserve-bytes` with mandatory 4 KiB alignment, size bounds and no-RKP-pool declarations. Four new tests replay the exact **2,117,184-byte** runtime FDT and the observed 2,117,632-byte page-rounded reservation. [GitHub Actions isolated HXL1 run #38186388440](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38186388440) finished **SUCCESS: 222/222 tests passed**, including 27/27 canary regressions. The new owner's WSL offline forensic replay and any v3 guest capture are still pending. An independently developed bootloader-triage workflow can fail separately and does not change this status.

**Immediate offline replay (NO new guest run):**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary

python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py \
  --canary-dir "$HOME/s20-artifacts/hxl1-research/qemu-memreserve-canary-v2-20261011" \
  --delivery-dir "$HOME/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-v2-20261011" \
  --audit-delivery-only
```

If full FDT self-coverage is still a meaningful diagnostic, a **separate**, unmodified factory-kernel QEMU v3 run could construct a new `--self-reserve-bytes 2117632` canary and capture it in *new* paths. This cannot itself prove the early Linux memblock allocator reserved any memory. Next engineering priority is to inspect the original stock `/memreserve/` and early `arm64` `memblock_reserve` handling, then obtain allocator exclusion evidence before constructing a protected pool.

---

## October 11, 22:53 UTC — canary guest capture was truncated; v2 fixed and regression-tested

Owner WSL pulled through `0b616b0` and ran the original `tools.test_y2q_hxl1_qemu_fdt_canary`: **17/17 PASS**. It built the original diagnostic self-reservation `canary-override.dtb` with SHA `85dcc18460e79d8543d0972a34c56844206696ea2030c7eb0f783412166fa440`. The local original-image QEMU/GDB script printed a **false-positive full-FDT capture success** (its own condition only checked an unvarying **1 MiB dump**). The next offline verifier failed:

```text
[STOP] Invalid declared DTB size
```

**Verified in committed source:** adding an FDT memreserve entry increases `fdt_totalsize` by **16 bytes**. Given the exact baseline `1,048,576`-byte header, the canary needs **1,048,592 bytes**, whereas the original capture script dumped only **1,048,576 bytes**. Thus **the guest-delivery canary is NOT verified yet**; the message claiming a completed dump was invalid. The original evidence files are preserved, not overwritten. Also the old self-reserve length of 1 MiB did not cover its added DTB bytes; the correct minimal 4 KiB page-rounded self-reserve is `1,052,672` bytes (`[0x48000000,0x48101000)`). That interval is FDT-occupied, **NOT** a selected RKP protected pool.

**Fixes committed through GitHub:** builder rounds its reservation up to the complete augmented DTB's final occupied page; GDB reads the original guest FDT big-endian `totalsize` from `X0+4` and performs a bounded exact-length binary dump; the shell validates GDB reported total, captured file length and DTB header total as equal before reporting success. Offline verification independently checks the same requirements, with an explicit truncation error, manifest consistency and full self-reserve coverage. Six additional regression tests model the exact 1MiB+16 overflow. [GitHub Actions run #38182473039](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38182473039) completed **SUCCESS with 218/218 tests PASS**, including **23/23 updated canary tests**. The new v2 live QEMU capture on owner's WSL is **NOT YET RUN**.

**New owner command — preserve both old evidence directories and use fresh v2 paths:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary

CAN="$HOME/s20-artifacts/hxl1-research/qemu-memreserve-canary-v2-20261011"
CAP="$HOME/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-v2-20261011"

python3 tools/y2q_hxl1_qemu_fdt_canary.py --output-dir "$CAN"
bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh "$CAN" "$CAP"
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py --canary-dir "$CAN" --delivery-dir "$CAP"
```

Only a passed *actual guest GDB FDT* verifier may establish that the FDT memreserve entry was delivered. Even then **Linux memblock behavior, guest reserved UH pool, guest MMU verification, Linux boot, bootloader unlock and KernelSU are still not proven**. The canary deliberately reserves only the FDT's own memory; it does not provide allocatable RKP pages. See [diagnostic self-canary v2](SM-G986U1-HXL1-QEMU-FDT-MEMRESERVE-CANARY-20261011.md#2253-utc--owner-guest-dump-exposed-fixed-length-truncation-corrected-canary-v2).

---

## October 11, 22:46 UTC — full runtime HXL1 FDT captured; reservation-delivery canary ready

The owner pulled the current branch and ran `tools.test_y2q_hxl1_qemu_runtime_fdt_compare`: **16/16 PASS**. A second, **bounded read-only QEMU/GDB** execution of the SHA-pinned original HXL1 factory Image captured the **complete 1,048,576-byte runtime device tree** at the previously measured guest `X0=0x48000000`, physically `[0x48000000,0x48100000)`. Owner's report:

```text
[GUEST FDT SHA256] e842cd6cc6b7fc391420bd571dd0f9af3aec7f223101367ddcf14853bd3a7814
[BYTE IDENTICAL TO dumpdtb] False
[SEMANTIC DIFFERENCES] [none]
[RUNTIME MEMRESERVE] 0
[RUNTIME /reserved-memory] 0
[KERNEL IMAGE OVERLAP] None
[RKP POOL RESERVED] NO
```

The **runtime FDT binary differs from the QEMU generated dump**, but the comparison's **limited** semantic inventory found no changes in memory layout, fixed/dynamic reservation entries, /chosen initrd metadata or node counts. These checks **do not prove all properties match**. We can now conclusively say the original guest at kernel entry received **no explicit FDT memreserve or /reserved-memory entries**, so its UH protected pool is still **NOT RESERVED**. This direct-guest result supersedes assumptions from `dumpdtb` alone.

**Progress beyond inventory:** committed a narrowly scoped `-dtb` **self-reservation delivery canary**, not a protected pool. `tools/y2q_hxl1_qemu_fdt_canary.py` adds exactly one FDT memreserve entry to an unchanged copy of the SHA-pinned generated DTB, covering the **already occupied FDT itself** (`[0x48000000,0x48100000)`), and proves no other FDT nodes, memory ranges, device properties or strings change. The separately bounded `tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh` uses `-dtb` to supply this diagnostic guest FDT while retaining the unmodified original factory `-kernel`; GDB captures the kernel's actual received FDT at the original PC with the original X0 and validates the full 1 MiB read. `tools/y2q_hxl1_qemu_fdt_canary_verify.py` cross-checks all original and delivered FDT hashes and requires the exact single canary to be present in the **guest** FDT. It still reports Linux memblock, UH pool and KernelSU unverified.

**Tests:** 17 new self-canary fixture tests and guard tests passed in successful isolated [GitHub Actions run #38182029643](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38182029643), **212/212 total tests PASS**. The **actual owner's -dtb delivery experiment is NOT YET RUN**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary
python3 tools/y2q_hxl1_qemu_fdt_canary.py
bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py
```

More details: [full HXL1 -dtb canary purpose, provenance and verification](SM-G986U1-HXL1-QEMU-FDT-MEMRESERVE-CANARY-20261011.md). A successful canary would prove **the FDT memreserve override reaches the guest entry**, not that Linux memblock honors it or that any free pages exist. Avoid selecting a real protected pool until physical occupancy/early memblock confirmation, and do not import the incompatible newer fork's `KDP_SET_NS_FLAGS` handler for HXL1 `RKP_GET_RKP_GET_BUFFER_BITMAP`. No physical phone change, bootloader unlock, root or KernelSU installation has been established.

---

## October 11, 22:34 UTC — genuine HXL1 kernel-entry FDT pointer and 1 MiB span confirmed

Owner WSL pulled through `b289dd0`, ran `tools.test_y2q_hxl1_qemu_entry_fdt_audit` **18/18 PASS**, executed SHA-pinned unmodified HXL1 Image inside bounded local QEMU/GDB, and received the exact boot-time device-tree header correlation:

```text
[ENTRY] GUEST_ENTRY_FDT_HEADER_CORRELATED
[X0-X3] {'X0': '0x48000000', 'X1': '0x0', 'X2': '0x0', 'X3': '0x0'}
[RUNTIME FDT CANDIDATE] {'start': '0x48000000', 'endExclusive': '0x48100000', 'sizeBytes': 1048576}
[IMAGE INTERSECTION] None
[PROTECTED MEMORY RESERVED] NO
```

This is **new actual guest CPU evidence**: GDB hardware breakpoint hit the original SHA-pinned ARM64 Image entry `0x40080000`, and live `X0` pointed to the expected big-endian FDT header magic with exactly **1 MiB declared FDT extent `[0x48000000,0x48100000)`**. `X1–X3` were zero as required by the ARM64 Linux boot convention. That runtime FDT span does **not** intersect the independently recorded *candidate, not physically attested* Image physical footprint `[0x40080000,0x443bb000)`. Previous `dumpdtb` still reported **no** FDT memreserve/`reserved-memory` and no actual protected RKP pool is established. The original 16-byte header **does not prove** the rest of the live DTB matches the generated dump or that Linux's memblock reserves anything.

**Added immediately:** `tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh` (separate bounded SHA-pinned local QEMU/GDB run, guest `X0=0x48000000` and `PC=0x40080000` gated, reads full 1,048,576-byte FDT into a new on-host file, no guest writes) and `tools/y2q_hxl1_qemu_runtime_fdt_compare.py` with 16 fixture/guard tests registered in isolated CI. The comparator checks new/old GDB breakpoint markers, all 16 header bytes, exact file length, the pinned generated FDT sha, runtime `/memory` and `/reserved-memory`/memreserve/`/chosen`, and avoids assuming runtime FDT is necessarily byte-identical to `dumpdtb`. One synthetic test initially failed because its expected error wording differed from the strict implementation; diagnostic corrected. **All 16 full-runtime-FDT tests PASSED**, and the full isolated HXL1 suite completed **195/195 OK** in [GitHub Actions run #38181271133](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38181271133). The real 1 MiB guest dump remains owner-pending. The full runtime FDT has **NOT YET BEEN CAPTURED on the owner's WSL**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_runtime_fdt_compare
bash tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh
python3 tools/y2q_hxl1_qemu_runtime_fdt_compare.py
```

Expected new artifacts: `~/s20-artifacts/hxl1-research/qemu-runtime-fdt-20261011/runtime-fdt.dtb`, `gdb-session.log`, `runtime-fdt-comparison.json`. If GDB times out or the guest read fails, retain the directory and use a **fresh** output path for any subsequent attempt, while passing `--runtime-dtb`, `--gdb-log`, `--output` as corresponding CLI overrides. The 1 MiB binary guest read is time-bounded to 60 seconds; a partial file is an **INCONCLUSIVE** capture, not guest boot failure. No pool is selected or reserved, the original Image remains immutable, and bootloader unlock/KernelSU are still unproven.

---

## October 11, 22:26 UTC — boot-memory audit passes; runtime ARM64 handoff FDT measurement

Owner pulled `22a1962` and ran `tools.test_y2q_hxl1_qemu_boot_memory_audit`: **15/15 PASS**, then ran the actual SHA-pinned factory original-image and QEMU-generated FDT cross-audit. Its observed output was:

```text
[STOCK] ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
[DTB] 85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87
[RAM BYTES] 2147483648
[RAM] 0x40000000 0xc0000000
[ORIGINAL IMAGE PROBABLE SPAN] 0x40080000 0x443bb000 status: POSSIBLE_QEMU_IMAGE_PLACEMENT_NOT_PHYSICALLY_ATTESTED
[FDT RESERVATIONS] 0
[PROTECTED POOL VERIFIED] NO
```

The **possible 67+ MiB stock Image span** at `[0x40080000,0x443bb000)` comes from the earlier trace-correlated kernel entry PC and the larger of the genuine Image file and ARM64 `image_size` header fields. It is **not** a measured complete guest-physical Image/BSS allocation or a verified gap. The dynamically generated `virt` DTB has **zero** explicit FDT reservations; the live early kernel's memblock/FDT runtime placements remain unmeasured. It is unsafe to select a UH RKP pool until early physical reservation is installed and confirmed.

**New targeted measurement code committed:** `tools/run_y2q_hxl1_qemu_entry_fdt_capture.sh` starts the same **SHA-pinned, unmodified** HXL1 Image on the proven `virt,gic-version=3`, Cortex-A57, 1 vCPU, 2 GiB guest profile, suspended with `-S`, and sets a localhost GDB hardware breakpoint at `0x40080000`. At the breakpoint it records `X0–X3` and reads **only the first sixteen bytes** at `X0`. Under the AArch64 Linux entry convention **X0 should contain the physical address of the boot-time device tree**. `tools/y2q_hxl1_qemu_entry_fdt_audit.py` validates the marker, entry PC, register values and big-endian DTB header magic/size, checks RAM bounds and possible overlap with the candidate Image, and **pins original Image + generated DTB provenance** to existing reports. Unknown/bad pointer, unreadable memory and missing breakpoint remain explicitly **INCONCLUSIVE**. No guest physical reservation, UH handler, memory write or phone action occurs. All **17 original synthetic guard tests passed in GitHub Actions run #38180648987 (178/178 full-suite tests)**. The 18th declared-DTB-padding regression also **passed**, and [GitHub Actions run #38180778127](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38180778127) completed **SUCCESS: 179/179 tests**, including all **18 entry/FDT tests**. The physical entry-point capture on the owner's workstation remains pending. The new owner GDB entry capture remains pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_entry_fdt_audit
bash tools/run_y2q_hxl1_qemu_entry_fdt_capture.sh
python3 tools/y2q_hxl1_qemu_entry_fdt_audit.py
```

Output: `~/s20-artifacts/hxl1-research/qemu-entry-fdt-20261011/{gdb-session.log,entry-fdt-audit.json}`; the prior boot-memory/DTB reports are preserved. This is a bounded **emulated guest** debug session, not an actual handset or a Linux userspace boot. Its result determines the next guest-runtime memory/DTB verification step. Bootloader unlock, RTmutex exploit and KernelSU deployment remain blocked and are not advanced by this guest entry observation.

---

## October 11, 22:21 UTC — actual QEMU virt DTB captured, no reserved RKP guest RAM

The owner ran `tools.test_y2q_hxl1_qemu_virt_dtb_inventory` **11/11 PASS**, and completed a no-kernel-execution stock-QEMU `dumpdtb` using the SHA-pinned HXL1 kernel and original `virt,gic-version=3`, Cortex-A57, 1 CPU, 2048 MiB RAM profile:

```text
[DTB] /home/main/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/qemu-virt.dtb
[DTB SHA256] 85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87
[MEMORY] /memory@40000000 0x40000000 0xc0000000
[RAM RESERVATION VERIFIED] NO
```

The actual generated `virt` FDT confirms one **2 GiB RAM range `[0x40000000,0xc0000000)`** and reports no explicit memreserve/`/reserved-memory` nodes in this bounded inventory. Importantly **this is NOT a free-RAM map**. The lack of memreserve does not exclude occupied kernel Image/BSS/DTB, loader allocations, page tables, early guest kernel stacks, runtime memblock allocations or temporary regions. It therefore **does not identify any safe RKP protected pool address**. Original guest RAM and firmware remain unmodified, and the root/KernelSU/bootloader gates remain closed.

**Next evidence-only code already committed:** `tools/y2q_hxl1_qemu_boot_memory_audit.py` and 15 synthetic regression tests in HXL1 CI. It cross-checks the **genuine** `kernel.bin` SHA and ARM64 header file/image size against the captured unmodified `qemu-virt.dtb` and its original hashed `qemu-virt-inventory.json`. The trace-correlated `0x40080000` Image PC is deliberately treated as a **candidate physical load base**, not an independently measured full physical footprint; the report lists the observed span and all missing boot-resource locations, never chooses a carveout, and marks guest memory reservation and real QEMU adapter readiness FALSE. All **15 new synthetic regression tests passed** in GitHub Actions run [#38180253727](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38180253727), contributing to **161/161 tests passing**. The owner's *actual original Image/DTB audit report* remains pending; passing fixtures is not physical footprint proof.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_boot_memory_audit
python3 tools/y2q_hxl1_qemu_boot_memory_audit.py
```

New output: `~/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/boot-memory-conflict-audit.json`. The audited data cannot justify setting `ram_reservation_verified=true` in `hxl1_rkp_guest_commit`. Before a genuine guest-memory SMC adapter, capture the actual loader/runtime FDT guest physical address and early memblock reservations, then independently install and verify a nonoverlapping reserved pool. **No additional QEMU boot is required for this audit.**

---

## October 11, 22:13 UTC — transaction WSL 9/9 PASS; QEMU virt generated FDT inventory tool

Owner pulled through `deff448` and ran `tools.test_y2q_hxl1_rkp_guest_commit`: **9/9 PASS**, with actual native-host C compilation and all injected write/rollback/readback failure fixtures. This independently corroborates 135/135 earlier successful CI tests. Entire original three-part host library is now **22/22 owner-validated** (7 pool + 6 staging + 9 transaction), but has **no real QEMU memory mapping, SMC handler or reserved physical pool**.

**New committed test-gated evidence step:** `tools/run_y2q_hxl1_qemu_virt_dtb_capture.sh` + `tools/y2q_hxl1_qemu_virt_dtb_inventory.py` and 11 synthetic regression tests, registered in isolated HXL1 CI. The shell script verifies exact SHA-pinned HXL1 factory `kernel.bin`, preserves existing outputs, and requests the QEMU `virt,gic-version=3` generated DTB with the same Cortex-A57, 1 vCPU, 2 GiB profile that hit the original SMC in GDB. `-S` and QEMU's `dumpdtb` property prevent intentional execution of the stock kernel; no on-device operation is involved. The parser is a bounded, pure-Python binary FDT reader that lists `/memory` regions, FDT memreserve entries, `/reserved-memory` fixed/dynamic nodes and initrd metadata, without interpreting gaps as available pages. The 11 new tests **passed in CI (146/146 total)** on run [#38179715298](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38179715298). Owner WSL DTB output remains pending.

Run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_virt_dtb_inventory
bash tools/run_y2q_hxl1_qemu_virt_dtb_capture.sh
python3 tools/y2q_hxl1_qemu_virt_dtb_inventory.py
```

Report: `~/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/qemu-virt-inventory.json`. **Do not select any guest-physical carveout based on absence from DTB reservations alone.** The inventory is a prerequisite to verifying a safely reserved protected pool; it is not sufficient. On failure/unsupported machine property, inspect `qemu-dtb-stdout.log` rather than executing an uncontrolled full QEMU boot. Full source ABI and memory contract are in [RKP integration proof gates](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md#2213-utc--transaction-confirmed-on-owner-wsl-qemu-virt-dtb-inventory-gate).

---

## October 11, 22:09 UTC — full isolated HXL1 workflow PASS (135/135)

After applying `libc6-dev-arm64-cross` to the isolated GitHub Actions workflow's AArch64 cross-compiler installation, [Actions run 38179184038](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38179184038) for commit `d8dac2e` completed **SUCCESS**. The fetched job logs report:

```text
Ran 135 tests in 3.787s
OK
```

This included **all nine new guest commit tests**: pointer-last publishing, dirty original pointer/preexisting reserved data refusal, fault injection, bytewise readback and rollback, all-vCPU quiescence and physical reservation gates, and the **partial original-pointer publication plus failed rollback** check. Prior workflow failures on two original-source AArch64 regressions were environmental (missing `bits/libc-header-start.h`), not RKP adapter failures. The cross-libc package fix has been validated by this full green run.

This confirms the existing original-source unit fixtures and all current host-only C interfaces compile and pass on `ubuntu-latest`. **It does not execute the factory HXL1 guest kernel in CI, implement real guest DTB/memblock reservation, prove an HXL1-compatible secure hypervisor, or install KernelSU**. The original owner-verified factory-image and SMC breakpoint logs retain their separate status.

**Next real emulator work:** inspect the exact `virt` generated FDT/device-memory ranges, reserve an actual candidate protected pool and descriptor backing before Linux memory initialization, implement vCPU-context guest VA→PA checks without hardcoded linear-map offsets, and wire the tested transactional commit layer into the HXL1-specific command-0x15 SMC handler. Do not use the upstream fork's `KDP_SET_NS_FLAGS` dispatch for the same numeric X0/X1; validate all further HXL1 commands against original source.

---

## October 11, 22:00 UTC — 13/13 host C tests PASS; guarded physical guest-memory commit layer

The owner executed the combined `tools.test_y2q_hxl1_rkp_pool_model` (7 tests) and `tools.test_y2q_hxl1_rkp_guest_stage` (6 tests) against current GitHub branch: **13/13 PASS**. Real host C builds, host pool ownership, sparse bitmap, 32-byte descriptor staging and synthetic mapping rejection are validated. Still **no guest physical reservation, MMU translation, original secure-monitor response, Linux boot or physical device access**.

New immediately committed implementation: `tools/hxl1_rkp_guest_commit.{h,c}` adds transactional *backend-agnostic* physical memory operations gated on verified guest mapping, all-vCPU quiescence and externally reserved memory. It snapshots original contents, rejects dirty/uninitialized states, writes the bitmap before the pointer table before the descriptor, updates original `rkp_s_bitmap_buffer` pointer **last**, validates every readback and restores attempted regions in reverse order after failure. A partially published kernel pointer followed by failed rollback is marked **uncertain/untrusted** and must halt guest emulation; it cannot be treated as safely reverted. **Nine** new synthetic C+Python regression tests were committed to HXL1 GitHub Actions; first eight transaction tests **passed in GitHub Actions** on 2026-10-11 22:06 UTC, while overall workflow failed due to a missing AArch64 libc sysroot in **older unrelated** source-slice tests. CI workflow now installs `libc6-dev-arm64-cross` to fix that known independent environment failure. New full-suite result still pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_rkp_pool_model \
  tools.test_y2q_hxl1_rkp_guest_stage \
  tools.test_y2q_hxl1_rkp_guest_commit
```

Read [source-derived RKP guest-memory boundary and rollback gate](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md#2200-utc--1313-owner-regression-pass-and-new-transactional-writer). The code is an internal library with a simulated memory backend, **not a ready-to-apply QEMU 10.2.2 patch**. Next engineering requirement is an HXL1-specific physically reserved QEMU `virt` RAM region backed by actual early guest page tables, with a verified kernel `X2` global pointer write through correct MMU-aware guest access. The existing Samsung production-QEMU `KDP_SET_NS_FLAGS` handler is incompatible with original HXL1 `RKP_GET_RKP_GET_BUFFER_BITMAP` and remains prohibited. Root/KernelSU/bootloader unlock remain blocked.

---

## October 11, 15:44 UTC — 7/7 host C pool tests passed; protected guest descriptor staging committed

The owner pulled `2bd6696` and ran `tools.test_y2q_hxl1_rkp_pool_model`: **7/7 PASS** including strict-warning C compilation, externally reserved pool checks, 4 KiB page alloc/reuse/double-free tests, and 1 GiB sparse bitmap boundary. This is the first empirically successful **native host C** version of the RKP memory model; it is **not** an HXL1 UH hypervisor or source-faithful QEMU boot.

**Immediately completed code:** `tools/hxl1_rkp_guest_stage.{h,c}`, `tools/hxl1_rkp_guest_stage_test.c`, and `tools/test_y2q_hxl1_rkp_guest_stage.py` plus HXL1 CI wiring. This stages a source-derived 32-byte descriptor, 64-bit `char **map` guest pointers, 1 GiB unit bytes and the global pointer slot `X2` as **HOST-ONLY** little-endian buffers. Every guest VA/PA relationship must be supplied by the adapter and validated through a mandatory callback; fake/overlapping/out-of-reservation mappings fail closed. No guest RAM writes, DTB changes, SMC interception or real physical page reservation are performed. **The new six-test staging suite has not yet been owner/CI-verified**. The complete [HXL1 RKP guest memory ABI and safety boundary](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md) now details the remaining genuine QEMU integration proof gates.

Next owner command:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_rkp_pool_model \
  tools.test_y2q_hxl1_rkp_guest_stage
```

**Do not** use synthetic staging addresses on QEMU, claim the upstream fork `KDP_SET_NS_FLAGS` handles the actual stock HXL1 `RKP_GET_RKP_GET_BUFFER_BITMAP`, or treat passing host tests as boot/root. To integrate, first capture a real original `virt` guest RAM map and verify protected-pool reservation in the device tree and kernel memblock, then check guest virtual-to-physical mapping and implement write atomicity. The stock handset and firmware remain untouched.

---

## October 11, 15:34 UTC — source-confirmed RKP preflight and host-only bitmap pool model

Owner pulled through `5707559` and verified the exact original-source RKP bitmap preflight: **14/14 unit tests passed**, and **14/14 source-specific checks passed**: commands `0x11–0x15`, 1 GiB bitmap sparse unit, descriptor fields `start_addr/end_addr/maxn/map`, physical/page bit offset logic, 4 KiB factory kernel pages, `paging_init` bitmap call before normal kernel mappings, later RO/DBL bitmap/init commands, protected page allocation/free consumers. The script accurately printed **`[FORK] NOT READY; protected pool and descriptor reservation unimplemented`** and saved `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-preflight.json`.

**Implemented and committed since that confirmed gate:** reusable QEMU-neutral host C model `tools/hxl1_rkp_pool_model.h` and `.c`, synthetic fixture `tools/hxl1_rkp_pool_model_test.c` and Python native-compiler regression runner `tools/test_y2q_hxl1_rkp_pool_model.py`, wired to isolated HXL1 CI. It models bounded aligned externally-reserved guest physical ranges (without actually modifying QEMU's DTB or memmap), 4 KiB page alloc/free with separate static protected membership bits, and host-only 1 GiB sparse-unit bitmap byte arrays; it does not write guest RAM, assign guest virtual pointer arrays or hook a secure-monitor call. **Ownership bitmap bit=1 convention is a model hypothesis, not measured UH firmware output**. Owner/CI pass for the newly committed C tests **has not been verified**; avoid promoting them to confirmed status.

Run only native C model tests (no QEMU/handset):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rkp_pool_model
```

New integration contract: [HXL1 RKP QEMU pool boundary, source-derived ABI, and proof gates](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md). Before integrating any SMC `0x15` handler, the actual guest reserved-memory carveout, correct `sparse_bitmap_for_kernel_t` guest VA/PA pointer chain, bitmap backing and non-overlap with Linux allocator must be independently implemented/verified. The public fork's app 2/command 0x15 **KDP namespace-flags** handler and generic fake-success path remain **explicitly incompatible**. Original factory kernel, kernel-source QEMU guest init, real futex race, bootloader unlock and KernelSU deployment remain separate unresolved milestones.

---

## October 11, 15:22 UTC — exact HXL1 bitmap ABI proven, next source-faithful emulation preflight

Owner verified **23/23 tests PASS** (5 GDB capture shell guards + 18 exact-source ABI regressions), confirming the prior test-order bug is fixed. The **actual original HXL1 source ABI audit** passed, producing `[HXL1 SOURCE] EXACT_LOCAL_SOURCE_DEFINITIONS_MATCH_CAPTURED_RKP_BITMAP_CALL`, **`X0=0xc300c002`**, **`X1=0x15`**, **`X2=0xffffff800a4dd0b8`** matching the recovered `rkp_s_bitmap_buffer` original symbol, and **`X3=0x40000000`**. This completes the exact HXL1 app-ID/command/argument source-correlation gate; no more SMC GDB capture is needed.

The newest source-based conclusion is **RKP_GET_RKP_GET_BUFFER_BITMAP**, **not** the newer Samsung QEMU fork's KDP_SET_NS_FLAGS, despite the fork using the same numeric X0/X1. The relevant public SM8250 `include/linux/rkp.h` also expects RKP commands `0x11–0x15` and a `sparse_bitmap_for_kernel_t` descriptor, whereas the fork implements different command values. This is an actual **ABI collision**; **NEVER import its KDP handler unchanged or assign universal success to unknown SMCs**.

**New code now committed:** `tools/y2q_hxl1_rkp_bitmap_preflight.py` with 14 source-gated synthetic regression tests and updated isolated HXL1 CI. It checks original local HXL1 `uh.h`, `rkp.h`, `arch/arm64/mm/mmu.c`, `init/main.c`, `arch/arm64/mm/pgd.c`; it compares the prior owner-validated source-hash and GDB ABI report to the unmodified files, then extracts RKP bitmap descriptor, 1GiB sparse indexing, PAGE_SIZE, paging init order and protected allocator requirements. Its owner/CI PASS is **pending**; not yet a validated firmware fact beyond the prior ABI proof. It does not run QEMU or alter guest hardware or the phone.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rkp_bitmap_preflight
python3 tools/y2q_hxl1_rkp_bitmap_preflight.py
```

Fresh output: `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-preflight.json`. A perfect source witness report still reports QEMU adapter *NOT READY*, since the guest-physical bitmap backing and protected RKP allocation pool must be modeled and reserved independently. Next milestone after exact source preflight PASS is a deliberately isolated, HXL1-specific QEMU 10.2.2 fork component with **only** source-matched SMC dispatch, bounds-checked original sparse bitmap memory, and explicit rejection of unsupported commands. Kernel init, genuine protected page ownership, Linux userspace, bootloader unlock and KernelSU remain NOT VERIFIED.

See [QEMU adaptation and source verification](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1522-utc--exact-hxl1-source-and-rkp-bitmap-symbol-are-corroborated).

---

## October 11, 15:04 UTC — original HXL1 SMC guest registers captured; fork RKP/KDP ID conflict

The user ran the 13-unit secure monitor gate test group plus 5-unit QEMU GDB guard suite: **17/18 PASS, 1 FAIL** from a **test-only check-order defect**. The guard test expected existing-output rejection but its temporary HOME lacked the kernel image, and the shell checked for kernel presence first. GitHub code was fixed so existing output refusal precedes image checks, and original kernel SHA validation now precedes optional QEMU/GDB dependency checks. **The corrected suite's 5/5 owner/CI outcome is pending**, not claimed. The secure monitor gate analyzer itself PASSED and wrote `qemu-first-failure-20261011/secure-monitor-gate.json`.

The **actual original HXL1 guest GDB breakpoint succeeded**, capturing pre-SMC registers at the SHA-pinned factory `SMC #0` instruction `d4000003`:

```text
HXL1_SMC_BREAKPOINT_HIT PC=0xffffff80080a5794
X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000
X4=0x0 X5=0x0 X6=0x3f
```

**CRITICAL newly verified public-source vs fork incompatibility:** the upstream 10.2.2 Samsung production-QEMU fork classifies `X0=0xc300c002` as **KDP**, `X1=0x15` as **KDP_SET_NS_FLAGS**, and would write guest `vfsmount.mnt_flags`. But public **Samsung Snapdragon 865 Linux kernel source** `nwrafael/android_kernel_samsung_sm8250/include/linux/uh.h` defines `APP_RKP=2`, `UH_PREFIX=0xc300c000`, hence **the same X0 is `UH_APP_RKP`**. Its `include/linux/rkp.h` maps **X1=0x15** to **`RKP_GET_RKP_GET_BUFFER_BITMAP`** and invokes precisely `uh_call(UH_APP_RKP, 0x15, &rkp_s_bitmap_buffer, memstart_addr,0,0)` in `rkp_robuffer_init()`; X2 plausibly points at that global and X3 is QEMU's `0x40000000` DRAM start. This is the most specific stock guest boot-subsystem identification to date, **but the adjacent SM8250 source is not proof of exact HXL1 source mappings**. The fork's RKP commands `0x02/0x07/0x08` also differ from adjacent original source `0x11/0x12/0x13/0x14/0x15`. ***Do not reuse its KDP dispatch or generic fake-success SMC handler on HXL1.***

A new `tools/y2q_hxl1_rkp_bitmap_abi_audit.py` and 18 synthetic regression tests were committed and wired to HXL1 CI, but the owner has **not yet run** them. The audit hashes and inspects **their retained original HXL1 source** `~/src/samsung-y2q-hxl1-stock/include/linux/uh.h` and `rkp.h`, parses the already retained GDB `X0…X6`, and checks the approximate original `vmlinux-stock.nm` symbol for `rkp_s_bitmap_buffer` against `X2`. It records a source-specific ABI match or mismatch in `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-source-abi.json`. No additional emulator launches are necessary for this proof gate.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_qemu_smc_register_capture \
  tools.test_y2q_hxl1_rkp_bitmap_abi_audit
python3 tools/y2q_hxl1_rkp_bitmap_abi_audit.py
```

**Next major engineering task only after exact ABI match:** derive the correct `RKP_GET_RKP_GET_BUFFER_BITMAP` guest-side return side effect and sparse bitmap ownership, then narrowly adapt a private QEMU secure monitor emulator. Do not alter stock Image, invoke the fork's KDP namespace-flags writer, patch away SMC, return generic success, or flash the physical device. Linux userspace boot, valid HXL1 kernel RT-mutex runtime, unlock and KernelSU remain unproven. Full trace and fork compatibility matrix: [Samsung QEMU adaptation note](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1504-utc--gdb-captured-rkp-looking-bitmap-call-upstream-kdp-id-collision-discovered).

---

## October 11, 14:48 UTC — stock QEMU SMC #0 decoded; UH guest register capture gate

The owner ran the new original-image fault-site analyzer on WSL after `13/13 PASS` regression tests. It validated original stock HXL1 `kernel.bin` SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`, found the three expected ELF-reconstructed Image offsets, and decoded actual original instruction words:

```text
ELR 0xffffff80080a5794 / offset 0x25794  opcode d4000003 -> SMC #0
ELR 0xffffff80082ac90c / offset 0x22c90c opcode f9402eb8 -> LDR X24,[X21,#0x58]; FAR 0x58
ELR 0xffffff80086de39c / offset 0x65e39c opcode a9412149 -> LDP X9,X8,[X10,#0x10]; FAR 0x10
```

**Major precision improvement:** The QEMU **Undefined Instruction** is a Samsung kernel **SMC #0** instruction hitting an unsupported/unhandled secure monitor path in the generic VM, rather than evidence for an unknown CPU ISA feature. The existing public Samsung-QEMU fork has a directly relevant `target/arm/tcg/op_helper.c:HELPER(pre_smc)` intervention supporting selected Samsung UH calls. However **X0…X6 were not captured**, so HXL1's exact secure-monitor application/command cannot yet be matched to its RKP/KDP dispatch (example fork IDs `0xc300c001`, `0xc300c002`). Do not blanket-stub all SMCs or copy another device's physical memory constants. Recovered nearest names `back`, `kmem_cache_alloc`, `dump_stack_minidump` are unverified symbols and cannot establish function membership or causal ordering. The two FAR values are consistent with null-base register accesses, but current register state is unmeasured and may not be causally downstream from SMC.

**Engineering work now committed:**
- `tools/y2q_hxl1_qemu_secure_monitor_gate.py`: exact original-kernel SHA gate, original ELR opcode checks, SMC/LDR/LDP decode, explicit `X0=UNOBSERVED` and near-null candidate reporting; **13 committed offline tests**.
- `tools/run_y2q_hxl1_qemu_smc_register_capture.sh`: one-shot **30-second** localhost-only QEMU+GDB hardware breakpoint at the original SMC ELR, meant to capture guest `X0…X6` without modifying the stock Image; cleans up the VM and prints **INCONCLUSIVE** when not hit. **5 committed guard tests**.
- Both suites enrolled in `.github/workflows/hxl1-cleanup-model.yml`. **Do not claim these new 18 tests pass until owner WSL or GitHub CI confirms execution**. The earlier owner-run 13/13 fault-site tests remain VERIFIED.

After pulling, run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_qemu_secure_monitor_gate \
  tools.test_y2q_hxl1_qemu_smc_register_capture
python3 tools/y2q_hxl1_qemu_secure_monitor_gate.py
bash tools/run_y2q_hxl1_qemu_smc_register_capture.sh
```

Review compact offline classification `qemu-first-failure-20261011/secure-monitor-gate.json` and GDB `qemu-smc-registers-20261011/gdb-session.log`. Only if `HXL1_SMC_BREAKPOINT_HIT` appears may `X0` be treated as an observed call identifier; confirm actual HXL1 source ABI before implementing a separately built Samsung-QEMU `pre_smc` adapter. If debugger miss occurs, inspect `gdb-session.log` and do **not** infer the factory kernel never reached the call. The stock handset remains untouched; source-faithful guest kernel init, real RT-mutex vulnerability, bootloader unlock and KernelSU deployment remain unproven.

See [Samsung QEMU adaptation note](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1448-utc--original-smc-0-identified-samsung-qemu-hypervisor-handler-selected-for-review).

---

## October 11, 14:38 UTC — QEMU original-kernel faults observed; image-relative opcode attribution

Owner successfully ran the direct Python CLI and **9/9** `y2q_hxl1_qemu_exception_summary` tests. Original 15-second generic-QEMU trace is **fully covered** at `216857` bytes. Its original SHA-pinned Image correlation still has `270` distinct matching offsets at `0x40080000`, with **0 mismatched opcode comparisons** in that report. Three `-d int` exceptions are documented:

```text
Undefined instruction: ELR 0xffffff80080a5794, ESR 0x02000000
Data Abort (read, L1 translation fault): ELR 0xffffff80082ac90c, FAR 0x58, ESR 0x96000005
Data Abort (read, L1 translation fault): ELR 0xffffff80086de39c, FAR 0x10, ESR 0x96000005
```

The original reconstructed vmlinux base **hypothesis** is `0xffffff8008080000`, giving candidate *Image-file-relative* offsets `0x25794`, `0x22c90c`, and `0x65e39c`. This VA base originates with `vmlinux-to-elf` reconstruction, not independently observed runtime KASLR. FARs `0x58`/`0x10` suggest bad/null-related pointer dereferences but do **not** yet prove a specific missing platform component. The first Undefined Instruction could be unsupported ISA capability or a deliberate trap; its exact stock opcode is needed. These exception events **do not** establish the last executed instruction or kernel init success, and no handset vulnerability/exploit/root is implied.

**Code delivered to GitHub:** new `tools/y2q_hxl1_qemu_fault_sites.py` with thirteen isolated unit tests, now included in HXL1 CI. It reads **existing** `exception-summary.json`, validates exact original `kernel.bin` SHA, decodes ESR, inspects original instruction words around the three ELRs and best-effort `aarch64-linux-gnu-objdump` disassembly, and correlates nearest recovered `vmlinux-stock.nm` symbols without claiming DWARF/factory provenance. Owner/CI results for this newly committed tool are not yet confirmed. See [Samsung QEMU adaptation report](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1438-utc-owner-qemu-exceptions--first-evidence-of-concrete-original-kernel-faults).

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fault_sites
python3 tools/y2q_hxl1_qemu_fault_sites.py
```

The new report `~/s20-artifacts/hxl1-research/qemu-first-failure-20261011/original-fault-sites.json` is created once only. **Next meaningful milestone:** classify the actual OEM faulting instruction and function at each ELR, then compare with the Samsung production-QEMU fork's supported CPU/UH/platform behavior. Do **not** blindly import Samsung memory carving, binary DEFEX/RKP bypass patches, or perform a new full QEMU build before this classification. Stage 3 PARTIAL, Stage 4 OPEN, guest kernel init OPEN, KernelSU BLOCKED.

---

## October 11, 14:11 UTC — QEMU offline exception-summary direct-script import fixed

Owner pulled through `e8b771c` and ran the **seven** `tools.test_y2q_hxl1_qemu_exception_summary` unit tests: **7/7 PASS**. Then invoking `python3 tools/y2q_hxl1_qemu_exception_summary.py` failed immediately with:

```text
ModuleNotFoundError: No module named 'tools'
```

**Cause:** Python directly launching a script within `tools/` uses the `tools` directory as a script import path; the code tried `from tools import y2q_hxl1_qemu_trace_attest as att` without first adding the repository root. This is a Python entry-point regression, **not a QEMU exception, incorrect stock Image SHA, or kernel boot finding**. The exception-summary tool never reached the owner evidence files and did **not** create its intended `exception-summary.json` report.

**Correction committed to GitHub:** only when run outside a package (`if not __package__`), prepend `Path(__file__).resolve().parents[1]` to `sys.path`. The module invocation form remains supported. Two new tests invoke the standalone script with `python3 -I` from an unrelated CWD, verify the CLI help imports and confirm that an existing JSON output is refused without overwriting it. The suite now contains **nine** tests. Their owner/CI pass has **not yet been observed**; do not claim otherwise.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_exception_summary
python3 tools/y2q_hxl1_qemu_exception_summary.py
```

This reuses the already captured and verified `qemu-first-failure-20261011` trace and `offline-trace-format-v2.json` report; no new virtual-machine execution, firmware extraction or on-device activity is needed. Next review the exception counts, translated-PC samples, unmatched opcode comparisons and candidate factory Image offsets, taking care that `-d in_asm` is a **translation** trace and does not establish a final executed PC.

---

## October 11, 14:01 UTC — original HXL1 instruction translation corroborated in QEMU

Owner-run evidence is a material stage improvement: **19/19 offline opcode-attestor regression tests passed** and the previously saved 15-second stock-QEMU trace produced:

```text
[EVIDENCE] FACTORY_IMAGE_INSTRUCTION_CORRELATION
[TRACE OPCODES] 11502
[BASE] 0x40080000 compared 288 matched 270 tail-matched 0 entry-word True
[BASE] 0x80080000 compared 0 matched 0 tail-matched 0 entry-word False
```

This supports **original stock factory Image code at guest PC 0x40080000 being translated by QEMU**: 270 distinct Image word offsets correlate with the SHA-pinned HXL1 kernel image, including offset zero. It is NOT a complete kernel boot, verified Linux printk output, an exact last-executed PC, a live-device primitive or KernelSU installation. QEMU `-d in_asm` emits **translated basic blocks**; it does not tell us whether those blocks executed to completion or establish the last executed PC. QEMU `-d exec` is different and records executed basic-block entries. The original trace contains only `in_asm,int,guest_errors,unimp`; there is no `exec` instrumentation in that existing run.

**New committed incremental read-only tool:** `tools/y2q_hxl1_qemu_exception_summary.py` and seven unit tests. It consumes the **already retained** `offline-trace-format-v2.json`, original trace, console and exact hashed Image, prints first/last sampled translated PCs, image correlation and mismatches, and bounds QEMU exception/guest-error lines (ESR/FAR/ELR when present). New summary JSON: `~/s20-artifacts/hxl1-research/qemu-first-failure-20261011/exception-summary.json`. The script NEVER reruns QEMU, mutates firmware, or contacts the phone. Test source and CI workflow are committed, but the new suite's WSL/CI result has not been verified yet.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_exception_summary
python3 tools/y2q_hxl1_qemu_exception_summary.py
```

**Decision:** If the retained log contains a specific exception, correlate its addresses and ARM64 syndrome with boot phase before reusing individual Samsung-QEMU fork platform handlers; if it does not, use narrowly bounded `-d exec,int` on a future isolated QEMU attempt only when the existing report proves insufficient. Do not assume that 270 matched original instructions imply a healthy console, scheduler, Android boot or RT-mutex execution. Stages 4–6 and KernelSU remain blocked pending later proof.

---

## October 11, 13:43 UTC — original trace format unresolved (zero parsed opcodes, not zero execution)

The owner reran the earlier QEMU offline trace analyzer: **12/12 unit tests PASSED**, but **zero opcode words were parsed** from the retained `qemu-first-failure-20261011/tcg-instructions.log`, giving **zero comparisons** at both candidate physical load addresses. The `NO_FACTORY_IMAGE_INSTRUCTION_CORRELATION_IN_SAMPLED_TRACE` label was **misleading** for this particular result: the analyzer never compared any decoded word, and the earlier first-failure report independently observed QEMU `IN:` translation-block markers. Actual factory Image execution, entry and Linux boot remain **UNDETERMINED**.

**Implemented and committed:** `tools/y2q_hxl1_qemu_trace_attest.py` now decodes QEMU's alternate `OBJD-T:` original guest byte stream with bare preceding `0xPC:` headers, explicitly excludes `OBJD-H:` host JIT code, recognizes whether a trace contains address-only lines without supported opcodes, and prints escaped first lines and translated PC candidates when no machine words parse. The regression suite was expanded to **19 tests**, including raw byte order, split `OBJD-T` chunks, host rejection, PC-only and unknown decoder formats; **these expanded tests remain unconfirmed on owner's WSL**. GitHub guide: [Samsung QEMU adaptation and trace rerun](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1343-utc--no-recognized-opcode-lines-trace-dialect-fix).

**Next action:** only run the corrected `tools.test_y2q_hxl1_qemu_trace_attest` suite and analyze the **existing** trace to a *fresh* `offline-trace-format-v2.json` file, preserving `offline-trace-attestation.json`. Inspect actual PC/hex bytes before changing virtual RAM, bootloader logic, security-hypervisor stubs, or launching another QEMU session. No physical handset access or new source rebuild is warranted.

---

## October 11, 13:28 UTC — traced QEMU timeout; offline Image-PC check queued

Owner ran the original-Image QEMU triage after pulling branch update: `tools.test_y2q_hxl1_qemu_earlyboot_triage` **8/8 PASS**; original Image SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` and ARM64 `text_offset=0x80000` confirmed. The **actual** bounded QEMU run returned `[QEMU] TIMEOUT`, `[TRACE BLOCKS] True`, `[LINUX BANNER] False`. QEMU translated instructions, but original factory kernel entry has **not** been proven; no claim of kernel panic or boot is justified.

New **GitHub-committed, offline-only** `tools/y2q_hxl1_qemu_trace_attest.py` and `tools/test_y2q_hxl1_qemu_trace_attest.py` examine the existing 15-second trace log in bounded head/tail sections and match physical translated instruction PC/opcode pairs against the original SHA-pinned Image under explicit candidate load bases. Read [full run instructions and proof interpretations](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1328-utc-follow-up--offline-existing-trace-image-opcode-attestation). The test suite is wired into the existing isolated `.github/workflows/hxl1-cleanup-model.yml`; owner QEMU trace analysis **not yet executed**. If no candidate matches, review reported earliest PCs or supply a separately supported candidate physical base; do not initiate another 60-second silent QEMU run.

Until original factory ARM64 kernel Image execution/location is corroborated, **do not apply** the newer Samsung QEMU fork's hard-coded RAM/CPU/hypervisor/DEFEX settings to the Kona HXL1 guest. Stage 3 remains PARTIAL, Stage 4 physical handoff OPEN, KernelSU BLOCKED, phone untouched.

---

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
