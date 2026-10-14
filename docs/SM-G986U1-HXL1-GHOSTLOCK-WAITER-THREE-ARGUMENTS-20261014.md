## New original `do_futex` SP-integrity census — October 14, 2026

The owner uploaded the fully completed read-only audit, `hxl1-waiter-source-compiled-20261014T105255123936007Z.json`, independently SHA-256 checked as **`f90df3db38e68e246fda6052896f72607b8dfd8a950e19c8a45d70c7500f3a40`**. Its embedded status reports **12 original source landmarks**, all **three compiled waiter helper argument sites**, and `originalRecoveredNmIndependentlyRehashed=true`. It continues to mark runtime reuse, entire waiter lifetime and root unverified.

The original HXL1 `do_futex.disasm.txt` was re-read directly from the hash-pinned previously uploaded disassembly archive. Across all **1,766 decoded original instruction slots**, exactly **158 instructions use the architectural stack pointer**. Auditing every SP use reveals only two instructions that **write SP explicitly**:

| Original do_futex offset | Original ARM64 machine word | Instruction | Meaning |
|---|---|---|---|
| `+0x0` | `d10783ff` | `sub sp, sp, #0x1e0` | 480-byte entry-frame allocation |
| `+0xb78` | `910783ff` | `add sp, sp, #0x1e0` | 480-byte frame restoration |

The latter is followed immediately by `ret` at `+0xb7c` (`d65f03c0`). There are **zero** memory addressing forms that write back to SP, and **zero** unexpected instruction families referencing SP. The other 156 SP references do not have SP as their destination. This is more than repeating three matching expressions: on ordinary ABI-compliant execution through one `do_futex` frame, the disassembly contains no other explicit SP changes before the return epilogue.

This supports treating `SP + 0xc0` as a constant **relative to that particular function's 480-byte allocated frame**, assuming ordinary AArch64 call-return stack-pointer preservation. `0xc0` falls within `0x1e0`. It does **not** establish whether the three waiter-related callsites are dynamically taken on one feasible control-flow path, precisely which bytes comprise the compiler C-local `rt_waiter`, whether another syscall has overlapping live objects, or a working privilege-escalation primitive.

The new `compiledSpFrameInventory` field in `tools/y2q_hxl1_waiter_argument_lifetime_audit.py` implements this original machine-code census, and the existing WSL runner prints the SP writer and frame results. Seven fail-closed tests were added to `tools/test_y2q_hxl1_waiter_argument_lifetime_audit.py`, raising the suite from 12 to **19 written tests**. The original full archive was independently rechecked and passed this census locally; **the new 19-test suite has not yet been confirmed passing on the owner's WSL host or GitHub CI**. The detailed independently generated JSON is stored as `hxl1-original-dofutex-sp-frame-census-20261014.json`, SHA-256 `ecc56228da824198da07c0bbb96597a2c407169db0b8807b6ecdb55ce6989560`, and its [versioned research summary](../research/y2q-G986U1UESCHXL1/ghostlock-dofutex-sp-frame-census-20261014.json) is committed.

Single owner verification (no new firmware extraction or device operations):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

This remains a source and compiled-frame consistency result, not a validated GhostLock exploit, temporary root, KernelSU payload, or device deployment.

---

# HXL1 GhostLock — original waiter source/compiled argument audit (2026-10-14)

**Read-only research.** Target SM-G986U1, G986U1UESCHXL1, original Linux 4.19.113-27095354. This study used two previously uploaded archives, without phone access, exploit execution, firmware flashing, kernel patching or raw runtime memory.

## What has been newly independently verified

The original source-dispatch archive SHA-256 is `deac172780286aeca1d3b1d9ab7f036e84532a6d087cc89721fd5cc7d16fe1a3` (`kernel/futex.c` SHA-256 `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`). The original compiled-disassembly archive SHA-256 is `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997` (`do_futex.disasm.txt` SHA-256 `56286516ae9e6a873beab22b16af3ab330a768dc1b02f901854eb96f193789a5`). All **1,766 original `do_futex` instruction addresses** were parsed contiguously; exact machine words, operands and static call destinations of 10 relevant instructions were checked.

Three original branch-with-link callsites each have a nearby, straight-line construction of the **same literal expression `sp + 0xc0`** in the AArch64 argument register appropriate for that callee:

| Source / machine role | Relative `do_futex` callsite | Stack-derived argument | Previously recovered label |
|---|---|---|---|
| Initialize waiter | `+0x1198` | `x0 = sp + 0xc0` | `rt_mutex_init_waiter` |
| Proxy wait | `+0x1308` | `x2 = sp + 0xc0` | `rt_mutex_wait_proxy_lock` |
| Conditional proxy cleanup | `+0x1328` | `x1 = sp + 0xc0` | `rt_mutex_cleanup_proxy_lock` |

The source archive independently confirms **12 ordered landmarks** in `futex_wait_requeue_pi`:

`rt_waiter` local declaration (line 3238), explicit stack-allocation comment (3264), `rt_mutex_init_waiter(&rt_waiter)` (3267), `q.rt_waiter = &rt_waiter` (3274), futex-wait setup (3281), futex-wait queueing (3296), `!q.rt_waiter` branch (3314), proxy wait (3343), **conditional** proxy cleanup (3346), debug waiter release (3349), unqueue (3373), and `return ret` (3402).

**What this means:** Source and original machine code independently agree that a stack-derived address is prepared for waiter initialization, waiting, and conditional cleanup. These observations are stronger than relying on adjacent disassembly instructions or K40-derived offsets. The source queue pointer statement is confirmed in C but has not been fully attributed to an original compiler-generated object field.

**What this does not mean:** The three locations are separate static sites in possibly distinct control-flow paths. Equality of the *expression* `sp + 0xc0` is not yet a path-sensitive proof that their effective runtime pointer values match. Nor does it prove exact compiler C-local object identity, byte size, lifetime across suspension, cross-syscall stack reuse, or usable GhostLock privilege escalation.

The original recovered `vmlinux-stock.nm` was not mounted in this local container, so original callee *labels* here are inherited from the earlier owner NM lookups rather than independently rehashed in this new execution. The WSL tool accepts `--nm` to require the pinned original SHA-256 `c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f` and exact address-to-label agreement. The complete original kernel Image was not rehashed again.

## New offline automation

- `tools/y2q_hxl1_waiter_argument_lifetime_audit.py` verifies source and disassembly archive byte hashes and member hashes, 12 source markers, 1,766 contiguous original instruction rows, and exact instruction words for the three straight-line argument/call sequences. Optional `--nm` independent source-label checks; no device writes.
- `tools/test_y2q_hxl1_waiter_argument_lifetime_audit.py`: 12 local tests **passed**, covering instruction word/operand drift, overwrites between argument formation and call, missing queue assignment, falsely unconditional cleanup, repeated initialization, source/archive hash mismatch, and standalone CLI.
- `tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh`: one-command owner WSL runner; searches a bounded set of already existing artifact paths for the exact archived hashes and includes the original NM when found.
- `.github/workflows/hxl1-ghostlock-stack-gate-ci.yml` includes syntax and offline tests. **Owner WSL / hosted CI execution of the newly committed code remains pending.**

Run after pulling the research branch:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh
```

If the original archives were moved outside the standard bounded research directories, set `HXL1_SOURCE_ARCHIVE` and `HXL1_DISASSEMBLY_ARCHIVE` to the already-saved file paths. Do not replace old evidence with freshly generated substitutes merely to obtain a passing result.

The exact local output, `owner-archive-waiter-argument-lifetime-audit.json`, has SHA-256 `e9d5aae22e7a6b35cb11fc9a1b240948112f75c553fe972b6b9022646f20cbcc`. Its concise GitHub ledger is `research/y2q-G986U1UESCHXL1/ghostlock-waiter-three-argument-sites-20261014.json`.

**Porting readiness is unchanged:** stages 1–2 complete, stage 3 partial, stages 4–6 open, stages 7–8 blocked, stage 9 deferred. No proven overlap, temporary root, physical kernel handoff, KernelSU or production profile.
