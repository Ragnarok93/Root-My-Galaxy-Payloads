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
