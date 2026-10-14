# HXL1 GhostLock: factory ARM64 sendmsg frame evidence (2026-10-14)

**Read-only source/runtime research checkpoint; no root or KernelSU validation.**

The owner supplied ghostlock-sendmsg-frame-20261014T071250203042958Z.json. The exact uploaded JSON (12,462 bytes) was independently SHA-256 hashed as a0426c036e614611c368338c9f80e298f13b23bc238e1b3dc67aa1a3c20dcc10.

The owner-side audit reports original stock kernel Image SHA-256 ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123 verified and original Nm SHA-256 c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f. It validated all saved .bin and .disasm.txt pairs, including every instruction word against original Image bytes. Only the JSON, not the actual ELF/Image/disassembly, was uploaded in this turn.

## Six original-image static frames

| Recovered function | Instruction slots | Literal stack entry | SP-relative constructions |
| --- | ---: | ---: | ---: |
| __sys_sendmsg | 60 | 144 bytes | 2 |
| ___sys_sendmsg | 182 | 400 bytes | 8 |
| __sys_sendto | 102 | 320 bytes | 7 |
| __sys_sendmmsg | 166 | 352 bytes | 3 |
| rw_copy_check_uvector | 134 | 80 bytes | 1 |
| copy_msghdr_from_user | 102 | 112 bytes | 3 |

**746 original machine instruction slots attested.** Each function shows a literal SP allocation and a matching restoration. The prior parser deliberately marks allRuntimePathsCertified=false and sourceLocalVariablesIdentified=false. Neither all-path frame balance nor the lifetime of any C-local object has been proven.

The original ___sys_sendmsg 400-byte entry frame contains SP-relative constructions at +0x8, +0x10 and +0x38 (some repeated). These are raw instruction operands, NOT authenticated C-local variable offsets. Do not call them the K40 iovstack or a freed futex waiter merely because a similar size appears on another 4.19 device.

The names ____sys_sendmsg and futex_wait_requeue_pi were not found in recovered kallsyms. That does not prove the functions were not emitted or that inlining occurred.

## Next automated gate: verified static callsite inventory

The new tools/y2q_hxl1_ghostlock_sendmsg_callsite_audit.py locates the exact owner frame report and previously accepted original window manifest by SHA-256, then rechecks the cached original .bin and .disasm.txt files and all six reported static frame summaries. It inventories BL/BLR call instructions and preceding syntactic SP-relative instructions in at most 12 adjacent instruction slots. Presence of an intervening branch/call is flagged.

The result labels proximity as **TEXTUAL ONLY**, never a pointer-def/use proof, source object identity, syscall stack reuse, stable blocking-carrier lifetime or exploit primitive. It requires an exact count of 746 verified slots and remains research-only.

The added 13 test cases and CI integration are committed, but owner/CI execution of the new script has not yet been independently confirmed.

### One-shot WSL verification; no new kernel extraction or ADB

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_sendmsg_callsite_audit

    EVIDENCE="$HOME/s20-artifacts/hxl1-research"
    OUT="$EVIDENCE/ghostlock-sendmsg-calls-$(date -u +%Y%m%dT%H%M%SZ).json"
    python3 -m tools.y2q_hxl1_ghostlock_sendmsg_callsite_audit \
      --evidence-dir "$EVIDENCE" \
      --output "$OUT"
    cat "$OUT"

If the saved original report, .bin files or disassemblies have been moved or altered, the tool fails instead of repeating the original Image extraction or generating substitute evidence.

**Gates unchanged:** actual waiter compiler-local layout, kernel lifetime/overlap, runtime GhostLock primitive, physical load/KASLR, root, signed kernel module loading and KernelSU remain unverified. Current readiness still has Stages 1–2 complete, Stage 3 partial, Stages 4–6 open, Stages 7–8 blocked, Stage 9 deferred.

Accepted raw report checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-original-sendmsg-frame-owner-20261014.json.
