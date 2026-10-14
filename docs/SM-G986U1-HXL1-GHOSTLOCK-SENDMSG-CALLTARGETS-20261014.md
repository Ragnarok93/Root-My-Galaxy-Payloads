# HXL1 GhostLock — 41 original sendmsg calls, 21 static destinations (2026-10-14)

Research-only. No exploit build, ADB, root attempt, kernel flashing or KernelSU loading.

## Accepted owner output

On branch feature/s20plus-investigation-shizuku-20261009 at b2b567e, the owner ran tools.test_y2q_hxl1_ghostlock_sendmsg_callsite_audit with **13/13 PASS**. The subsequent offline callsite audit on already-saved HXL1 code windows reported 746 original ARM64 instruction slots verified, **41 direct branch-with-link calls**, zero BLR indirect calls in these six windows, and **21 distinct static branch targets**.

The user's uploaded content was a full console paste with embedded JSON, SHA-256 ea9d18bea3ef841300dd9e3173004fc91d374ff6828eccaf16f573c960ddbdae, 31,798 bytes. This hash is for the console paste, **not the original standalone JSON at** /home/main/s20-artifacts/hxl1-research/ghostlock-sendmsg-calls-20261014T075055Z.json. That standalone file was not separately uploaded and independently rehashed here. Its embedded JSON pins previously checked original Image, NM, original window manifest and frame-report hashes.

| Original function | Static BL callsites | Calls with SP construction in preceding 12 slots |
| --- | ---: | ---: |
| __sys_sendmsg | 4 | 3 |
| ___sys_sendmsg | 15 | 6 |
| __sys_sendto | 7 | 6 |
| __sys_sendmmsg | 6 | 1 |
| rw_copy_check_uvector | 4 | 0 |
| copy_msghdr_from_user | 5 | 3 |
| **Total** | **41** | **19** |

Two other requested names remain missing from recovered NM, with no proof they were absent from the compiled original kernel: ____sys_sendmsg and futex_wait_requeue_pi.

Four original static branch destinations directly link known recovered entry labels:
- __sys_sendmsg -> ___sys_sendmsg (call at 0xffffff800966f248)
- __sys_sendmmsg -> ___sys_sendmsg (calls at 0xffffff800966f750 and 0xffffff800966f7d4)
- ___sys_sendmsg -> copy_msghdr_from_user (call at 0xffffff800966f304)

The prior callsite script marked 40/41 callsite windows as having an intervening branch **or another call**. This is a conservative syntactic flag, not proof that 40 distinct runtime paths diverge. Most 12-instruction proximity windows contain other control transfers; the 19 SP-construction proximities are therefore not an argument-register def/use proof.

## Next offline investigation: symbolize only the 21 distinct destinations

New tools/y2q_hxl1_ghostlock_call_target_crosswalk.py:
1. Validates the already-written callsite result against HXL1 image/NM/prior frame digest pins, six known per-function call counts, the 41/21/19 totals and four specific previously verified original internal edges.
2. Independently rehashes the exact owner's recovered vmlinux-stock.nm (SHA-256 c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f).
3. Finds *exact recovered text-label* matches for each of 21 branch targets. If a target lies between two text labels, reports only an **UNVERIFIED interior interval**, not a callee identity. No in-memory address/KASLR assumption.
4. Groups repeated call destinations so subsequent static research can focus on a small number of actual recovered kernel functions.
5. Never treats an exact recovered label, textual SP proximity or the branch target's VA as proof of C source local variables, waiter lifespan, stack overlap, runtime memory addresses or a working GhostLock exploit.

Twelve fail-closed tests cover changes to hard-pinned evidence counts, false pointer-flow claims, changed/missing known edges, missing symbols, exact aliases, interior addresses, NM digest drift and direct CLI imports. The added tests are included in .github/workflows/hxl1-ghostlock-stack-gate-ci.yml; full owner/CI execution of these new tests has **not yet been confirmed**.

### Single owner-side WSL run, using the same saved reports

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_call_target_crosswalk

    EVIDENCE="$HOME/s20-artifacts/hxl1-research"
    OUT="$EVIDENCE/ghostlock-call-targets-$(date -u +%Y%m%dT%H%M%SZ).json"
    python3 -m tools.y2q_hxl1_ghostlock_call_target_crosswalk \
      --report "$EVIDENCE/ghostlock-sendmsg-calls-20261014T075055Z.json" \
      --nm "$EVIDENCE/vmlinux-stock.nm" \
      --output "$OUT"

    python3 - "$OUT" <<'PY'
    import json,sys
    d=json.load(open(sys.argv[1]))
    print("Callsites:",d["callsites"],"unique:",d["uniqueDestinations"])
    for t in d["directTargets"]:
        print(t["targetStaticVA"],"x"+str(t["totalIncomingCalls"]),
              t["status"],t.get("labels",t.get("lowerLabels",[])))
    print("Waiter reuse proved:",d["sendmsgFutexWaiterLifetimeOverlapVerified"])
    PY

The tool requires no raw firmware scan, new original disassembly, online REA query, device access or code compilation. It stops if the original NM hash is different or if the owner report does not preserve the already-observed callsites, counts and negative runtime findings.

**Readiness:** Stage 3 partial. Stage 5 open. Stage 7 blocked. No rt_mutex_waiter-to-sendmsg alias, original compiled waiter C-local, reliable runtime corruption primitive, KASLR proof, root, KernelSU or release profile confirmed.

Machine-readable checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-sendmsg-41-calls-owner-20261014.json.
