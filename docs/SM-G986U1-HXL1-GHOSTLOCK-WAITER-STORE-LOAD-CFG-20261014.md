# SM-G986U1 HXL1 GhostLock — original waiter-pointer store/load CFG (2026-10-14)

**Offline static original Samsung source and binary study; NOT a root/exploit test.**

## Owner report and provenance

The owner-uploaded hxl1-waiter-source-compiled-20261014T110728979320740Z.json is 6461 bytes with SHA-256 440c7fa2426b5e620eb6b28c1d7ad1ac20057767a4e6b0b56f8574f8d2407da3. Its read-only tool reports 12 source landmarks, three original compiled waiter-helper arguments, independent recovered-NM rehash, the 480-byte do_futex frame with exactly two SP writes among 158 SP references, and a conditional x25 pointer store. The report does not include 25-test console output; do not infer the 25-test suite passed on owner WSL or hosted CI.

Both original archives were independently rehashed and inspected:
- Source-dispatch archive SHA-256 deac172780286aeca1d3b1d9ab7f036e84532a6d087cc89721fd5cc7d16fe1a3; internal kernel/futex.c SHA-256 493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5.
- Disassembly archive SHA-256 20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997; internal do_futex.disasm.txt SHA-256 56286516ae9e6a873beab22b16af3ab330a768dc1b02f901854eb96f193789a5.

## New observed original instruction relationships

| Relative original do_futex PC | Original instruction | Evidence meaning |
| --- | --- | --- |
| +0x1194 | add x25, sp, #0xc0 | Stack-derived waiter candidate |
| +0x11d0 | stp x25, x27, [sp, #160] | First pointer stored at SP+0xa0 |
| +0x12ec | ldp x8, x9, [sp, #152] | Second register x9 loaded from the exact same SP+0xa0 slot |
| +0x12f0 | cbz x9, ... | Null-test of reloaded value |
| +0x12f4 | cbz x8, ... | Separate test of adjacent pointer |
| +0x12fc | add x2, sp, #0xc0 | Stack-derived proxy-wait argument |
| +0x1308 | bl rt_mutex_wait_proxy_lock | Direct original callee |
| +0x1320 | add x1, sp, #0xc0 | Stack-derived cleanup argument |
| +0x1328 | bl rt_mutex_cleanup_proxy_lock | Conditional direct original callee |

The bounded original machine-code CFG contains a 31-instruction static path from the store (+0x11d0) to load (+0x12ec), with conditional branch sites at +0x11dc, +0x1230, +0x12c0, +0x12d0 and +0x12e0. This is a **conservative static path**, not proof the branch predicates are jointly feasible or that the same runtime pointer stays live. Indirect memory aliasing is not fully analyzed.

Source kernel/futex.c has a struct futex_q declaration at line 244, a __randomize_layout annotation at 254, the assignment q.rt_waiter = &rt_waiter at 3274, and if (!q.rt_waiter) at 3314. The assembly's slot store, slot reload, and x9 null-test give stronger source/machine consistency for **candidate q.rt_waiter mapping**. The source annotation alone does NOT prove layout randomization was enabled for the OEM build; OEM compiler-exact field layout and original local object bounds have not been certified. The C field mapping must remain CANDIDATE_CORROBORATED_NOT_FACTORY_LAYOUT_CERTIFIED, not a proven factory offset.

## Automated work and verification

- New tool: tools/y2q_hxl1_waiter_store_load_cfg.py. Rehashes original archive and member bytes, validates 1766 contiguous native instruction slots and 11 precise original machine-word/operand fingerprints, checks six source anchors, and finds only bounded conservative static graph paths.
- New synthetic regression module: tools/test_y2q_hxl1_waiter_store_load_cfg.py (15 tests written; a locally developed equivalent suite ran 15/15 successfully). The committed module's owner/CI result is not yet observed.
- Both modules added to the existing HXL1 GhostLock CI workflow.
- Existing runner tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh now invokes both previous argument/frame and new store/load audits. Reuses original SHA-matched evidence; never reruns firmware extraction, ADB, QEMU, exploitation, or KernelSU.

Owner one-command verification:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh

Independently generated local proof artifact: owner-hxl1-waiter-store-load-static-cfg-20261014.json, SHA-256 2cd5d67c9e41cd2d41478535271612e0a95092cbd051a1ad5e770a0ed4491325.
Versioned GitHub research checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-owner-waiter-store-load-cfg-20261014.json.

**No readiness promotion.** Compiler-exact futex_q field layout and aliasing, path-sensitive waiter lifetime, cross-syscall reuse, GhostLock exploitability, temporary root, and KernelSU remain UNVERIFIED. Stages 1–2 complete, 3 partial, 4–6 open, 7–8 blocked, 9 deferred.
