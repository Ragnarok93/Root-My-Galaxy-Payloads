# HXL1: confirmed 47/47 waiter audit tests and four-call NM crosswalk (2026-10-14)

Read-only stock-kernel analysis. Target Samsung SM-G986U1, HXL1. No exploit, kernel patch, device operation, root, KernelSU, or bootloader modification.

## Verified owner run

The WSL transcript (uploaded as Pasted text(20261014-113812).txt) was independently hashed SHA-256 15acc86b1565e7812d8c1898e9ffd0d9342d7cef014eb8b3c40a875655868b06. It reports a successful git fast-forward through ac4cd4a and **47/47 passing tests** in three independently executed suites:

| Suite | Tests passed |
| --- | ---: |
| tools.test_y2q_hxl1_waiter_argument_lifetime_audit | 25/25 |
| tools.test_y2q_hxl1_waiter_store_load_cfg | 15/15 |
| tools.test_y2q_hxl1_waiter_store_load_witness | 7/7 |

All three owner-run original static audits completed without error, with newly generated output reports retained on WSL:
- hxl1-waiter-source-compiled-20261014T113759004974450Z.json
- hxl1-waiter-store-load-cfg-20261014T113759435482789Z.json
- hxl1-waiter-store-load-witness-20261014T113759545161808Z.json

**The standalone JSON files from this specific 11:37 run were not individually uploaded or separately rehashed here;** the timestamped WSL paths are reported paths, not container files. The owner transcript reports independent original recovered-NM rehash.

Stock original evidence confirmed: 12 source lifetime landmarks; 3 original compiled waiter-helper argument sites; 1,766 original do_futex instructions; 480-byte frame; exactly two explicit SP writes among 158 SP-referencing instructions; conditional store of the x25-carried stack-derived pointer at SP+0xa0; later load into x9 from that same slot and an x9 null check; 31-instruction conservative static path with **five branch decisions, four direct calls and one explicit store**. None demonstrates path-predicate feasibility, complete interprocedural memory effects, factory q.rt_waiter field offset, cross-syscall frame reuse, a live GhostLock primitive, root or KernelSU.

## New automated next evidence

Instead of requesting a new kernel extraction or more raw disassembly, the already-existing tools/y2q_hxl1_waiter_store_load_witness.py has been extended with an optional **original recovered-NM digest-pinned four-call crosswalk**. The owner runner now passes its previously validated vmlinux-stock.nm file to the witness, and the tool reports exact labels or explicitly uncertain interior bounds for these four existing original callsites:

| do_futex relative callsite | Original direct branch destination |
| --- | --- |
| +0x11d4 | 0xffffff80081929ac |
| +0x12a4 | 0xffffff8008192f44 |
| +0x12b0 | 0xffffff800996d544 |
| +0x12e8 | 0xffffff800996d774 |

The original NM must match SHA-256 c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f. The tool uses the existing read-only recovered text-symbol resolver and **does not equate a recovered symbol with known memory side effects or original C-object identity**. Indirect trampoline targets, when present, remain unverified; even an exact callee label does not certify memory safety.

Six new regression cases added to tools/test_y2q_hxl1_waiter_store_load_witness.py, now **13 written cases** for that module. All of the new tests are CI-wired via the existing GhostLock workflow; **execution of the added 6 cases has not yet been confirmed**. The previous **7/7** for this module remain confirmed by owner transcript.

Run just the existing read-only one-command pipeline on WSL; it handles all suites, the two SHA-pinned original archives, the recovered NM, and a new independently timestamped report:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_waiter_argument_lifetime_audit.sh

**Current porting readiness unchanged:** COMPLETE, COMPLETE, PARTIAL, OPEN, OPEN, OPEN, BLOCKED, BLOCKED, DEFERRED. Next significant question is what the **four effective callees can do to the watched memory**; simple static label matches alone cannot resolve that.

Versioned owner transcript checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-owner-waiter-47-tests-20261014T1138.json.
