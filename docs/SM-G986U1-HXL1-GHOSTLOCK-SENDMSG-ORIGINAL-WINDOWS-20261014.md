## Preferred one-command runner

The more concise and safer default is now the committed script tools/run_y2q_hxl1_ghostlock_sendmsg_frame_attest.sh. It runs the 15 regressions, finds the unique one-level research-output manifest with SHA-256 8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8, invokes the full byte-level original kernel and disassembly verifier, and prints an abbreviated static-frame result:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_ghostlock_sendmsg_frame_attest.sh

This does not launch ADB, REA, GhostLock, QEMU, firmware extraction, payload assembly, or KernelSU. It requires the six original saved .bin and .disasm.txt siblings, the exact original kernel.bin and recovered nm. If the original owner report or saved binary files are not present, it fails closed; no substitute is generated. The new suite and owner code verification remain pending external execution.

---

# HXL1 GhostLock — original sendmsg code windows (2026-10-14)

Research-only follow-up to the user-uploaded original-sendmsg-windows.json. The uploaded 6416-byte JSON has SHA-256 8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8. **Only the report JSON was supplied, not the six saved code slices or their disassembly text.** The owner-run report claims exact kernel.bin SHA verification, but the underlying kernel bytes were not independently submitted in this turn.

Original Image SHA-256: ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123.
Original recovered nm SHA-256: c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f.
Static Image text origin: 0xffffff8008080000. Of eight requested symbols, **six original-code windows were saved and none was truncated**.

| Recovered original text label | Static Image address | Original code bytes |
| --- | --- | ---: |
| __sys_sendmsg | 0xffffff800966f1b4 | 240 |
| ___sys_sendmsg | 0xffffff800966f2a4 | 728 |
| ____sys_sendmsg | NOT_FOUND_IN_RECOVERED_NM | — |
| __sys_sendto | 0xffffff800966ea64 | 408 |
| __sys_sendmmsg | 0xffffff800966f66c | 664 |
| rw_copy_check_uvector | 0xffffff80082db784 | 536 |
| copy_msghdr_from_user | 0xffffff800967357c | 408 |
| futex_wait_requeue_pi | NOT_FOUND_IN_RECOVERED_NM | — |

Missing recovered symbol names do not prove compilation absence or source inlining. Adjacent original text-symbol addresses do not establish stack-variable adjacency, and a saved disassembly file's SHA does not establish its machine words without rechecking the actual file. Exact source-local placement, waiter lifetime, cross-syscall alias, vulnerable primitive and root remain unverified.

## Newly committed verifier

tools/y2q_hxl1_ghostlock_sendmsg_frame_attest.py rehashes original kernel.bin and recovered nm, validates every saved binary window against the original kernel at its reported relative offset, verifies every saved disassembly digest, and decodes each native instruction slot against its original Image machine word. It then reuses the existing static AArch64 frame-footprint helper for literal SP adjustments only; no compiler C-local identities or runtime aliasing are certified.

tools/test_y2q_hxl1_ghostlock_sendmsg_frame_attest.py contains 15 synthetic cases (original byte matching, altered code and disassembly, reordered symbols, absent symbols, forged runtime claims, standalone entrypoint). Both were added to .github/workflows/hxl1-ghostlock-stack-gate-ci.yml. These new tests and the original-kernel auditor **have not yet been observed running successfully on the owner's WSL host or GitHub CI**.

## One-shot owner execution on the original saved artifacts

Run from the existing research checkout. The short lookup searches only one directory level for a report whose SHA-256 equals the exact uploaded JSON. It will not rerun firmware extraction, target generation, ADB or REA.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_sendmsg_frame_attest

    EVIDENCE="$HOME/s20-artifacts/hxl1-research"
    REPORT="$(python3 - "$EVIDENCE" <<'PY'
    from pathlib import Path
    import hashlib,sys
    root=Path(sys.argv[1])
    expected="8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8"
    matches=[]
    for path in root.glob("ghostlock-original-sendmsg-*/original-sendmsg-windows.json"):
        if path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==expected:
            matches.append(path)
    if len(matches)!=1:
        raise SystemExit("Expected exactly one original matching manifest, found "+str(len(matches)))
    print(matches[0])
    PY
    )" || exit $?

    OUT="$EVIDENCE/ghostlock-frame-attest-$(date -u +%Y%m%dT%H%M%SZ).json"
    python3 -m tools.y2q_hxl1_ghostlock_sendmsg_frame_attest \
      --report "$REPORT" \
      --kernel "$HOME/s20-artifacts/kernel.bin" \
      --nm "$EVIDENCE/vmlinux-stock.nm" \
      --output "$OUT" && cat "$OUT"

The tool expects the six .bin and six .disasm.txt files adjacent to the original owner report; if they are missing it correctly stops. Never replace them with other firmware disassembly just to get a passing result.

Full machine-readable checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-original-sendmsg-owner-result-20261014.json. Readiness unchanged: Stage 3 PARTIAL, Stage 5 OPEN, Stage 7 KernelSU BLOCKED; no root or production target.
