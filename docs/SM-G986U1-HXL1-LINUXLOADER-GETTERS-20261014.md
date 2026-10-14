# HXL1 Stage 4: two original LinuxLoader index getter callsites (2026-10-14)

## New owner-observed evidence

On the exact SHA-pinned original LinuxLoader-HXL1.efi, the owner successfully ran all 12 cached-audit tests. The original Ghidra function audit completed with result file linuxloader-index-cache-20261014T052820Z.json, shared function FUN_0002bdf8 (static entry 0x2bdf8), 398 decompiled lines, and cached pseudocode SHA256 885c6f0fe59139c559194c6bf962b221bb0e5bbef8dedff501f12473d9adfc09.

The native value tracer remains CANCELLED, and both cached HighFunction p-code reports were tagged truncated. Those are limits on extended def-use, **not** missing formatter pseudocode. The source text around two independently corroborated literals shows the following immediate getter-to-format calls:

| Index output | Getter called in original pseudocode | Getter line | Non--1 guard | Formatter use |
|---|---|---|---|---|
| androidboot.dtbo_idx | FUN_00023b00() | 252 | line 253 | line 254 |
| androidboot.dtb_idx | FUN_00023b40() | 261 | line 262 | line 263 |

Both are inside the branch entered when FUN_000235b0() returns zero. Output is formatted by FUN_0000ddc4, using local buffers and iVar8. Thus the formatter's **immediate index-value providers** are identified, but their internal computations, the actual selected base DTB or overlay, and physical Linux handoff remain **unverified**.

The owner pasted output has SHA256 3b5fd729f1bf7c619821d7f2e8632800dc08704e7682eecb9a408a2cf1d9276b. The checkpoint is research/y2q-G986U1UESCHXL1/stage4-hxl1-dtb-dtbo-getter-callsites-20261014.json.

## Safe automated next steps

First, execute the standalone **no-provider** validator on the already saved owner report. It confirms model/firmware provenance, the original xrefs, exact pseudocode fingerprint, direct getter assignments, non--1 sentinel checks, use of the integer in the formatter, and the cancelled trace status. It explicitly refuses to infer the getters' internal implementation. All results go to a fresh directory outside Git.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_linuxloader_getter_callsites

    BASE="$HOME/s20-artifacts/hxl1-research"
    CACHE="$BASE/linuxloader-index-cache-20261014T052820Z.json"
    OUT="$BASE/linuxloader-getter-callsites-$(date -u +%Y%m%dT%H%M%SZ).json"

    python3 -m tools.y2q_hxl1_linuxloader_getter_callsites \
       --cached-report "$CACHE" --output "$OUT"
    cat "$OUT"

The new regression suite has **11 tests**, with hosted and owner verification still pending. All input hashes and source identities are checked against the exact original HXL1, and static evidence is not interpreted as loaded-kernel RAM.

### Optional next gate: two targeted function dossiers, no large trace

The original LinuxLoader function calls at analysis coordinates 0x23b00 and 0x23b40 are now narrow targets. If REA/Ghidra is available on the owner host and new analysis is justified, the following single guarded runner validates the same cache and original EFI SHA-256, executes **only two independent REA function requests** with per-target timeout, validates successful JSON against exact target/loader identity, and retains failures as .partial.json plus .stderr.txt. It **does not** rerun trace-native-values on FUN_0002bdf8, run QEMU, touch ADB, root the phone, or patch firmware.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash -n tools/run_y2q_hxl1_linuxloader_getter_functions.sh

    HXL1_GETTER_CACHE="$HOME/s20-artifacts/hxl1-research/linuxloader-index-cache-20261014T052820Z.json" \
      bash tools/run_y2q_hxl1_linuxloader_getter_functions.sh

Runner output resides under a new timestamped targeted-dtb-dtbo-getters-* directory; it reports each function separately and preserves errors without overwriting existing artifacts. Runtime timeouts/cancellation are not evidence that a getter does not exist; missing original Ghidra function entry identity is an unresolved static analysis limit, not a reason to invent one.

## Status and stop/go

Original string references and immediate getter callsites now have static provenance. Neither getter's internal logic has yet been independently decoded, so dtb_idx=0 has NOT been mapped to stock FDT candidate 1, and dtbo_idx=2 has NOT been mapped to any overlay. Bootloader-selected effective FDT, physical kernel load and Stage 4 remain OPEN. Stage 3 PARTIAL, Stages 5–6 OPEN, Stages 7–8 BLOCKED, Stage 9 DEFERRED. No KernelSU, root, new privilege or support feed promotion.
