## October 14, 19:06 UTC — owner original scan: first DTB global writer candidate FOUND

The owner supplied `hxl1-linuxloader-index-global-refs-20261014.json`, independently SHA-256 verified in this review as `3c1d00c0dc5353902a05e5b377b9b6b6dd304f9820678287e750e38741ee3a4c`. Its normal scan already checked **978,944 bytes** of executable `.text` in an original LinuxLoader PE authenticated on the owner's host against SHA-256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`. It also reconciled the original byte windows for both getter functions. No further broad PE scan or timed-out REA call is appropriate.

**New original-scan result:** three direct reference candidates to the two getter fields. The **DTBO index** (`0x32a4cc`) has one verified direct read at `0x23b18` and **no match for a direct scalar write in this scan**. The **DTB index** (`0x32a4d0`) has one direct read at `0x23b58` and **one 4-byte write candidate**: `0x250e8: ADRP x9` → `0x250f0: 0xb904d128 (STR W8, [X9,#0x4d0])`. The selected store sources **W8**, not a literal; its producer, reaching definition and conditional branch predicates are **not yet demonstrated**. Lack of a directly matched DTBO write does **not** exclude initialization from data or indirect/aliased stores. The corresponding [new owner evidence checkpoint](../research/y2q-G986U1UESCHXL1/stage4-hxl1-original-direct-dtb-writer-20261014.json) preserves this exact observation without promoting it to a boot-time selected DTB.

**Implemented new nonduplicative follow-up:** the existing [index-global scanner](../tools/y2q_hxl1_linuxloader_index_global_refs.py) now also accepts `--existing-refs`. In that mode it consumes the owner's **already-generated report** and the same original LinuxLoader EFI; checks loader SHA, PE section, reported summary counts, each original ADRP/access machine word and intervening base-register overwrite/branch; then emits a single bounded raw-word window around any already recorded direct writers. It does **not** scan the `.text` for all possible references again. Seventeen focused synthetic regressions, including changed-word, clobber, hash/summary contradiction and genuine writer-register detection, **passed in [GitHub Actions 38621737278](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38621737278)**.

**Only still-missing Stage 4 input from the owner (one command; no Ghidra or repeated scanning):**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m tools.y2q_hxl1_linuxloader_index_global_refs \
  --loader "$HOME/s20-artifacts/hxl1-research/abl-linuxloader/LinuxLoader-HXL1.efi" \
  --existing-refs "$HOME/s20-artifacts/hxl1-research/hxl1-linuxloader-index-global-refs-20261014.json" \
  --output "$HOME/s20-artifacts/hxl1-research/hxl1-linuxloader-dtb-writer-context-20261014.json"
```

Preserve an already-existing valid context report instead of rerunning. The resulting packet contains original instruction words and transfer targets around `0x250f0`, sufficient to start a **new** register-origin review without reaccessing the owner's stock EFI. There is still no actual DTB/DTBO value, chosen blob, physical Linux load/handoff proof, bootloader unlock, root or KernelSU.

---

## October 14, 19:00 UTC — correctness fix before original owner scan (12 CI tests PASS)

The preexisting `scan_words()` matched `ADRP xN, page` and a subsequent scalar `STR/LDR [xN,#imm]` within 28 instructions, but did not reject common **intervening assignments to the tracked xN register**. It could therefore report a false global writer after `mov xN, xM`, `ldr xN, [...]` or a pair-load to `xN`. This is a true false-positive problem for the currently unanswered Stage 4 *writer-provenance* question, not a new ABI or security finding.

**Fixed in-place:** `tools/y2q_hxl1_linuxloader_index_global_refs.py` now stops the candidate scan on recognized page-base overwrites (ADR/ADRP, immediate arithmetic, wide moves, common register ALU operations, scalar loads and both LDP destinations). A `STR` that merely uses xN as its *value* does **not** invalidate xN. Existing exact original DTB and DTBO getter reads are retained. No new PE/file extraction or REA request is performed.

**Verification:** 12/12 focused synthetic regression tests passed in [GitHub Actions run 38619750462](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38619750462), including five new clobber/non-clobber cases. This still recognizes only bounded direct scalar references, **not** general pointer aliases, register provenance across calls, pointer-copy chains or actual global initializers. `sameBasicBlockProven` remains false because the control decoder is not a full CFG engine. **No factory original-PE writer counts were obtained in this chat.**

**One current owner-side data gap, unchanged:** the original full-PE scan described below. Run it only if the retained `hxl1-linuxloader-index-global-refs-20261014.json` has not already been produced; preserve any existing valid report rather than rerunning blindly. Candidate writers are not authenticated producers until their dataflow and selection implications are confirmed. Stage 4 remains OPEN, no root/KernelSU or deployable profile claimed.

---

# HXL1 Stage 4 — two index-global writers, bounded direct-reference follow-up (2026-10-14)

**Project:** exact HXL1 `Root-My-Galaxy` firmware-to-profile research. No bootloader modifications, root operation, kernel patches, module load or OEM loader flashing were performed.

## Input evidence and finding

The owner uploaded:
- `callsite-evidence.json`: the cached original LinuxLoader formatter's `DTBO` and `DTB` getter calls, recorded at analysis coordinates `0x23b00` and `0x23b40`.
- The provider's two `.exitcode.txt` files, **both 124** (host-side deadline exceeded).
- The two `.partial.json` reports, **both** `cancelled`, `operation=analyze_function`, `cleanup=complete`. Neither is a successful Ghidra function analysis.
- The later `getter-raw-native-windows-20261014T181835Z.json`, derived from original PE-file candidate RVAs and bearing the expected HXL1 LinuxLoader SHA-256 **claim**.

Previously merged [raw getter decoder](../tools/y2q_hxl1_linuxloader_raw_getter_globals.py) and [original native report](../research/y2q-G986U1UESCHXL1/stage4-linuxloader-raw-getter-globals-20261014.json) show the **candidate** DTBO getter reads a 32-bit global at RVA `0x32a4cc`, while DTB reads a second 32-bit global at RVA `0x32a4d0`. They share a saved/checkword at RVA `0x32a4b8`. The candidate wrappers **read preexisting globals** and contain no observed index-selection algorithm. The next real question is who writes those globals.

The raw window output does **not** independently rehash the owner EFI in this conversation, establish that Ghidra analysis address == PE RVA, prove which runtime values were selected, or identify the actual active FDT.

## Implemented follow-up — one exact-hash local EFI pass

[Original global references scanner](../tools/y2q_hxl1_linuxloader_index_global_refs.py) scans the single original `.text` section for bounded `ADRP` and unsigned-offset `LDR/STR` byte, halfword, word and dword operations targeting the two **exact** 32-bit index global RVAs. It:

1. Requires the exact original LinuxLoader SHA-256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003` and validates the PE32+/ARM64 section headers.
2. Reinterprets the supplied raw getter code windows using the existing verifier and **byte-for-byte compares every supplied original instruction** with the authenticated EFI. Any mismatch stops.
3. Enumerates only **direct, bounded, same-register scalar memory-access candidates** and labels each as a *potential* reader or writer. It does not claim dataflow completeness, simultaneous path predicates or Ghidra-to-PE address equality.
4. Writes a fresh, read-only JSON report, without REA, Ghidra, protected ADB reads or device writes.

**Tests:** 7 focused synthetic tests passed locally; [isolated GitHub CI passed](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38617831654). The target EFI file itself was not accessible in this chat and the owner has not yet run the new full-PE scanner, so no original direct-writer counts are claimed.

One bounded owner WSL invocation, only when pursuing the still-missing index-global writer origin:

```bash
cd ~/src/Root-My-Galaxy-Payloads && git pull --ff-only
RAW="$(find "$HOME/s20-artifacts/hxl1-research" -type f -name 'getter-raw-native-windows-*.json' -print -quit)"
test -n "$RAW" && test -f "$RAW"
python3 -m tools.y2q_hxl1_linuxloader_index_global_refs \
  --loader "$HOME/s20-artifacts/hxl1-research/abl-linuxloader/LinuxLoader-HXL1.efi" \
  --raw-windows "$RAW" \
  --output "$HOME/s20-artifacts/hxl1-research/hxl1-linuxloader-index-global-refs-20261014.json"
```

The generated JSON is sufficient to review those candidate writers **without another full loader analysis or provider request**. A zero direct-match result is **not proof** that a global has no writers: register aliasing, indirect calls, stores through pointers, literal pools, atomic/pair accesses and initialization through firmware data may escape this narrow scan.

## Readiness

Existing stage 4 is **OPEN** pending bootloader-selected original DTB/DTBO and physical handoff evidence. The owners' live boot properties `ro.boot.dtb_idx=0` / `ro.boot.dtbo_idx=2` remain **observed properties**, not evidence that those numbers index the stored four FDT candidates in a particular order. No root or KernelSU claim follows.
