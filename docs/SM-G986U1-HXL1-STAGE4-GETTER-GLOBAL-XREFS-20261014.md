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
