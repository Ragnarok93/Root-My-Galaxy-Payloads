# HXL1 WSL OEM debug inventory — result and scanner correction (2026-10-14)

## Observed owner output

Input: `oem-debug-inventory-20261014T031620Z.json`, scanning `/home/main/s20-artifacts` and `/home/main/src`. The scan recorded **40,000 files examined**, **43 filename candidates**, **truncated=true**, and these legacy classifications: 12 non-AArch64/non-ELF, 3 reconstructed stock artifacts, 18 with no apparent debug metadata, and 10 QEMU/comparison artifacts.

**No verified OEM debug-symbol ELF was identified in the scanned portion. This is explicitly not an exhaustive negative result.** The only two listed `.debug_info`-bearing kernel ELFs are the already-known QEMU normal and QEMU KASAN `vmlinux` comparison builds. The three reconstructed stock artifacts supply recovered code or symbol text but no factory DWARF.

The final candidate entries are ordinary files in `/home/main/src/linux-4.19.325/arch/` (e.g., `Kconfig.debug`, `vmlinux.lds.S`), exposing a **depth-first budget-exhaustion problem**: the original `os.walk` visits an alphabetically early, very large source subtree before sibling source/build roots. Such source names also generated non-ELF false candidates. `xbl.elf` has an unreadable ELF section table and therefore cannot be labeled confidently `NO_DEBUG_METADATA` from section-table inspection alone.

## Corrected read-only discovery script (v2)

`tools/y2q_hxl1_oem_debug_discovery.py` now:
1. Visits directories **breadth-first across all requested roots**, giving sibling working/build directories a chance before deep source-tree contents;
2. Ignores obvious source/linker names such as `Kconfig.debug`, `vmlinux.lds.S`, `System.map`, `kallsyms`, and counts matched-but-non-ELF filenames separately;
3. Reports ELF64 AArch64 candidates with unavailable section headers as **`UNREADABLE_ELF_SECTION_TABLE_INDETERMINATE`**, not a clean no-debug negative;
4. Reports depth-limited directories, errors, per-root coverage, pending-directory examples at truncation and the configured scan budget;
5. Keeps a fail-closed provenance distinction: no discovered file automatically becomes a verified OEM debug-symbol match.

**Locally verified:** 13/13 synthetic unit tests pass, including four new regression tests for multi-root fairness, deep-tree starvation, source-name noise, and unreadable section tables. Local CLI smoke: 78 files, 11 directories, no truncation. The owner has not yet run this new version on WSL; no new WSL candidate count is claimed.

Run one improved bounded pass:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_oem_debug_discovery
OUT="$HOME/s20-artifacts/hxl1-research/oem-debug-inventory-v2-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 tools/y2q_hxl1_oem_debug_discovery.py \
  --root "$HOME/s20-artifacts" \
  --root "$HOME/src" \
  --max-depth 7 \
  --max-entries 180000 \
  --output "$OUT"
echo "$OUT"
```

Even if `truncated=false`, the user-chosen depth bound and skipped directories constrain coverage; `scopeCompleteAtRequestedDepth` means only the specified depth and non-ignored directories were visited. No running exploit, phone access, module loading, or root/KernelSU success is implied.

## Research gates unchanged

The authentic HXL1 stock `kernel/futex.c`, select-source macro, operation-11 compiled dispatch, and verified disassembly windows remain the best available static evidence. The OEM-matching unstripped `vmlinux`/DWARF needed for **direct** factory local-variable attribution has **not** been authenticated. Cross-syscall runtime object relationships, exploitability, bootloader handoff and KernelSU remain separate unverified gates.
