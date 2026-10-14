## October 14 — focused artifact-only scan outcome (supersedes the earlier root-coverage uncertainty)

The owner supplied `oem-debug-artifacts-only-20261014T033146Z.json` (raw uploaded SHA-256 `fc08987fe6a6a3f217e7a5d563ccce962ec0adf29963500a9bec13faeb0f304a`). The independent report review validates the numerical counts and candidate classifications.

| Property | Outcome |
|---|---|
| Root scanned | `/home/main/s20-artifacts` only |
| Traversal | Breadth-first; `maxDepth=7`, `maxEntries=50000` |
| File entries / directories visited | **24,080 / 6,466** |
| Candidate ELF files | **29** |
| Truncated / errors / pending queue | `false` / 0 / 0 |
| `scopeCompleteAtRequestedDepth` | **true** |
| **Directories excluded by depth 7** | **895** |
| Known debug-bearing kernel ELFs | **2; both QEMU comparisons, not factory** |
| Independently authenticated OEM HXL1 `vmlinux` + DWARF | **none** |

Reconciled classes are **2 reconstructed stock ELF files**, **16 AArch64 ELF wrappers with no recognized debug sections**, **5 non-AArch64 or unsupported candidates**, **2 unreadable-section-table Qualcomm `xbl.elf` bootloader artifacts**, and **4 QEMU comparison artifacts**. No newly found file provides verified OEM compiler-local symbols.

**Decision:** Mark the *configured loose-ELF filename-filter scan through depth 7* `COMPLETE`; keep **factory debug artifact acquisition `UNRESOLVED`**. This is not a claim that the filesystem, the 895 deeper directories, skipped links or compressed firmware/source archives were exhaustively inspected. Even a debug-bearing file would still require matching OEM build provenance. Do not re-run broad directory sweeps without a specific likely debug artifact or evidence of a relevant OEM build output.

The machine-readable accepted-result checkpoint is `research/y2q-G986U1UESCHXL1/oem-debug-artifacts-only-result-20261014.json`.

**Next priority:** Review the already-collected firmware-to-profile and signed module/bootloader prerequisite evidence as separate gates. No conclusion from missing DWARF can establish GhostLock runtime behavior, kernel stack aliasing, temporary root, or KernelSU.

---

# SM-G986U1 HXL1 OEM debug-symbol scan v2 — owner results (2026-10-14 UTC)

**Scope:** review of the owner-uploaded, read-only `oem-debug-inventory-v2-20261014T032509Z.json` (SHA-256 `4b562b1ff2370a62bc81ec4c64f80f24cb3f0b2c33815abf5e46344de763e830`). No device access, builds, exploitation, or firmware changes.

## Verified inventory

- Breadth-first traversal across `/home/main/s20-artifacts` and `/home/main/src`: **180,000 files**, **11,342 directories**.
- Reported **29 candidates**, **17 filename-matched non-ELF files**, **zero scan errors**.
- Global report **`truncated=true`**, **9,805 pending directories**, **`scopeCompleteAtRequestedDepth=false`**. The provided pending-directory examples are source-tree Documentation paths. The JSON does **not** provide per-root pending-directory counts; therefore **do not conclude s20-artifacts root coverage was complete solely from these figures**.
- `/home/main/s20-artifacts`: 9,403 inspected files, 543 visited directories, **29 candidates**.
- `/home/main/src`: 170,597 inspected files, 10,799 visited directories, **zero candidates** *within the examined portion only*.
- Classes: 2 reconstructed stock `vmlinux` ELFs lacking debug sections; 16 original-image-derived Ghidra/REA and other ELF context wrappers lacking debug sections; 5 non-AArch64/unsupported candidates; 2 unreadable-section-table `xbl.elf` bootloader files; 4 QEMU comparison ELFs.

The only two machine-code-bearing `vmlinux` objects with `.debug_info` are `s20-artifacts/qemu-lab/kernel-build/vmlinux` and `s20-artifacts/qemu-lab-kasan/kernel-build/vmlinux`. These are comparison builds **not authenticated factory kernel debug symbols**. Both `xbl.elf` instances are Qualcomm bootloader files with unreadable section metadata, *not* evidence of factory **kernel** local-object debug information.

**Verdict: no authenticated OEM HXL1 debug artifact was found in the examined portion; the global search is incomplete.** This does not reverse the existing finding that HXL1's reconstructed stock ELF has no `.debug_info` or `.BTF`. It also does not prove Samsung never retained debug symbols elsewhere or in archives.

## One useful next pass (instead of another 180k-file source scan)

Run the existing scanner with only the **artifact root**, a 50k-entry bound, and a fresh report filename. This checks whether the artifact-root search can finish without being starved by unrelated Linux source files.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
OUT="$HOME/s20-artifacts/hxl1-research/oem-debug-artifacts-only-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 tools/y2q_hxl1_oem_debug_discovery.py \
  --root "$HOME/s20-artifacts" \
  --max-depth 7 \
  --max-entries 50000 \
  --output "$OUT" &&
python3 - "$OUT" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding='utf-8'))
print('report:', sys.argv[1])
print('files examined:', data['filesExamined'])
print('candidates:', data['candidateFiles'])
print('truncated:', data['truncated'])
print('errors:', data['errorCount'])
print('depth-limited directories:', data['depthLimitedDirectoryCount'])
print('scopeCompleteAtRequestedDepth:', data['scopeCompleteAtRequestedDepth'])
for item in data['candidates']:
    if item['classification'] in (
        'DEBUG_BEARING_CANDIDATE_REQUIRES_OEM_PROVENANCE',
        'METADATA_ONLY_CANDIDATE_REQUIRES_OEM_PROVENANCE'):
        print('NEEDS PROVENANCE:', item['path'])
PY
```

If `truncated=false`, `errorCount=0`, and `depthLimitedDirectoryCount=0`, the artifact root has no unvisited directories within the chosen non-ignored depth scope. Still, the scanner uses candidate filename filtering and does not unpack archives. Hence completion of this pass means **bounded loose-ELF discovery completed**, not proof of absence of all OEM DWARF in any packaging.

Further broad scanning of `/home/main/src` is lower priority unless the owner can indicate a specific build output location or matching debug package. The verified source-to-machine static mappings, kernel stack-lifetime uncertainty, unsigned module restrictions and bootloader issues are independent acceptance gates.

The machine-readable checkpoint is `research/y2q-G986U1UESCHXL1/oem-debug-inventory-v2-owner-result-20261014.json`.
