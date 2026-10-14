# SM-G986U1 / G986U1UESCHXL1 — consolidated firmware-to-profile gate audit

**2026-10-14, research-only.** This checkpoints the original Samsung S20+ HXL1 firmware evidence according to [PORTING.md](PORTING.md), the authoritative `tools/y2q_porting_readiness.py`, and the retained research manifest. It is **not** a root payload, exploit validation, unlocked bootloader, KernelSU integration, or feed-registration authorization.

## Final nine-stage static readiness matrix

| Stage | State | Already verified | Missing acceptance evidence |
|---|---|---|---|
| 1. Exact model/firmware | **COMPLETE** | Owner observed `SM-G986U1`, `G986U1UESCHXL1`, `4.19.113-27095354`, green Verified Boot, locked flashing, SELinux Enforcing | Recheck only if handset firmware changes |
| 2. Extract original inputs | **COMPLETE for extraction** | Pinned HXL1 boot v2, `kernel.bin`, `config.gz`, Samsung source, BL archive, DTB semantic inventory | Extraction alone does not certify loaded kernel RAM/actual runtime DTB |
| 3. Original ABI/source-to-machine | **PARTIAL** | Recovered original symbols; selected raw instructions and original source mapping; 4,102 preserved AArch64 instructions, operation 11, select 256-byte source buffer and 320-FD capacity | Factory C-local/object attribution and any still unresolved ABI definitions; original `vmlinux` DWARF unavailable |
| 4. Physical Linux handoff | **OPEN** | Original matching BL archive, ABL/XBL/XBL_CONFIG, boot-v2 components, four parsed FDT candidates; QEMU guest handoff research | Physical handset's actual selected DTB, kernel load base, runtime bootloader handoff. Do **not** equate XBL/ABL `PT_LOAD` or QEMU virt with Linux physical placement |
| 5. Per-boot runtime assumptions | **OPEN** | Source and static control-flow context, device identity | Independently measured relevant runtime metadata; no KASLR/physical or cross-syscall stack-memory reuse assumed |
| 6. Native target | **OPEN** | Firmware-locked, unprivileged identity-only AArch64 diagnostic and research package | Hardware-verified privilege transition absent. An inert diagnostic cannot certify a working HXL1 root payload |
| 7. KernelSU 4.19 | **BLOCKED** | Exact original `CONFIG_MODULES=y`, `CONFIG_MODVERSIONS=y`, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_KPROBES=n`, UH_RKP/KDP/DEFEX | Compatible stock 4.19 hooks, trusted module/loading mechanism and successful kernel initialization not demonstrated. Manual relocation is not signature authorization |
| 8. App/support feed | **BLOCKED** | Research-only identity matching, explicit stock firmware pin | Hardware-safe and reproducible root/KernelSU plus release review; HXL1 stays out of production feed |
| 9. Recovery/release signoff | **DEFERRED** | Retained immutable hashes and owner-host reports | Owned-device recovery plan, authorized hardware trials and release signoff |

**Total:** two complete, one partial, three open, two blocked, one deferred. The original `hxl1NineStagePortReadiness` expresses stage 2 as `COMPLETE_EXTRACTED_INPUTS`, normalized to COMPLETE **only within the extraction scope**.

## Verified provenance and supplemental results

The original `research/y2q-G986U1UESCHXL1/evidence.json` matches the expected HXL1 identity, kernel, module-security config, research-only flags, nine-stage matrix, and matching original BL archive.

| Input | Recorded SHA-256 |
|---|---|
| Stock `kernel.bin` | `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` |
| Original `boot.img` | `bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8` |
| Original `config.gz` | `1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd` |
| Matching original BL package | `f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b` |
| Uploaded original disassembly archive | `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997` |
| Owner-run select numeric crosswalk | `f1c5114692a059ebc1c5d1542af19170640989054b998697c26ca0f7eb21a478` |
| Owner-run depth-7 artifact-only debug scan | `fc08987fe6a6a3f217e7a5d563ccce962ec0adf29963500a9bec13faeb0f304a` |

**Limits:** Current audit verifies the *manifest's* stock-artifact pins and independently validates supplied static reports; it does **not** newly rehash the original 52-MB `kernel.bin` bytes or compare loaded kernel memory. The source/header and compiled select arithmetic agree for a 256-byte source array, six bitmaps of 64-bit words and a 320-descriptor local capacity; this does not prove futex/select stack aliasing. The bounded debug scan completed 24,080 files under `s20-artifacts` through depth 7 but skipped **895 deeper directories** and archived content. No authenticated matching OEM debug ELF was found within that scope. Clang10/18 and QEMU DWARF are comparison evidence, not factory C-variable location truth.

## Readiness consistency automation

New `tools/y2q_hxl1_readiness_consolidate.py` checks the existing manifest for identity, original SHA pins, stage statuses, stock verified-boot configuration, module-security barriers and no-production invariants. It optionally validates the latest owner select and debug reports, and checks a fresh authoritative `y2q_porting_readiness.py` report if provided. It **never promotes a stage automatically**.

The existing `tools/y2q_porting_readiness.py` remains the source of authority and can independently hash the raw original user files. To reconcile existing reports, without re-extraction or device access, run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_readiness_consolidate

# Optional: point --readiness at an EXISTING owner-generated port-readiness.json.
# Omit it if not present; do not invent a new one.
OUT="$HOME/s20-artifacts/hxl1-research/readiness-consolidated-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 tools/y2q_hxl1_readiness_consolidate.py \
  --evidence research/y2q-G986U1UESCHXL1/evidence.json \
  --select-crosswalk "$HOME/s20-artifacts/hxl1-research/hxl1-select-numeric-crosswalk-20261014.json" \
  --debug-inventory "$HOME/s20-artifacts/hxl1-research/oem-debug-artifacts-only-20261014T033146Z.json" \
  --output "$OUT"
echo "$OUT"
```

If the uploaded select or debug report files were kept in another directory, supply their actual paths; never imply the report is present from this command alone. **Production `support`, `src/targets`, payload and kernel trees are untouched** by the checker.

## Decision

Do not reopen broad DWARF search or rerun the successful original firmware extraction, selected disassembly/hash checks, or select capacity analysis without a new relevant input. Stage 3 is partial because no OEM C-local metadata is available; Stage 4 and Stage 5 concern actual physical handset runtime evidence, not QEMU simulation; Stage 7's module trust is independent of a Linux local vulnerability. Stage 8 remains blocked regardless of passing new static checks. The existing device is **not rooted or KernelSU-ready** by any evidence in this audit.

Machine-readable versioned checkpoint: `research/y2q-G986U1UESCHXL1/firmware-to-profile-readiness-consolidated-20261014.json`.
