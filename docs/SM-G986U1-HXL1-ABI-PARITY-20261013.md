# HXL1 Samsung Stage 3 — ABI candidate parity checkpoint (2026-10-13)

## Source of this checkpoint

Owner reported a successful **actual WSL-host** execution on 2026-10-13 of:

```sh
cd ~/src/Root-My-Galaxy-Payloads
python3 -m unittest -v tools.test_y2q_hxl1_stage3_abi_crosscheck
python3 tools/y2q_hxl1_stage3_abi_crosscheck.py
```

The owner-supplied console transcript reports seven unittest cases passed and:

```text
[CLANG18-CLANG10 CANDIDATE PARITY] 13/13
[OEM FACTORY MEMBER OFFSETS CERTIFIED] 0
[STAGE 3] PARTIAL
[SAVED REA] SAVED_LIVE_RECORDS_RECHECKED_NOT_FACTORY_REAUTHENTICATED
[REPORT] /home/main/s20-artifacts/hxl1-research/stage3-abi-parity-20261013T111940329715Z/abi-parity.md
```

The exact generated `abi-parity.json` and `abi-parity.md` **have not yet been submitted to the GitHub repository or independently inspected in this checkpoint**. The 13/13 result is an owner-host observation, not a separate CI execution of real factory inputs. Synthetic tests and successful candidate parity do not establish OEM member identities.

## What changed

The current feature branch has the new read-only `tools/y2q_hxl1_stage3_abi_crosscheck.py` and corresponding `tools/test_y2q_hxl1_stage3_abi_crosscheck.py`, added in commits `de10ac6` and `094216c`.

The new audit:
- Reuses the original pinned HXL1 Image and Samsung source.
- Reads the existing 13-member Clang10 **candidate** registry rather than regenerating it.
- Reads Clang18 Samsung-source DWARF from existing `kernel/fork.o` and `kernel/locking/rtmutex.o`.
- Checks preserved critical `stock.config` options.
- Rechecks previously saved REA/Ghidra provider records without issuing new Ghidra calls.
- Does not change any factory image, stock source, device, production `target.h`, or support feed.

## Evidentiary limits and next targeted review

1. **13/13** means cross-compiler candidate *numerical offset agreement*. It does not mean 13 independently factory-certified C-member identities.
2. The saved REA recheck authenticates retained, hashed isolated input/provider records to the report as far as implemented; it explicitly states `NOT_FACTORY_REAUTHENTICATED`. Do not interpret a matched static register chain or numeric memory displacement as a complete source-level member def/use proof.
3. Previous actual REA owner run reported three live functions and nine matched static register chains; review the per-function HighFunction/P-code completeness and exact candidate rows in the real saved JSON rather than extrapolating a full 13/13 Ghidra coverage claim.
4. The next useful inputs, to inspect **without re-running** compilation, firmware extraction or six REA calls:
   - `~/s20-artifacts/hxl1-research/stage3-abi-parity-20261013T111940329715Z/abi-parity.json`
   - `~/s20-artifacts/hxl1-research/stage3-abi-parity-20261013T111940329715Z/abi-parity.md`
   - The newest existing `stage3-rea-live-*/live-stage3-rea-review.json`
   - Three saved `*/live-function.json` records and `*/live-instructions.json`, if safely shareable
   - Existing Clang10 `factory-displacement-comparison.json` report

Retain the nine-stage boundaries: **Stage 1–2 COMPLETE; Stage 3 PARTIAL; Stage 4–6 OPEN; Stage 7–8 BLOCKED; Stage 9 DEFERRED**. The observed source pattern, static ABI parity, and REA analysis do not demonstrate runtime vulnerability exploitation, KernelSU loading, bootloader unlocking or on-device root.
