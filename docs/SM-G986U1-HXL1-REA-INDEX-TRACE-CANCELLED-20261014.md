## October 14, 05:05 UTC — correct standalone Python package import before re-running cached audit

Actual owner WSL validation: the original 10/10 offline synthetic tests passed, but the direct entry-point command failed with ModuleNotFoundError: No module named 'tools' at the deferred import of tools.y2q_linuxloader_rea_stage4_xrefs inside review_cached. No report was created at the owner's new linuxloader-index-cache-20261014T050521Z.json path. No REA provider analysis was run; cached EFI and reports were not changed.

Cause: a directly executed tools/filename.py starts with tools/ in sys.path, not the repository root. The pre-existing test runner did include the repository root, masking this integration defect.

The committed script now adds its own repository root before importing validated existing tools and tests the real CLI entry point in a new subprocess with -I (isolated Python) and an external working directory. Tests increased from 10 to 12. **Corrected suite and real cache rerun have not yet been observed passing on owner WSL**, so do not claim the original dataflow audit finished.

Re-run *only* the existing cached audit after pulling the fix:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_linuxloader_cached_index_audit

    BASE="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
    RUN="$BASE/rea-dt-index-LBaPQ6"
    OUT="$HOME/s20-artifacts/hxl1-research/linuxloader-index-cache-$(date -u +%Y%m%dT%H%M%SZ).json"

    python3 tools/y2q_hxl1_linuxloader_cached_index_audit.py \
      --run-dir "$RUN" --loader "$BASE/LinuxLoader-HXL1.efi" \
      --output "$OUT" &&
    cat "$OUT"

Do not rerun the cancelled REA trace, original xrefs or ADB root-property probe; this audits only saved, SHA-validated metadata and bounded pseudocode. The existing stage-4 loader selector and physical Linux kernel handoff remain unverified, regardless of the import fix.

Source-only checkpoint: research/y2q-G986U1UESCHXL1/stage4-cached-rea-cli-import-fix-20261014.json.

---

# SM-G986U1 HXL1 — Cancelled REA DTB/DTBO value trace (2026-10-14 UTC)

Research-only checkpoint. No handset modification, root, bootloader patch or firmware writes.

## Owner results

The owner confirmed **25/25** unit tests pass for the live device-tree read access tool, after the stale test assertion was fixed.

The saved **rea-shared-dtb-dtbo-native-values.partial.json** was independently reviewed and SHA-256 verified:
- SHA-256: 0bd68713838b2536f67ff683b284d35008b5fcdcc05cfac608dee9c0b1a5e847
- error: Analysis failed
- code/category: cancelled
- operation: analyze_function
- cleanup: complete
- retryable: true

No complete rea-shared-dtb-dtbo-native-values.json was found. **The error artifact has no completed native value flow, operation evidence ID or normalized result.** Its retryable flag does not establish why the provider stopped or suggest that rerunning the same analysis would succeed. Preserve the original partial; do not overwrite or promote it to success.

## Already proven original LinuxLoader static context

The SHA-pinned original LinuxLoader-HXL1.efi is 5e69a9718569cfa1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003. The androidboot.dtb_idx string at Ghidra analysis coordinate 0xbfd99 is referenced at 0x2c350; the androidboot.dtbo_idx string at 0xbfd82 is referenced at 0x2c308. Both are in original cached FUN_0002bdf8, entry 0x2bdf8.

This establishes a shared command-line **formatter**, not the upstream source or actual selecting mechanism for the two values. Observed physical-phone boot properties dtb_idx=0 and dtbo_idx=2 do not authenticate which embedded FDT or external overlay was used. Stage 4 remains OPEN.

## New no-provider offline cached-function audit

tools/y2q_hxl1_linuxloader_cached_index_audit.py loads and verifies the existing Ghidra xref and function JSONs with established Python validators, rehashes the source EFI, inspects the saved partial REA failure, and emits bounded pseudocode windows around the index literals. It does NOT start REA/Ghidra, repeat xrefs, use ADB, change firmware or claim that visible pseudocode identifies the index producer.

Ten synthetic tests passed locally; CI is configured but a hosted passing run is not confirmed.

Owner command, keeping originals intact:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_linuxloader_cached_index_audit

    BASE="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
    RUN="$BASE/rea-dt-index-LBaPQ6"
    OUT="$HOME/s20-artifacts/hxl1-research/linuxloader-index-cache-$(date -u +%Y%m%dT%H%M%SZ).json"

    python3 tools/y2q_hxl1_linuxloader_cached_index_audit.py \
      --run-dir "$RUN" \
      --loader "$BASE/LinuxLoader-HXL1.efi" \
      --output "$OUT"

    python3 - "$OUT" <<'PY'
    import json,sys
    d=json.load(open(sys.argv[1],encoding="utf-8"))
    print("cached original:",d["classification"])
    print("trace:",d["savedNativeTrace"]["state"])
    print("trace error:",d["savedNativeTrace"].get("code"))
    print("index-literal line count:",d["formatterContext"]["indexLiteralLineCount"])
    for x in d["formatterContext"]["boundedPseudocodeExcerpt"]:
        print(x["line"], x["text"])
    print("producer proved:",d["indexOperandsProducerVerified"])
    PY

Note: if the cached function or xrefs are absent/changed, the tool fails closed rather than initiating expensive new analysis. If the cached pseudocode has no literal or no unambiguous producer, report the limitation and stop. Code-location, direct static dataflow and actual runtime selector are distinct evidence classes.

Readiness remains 2 complete, 1 partial, 3 open, 2 blocked, 1 deferred; no privilege escalation or KernelSU verified.
