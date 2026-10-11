#!/usr/bin/env python3
"""Review exact HXL1 bootloader authorization roots with bounded REA value tracing.

This is a research-only static workflow. Every target comes from the owner's
SHA256-pinned original Odin/LinuxLoader function dossiers. It identifies the
difference between reporting a security result and producing it, requests
limited Ghidra high-p-code value traces, and preserves all unknowns.

It NEVER executes firmware, interfaces with a phone, patches images or claims
a bootloader unlock. No live firmware fuzzing is performed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import TriageError, HXL1_BL_SHA256
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, safe_segment,
)
from tools.y2q_hxl1_rea_decision_path_review import audit as check_original_dossiers
from tools.y2q_hxl1_rea_decision_path_review import load_json

# All entries here come from the owner-verified Ghidra session. None is an
# identified OEM unlock service implementation until further code evidence.
FOCUS = (
    {
        "module": "Odin", "entry": "0x1ec00",
        "hypothesis": "OEM value/status producer",
        "purpose": "Find where local_4c originates and whether it comes from a protected state service",
        "symbols": ("[OEM]Oem unlock value", "local_4c", "FUN_0000bfbc"),
    },
    {
        "module": "LinuxLoader", "entry": "0x5950",
        "hypothesis": "AVB unlock-state callback invocation",
        "purpose": "Identify the initialized function pointer behind param_1 + 0x40; check read failure treatment",
        "symbols": ("read_is_device_unlocked", "param_1 + 0x40", "device_state"),
    },
    {
        "module": "Odin", "entry": "0x1b6a8",
        "hypothesis": "OEM/FRP/KG failure reason reporter, not yet the policy enforcer",
        "purpose": "Locate the producer of piVar6[3] / error code 0xc and verify actual Ghidra body ownership",
        "symbols": ("Blocked By OEM Lock", "piVar6[3]", "iVar9 == 0xc"),
    },
    {
        "module": "LinuxLoader", "entry": "0x3f54",
        "hypothesis": "Unlocked-device verification diagnostic, not yet a bypass branch",
        "purpose": "Distinguish logging conditions from whether boot verification is actually performed",
        "symbols": ("Skipping boot verification", "FUN_00039cdc", "FUN_00004520"),
    },
    {
        "module": "LinuxLoader", "entry": "0x2274",
        "hypothesis": "Boot image authorization and AVB error handling",
        "purpose": "Review AVB-slot verification errors and trusted rollback handling",
        "symbols": ("AvbSlotVerify returned", "Rollback Version syscall", "Unlock Cnt"),
    },
)
MAX_TRACE_JSON = 32 * 1024 * 1024


def focal_context(code: str, terms: tuple[str, ...], *, radius: int = 8,
                  limit: int = 140) -> dict:
    """Bounded, line-numbered context from ORIGINAL Ghidra pseudocode."""
    lines = code.splitlines()
    matches = []
    for i, line in enumerate(lines):
        if any(term.casefold() in line.casefold() for term in terms):
            matches.append(i)
    subset = set()
    for i in matches[:24]:
        subset.update(range(max(0, i-radius), min(len(lines), i+radius+1)))
    if not subset:
        subset.update(range(min(12, len(lines))))
    selected = sorted(subset)[:limit]
    return {
        "lineCount": len(lines),
        "totalTermMatches": len(matches),
        "sampledMatches": [x+1 for x in matches[:24]],
        "truncated": (len(matches)>24 or len(selected)<len(subset)),
        "selected": [{"line": i+1, "code": lines[i][:500]} for i in selected],
    }


def trace_description(ev: dict) -> dict:
    """Do not infer reachability from an arbitrary graph schema or empty result."""
    result = ev.get("normalized_result")
    info = {
        "evidenceId": ev["evidence_id"],
        "normalizedType": type(result).__name__,
        "hasNormalizedResult": result is not None,
        "semanticsValidated": False,
        "indirectCallResolved": False,
        "trustedStateOriginEstablished": False,
        "runtimeBranchProven": False,
    }
    if isinstance(result, dict):
        info["topLevelKeys"] = sorted(str(x) for x in result.keys())[:64]
        info["collectionSizes"] = {
            str(k): len(v) for k, v in result.items()
            if isinstance(v, (list, dict)) and k in
            {"nodes", "edges", "calls", "procedures", "unknowns", "omitted", "limitations"}
        }
        info["errorOrCoverage"] = {
            k: result[k] for k in ("status", "coverage", "truncated")
            if k in result and isinstance(result[k], (str, bool, int, float, type(None)))
        }
    return info


def validate_first_pass(root: Path) -> tuple[dict, dict]:
    saved = check_original_dossiers(root)
    if not saved["allFiveReferencesVerified"]:
        failures = "; ".join(x["reason"] for x in saved["unresolved"])
        raise TriageError("Five-function original HXL1 proof gate incomplete: " + failures)
    names = {(item["module"], item["ghidraFunctionEntry"]) for item in saved["references"]}
    if any((f["module"], f["entry"]) not in names for f in FOCUS):
        raise TriageError("Focused trace target not backed by original five-function proof")
    originals = {t.name: t for t in choose_targets(root)}
    return saved, originals


def inspect_focus(root: Path, out: Path, *, execute: bool,
                  node: str, script: Path, count: int, timeout: int) -> dict:
    saved, originals = validate_first_pass(root)
    if execute and (not script.is_file() or script.is_symlink()):
        raise TriageError(f"REA fork not installed at {script}")
    runner = Runner(out, script, node=node, run_commands=execute,
                    deadline=timeout, max_traces=0)
    items = []
    for spec in FOCUS[:count]:
        module, entry = spec["module"], spec["entry"]
        target = originals[module]
        source_dir = root / "rea-security-audit" / module
        # Revalidate the *raw original Ghidra function result*, not the
        # lossy report snippets, before making any statement about code.
        evidence_sources = [
            item["xrefSource"] for item in saved["references"]
            if item["module"] == module and item["ghidraFunctionEntry"] == entry
        ]
        if len(evidence_sources) != 1:
            raise TriageError(f"Original Ghidra xref source is ambiguous for {module}:{entry}")
        source = evidence_sources[0]
        fn_path = source_dir / f"function-{safe_segment(source)}.json"
        # Presently this path is the original owner-run function xref file.
        fn_ev = evidence(fn_path, sha=target.sha256, operation="analyze_function",
                         parameter="procedure", value=source)
        fn = fn_ev["normalized_result"]
        if not isinstance(fn, dict) or not isinstance(fn.get("pseudocode"), str):
            raise TriageError(f"Missing original pseudocode for {module}:{entry}")
        context = focal_context(fn["pseudocode"], spec["symbols"])
        state = {
            "module": module, "originalSha256": target.sha256,
            "entry": entry, "hypothesis": spec["hypothesis"],
            "purpose": spec["purpose"],
            "originalFunctionEvidenceId": fn_ev["evidence_id"],
            "pseudocodeContext": context,
            "traceStatus": "PLANNED_NOT_EXECUTED",
            "traceSummary": None,
            "traceFile": str(source_dir / f"trace-{safe_segment(entry)}.json"),
            "actualAuthorizationBranchEstablished": False,
            "vulnerabilityDemonstrated": False,
        }
        trace_path = source_dir / f"trace-{safe_segment(entry)}.json"
        trace = runner.obtain(target, ["trace-native-values", str(target.path), entry],
                              trace_path, operation="trace_native_values",
                              parameter="procedure", value=entry)
        if trace is not None:
            state["traceStatus"] = "VERIFIED_REA_TRACE_EVIDENCE_UNINTERPRETED"
            state["traceSummary"] = trace_description(trace)
        items.append(state)
    return {
        "schemaVersion": 1, "originalArchiveSha256": HXL1_BL_SHA256,
        "mode": "STATIC_REA_EXECUTE" if execute else "PLAN_ONLY",
        "plannedOrNewCommands": runner.planned if not execute else [],
        "count": len(items), "targets": items,
        "noDeviceActions": True, "unlockMethodProven": False,
        "vulnerabilityProven": False, "secureStateOriginProven": False,
    }


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 original Odin/LinuxLoader — semantic decision roots", "",
        "**Host-only Ghidra/REA observations; unlock remains unproved.**", "",
        f"- Source archive: `{report['originalArchiveSha256']}`",
        f"- Mode: {report['mode']}",
        f"- Selected decision roots: {report['count']}", "",
    ]
    for item in report["targets"]:
        lines += [f"## {item['module']} {item['entry']}", "",
                  f"- Hypothesis: {item['hypothesis']}",
                  f"- Next question: {item['purpose']}",
                  f"- Original Ghidra Evidence: {item['originalFunctionEvidenceId']}",
                  f"- REA value trace: **{item['traceStatus']}**",
                  f"- Trace source: `{item['traceFile']}`",
                  f"- Matching pseudocode lines: {item['pseudocodeContext']['totalTermMatches']}", "",
                  "~~~c"]
        for line in item["pseudocodeContext"]["selected"]:
            lines.append(f"{line['line']:5d} | {line['code']}")
        lines += ["~~~", ""]
        if item["pseudocodeContext"]["truncated"]:
            lines += ["**Context truncated:** consult original function-*.json.", ""]
        if item["traceSummary"] is not None:
            s = item["traceSummary"]
            lines += [
                "REA trace metadata (not a semantic authorization conclusion):",
                "", f"- Evidence ID: {s['evidenceId']}",
                f"- Result keys: {s.get('topLevelKeys', [])}",
                f"- Collection counts: {s.get('collectionSizes', {})}",
                "",
            ]
    lines += [
        "## Interpretation and proof gates", "",
        "- Odin error label 0x0c is a reporting case, not proof of the function that made the decision.",
        "- The LinuxLoader unlocked-device string may be diagnostic-only; distinguish",
        "  logging masks from the verified-boot branch using full call/data flow.",
        "- The AvbOps callback offset, originating secure-state service, and",
        "  return-code semantics require validation against this exact Samsung binary.",
        "- This automation preserves raw def-use traces but does not claim the",
        "  secure-world source or remote call target is resolved.",
        "- Function 0x1b6a8 owns a reference numerically below its entry in",
        "  saved Ghidra evidence; examine discontiguous body ranges in Ghidra.",
        "- No modified firmware, signature bypass, host fuzzing or device-side test was run.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea", type=Path, default=Path.home() / "src/rea/scripts/rea.mjs")
    p.add_argument("--node", default="node")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--count", type=int, default=2)
    p.add_argument("--timeout", type=int, default=240)
    args = p.parse_args()
    if not (1 <= args.count <= len(FOCUS) and 30 <= args.timeout <= 1200):
        p.error("count or timeout out of range")
    try:
        root = args.input_dir.expanduser().resolve()
        out = root / "rea-security-audit"
        result = inspect_focus(root, out, execute=args.execute, script=args.rea,
                               node=args.node, count=args.count, timeout=args.timeout)
        (out / "semantic-roots.json").write_text(json.dumps(result, indent=2) + "\n")
        (out / "semantic-roots.md").write_text(markdown(result))
    except (TriageError, ValueError, OSError, KeyError, TypeError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for item in result["targets"]:
        print("[ROOT]", item["module"], item["entry"], item["traceStatus"])
    print("[REPORT]", out / "semantic-roots.md")
    print("[LIMIT] Original decompilation and static def-use only, no secure-state decision proven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
