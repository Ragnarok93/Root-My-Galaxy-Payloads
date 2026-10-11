#!/usr/bin/env python3
"""Offline HXL1 callback field attribution and AVB ops constructor queue.

Uses only original SHA256-validated saved REA/Ghidra results. Validates the
LinuxLoader 0x5950 indirect CALL target producer, field offset, and parameter
provenance, then samples the *full* original 0x2274 caller dossier for
initialization of its AvbOps-like object. No Ghidra/REA/phone execution.

External AOSP ABI variants below are COMPARISONS, never asserted as the
specific Samsung HXL1 AvbOps layout. Even matching layout offsets do NOT
resolve a concrete implementation or prove bootloader unlock.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_indirect_value_slices import (
    audit as saved_value_audit,
)

# These exact sites/offsets are observational data from the owner-executed
# 2026-10-11 original HXL1 Ghidra p-code backward slices.
EXPECTED = (
    ("0x5dc4", 0x40, "lock-state-output-candidate"),
    ("0x5ea4", 0x48, "other-avb-callback"),
    ("0x6020", 0x48, "other-avb-callback"),
)
PARENT = "0x5950"
AVB_CALLER = "0x2274"
CALLER_VARIABLE = "pbVar20"

# Source-order comparisons only; the extra fields changed over libavb
# development. Samsung firmware's actual implementation has not been pinned
# to either reference header revision.
AOSP_LAYOUT_EXAMPLES = {
    "legacy_no_extra_fields": [
        "user_data", "ab_ops", "read_from_partition",
        "write_to_partition", "validate_vbmeta_public_key",
        "read_rollback_index", "write_rollback_index",
        "read_is_device_unlocked", "get_unique_guid_for_partition",
    ],
    "newer_cert_and_preloaded_fields": [
        "user_data", "ab_ops", "cert_ops", "read_from_partition",
        "get_preloaded_partition", "write_to_partition",
        "validate_vbmeta_public_key", "read_rollback_index",
        "write_rollback_index", "read_is_device_unlocked",
        "get_unique_guid_for_partition",
    ],
}


def parsed_pointer_field(chain: list[dict]) -> dict:
    """Require observed CALLIND <- LOAD <- CAST <- INT_ADD <- param_1.

    This is not a general symbolic executor; stop rather than guessing if
    Ghidra changes or produces an ambiguous dependency chain.
    """
    if len(chain) < 5:
        raise TriageError("Saved CALLIND chain too short to establish field offset")
    head = chain[0]
    if (head.get("opcode") != "CALLIND" or head.get("distance") != 0):
        raise TriageError("No root CALLIND target in original p-code chain")
    loaded = [x for x in chain if x.get("opcode") == "LOAD"]
    add = [x for x in chain if x.get("opcode") == "INT_ADD"]
    params = [x for x in chain if x.get("kind") == "parameter"]
    if len(loaded) != 1 or len(add) != 1 or len(params) != 1:
        raise TriageError("Ambiguous pointer load/address/parameter p-code producers")
    if params[0].get("parameter", {}).get("ordinal") != 0:
        raise TriageError("Function pointer not rooted in first AVB ops parameter")
    inputs = add[0].get("inputs")
    if not isinstance(inputs, list) or len(inputs) != 2:
        raise TriageError("Malformed original pointer-offset expression")
    v = inputs[1]
    if not isinstance(v, dict) or v.get("kind") != "constant":
        raise TriageError("Missing exact Ghidra constant pointer-field offset")
    try:
        displacement = int(v["constantHex"], 16)
    except (KeyError, TypeError, ValueError) as exc:
        raise TriageError("Cannot parse Ghidra pointer offset constant") from exc
    if not 0 <= displacement <= 0x200 or displacement % 8:
        raise TriageError("Implausible unaligned AVB function-pointer displacement")
    if not (head["distance"] < loaded[0]["distance"] <
            add[0]["distance"] < params[0]["distance"]):
        raise TriageError("Original Ghidra pointer producer ordering is inconsistent")
    return {
        "base": "param_1", "byteOffset": displacement,
        "hexOffset": hex(displacement),
        "memoryLoadAddress": loaded[0].get("address"),
        "pointerArithmeticAddress": add[0].get("address"),
        "callInstruction": head.get("address"),
        "rootArgumentInput0": head.get("inputs", [None])[0],
        "staticCalleeResolved": False,
    }


def related_code(lines: list[dict], expression: str, *, radius=7,
                 cap=180) -> dict:
    if not isinstance(lines, list) or any(
            not isinstance(x, dict) or not isinstance(x.get("code"), str)
            or type(x.get("line")) is not int for x in lines):
        raise TriageError("Original function dossier lines invalid")
    pattern = re.compile(expression, re.I)
    match = [i for i, row in enumerate(lines) if pattern.search(row["code"])]
    selected = set()
    for i in match[:32]:
        selected.update(range(max(0, i-radius), min(len(lines), i+radius+1)))
    return {
        "matchingLineNumbers": [lines[i]["line"] for i in match],
        "allMatchesShown": len(match) <= 32,
        "excerptTruncated": len(selected) > cap or len(match) > 32,
        "selectedLines": [lines[i] for i in sorted(selected)[:cap]],
    }


def inspect_caller_context(dossiers: dict) -> dict:
    caller = dossiers["linuxLoaderAvbImage"]
    user = dossiers["linuxLoaderUnlockCallbackUser"]
    code = caller["candidateCallAndInitializerContext"]
    # The original saved-only slicer exposed only bounded 0x2274 caller
    # context. To inspect all variable assignments we MUST load the original
    # SHA-validated dossier separately in audit(); never silently use this
    # abbreviated context as complete function evidence.
    return {
        "callerEntry": caller["entry"],
        "callerEvidenceId": caller["evidenceId"],
        "recordedCallSiteCandidate": "FUN_00005950",
        "savedCallerExcerptLineNumbers": code["matchedLineNumbers"],
        "calleeEntry": user["entry"],
        "calleeEvidenceId": user["evidenceId"],
    }


def inspect(snapshot: dict, full_caller: list[dict]) -> dict:
    original = snapshot
    sites = {}
    for item in original["callSlices"]:
        if item.get("module") != "LinuxLoader":
            continue
        site = item.get("callsite")
        if not isinstance(site, str) or site in sites:
            raise TriageError("Duplicate/malformed original LinuxLoader site")
        sites[site] = item
    expected = {site for site, _, _ in EXPECTED}
    if set(sites) != expected:
        raise TriageError("Expected three original LinuxLoader CALLIND sites")
    calls = []
    for address, expected_disp, label in EXPECTED:
        item = sites[address]
        if item.get("GhidraResolution") != "unresolved":
            raise TriageError("Owner's original provider-resolved results have changed")
        origin = parsed_pointer_field(item["chain"])
        if origin["byteOffset"] != expected_disp or origin["callInstruction"] != address:
            raise TriageError(
                f"Original HXL1 {address} callback slot differs from saved evidence")
        calls.append({
            "callsite": address, "semanticHypothesis": label,
            "pcode": origin, "verifiedOriginalValueSlice": True,
            "callbackImplementationKnown": False,
        })
    offsets = {x["callsite"]: x["pcode"]["byteOffset"] for x in calls}
    if (offsets["0x5dc4"] == offsets["0x5ea4"]
            or offsets["0x5ea4"] != offsets["0x6020"]):
        raise TriageError("AVB callback field identities inconsistent")
    caller_hits = related_code(full_caller, r"\bpbVar20\b", radius=8, cap=220)
    assignments = [
        row for row in full_caller if re.search(
            r"\bpbVar20\s*=(?!=)", row["code"])
    ]
    callsites = [x for x in full_caller if
                 "FUN_00005950(" in x["code"]]
    if not callsites:
        raise TriageError("Original AVB caller lacks proven callback-user invocation")
    return {
        "root": PARENT, "callSites": calls,
        "pointerSlotRelationship": "0x5ea4 and 0x6020 share offset +0x48",
        "strongerCallbackCandidate": "0x5dc4",
        "reason": "Only 0x5dc4 loads +0x40 and passes lock-state output pointer",
        "avbOpsLikeObjectInitializer": {
            "callerFunction": AVB_CALLER,
            "symbolicPointer": CALLER_VARIABLE,
            "totalCallerLines": len(full_caller),
            "variableOccurrenceLines": caller_hits["matchingLineNumbers"],
            "assignmentStatements": assignments[:35],
            "callToAvbConsumer": callsites[:12],
            "boundedCallerContext": caller_hits,
            "initializerVerified": False,
        },
        "aospVersionComparisons": {
            version: {
                "readIsUnlockedOffset": hex(names.index("read_is_device_unlocked")*8),
                "guidCallbackOffset": hex(names.index("get_unique_guid_for_partition")*8),
            }
            for version, names in AOSP_LAYOUT_EXAMPLES.items()
        },
        "samsungExactAvbStructRevisionKnown": False,
        "secureStateOriginProven": False,
        "unlockMethodProven": False,
    }


def audit(root: Path) -> dict:
    from tools.y2q_hxl1_rea_security_audit import choose_targets, evidence, function_record
    source = saved_value_audit(root)   # All original SHA/provenance checks first.
    targets = {t.name: t for t in choose_targets(root)}
    file = root / "rea-security-audit" / "LinuxLoader" / "function-0x3f34.json"
    original = evidence(
        file, sha=targets["LinuxLoader"].sha256,
        operation="analyze_function", parameter="procedure", value="0x3f34")
    qualified = function_record(original, "0x3f34")
    if qualified["entry"] != AVB_CALLER:
        raise TriageError("Exact AVB caller owning original function differs")
    pseudo = original["normalized_result"].get("pseudocode")
    if not isinstance(pseudo, str) or len(pseudo) > 200000:
        raise TriageError("Original AVB caller pseudocode missing/oversized")
    full = [{"line": n+1, "code": line} for n, line in enumerate(pseudo.splitlines())]
    report = inspect(source, full)
    report.update({
        "schemaVersion": 1, "originalArchiveSha256": HXL1_BL_SHA256,
        "originalGhidraCallerEvidenceId": original["evidence_id"],
        "allOriginalHxl1SourcesVerified": True,
        "mode": "SAVED_ONLY_NO_NEW_REA",
        "deviceModified": False,
    })
    return report


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 AVB lock-state callback field and object provenance", "",
        "**Original saved HXL1 REA p-code and Ghidra decompiler only.**",
        "No unlock, verified callback initializer or secure-state producer proven.",
        "", "HXL1 archive: " + report["originalArchiveSha256"],
        "New Ghidra/REA calls: none", "",
        "## Source-attested indirect calls", "",
    ]
    for item in report["callSites"]:
        pointer = item["pcode"]
        lines += [
            "### " + item["callsite"], "",
            "- AVB-like structure field: param_1+" + pointer["hexOffset"],
            "- LOAD native address: " + str(pointer["memoryLoadAddress"]),
            "- Interpretation: " + item["semanticHypothesis"],
            "- Ghidra-resolved implementation: no", "",
        ]
    lines += [
        "## Complete original AVB caller 0x2274 — pbVar20 provenance", "",
    ]
    initializer = report["avbOpsLikeObjectInitializer"]
    lines += [
        "- Original caller pseudocode lines: " + str(initializer["totalCallerLines"]),
        "- pbVar20 occurrence lines: " + str(initializer["variableOccurrenceLines"]),
        "- Assignment statements: " + str(len(initializer["assignmentStatements"])),
        "- FUN_00005950 calls: " + str(len(initializer["callToAvbConsumer"])),
        "", "### Candidate assignment lines", "", "~~~c",
    ]
    for x in initializer["assignmentStatements"]:
        lines.append(f"{x['line']:5d} | {x['code'][:600]}")
    lines += ["~~~", "", "### Original caller context", "", "~~~c"]
    for x in initializer["boundedCallerContext"]["selectedLines"]:
        lines.append(f"{x['line']:5d} | {x['code'][:600]}")
    lines += ["~~~", "", "## AOSP ABI revision comparison (external reference, NOT HXL1 proof)", ""]
    for version, offsets in report["aospVersionComparisons"].items():
        lines.append(
            "- " + version + ": read_is_device_unlocked " +
            offsets["readIsUnlockedOffset"] +
            "; get_unique_guid_for_partition " +
            offsets["guidCallbackOffset"]
        )
    lines += [
        "",
        "HXL1's +0x40/+0x48 is consistent with a layout differing",
        "from both examples. Do NOT impose a different AVB header",
        "or treat these fields as verified, absolute struct definitions.",
        "",
        "## Remaining proof gates", "",
        "- Locate the actual constructor or pointer-table writer for",
        "  the AvbOps-like object passed as pbVar20.",
        "- Prove the implementation assigned at +0x40, and trace any",
        "  TrustZone/RPMB/fuse/partition-derived source independently.",
        "- Distinguish reporting androidboot.vbmeta.device_state from",
        "  enforceable custom-image signature and flashing authorization.",
        "- This is static original-firmware analysis, not an unlock.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path,
                    default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    args = ap.parse_args()
    try:
        root = args.input_dir.expanduser().resolve()
        report = audit(root)
        out = root / "rea-security-audit"
        (out / "avb-callback-fields.json").write_text(json.dumps(report, indent=2) + "\n")
        (out / "avb-callback-fields.md").write_text(markdown(report))
    except (TriageError, OSError, KeyError, TypeError, ValueError) as exc:
        print("[STOP]", str(exc), file=sys.stderr)
        return 2
    for x in report["callSites"]:
        print("[FIELD]", x["callsite"], x["pcode"]["hexOffset"])
    print("[AVB]", "caller 0x2274, variable pbVar20, assignment statements",
          len(report["avbOpsLikeObjectInitializer"]["assignmentStatements"]))
    print("[REPORT]", out / "avb-callback-fields.md")
    print("[LIMIT] Callback initializer, source of lock state and unlock unproved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
