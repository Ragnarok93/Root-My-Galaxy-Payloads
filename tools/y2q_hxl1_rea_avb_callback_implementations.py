#!/usr/bin/env python3
"""Original-HXL1 AVB callback implementation identification (host-only).

Pin and verify the owner's SHA256-attested LinuxLoader constructor, original
AVB caller, and the observed +0x40/+0x48 p-code LOAD fields before querying
ONLY the constructor-assigned targets. Default is PLAN ONLY.

The original 0xb7a4 Ghidra decompilation assigns:
  puVar2[8] = FUN_0000b2bc;    (byte offset +0x40)
  puVar2[9] = &LAB_0000b30c;  (byte offset +0x48)
Neither assignment alone proves the implementation's trust authority.
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
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, function_record, safe_segment,
)
from tools.y2q_hxl1_rea_avb_constructor import audit as verify_constructor
from tools.y2q_hxl1_avb_callback_fields import audit as verify_field_sources

CONSTRUCTOR = "0xb7a4"
LOCK_CALLBACK = "0xb2bc"
GUID_LABEL = "0xb30c"
VALIDATION_CAP = 150000
EXPECTED_SLOT_ASSIGNMENTS = (
    (8, "FUN_0000b2bc", "+0x40", "read-is-unlocked-candidate"),
    (9, "&LAB_0000b30c", "+0x48", "other-avb-callback-label"),
)
PATTERN_ALLOCATION = re.compile(
    r"\bpuVar2\s*=\s*\(undefined8\s*\*\)\s*FUN_00008cd4\s*\(\s*0x60\s*\)\s*;"
)
PATTERN_USER_DATA = re.compile(r"^\s*\*puVar2\s*=\s*param_1\s*;\s*$", re.M)
NEXT_KEYWORDS = re.compile(
    r"unlock|lock|secure|state|rpmb|fuse|scm|qsee|vault|read|"
    r"return|\\bif\\b|boot|error|partition", re.I,
)


def verified_constructor_slots(ev: dict) -> dict:
    """Validate *exact* saved Ghidra constructor pseudo assignments.

    Do not reinterpret this as a verified native STORE or runtime call target.
    """
    verified = function_record(ev, CONSTRUCTOR)
    if verified["entry"] != CONSTRUCTOR:
        raise TriageError("Source-attested Ghidra constructor owner mismatch")
    raw = ev["normalized_result"].get("pseudocode")
    if not isinstance(raw, str) or not 0 < len(raw) <= VALIDATION_CAP:
        raise TriageError("Missing or oversized original constructor pseudocode")
    lines = raw.splitlines()
    if len(lines) > 350:
        raise TriageError("Unexpectedly large HXL1 AvbOps constructor")
    alloc_lines = [i+1 for i,l in enumerate(lines) if PATTERN_ALLOCATION.search(l)]
    userdata_lines = [i+1 for i,l in enumerate(lines) if PATTERN_USER_DATA.match(l)]
    if len(alloc_lines) != 1 or len(userdata_lines) != 1:
        raise TriageError("Original constructor allocation or user-data assignment mismatch")
    slots = []
    for ordinal, symbol, offset, role in EXPECTED_SLOT_ASSIGNMENTS:
        expr = re.compile(
            r"^\s*puVar2\[\s*" + str(ordinal) + r"\s*\]\s*=\s*" +
            re.escape(symbol) + r"\s*;\s*$"
        )
        matches = [(i+1, s.strip()) for i,s in enumerate(lines) if expr.match(s)]
        all_assignments = [
            (i+1, s.strip()) for i,s in enumerate(lines)
            if re.match(r"^\s*puVar2\[\s*"+str(ordinal)+r"\s*\]\s*=", s)
        ]
        if len(matches) != 1 or len(all_assignments) != 1:
            raise TriageError(f"AvbOps slot {ordinal} has missing/conflicting original assignments")
        slots.append({
            "slotIndex": ordinal, "byteOffset": offset, "symbol": symbol,
            "semanticRoleHypothesis": role, "lineNumber": matches[0][0],
            "originalGhidraAssignment": matches[0][1],
            "nativeStoreValidated": False, "runtimeFunctionPointerObserved": False,
        })
    if not alloc_lines[0] < userdata_lines[0] < min(x["lineNumber"] for x in slots):
        raise TriageError("Unexpected Ghidra allocation/slot assignment ordering")
    return {
        "constructor": CONSTRUCTOR, "originalEvidenceId": ev["evidence_id"],
        "allocationBytes": 0x60,
        "allocationLine": alloc_lines[0],
        "userDataLine": userdata_lines[0],
        "slots": slots,
        "nativeStoreValidated": False,
        "callbackFunctionVerified": False,
        "callbackTrustSourceVerified": False,
    }


def callback_dossier(ev: dict) -> dict:
    record = function_record(ev, LOCK_CALLBACK)
    if record["entry"] != LOCK_CALLBACK:
        raise TriageError("Lock-state callback candidate has unexpected owning procedure")
    data = ev["normalized_result"]
    pseudo = data.get("pseudocode")
    if not isinstance(pseudo, str) or not pseudo.strip() or len(pseudo) > 300000:
        raise TriageError("Original callback pseudocode missing/oversized")
    lines = pseudo.splitlines()
    if len(lines) > 5000:
        raise TriageError("Callback dossier exceeds bounded decompilation limit")
    # Full display for small functions, otherwise context around decision-bearing
    # lines. Original function Evidence always remains unmodified in its saved JSON.
    matching = [i for i,v in enumerate(lines) if NEXT_KEYWORDS.search(v)]
    keep = set(range(min(40, len(lines))))
    for i in matching[:40]:
        keep.update(range(max(0, i-5), min(len(lines), i+7)))
    chosen = sorted(keep)[:230]
    return {
        "function": LOCK_CALLBACK, "originalEvidenceId": ev["evidence_id"],
        "owningProcedure": record["entry"], "pcodeAvailable": record["pcodeAvailable"],
        "totalPseudocodeLines": len(lines),
        "keywordMatchLines": [i+1 for i in matching[:45]],
        "displayTruncated": len(keep) > len(chosen) or len(matching) > 40,
        "selectedPseudocode": [
            {"line": i+1, "code": lines[i][:650]} for i in chosen
        ],
        "returnCodeSemanticsVerified": False,
        "secureStateSourceVerified": False,
        "signatureAcceptanceControlledByThisCallback": False,
    }


def label_dossier(ev: dict) -> dict:
    d = ev.get("normalized_result")
    if not isinstance(d, dict) or d.get("address") != GUID_LABEL:
        raise TriageError("Incorrect target instruction from original LinuxLoader")
    status = d.get("status")
    if status not in ("decoded", "not-instruction-boundary", "data",
                      "undecodable", "outside-memory"):
        raise TriageError("Invalid native instruction decode status at AvbOps slot 9 label")
    return {
        "address": GUID_LABEL, "originalEvidenceId": ev["evidence_id"],
        "nativeStatus": status,
        "owningProcedure": d.get("procedure"),
        "mnemonic": d.get("mnemonic"), "disassembly": d.get("raw_disassembly"),
        "functionEntryProven": False,
        "semanticRoleProven": False,
    }


def audit(root: Path, *, execute: bool = False,
          rea: Path | None = None, node: str = "node",
          timeout: int = 240, recover_partials: bool = False) -> dict:
    # Preserve all original stock-FW and owner-recorded association gates.
    prev = verify_constructor(root)
    if prev["sourceAttested"] is not True or prev.get("constructorEvidence") is None:
        raise TriageError("Original HXL1 0xb7a4 constructor Evidence not verified")
    fields = verify_field_sources(root)
    if fields.get("allOriginalHxl1SourcesVerified") is not True:
        raise TriageError("Original HXL1 callback field Evidence not verified")
    observed = {x["callsite"]: x["pcode"]["hexOffset"] for x in fields["callSites"]}
    if observed != {"0x5dc4": "0x40", "0x5ea4": "0x48", "0x6020": "0x48"}:
        raise TriageError("Original callsite and callback field offsets inconsistent")
    target = {x.name: x for x in choose_targets(root)}["LinuxLoader"]
    original = evidence(
        root / "rea-security-audit/LinuxLoader/function-0xb7a4.json",
        sha=target.sha256, operation="analyze_function",
        parameter="procedure", value=CONSTRUCTOR)
    slots = verified_constructor_slots(original)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA script absent or unsafe on owner host")
    folder = root / "rea-security-audit/LinuxLoader"
    runner = Runner(root / "rea-security-audit",
                    rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    # Ghidra FUN_0000b2bc implies a function entry candidate.
    callback = runner.obtain(
        target, ["function", str(target.path), LOCK_CALLBACK],
        folder / ("function-" + safe_segment(LOCK_CALLBACK) + ".json"),
        operation="analyze_function", parameter="procedure", value=LOCK_CALLBACK)
    # LAB_0000b30c is a *label*, not necessarily a function entry.
    label = runner.obtain(
        target, ["inspect-native-instruction", str(target.path), GUID_LABEL],
        folder / ("instruction-" + safe_segment(GUID_LABEL) + ".json"),
        operation="inspect_native_instruction", parameter="address", value=GUID_LABEL)
    return {
        "schemaVersion": 1, "archiveSha256": HXL1_BL_SHA256,
        "originalGhidraConstructor": slots,
        "mode": "STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "newQueries": len(runner.planned),
        "lockStateCallback": callback_dossier(callback) if callback else None,
        "otherCallbackLabel": label_dossier(label) if label else None,
        "originalEvidencesAttested": True,
        "samsungSecureStateAuthorityVerified": False,
        "bootloaderAuthorizationBypassVerified": False,
        "unlockDemonstrated": False, "deviceModified": False,
    }


def markdown(report: dict) -> str:
    slots = report["originalGhidraConstructor"]
    lines = [
        "# HXL1 original AVB callback table assignments and implementation",
        "", "**Saved original stock HXL1 Ghidra Evidence only; no unlock is proven.**",
        "", "Source BL SHA256: " + report["archiveSha256"],
        "New Ghidra queries: " + str(report["newQueries"]), "",
        "## Verified Ghidra constructor assignments", "",
        f"- Constructor: {slots['constructor']}",
        f"- Original Evidence: {slots['originalEvidenceId']}",
        f"- Allocated object size: {slots['allocationBytes']} bytes",
    ]
    for s in slots["slots"]:
        lines += [
            "- Slot " + str(s["slotIndex"]) + " / " + s["byteOffset"] +
            " => " + s["symbol"] + " (original line " +
            str(s["lineNumber"]) + ")",
            "  - " + s["originalGhidraAssignment"],
        ]
    lines += [
        "", "Assignments are **decompiler observations**. Native STORE",
        "aliasing, runtime reachability, and the protected state source",
        "have not been proven.", "",
        "## +0x40 callback 0xb2bc — original Ghidra dossier", "",
    ]
    fn = report["lockStateCallback"]
    if fn is None:
        lines += ["No original function dossier collected yet.", ""]
    else:
        lines += [
            "- Evidence: " + fn["originalEvidenceId"],
            "- Owning entry: " + fn["owningProcedure"],
            "- Original pseudocode lines: " + str(fn["totalPseudocodeLines"]),
            "- Ghidra p-code available: " + str(fn["pcodeAvailable"]),
            "", "~~~c",
        ]
        for row in fn["selectedPseudocode"]:
            lines.append(f"{row['line']:5d} | {row['code']}")
        lines += ["~~~", ""]
        if fn["displayTruncated"]:
            lines += ["Pseudocode excerpt truncated; inspect the saved original JSON.", ""]
    lines += ["## +0x48 target LAB_0000b30c — native instruction check", ""]
    label = report["otherCallbackLabel"]
    if label is None:
        lines += ["Exact original instruction not yet inspected.", ""]
    else:
        lines += [
            "- Evidence: " + label["originalEvidenceId"],
            "- Instruction status: " + label["nativeStatus"],
            "- Owning function (if Ghidra identified): " + str(label["owningProcedure"]),
            "- Native instruction: " + str(label["disassembly"]),
            "- Function entry at label verified: False", "",
        ]
    lines += [
        "## Unproven security gates", "",
        "- Prove whether the 0xb2bc code reads a Samsung/Qualcomm trusted",
        "  state provider or merely translates a higher-level state.",
        "- Identify the underlying source and failure treatment without",
        "  presuming VaultKeeper, RPMB, eFuse, or a vulnerable branch.",
        "- The 0xb30c LAB label cannot be promoted to a function entry",
        "  until independently established from native instructions.",
        "- Boot-property reporting is distinct from Odin flashing",
        "  authorization and secure boot image verification.",
        "- No flash, device write, signature bypass or unlock was attempted.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path, default=Path.home() /
                    "s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea", type=Path, default=Path.home() /
                    "src/rea/scripts/rea.mjs")
    ap.add_argument("--node", default="node")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--recover-partials", action="store_true")
    ap.add_argument("--timeout", type=int, default=240)
    opts = ap.parse_args()
    if not 30 <= opts.timeout <= 1200:
        ap.error("Timeout outside bounded source analysis range")
    try:
        root = opts.input_dir.expanduser().resolve()
        report = audit(root, execute=opts.execute, rea=opts.rea, node=opts.node,
                       timeout=opts.timeout, recover_partials=opts.recover_partials)
        out = root / "rea-security-audit"
        (out / "avb-callback-implementations.json").write_text(
            json.dumps(report, indent=2) + "\n")
        (out / "avb-callback-implementations.md").write_text(markdown(report))
    except (TriageError, OSError, ValueError, KeyError, TypeError) as err:
        print("[STOP]", err, file=sys.stderr)
        return 2
    cb = report["lockStateCallback"]
    lb = report["otherCallbackLabel"]
    print("[SLOT] +0x40", LOCK_CALLBACK,
          "function-verified" if cb else "not-collected")
    print("[SLOT] +0x48", GUID_LABEL,
          lb["nativeStatus"] if lb else "not-collected")
    print("[REPORT]", out / "avb-callback-implementations.md")
    print("[LIMIT] Secure lock-state origin and unlock authorization unproven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
