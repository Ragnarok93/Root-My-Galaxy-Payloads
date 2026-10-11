#!/usr/bin/env python3
"""Bounded original-HXL1 LinuxLoader AvbOps constructor evidence audit.

At saved LinuxLoader 0x2274 line 343, pbVar20 is assigned the result of
FUN_0000b7a4(pcVar19); later the same decompiler variable is passed to
FUN_00005950. Only an original-SHA-validated Ghidra dossier of 0xb7a4 can
establish which callback slots it actually initializes.

Default: inspect/PLAN only; --execute makes ONE bounded Ghidra function query.
The tool does not execute firmware, modify images, or communicate with a phone.
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
from tools.y2q_hxl1_avb_callback_fields import audit as validate_saved_fields

CONSTRUCTOR = "0xb7a4"
CONSUMER = "0x5950"
CALLER = "0x2274"
MAX_FUNCTION_CHARS = 400000
PATTERN_CONSTRUCTOR = re.compile(
    r"\bpbVar20\s*=\s*\(byte\s*\*\)\s*FUN_0000b7a4\s*\(\s*pcVar19\s*\)\s*;"
)
PATTERN_CONSUMER = re.compile(r"\bFUN_00005950\s*\(\s*pbVar20\s*,")
PATTERN_CALL = re.compile(r"\b(?:thunk_)?FUN_([0-9a-f]{8})\s*\(", re.I)
PATTERN_FIELD = re.compile(r"(?:\+\s*0x(?:40|48)\b|\[\s*(?:8|9)\s*\])", re.I)
PATTERN_POINTER = re.compile(r"(\*\s*\([^)]*\)\s*|\*\s*\w+\s*=)")
PATTERN_ALLOC = re.compile(r"alloc|free|memset|memcpy|zero|init|write|register", re.I)


def attest_original_caller(root: Path, sha: str) -> dict:
    path = root / "rea-security-audit" / "LinuxLoader" / "function-0x3f34.json"
    original = evidence(path, sha=sha, operation="analyze_function",
                        parameter="procedure", value="0x3f34")
    record = function_record(original, "0x3f34")
    if record["entry"] != CALLER:
        raise TriageError("Original source does not own AVB constructor call")
    pseudo = original["normalized_result"]["pseudocode"]
    lines = pseudo.splitlines()
    allocs = [(i + 1, x) for i, x in enumerate(lines)
              if PATTERN_CONSTRUCTOR.search(x)]
    consumers = [(i + 1, x) for i, x in enumerate(lines)
                 if PATTERN_CONSUMER.search(x)]
    if len(allocs) != 1 or len(consumers) != 1:
        raise TriageError("Original Ghidra allocation/consumer evidence missing or ambiguous")
    if allocs[0][0] >= consumers[0][0]:
        raise TriageError("Original Ghidra constructor/callsite order changed")
    return {
        "originalCallerEvidenceId": original["evidence_id"],
        "caller": CALLER,
        "constructorAssignmentLine": allocs[0][0],
        "constructorAssignment": allocs[0][1].strip(),
        "consumerLine": consumers[0][0],
        "consumerStatement": consumers[0][1].strip(),
        "pointerIdentity": "GHIDRA_SAME_PSEUDOCODE_VARIABLE",
        "dominationOrControlFlowProven": False,
        "allocationAndCleanupPathsDistinguished": False,
    }


def inspect_constructor(ev: dict) -> dict:
    data = ev.get("normalized_result")
    if not isinstance(data, dict):
        raise TriageError("Ghidra constructor has no normalized result")
    record = function_record(ev, CONSTRUCTOR)
    if record["entry"] != CONSTRUCTOR:
        raise TriageError("Original Ghidra constructor entry is not 0xb7a4")
    pseudo = data.get("pseudocode")
    if not isinstance(pseudo, str) or not pseudo.strip() or len(pseudo) > MAX_FUNCTION_CHARS:
        raise TriageError("Original HXL1 constructor pseudocode missing or excessive")
    lines = pseudo.splitlines()
    if len(lines) > 8000:
        raise TriageError("Excessive constructor pseudocode line count")
    hits = []
    callees = {}
    slot_lines = []
    for i, line in enumerate(lines):
        m = PATTERN_FIELD.search(line)
        if m:
            slot_lines.append(i)
        for symbol in PATTERN_CALL.findall(line):
            label = "0x" + symbol.lower().lstrip("0")
            callees.setdefault(label, []).append(i + 1)
        if m or PATTERN_ALLOC.search(line) or PATTERN_POINTER.search(line):
            hits.append(i)
    keep = set(range(min(30, len(lines))))
    for i in (hits[:48] + slot_lines[:32]):
        keep.update(range(max(0, i - 4), min(len(lines), i + 6)))
    selected = sorted(keep)[:220]
    # Pseudocode matching a field is a lexical observation, not a proven STORE
    # alias or executed memory write.
    return {
        "entry": CONSTRUCTOR, "evidenceId": ev["evidence_id"],
        "pcodeAvailable": record["pcodeAvailable"],
        "totalLines": len(lines),
        "fullPseudocodeSha256": __import__("hashlib").sha256(pseudo.encode()).hexdigest(),
        "fieldOffsetCandidateLines": [i + 1 for i in slot_lines],
        "fieldMatchesAreLexicalOnly": True,
        "directCalleesInPseudocode": [
            {"entry": key, "lines": value[:16]}
            for key, value in list(callees.items())[:80]
        ],
        "selectedPseudocode": [
            {"line": i + 1, "code": lines[i][:600]} for i in selected
        ],
        "selectedContextTruncated": len(keep) > len(selected) or len(hits) > 48,
        "callbacksAssignedVerified": False,
        "lockStateCallbackFunctionIdentified": False,
        "trustedSourceOfStateIdentified": False,
    }


def audit(root: Path, *, execute: bool = False, rea: Path | None = None,
          node: str = "node", timeout: int = 240,
          recover_partials: bool = False) -> dict:
    verified = validate_saved_fields(root)
    if not verified.get("allOriginalHxl1SourcesVerified"):
        raise TriageError("Original HXL1 source and callback field proofs incomplete")
    targets = {x.name: x for x in choose_targets(root)}
    linux = targets["LinuxLoader"]
    provenance = attest_original_caller(root, linux.sha256)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA script missing or unsafe on host")
    result_dir = root / "rea-security-audit" / "LinuxLoader"
    runner = Runner(root / "rea-security-audit",
                    rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    # NEVER replace the owner's saved 0x2274 and 0x5950 root evidence.
    filename = "function-" + safe_segment(CONSTRUCTOR) + ".json"
    response = runner.obtain(
        linux, ["function", str(linux.path), CONSTRUCTOR],
        result_dir / filename, operation="analyze_function",
        parameter="procedure", value=CONSTRUCTOR)
    observed = inspect_constructor(response) if response is not None else None
    return {
        "schemaVersion": 1,
        "originalArchiveSha256": HXL1_BL_SHA256,
        "sourceAttested": True, "mode": "STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "caller": provenance, "constructorFunction": CONSTRUCTOR,
        "constructorEvidence": observed,
        "queryCommands": len(runner.planned),
        "callbackTableInitializerProven": False,
        "secureLockStateAuthorityProven": False,
        "signatureAuthorizationBypassProven": False,
        "bootloaderUnlocked": False, "phoneModified": False,
    }


def markdown(report: dict) -> str:
    c = report["caller"]
    lines = [
        "# HXL1 original LinuxLoader AvbOps allocation/initializer source",
        "",
        "**Original SHA256-pinned Ghidra evidence only.**",
        "No callback implementation, secured unlock state, or authorization bypass proven.",
        "", "- Original BL SHA256: " + report["originalArchiveSha256"],
        "- Mode: " + report["mode"],
        "- New Ghidra queries: " + str(report["queryCommands"]), "",
        "## Authenticated 0x2274 source and constructor call", "",
        "- Caller Evidence: " + c["originalCallerEvidenceId"],
        "- Constructor result assignment (line " + str(c["constructorAssignmentLine"]) +
          "): " + c["constructorAssignment"],
        "- AVB verification consumer (line " + str(c["consumerLine"]) +
          "): " + c["consumerStatement"],
        "- Constructor candidate: FUN_0000b7a4 / " + CONSTRUCTOR,
        "- Same decompiler variable; full control-flow dominance not yet established.", "",
    ]
    e = report["constructorEvidence"]
    if e is None:
        lines += [
            "## Constructor dossier not yet collected", "",
            "Ghidra function dossier for 0xb7a4 is planned but not present.", "",
        ]
    else:
        lines += [
            "## Original constructor 0xb7a4", "",
            "- Original Ghidra Evidence: " + e["evidenceId"],
            "- Full pseudocode lines: " + str(e["totalLines"]),
            "- SHA256 of full decompilation text: " + e["fullPseudocodeSha256"],
            "- Ghidra native p-code available: " + str(e["pcodeAvailable"]),
            "- Lines mentioning +0x40/+0x48 or indexed callback slots: " +
              str(e["fieldOffsetCandidateLines"]),
            "- Static decompilation callees: " + str(e["directCalleesInPseudocode"][:30]),
            "- Callback-slot *write* proven: False (requires actual STORE/dataflow)", "",
            "### Bounded original pseudocode excerpt", "", "~~~c",
        ]
        for row in e["selectedPseudocode"]:
            lines.append(f"{row['line']:5d} | {row['code']}")
        lines += ["~~~", ""]
        if e["selectedContextTruncated"]:
            lines += ["Excerpt truncated; inspect original saved function Evidence.", ""]
    lines += [
        "## Remaining gates", "",
        "1. Determine whether 0xb7a4 initializes callback fields +0x40/+0x48",
        "   itself or delegates to a direct helper. Trace only source-proved callees.",
        "2. Identify the concrete pointer installed at +0x40. A string name",
        "   and an ABI-compatible offset are not proof of the implementation.",
        "3. Trace return/error behavior of the callback separately from",
        "   trust/lock authorization in AVB, Odin and secure-world components.",
        "4. Static observations never demonstrate exploitable access or",
        "   a working bootloader unlock.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path,
                   default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea", type=Path,
                   default=Path.home() / "src/rea/scripts/rea.mjs")
    p.add_argument("--node", default="node")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--recover-partials", action="store_true")
    p.add_argument("--timeout", type=int, default=240)
    a = p.parse_args()
    if not 30 <= a.timeout <= 1200:
        p.error("Ghidra execution timeout out of bounds")
    try:
        root = a.input_dir.expanduser().resolve()
        report = audit(root, execute=a.execute, rea=a.rea, node=a.node,
                       timeout=a.timeout, recover_partials=a.recover_partials)
        folder = root / "rea-security-audit"
        (folder / "avb-constructor.json").write_text(json.dumps(report, indent=2) + "\n")
        (folder / "avb-constructor.md").write_text(markdown(report))
    except (TriageError, OSError, KeyError, ValueError, TypeError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    status = "VERIFIED_GHIDRA_FUNCTION" if report["constructorEvidence"] else "PLAN_ONLY"
    print("[CALLER]", report["caller"]["caller"], "=>", report["constructorFunction"])
    print("[FUNCTION]", report["constructorFunction"], status)
    print("[REPORT]", folder / "avb-constructor.md")
    print("[LIMIT] Callback slot writers, unlock-state origin and bypass unproved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
