#!/usr/bin/env python3
"""Source-attested HXL1 AVB lock-state supplier audit (host-side static only).

The original 0xb2bc callback decompilation returns 2 on NULL output and,
otherwise, returns 0 while storing FUN_00033770() into the output byte.
This script verifies the original SHA-pinned Ghidra Evidence and
makes at most ONE new Ghidra function query of the direct callee 0x33770.

It DOES NOT treat the reported unlocked bit as the source of authorization,
prove native STORE aliasing, execute firmware, or operate on a handset.
"""
from __future__ import annotations

import argparse
import hashlib
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
from tools.y2q_hxl1_rea_avb_callback_implementations import (
    audit as verify_callback_implementations,
    LOCK_CALLBACK,
)

SOURCE_FN = "0x33770"
MAX_PSEUDOCODE_BYTES = 320000
LINE_CAP = 6000
SELECT_CAP = 240

# Require original Ghidra's very specific wrapper shape, including the
# independent callback status and the output byte assignment. These are
# lexical proof gates, NOT SSA, control-flow dominance, or native code proof.
SOURCE_ASSIGN = re.compile(
    r"^\s*uVar1\s*=\s*FUN_00033770\s*\(\s*\)\s*;\s*$", re.M)
OUTPUT_ASSIGN = re.compile(
    r"^\s*\*param_2\s*=\s*uVar1\s*;\s*$", re.M)
NULL_CHECK = re.compile(
    r"if\s*\(\s*param_2\s*==\s*\(undefined1\s*\*\)\s*0x0\s*\)")
BAD_RETURN = re.compile(r"^\s*uVar3\s*=\s*2\s*;\s*$", re.M)
GOOD_RETURN = re.compile(r"^\s*uVar3\s*=\s*0\s*;\s*$", re.M)
FINAL_RETURN = re.compile(r"^\s*return\s+uVar3\s*;\s*$", re.M)
FN_RE = re.compile(r"\b(?:thunk_)?FUN_([0-9a-f]{8})\s*\(", re.I)
GLOBAL_RE = re.compile(r"\bDAT_([0-9a-f]{8})\b", re.I)
SOURCE_KEYWORDS = re.compile(
    r"unlock|lock|oem|secure|trust|qsee|scm|rpm[bB]|fuse|boot|state|"
    r"rollback|read|write|return|if\s*\(|DAT_|FUN_|switch|case|0x", re.I)


def verify_wrapper(ev: dict) -> dict:
    rec = function_record(ev, LOCK_CALLBACK)
    if rec["entry"] != LOCK_CALLBACK:
        raise TriageError("Original callback owner not 0xb2bc")
    pseudo = ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo, str) or not 0 < len(pseudo) <= 25000:
        raise TriageError("Original HXL1 lock-state callback pseudo missing/oversized")
    patterns = {
        "nullOutputCheck": NULL_CHECK,
        "sourceReadCall": SOURCE_ASSIGN,
        "outputByteAssignment": OUTPUT_ASSIGN,
        "nullError2": BAD_RETURN,
        "success0": GOOD_RETURN,
        "finalStatusReturn": FINAL_RETURN,
    }
    observations = {}
    lines = pseudo.splitlines()
    for label, pat in patterns.items():
        matches = list(pat.finditer(pseudo))
        if len(matches) != 1:
            raise TriageError(f"Original Ghidra callback has missing/ambiguous {label}")
        line = pseudo[:matches[0].start()].count("\n") + 1
        observations[label] = {"line": line, "source": lines[line-1].strip()}
    null_line = observations["nullOutputCheck"]["line"]
    source_line = observations["sourceReadCall"]["line"]
    output_line = observations["outputByteAssignment"]["line"]
    if not (
        null_line < observations["nullError2"]["line"] < source_line
        < observations["success0"]["line"] < output_line
        < observations["finalStatusReturn"]["line"]
    ):
        raise TriageError("Original callback decompilation branch ordering changed")
    return {
        "entry": LOCK_CALLBACK,
        "evidenceId": ev["evidence_id"],
        "lines": len(lines),
        "observations": observations,
        "sourceFunction": SOURCE_FN,
        "nullOutputStatusInPseudocode": 2,
        "nonNullOutputStatusInPseudocode": 0,
        "runtimeBehaviorOrSecurityAuthorityProven": False,
        "protectedStateSourceIdentified": False,
    }


def source_dossier(ev: dict) -> dict:
    rec = function_record(ev, SOURCE_FN)
    if rec["entry"] != SOURCE_FN:
        raise TriageError("HXL1 Ghidra 0x33770 function identity not established")
    pseudo = ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo, str) or not pseudo.strip() or len(pseudo) > MAX_PSEUDOCODE_BYTES:
        raise TriageError("Original 0x33770 Ghidra pseudocode missing or too large")
    lines = pseudo.splitlines()
    if len(lines) > LINE_CAP:
        raise TriageError("Original source-provider Ghidra dossier exceeds bounded lines")
    matches = [i for i, text in enumerate(lines) if SOURCE_KEYWORDS.search(text)]
    selected = set(range(min(40, len(lines))))
    for i in matches[:60]:
        selected.update(range(max(0, i-4), min(len(lines), i+6)))
    chosen = sorted(selected)[:SELECT_CAP]
    calls = {}
    globals_seen = {}
    for i, line in enumerate(lines):
        for address in FN_RE.findall(line):
            name = "0x" + address.lower().lstrip("0")
            if name == "0x":
                name = "0x0"
            calls.setdefault(name, []).append(i+1)
        for address in GLOBAL_RE.findall(line):
            name = "0x" + address.lower().lstrip("0")
            globals_seen.setdefault(name, []).append(i+1)
    return {
        "entry": SOURCE_FN, "evidenceId": ev["evidence_id"],
        "pcodeAvailable": rec["pcodeAvailable"],
        "fullPseudocodeSha256": hashlib.sha256(pseudo.encode()).hexdigest(),
        "fullPseudocodeLineCount": len(lines),
        "sourceKeywordLines": [i+1 for i in matches[:80]],
        "excerptTruncated": len(selected)>len(chosen) or len(matches)>60,
        "selectedOriginalPseudocode": [
            {"line": i+1, "code": lines[i][:750]} for i in chosen
        ],
        "functionReferences": [
            {"entry": name, "lines": ln[:16]}
            for name,ln in list(calls.items())[:100]
        ],
        "globalReferences": [
            {"address": name, "lines": ln[:16]}
            for name,ln in list(globals_seen.items())[:100]
        ],
        "directCallsStillRequireDestinationVerification": True,
        "trustAnchorIdentified": False, "sourceSecurityAuthorityProven": False,
    }


def audit(root: Path, *, execute: bool = False,
          rea: Path | None = None, node: str = "node",
          timeout: int = 240, recover_partials: bool = False) -> dict:
    prior = verify_callback_implementations(root)
    if (not prior["originalEvidencesAttested"]
            or prior["lockStateCallback"] is None
            or prior["otherCallbackLabel"] is None):
        raise TriageError("Original 0xb2bc function and 0xb30c label not source-attested")
    if prior["lockStateCallback"]["owningProcedure"] != LOCK_CALLBACK:
        raise TriageError("Unverified original AvbOps +0x40 callback owner")
    targets = {t.name: t for t in choose_targets(root)}
    target = targets["LinuxLoader"]
    folder = root / "rea-security-audit" / "LinuxLoader"
    cb = evidence(folder / ("function-" + safe_segment(LOCK_CALLBACK) + ".json"),
                  sha=target.sha256, operation="analyze_function",
                  parameter="procedure", value=LOCK_CALLBACK)
    wrapper = verify_wrapper(cb)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA Node script missing/symlinked")
    runner = Runner(root / "rea-security-audit",
                    rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    source = runner.obtain(
        target, ["function", str(target.path), SOURCE_FN],
        folder / ("function-" + safe_segment(SOURCE_FN) + ".json"),
        operation="analyze_function", parameter="procedure", value=SOURCE_FN)
    return {
        "schemaVersion": 1, "originalBLArchiveSHA256": HXL1_BL_SHA256,
        "originalHXL1ProvenanceVerified": True,
        "mode": "STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "queriesRequested": len(runner.planned),
        "callback": wrapper,
        "sourceProvider": source_dossier(source) if source else None,
        "actualSecurityStateOriginVerified": False,
        "deviceBootloaderUnlocked": False,
        "signatureOrOdinPolicyBypassVerified": False,
        "handsetModified": False,
    }


def markdown(report: dict) -> str:
    callback = report["callback"]
    lines = [
        "# Original HXL1 LinuxLoader unlock-state source 0x33770",
        "",
        "Original Samsung firmware static decompilation, authenticated evidence.",
        "No unlock, bypass, secure-state authority or runtime behavior claimed.",
        "", "- BL archive SHA256: " + report["originalBLArchiveSHA256"],
        "- Execution mode: " + report["mode"],
        "- New host Ghidra queries: " + str(report["queriesRequested"]), "",
        "## Callback wrapper 0xb2bc — exact original Ghidra observations", "",
        "- Callback Evidence: " + callback["evidenceId"],
        "- Direct source call: " + callback["sourceFunction"],
        "- NULL output branch sets status 2; non-NULL output branch sets status 0.",
        "- Success status is separate from the unlock-state output byte.",
        "- Native flow and secure-state origin require additional evidence.", "",
        "### Source-verified original callback statements", "", "~~~c",
    ]
    for k, obs in callback["observations"].items():
        lines.append(f"{obs['line']:5d} | {obs['source']}")
    lines += ["~~~", "", "## Original candidate state producer 0x33770", ""]
    src = report["sourceProvider"]
    if src is None:
        lines += ["Only the original direct call is verified; Ghidra source dossier not yet collected.", ""]
    else:
        lines += [
            "- Original Ghidra Evidence: " + src["evidenceId"],
            "- Owning function entry: " + src["entry"],
            "- Pseudocode lines: " + str(src["fullPseudocodeLineCount"]),
            "- Full decompilation SHA256: " + src["fullPseudocodeSha256"],
            "- Ghidra native p-code available: " + str(src["pcodeAvailable"]),
            "- Direct-function lexical references: " + str(src["functionReferences"]),
            "- Global-data lexical references: " + str(src["globalReferences"]),
            "", "### Bounded original function pseudocode", "", "~~~c",
        ]
        for line in src["selectedOriginalPseudocode"]:
            lines.append(f"{line['line']:5d} | {line['code']}")
        lines += ["~~~", ""]
        if src["excerptTruncated"]:
            lines += ["This is a bounded excerpt; original function Evidence is preserved in full.", ""]
    lines += [
        "## Outstanding proof gates", "",
        "1. Determine whether 0x33770 reads a global, persistent partition,",
        "   secure service, or a derived predicate. Do not infer one from",
        "   the callback's name or its return value.",
        "2. Distinguish any final AVB device-state output from enforcement",
        "   of image signatures and Odin flashing authorization.",
        "3. Follow only Ghidra-supported function and storage references",
        "   and preserve unresolved aliases/returns as unknown.",
        "4. No device, firmware, unlock state or signature was modified.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path,
                    default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea", type=Path, default=Path.home() / "src/rea/scripts/rea.mjs")
    ap.add_argument("--node", default="node")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--recover-partials", action="store_true")
    ap.add_argument("--timeout", type=int, default=240)
    opts = ap.parse_args()
    if not 30 <= opts.timeout <= 1200:
        ap.error("Invalid bounded static REA timeout")
    try:
        root = opts.input_dir.expanduser().resolve()
        report = audit(root, execute=opts.execute, rea=opts.rea,
                       node=opts.node, timeout=opts.timeout,
                       recover_partials=opts.recover_partials)
        out = root / "rea-security-audit"
        (out / "avb-unlock-state-source.json").write_text(json.dumps(report, indent=2) + "\n")
        (out / "avb-unlock-state-source.md").write_text(markdown(report))
    except (TriageError, OSError, ValueError, TypeError, KeyError) as err:
        print("[STOP]", err, file=sys.stderr)
        return 2
    print("[CALLBACK]", LOCK_CALLBACK, "source", SOURCE_FN,
          "status NULL=2 nonNULL=0")
    print("[SOURCE]", SOURCE_FN,
          "GHIDRA_FUNCTION_VERIFIED" if report["sourceProvider"] else "PLAN_ONLY")
    print("[REPORT]", out / "avb-unlock-state-source.md")
    print("[LIMIT] Source authority, signed-image policy and unlock NOT verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
