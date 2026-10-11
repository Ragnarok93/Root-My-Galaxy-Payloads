#!/usr/bin/env python3
"""Read-only original HXL1 IsUnlocked native ABI/global provenance checks.

Original Ghidra decompilations disagree: caller 0xb2bc assigns the
value of FUN_00033770() to a byte, while 0x33770 itself decompiles as
void with no return, references DAT_00351055 in a diagnostic and
stack-guard/error context. Neither a valid returned byte nor a trusted
security bit can be concluded from the pseudocode.

Default PLAN ONLY. --execute requests exactly two original instruction
listings and two bounded cross-reference lists. No firmware execution,
unlock attempt, patching, or phone communication.
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
    Runner, choose_targets, evidence, function_record, reference_sources,
    safe_segment,
)
from tools.y2q_hxl1_rea_avb_state_source import (
    audit as validate_state_source,
    verify_wrapper,
)
WRAPPER = "0xb2bc"
SOURCE = "0x33770"
GLOBAL_CANDIDATE = "0x351055"
GUARD_COMPARISON = "0x32a4b8"
INSTRUCTION_QUERIES = (WRAPPER, SOURCE)
XREF_QUERIES = (GLOBAL_CANDIDATE, GUARD_COMPARISON)
MAX_INSTRUCTIONS = 3000


def competing_decompilations(wrapper: dict, source: dict) -> dict:
    valid = verify_wrapper(wrapper)
    owner = function_record(source, SOURCE)
    if owner["entry"] != SOURCE:
        raise TriageError("Original source function identity mismatch")
    text = source["normalized_result"]["pseudocode"]
    lines = text.splitlines()
    if len(lines) < 12 or len(lines) > 100 or not re.search(
        r"\bvoid\s+FUN_00033770\s*\(\s*void\s*\)", text):
        raise TriageError("Original 0x33770 void-function ABI hypothesis changed")
    if re.search(r"\breturn\s+[^;\s]+\s*;", text):
        raise TriageError("Original 0x33770 now decompiles as value-returning function")
    diag = [(i+1, s) for i,s in enumerate(lines)
            if '"IsUnlocked"' in s and "DAT_00351055" in s]
    canary = [(i+1, s) for i,s in enumerate(lines)
              if "DAT_0032a4b8" in s]
    other_global = [(i+1, s) for i,s in enumerate(lines)
                    if "DAT_00351055" in s]
    if len(diag) != 1 or len(canary) < 2 or len(other_global) != 2:
        raise TriageError("Original IsUnlocked diagnostic/global context differs")
    if not any("FUN_0001e81c(DAT_00351055)" in x[1] for x in other_global):
        raise TriageError("Original 0x33770 failure-branch global alias missing")
    return {
        "wrapperEntry": WRAPPER, "sourceEntry": SOURCE,
        "wrapperEvidenceId": wrapper["evidence_id"],
        "sourceEvidenceId": source["evidence_id"],
        "wrapperAssignsByteFromSource": True,
        "sourceDecompilesVoid": True,
        "sourceHasExplicitValueReturn": False,
        "abiReturnTypeInconsistent": True,
        "diagnosticLines": [{"line": i, "code": s.strip()} for i,s in diag],
        "globalCandidateOtherUses": [
            {"line": i, "code": s.strip()} for i,s in other_global],
        "guardComparisonContext": [
            {"line": i, "code": s.strip()} for i,s in canary],
        "returnRegisterDefinitionVerified": False,
        "originalGlobalIsStateProducerVerified": False,
        "crossReferenceIsWriteVerified": False,
        "trustedLockAuthorizationVerified": False,
    }


def instruction_observation(ev: dict, *, entry: str) -> dict:
    """Preserve verbatim bounded provider-native instruction records.

    REA providers may encode native instruction rows differently. Never
    infer register effects from an unrecognized presentation format.
    """
    payload = ev.get("normalized_result")
    records = payload if isinstance(payload, list) else (
        payload.get("instructions") if isinstance(payload, dict) else None)
    if not isinstance(records, list) or len(records) > MAX_INSTRUCTIONS:
        return {
            "evidenceId": ev["evidence_id"], "function": entry,
            "format": type(payload).__name__,
            "recordsRecognized": False, "records": [],
            "nativeReturnRegisterVerified": False,
        }
    selected = []
    for i, item in enumerate(records[:210]):
        if isinstance(item, dict):
            chosen = {k: item.get(k) for k in
                      ("address", "mnemonic", "operands", "disassembly",
                       "instruction", "text", "bytes") if k in item}
            selected.append({"ordinal": i, "fields": chosen or
                             {"raw": str(item)[:480]}})
        else:
            selected.append({"ordinal": i, "raw": str(item)[:480]})
    return {
        "evidenceId": ev["evidence_id"], "function": entry,
        "format": "list", "recordsRecognized": True, "recordCount": len(records),
        "records": selected, "displayTruncated": len(records) > len(selected),
        "nativeReturnRegisterVerified": False,
    }


def audit(root: Path, *, execute: bool=False, rea: Path | None=None,
          node: str="node", timeout: int=240, recover_partials: bool=False) -> dict:
    state = validate_state_source(root)
    if (state.get("originalHXL1ProvenanceVerified") is not True
            or state.get("sourceProvider") is None):
        raise TriageError("Original HXL1 0x33770 dossier is not source-verified")
    targets = {t.name: t for t in choose_targets(root)}
    target = targets["LinuxLoader"]
    folder = root / "rea-security-audit" / "LinuxLoader"
    original_wrapper = evidence(
        folder / ("function-" + safe_segment(WRAPPER) + ".json"),
        sha=target.sha256, operation="analyze_function",
        parameter="procedure", value=WRAPPER)
    original_source = evidence(
        folder / ("function-" + safe_segment(SOURCE) + ".json"),
        sha=target.sha256, operation="analyze_function",
        parameter="procedure", value=SOURCE)
    discrepancy = competing_decompilations(original_wrapper, original_source)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA entrypoint missing or unsafe")
    runner = Runner(root / "rea-security-audit",
                    rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    instructions = []
    for entry in INSTRUCTION_QUERIES:
        result = runner.obtain(
            target, ["instructions", str(target.path), entry],
            folder / ("instructions-" + safe_segment(entry) + ".json"),
            operation="read_function_instructions",
            parameter="procedure", value=entry)
        instructions.append({
            "entry": entry,
            "status": "PROVIDER_RECORD" if result is not None else "PLANNED",
            "observation": instruction_observation(result, entry=entry)
                           if result is not None else None,
        })
    global_refs = []
    for address in XREF_QUERIES:
        result = runner.obtain(
            target, ["xrefs", str(target.path), address],
            folder / ("xrefs-global-" + safe_segment(address) + ".json"),
            operation="xrefs", parameter="address", value=address)
        sources = reference_sources(result) if result is not None else []
        global_refs.append({
            "address": address, "role": "diagnostic-value-candidate" if
            address == GLOBAL_CANDIDATE else "guard-related-comparison",
            "status": "PROVIDER_XREFS" if result is not None else "PLANNED",
            "evidenceId": result["evidence_id"] if result is not None else None,
            "sourceCount": len(sources),
            "sourceAddresses": sources[:150],
            "truncated": len(sources)>150,
            "readerWriterClassification": "UNKNOWN",
            "dataAuthorityVerified": False,
        })
    return {
        "schemaVersion": 1, "mode": "STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "originalArchiveSha256": HXL1_BL_SHA256,
        "originalSourceVerified": True,
        "queriesRequested": len(runner.planned),
        "conflictingDecompilerEvidence": discrepancy,
        "instructions": instructions, "globalReferences": global_refs,
        "trustAuthorityEstablished": False, "unlockedBootloader": False,
        "firmwareModified": False, "handsetModified": False,
    }


def markdown(result: dict) -> str:
    d = result["conflictingDecompilerEvidence"]
    lines = [
        "# Original HXL1 AVB unlock byte — native ABI discrepancy and global xrefs",
        "", "**Static owner-source-attested analysis; no unlock or bypass proven.**",
        "", "- Archive: " + result["originalArchiveSha256"],
        "- Mode: " + result["mode"],
        "- New Ghidra queries: " + str(result["queriesRequested"]),
        "- Original 0xb2bc Evidence: " + d["wrapperEvidenceId"],
        "- Original 0x33770 Evidence: " + d["sourceEvidenceId"], "",
        "## Ghidra discrepancy (must resolve before treating returned byte as valid)",
        "", "- Caller assigns uVar1 = FUN_00033770(), but",
        "  independent 0x33770 pseudocode declares void and returns no expression.",
        "- DAT_00351055 is referenced in an IsUnlocked log message **and**",
        "  the apparent failure/guard tail; it is not a proven state writer.",
        "- DAT_0032a4b8 is seen in a save-and-compare pattern compatible",
        "  with stack-guard bookkeeping, not an established unlock state.", "",
        "### Exact original global references", "", "~~~c",
    ]
    for x in d["globalCandidateOtherUses"]+d["guardComparisonContext"]:
        lines.append(f"{x['line']:5d} | {x['code']}")
    lines += ["~~~", "", "## Native function instruction listings", ""]
    for entry in result["instructions"]:
        lines += [
            "### " + entry["entry"], "",
            "- Status: " + entry["status"],
        ]
        obs = entry["observation"]
        if obs is not None:
            lines += [
                "- Ghidra Evidence: " + obs["evidenceId"],
                "- Provider-native rows recognized: " + str(obs["recordsRecognized"]),
                "- Native return register provenance verified: False",
                "", "~~~text",
            ]
            for row in obs["records"]:
                lines.append(str(row)[:750])
            lines += ["~~~", ""]
    lines += ["## Exact global cross-reference inventories", ""]
    for x in result["globalReferences"]:
        lines += [
            "### " + x["address"], "",
            "- Interpretation: " + x["role"],
            "- Status: " + x["status"],
            "- Evidence: " + str(x["evidenceId"]),
            "- Xrefs (bounded display): " + str(x["sourceAddresses"]),
            "- All references are *unclassified* until inspecting actual instructions.",
            "",
        ]
    lines += [
        "## Next proof gates", "",
        "1. Inspect native instruction effects at the 0xb2bc call and",
        "   0x33770 epilogue. Determine whether W0 is assigned on all",
        "   success paths; a decompiler-inferred byte is not enough.",
        "2. Only then classify reference sites to DAT_00351055 as",
        "   readers/writers and identify the earliest state producer.",
        "3. Separate diagnostic boot-property state from the",
        "   secure boot signature and Odin OEM flash policies.",
        "4. All data and conclusions are static. No device action.", "",
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
    a = ap.parse_args()
    if not 30 <= a.timeout <= 1200:
        ap.error("Timeout out of bounded range")
    try:
        root = a.input_dir.expanduser().resolve()
        report = audit(root, execute=a.execute, rea=a.rea, node=a.node,
                       timeout=a.timeout, recover_partials=a.recover_partials)
        output = root / "rea-security-audit"
        (output / "avb-global-abi.json").write_text(json.dumps(report, indent=2)+"\n")
        (output / "avb-global-abi.md").write_text(markdown(report))
    except (TriageError, OSError, ValueError, TypeError, KeyError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[ABI] 0xb2bc uses byte result of 0x33770; 0x33770 Ghidra return type is void")
    for x in report["instructions"]:
        print("[INSTRUCTIONS]", x["entry"], x["status"])
    for x in report["globalReferences"]:
        print("[XREF]", x["address"], x["status"], x["sourceCount"])
    print("[REPORT]", output / "avb-global-abi.md")
    print("[LIMIT] xrefs are NOT proven writes; W0 byte and trusted state unresolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
