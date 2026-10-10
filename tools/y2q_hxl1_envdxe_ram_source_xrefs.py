#!/usr/bin/env python3
"""Authenticate HXL1 stock EnvDxe startup callees and exact diagnostic xrefs.

All inputs are previously verified original-PE REA/Ghidra evidence.
This program does not contact the handset, bypass kernel read protections,
infer a boot-time physical RAM base, or assert provider registration from a
mere string/indirect call.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_envdxe_entry_strings import (
    analyze as entry_strings_audit, evidence_json, contains,
    PE_SHA256, REPORT_DIR, ExtractionError, COORD, MAX_CODE,
)

TARGET_FUNCTIONS = (
    ("startup-helper", "0x10f4", "FUN_000010f4"),
    ("env-initializer", "0x1150", "FUN_00001150"),
)
TARGET_STRING_XREFS = (
    ("ram-table-lib", "ram-partition", "0xa87e", "RamPartitionTableLib.c"),
    ("ram-entry-limit", "ram-partition", "0xa895", "mRamPartitionTableEntryCount <= 4"),
    ("env-driver-source", "env-driver", "0x90bf", "EnvDxe.c"),
)
ADDRESS = re.compile(r"^(?:0x[0-9a-fA-F]+|[A-Za-z0-9._~-]+:0x[0-9a-fA-F]+)$")
MAX_REFS = 10000
MAX_PCODE = 120000

def canonical_address(value: str) -> str:
    if not isinstance(value, str) or not ADDRESS.fullmatch(value):
        raise ExtractionError("Malformed original Ghidra xref address")
    return value


def validated_baseline(folder: Path) -> dict:
    baseline = entry_strings_audit(folder)
    if baseline.get("originalEnvDxeSha256") != PE_SHA256:
        raise ExtractionError("Baseline is not exact stock EnvDxe")
    functions = baseline.get("entryFunction")
    if not isinstance(functions, dict):
        raise ExtractionError("Authenticated original EnvDxe entry evidence missing")
    code = functions.get("pseudocode")
    if (not isinstance(code, str) or
        "FUN_000010f4()" not in code or
        "FUN_00001150(" not in code):
        raise ExtractionError("Original PE startup call graph changed")
    searches = baseline.get("stringSearches")
    if not isinstance(searches, list):
        raise ExtractionError("Original Ghidra diagnostic string results missing")
    by_label = {s["label"]: s for s in searches if isinstance(s, dict)}
    for _, group, coordinate, exact_text in TARGET_STRING_XREFS:
        rec = by_label.get(group, {})
        hits = [h for h in rec.get("hits", [])
                if h.get("address") == coordinate and
                h.get("value") == exact_text]
        if len(hits) != 1:
            raise ExtractionError("Original stock EnvDxe string address/text not proven: "
                                  + coordinate)
    return baseline


def audited_xrefs(folder: Path, item: tuple[str, str, str, str]) -> dict:
    label, group, at, text = item
    ev = evidence_json(folder, "rea-envdxe-xrefs-"+label+".json")
    if (ev.get("operation") != "xrefs" or
        ev.get("parameters", {}).get("address") != at):
        raise ExtractionError("Original Ghidra xref target mismatch: "+label)
    refs = ev.get("normalized_result")
    if not isinstance(refs, list) or len(refs) > MAX_REFS:
        raise ExtractionError("Invalid reference array for original EnvDxe: "+label)
    addresses = [canonical_address(a) for a in refs]
    return {
        "label": label,
        "sourceStringGroup": group,
        "sourceStringAddress": at,
        "sourceStringText": text,
        "evidenceId": ev["evidence_id"],
        "crossReferenceCount": len(refs),
        "referenceInstructionAddresses": list(dict.fromkeys(addresses)),
        "registrationFunctionProven": False,
    }


def audited_function(folder: Path, item: tuple[str, str, str]) -> dict:
    label, at, expected_name = item
    ev = evidence_json(folder, "rea-envdxe-function-"+label+".json")
    if (ev.get("operation") != "analyze_function" or
        ev.get("parameters", {}).get("procedure") != at):
        raise ExtractionError("Original HXL1 EnvDxe callsite query mismatch: "+label)
    result = ev.get("normalized_result")
    if not isinstance(result, dict):
        raise ExtractionError("Original Ghidra function result missing: "+label)
    proc = result.get("procedure")
    if not isinstance(proc, dict):
        raise ExtractionError("Ghidra function identity missing: "+label)
    body = proc.get("body")
    entry = proc.get("address")
    if (not isinstance(entry, str) or COORD.fullmatch(entry) is None or
        not isinstance(body, dict) or body.get("available") is not True or
        body.get("provenance") != "ghidra-function-body-address-set" or
        not isinstance(body.get("ranges"), list) or
        not contains(at, body["ranges"]) or not contains(entry, body["ranges"])):
        raise ExtractionError("Original EnvDxe callsite not in Ghidra function body")
    code = result.get("pseudocode")
    if not isinstance(code, str) or not code or len(code) > MAX_CODE:
        raise ExtractionError("Ghidra decompilation absent/oversized: "+label)
    pcode = result.get("native_value_flow")
    if not isinstance(pcode, dict) or not isinstance(pcode.get("available"), bool):
        raise ExtractionError("Ghidra native value flow not classified: "+label)
    # Ghidra can supply a renamed function. Its containing body is stronger
    # provenance than the untrusted function name.
    return {
        "label":label, "requestedCallee":at,
        "expectedOriginalSymbol":expected_name,
        "containingFunctionEntry":entry,
        "name":proc.get("name"),
        "functionRanges":body["ranges"],
        "highFunctionPcodeAvailable":pcode["available"],
        "evidenceId":ev["evidence_id"],
        "pseudocode":code,
        "protocolRegistrationProven":False,
        "runtimeRamPartitionsObserved":False,
    }


def audit(folder: Path) -> dict:
    baseline = validated_baseline(folder)
    return {
        "classification":"ORIGINAL_HXL1_ENV_DXE_TARGETED_STARTUP_AND_RAM_ASSERT_XREFS",
        "originalEnvDxeSha256":PE_SHA256,
        "entryEvidenceId":baseline["entryFunction"]["evidenceId"],
        "guidZeroXrefsEvidenceId":baseline["guidXrefsEvidenceId"],
        "diagnostics":[audited_xrefs(folder,item) for item in TARGET_STRING_XREFS],
        "startupFunctions":[audited_function(folder,item) for item in TARGET_FUNCTIONS],
        "ramProtocolInstallerConfirmed":False,
        "getRamPartitionsProviderConfirmed":False,
        "runtimeRamTableMeasured":False,
        "kernelPhysicalLoadMeasured":False,
        "deviceModified":False,
    }


def render(report: dict) -> str:
    rows = [
        "# Original HXL1 EnvDxe: initializer and RAM-table source xrefs", "",
        "Original EnvDxe SHA256: "+report["originalEnvDxeSha256"], "",
        "Entrypoint evidence: "+report["entryEvidenceId"],
        "Previously verified zero-GUID-xrefs evidence: "
            +report["guidZeroXrefsEvidenceId"], "",
        "All addresses here are static Ghidra coordinates, not physical RAM.",
        "",
        "## Diagnosed source strings", ""
    ]
    for item in report["diagnostics"]:
        rows += [
            "### "+item["sourceStringText"]+" at "+item["sourceStringAddress"],
            "", "Original xrefs evidence ID: "+item["evidenceId"],
            "Reference instruction count: "+str(item["crossReferenceCount"]),
            ""
        ]
        if item["crossReferenceCount"] == 0:
            rows += ["No direct references. This is not proof of code absence.", ""]
        for at in item["referenceInstructionAddresses"]:
            rows += ["- "+at]
        rows += [""]
    rows += ["## Exact PE startup callees", ""]
    for item in report["startupFunctions"]:
        rows += ["### "+item["label"]+" ("+item["requestedCallee"]+")", "",
                 "Owning Ghidra function: "+item["containingFunctionEntry"],
                 "REA Evidence ID: "+item["evidenceId"],
                 "Native HighFunction p-code available: "+
                 str(item["highFunctionPcodeAvailable"]),
                 "", "~~~c", item["pseudocode"], "~~~", ""]
    rows += [
        "## Unresolved", "",
        "Do not infer protocol installation from strings, a callback table,",
        "or a function name. Next inspect functions containing authenticated",
        "reference *source* instructions and correlate the initialization",
        "branch with the actual firmware service installer/callback table.",
        "The assertion <= 4 is a compiled check, not a measured DRAM layout.",
        "No runtime BaseMemory/KASLR or numerical Linux physical entry proved.",
        ""
    ]
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out",type=Path,default=REPORT_DIR)
    ap.add_argument("--verify-single",choices=[x[0] for x in TARGET_STRING_XREFS]
                    +[x[0] for x in TARGET_FUNCTIONS])
    args=ap.parse_args()
    try:
        if args.verify_single:
            x=next((q for q in TARGET_STRING_XREFS if q[0]==args.verify_single),None)
            if x is not None:
                record=audited_xrefs(args.out,x)
                print("[XREFS VERIFIED]", record["label"],
                      record["crossReferenceCount"])
            else:
                y=next(q for q in TARGET_FUNCTIONS if q[0]==args.verify_single)
                record=audited_function(args.out,y)
                print("[FUNCTION VERIFIED]",record["label"],
                      record["containingFunctionEntry"])
            return 0
        result=audit(args.out)
        (args.out/"rea-envdxe-ram-source-xrefs.json").write_text(
            json.dumps(result,indent=2)+"\n")
        (args.out/"rea-envdxe-ram-source-xrefs.md").write_text(render(result))
    except (ExtractionError, OSError, ValueError, KeyError) as err:
        print("[STOP]",err,file=sys.stderr)
        return 2
    for rec in result["diagnostics"]:
        print("[XREFS]",rec["sourceStringText"],rec["crossReferenceCount"],
              "refs:",",".join(rec["referenceInstructionAddresses"][:15]))
    for rec in result["startupFunctions"]:
        print("[FUNCTION]",rec["label"],rec["containingFunctionEntry"],
              "pcode",rec["highFunctionPcodeAvailable"],
              "lines",len(rec["pseudocode"].splitlines()))
    print("[REPORT]",args.out/"rea-envdxe-ram-source-xrefs.md")
    print("[LIMIT] No proof yet of protocol registration or numerical runtime RAM base")
    return 0


if __name__=="__main__":
    sys.exit(main())
