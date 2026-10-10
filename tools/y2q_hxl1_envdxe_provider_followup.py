#!/usr/bin/env python3
"""Follow only proven HXL1 EnvDxe initialization and RAM assertion callsites.

Requires original SHA256-pinned EnvDxe plus authenticated earlier REA/Ghidra
entrypoint, diagnostic-string xrefs, startup function dossiers and exact
GUID byte readback. Three direct, grounded function queries are analyzed.
All addresses here are PE static analysis coordinates, NEVER live RAM.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_ram_source_xrefs import audit as source_audit
from tools.y2q_hxl1_envdxe_entry_strings import (
    evidence_json, contains, COORD, MAX_CODE, ExtractionError, PE_SHA256,
    REPORT_DIR,
)

TARGETS = (
    ("initializer-dispatch", "0x22b0", ("0x22b0",)),
    ("ram-table-region-a", "0x554c", ("0x554c", "0x5554")),
    ("ram-table-region-b", "0x572c", ("0x572c", "0x5734")),
)
MAX_PSEUDOCODE = 240000
CALL = re.compile(r"\b(?:thunk_)?FUN_[0-9a-fA-F]{6,16}\b")
MAX_CALLS = 160

def authenticate_parent(folder: Path) -> dict:
    parent = source_audit(folder)
    if parent.get("originalEnvDxeSha256") != PE_SHA256:
        raise ExtractionError("Original stock EnvDxe parent digest mismatch")
    sources = {r["label"]: r for r in parent.get("startupFunctions", [])
               if isinstance(r, dict) and "label" in r}
    init = sources.get("env-initializer")
    if (not isinstance(init, dict) or
        init.get("requestedCallee") != "0x1150" or
        init.get("containingFunctionEntry") != "0x1150" or
        "thunk_FUN_000022b0(" not in init.get("pseudocode", "")):
        raise ExtractionError("Original initializer-to-0x22b0 call not authenticated")
    refs = {r["label"]: r for r in parent.get("diagnostics", [])
            if isinstance(r, dict) and "label" in r}
    expect = {
        "ram-table-lib": ("0xa87e", ("0x554c", "0x572c")),
        "ram-entry-limit": ("0xa895", ("0x5554", "0x5734")),
    }
    for label, (original_at, expected_sources) in expect.items():
        record = refs.get(label)
        if (not isinstance(record, dict) or
            record.get("sourceStringAddress") != original_at or
            tuple(record.get("referenceInstructionAddresses", ())) != expected_sources or
            record.get("crossReferenceCount") != 2 or
            not isinstance(record.get("evidenceId"), str)):
            raise ExtractionError("Original RAM-table paired source references changed: " + label)
    if parent.get("ramProtocolInstallerConfirmed") is not False or parent.get("kernelPhysicalLoadMeasured") is not False:
        raise ExtractionError("Prior unverified firmware behavior incorrectly promoted")
    return parent


def audit_one(folder: Path, target: tuple[str, str, tuple[str, ...]]) -> dict:
    label, query, locations = target
    ev = evidence_json(folder, "rea-envdxe-followup-" + label + ".json")
    if (ev.get("operation") != "analyze_function" or
        ev.get("parameters", {}).get("procedure") != query):
        raise ExtractionError("Wrong Ghidra original target function: " + label)
    body = ev.get("normalized_result")
    if not isinstance(body, dict) or not isinstance(body.get("procedure"), dict):
        raise ExtractionError("No original Ghidra procedure dossier: " + label)
    proc = body["procedure"]
    entry, ranges = proc.get("address"), proc.get("body")
    if (not isinstance(entry, str) or COORD.fullmatch(entry) is None or
        not isinstance(ranges, dict) or ranges.get("available") is not True or
        ranges.get("provenance") != "ghidra-function-body-address-set" or
        not isinstance(ranges.get("ranges"), list) or
        not contains(entry, ranges["ranges"]) or
        not all(contains(at, ranges["ranges"]) for at in locations)):
        raise ExtractionError("Observed callsite(s) not within Ghidra function body: " + label)
    code = body.get("pseudocode")
    if not isinstance(code, str) or not code.strip() or len(code) > MAX_PSEUDOCODE:
        raise ExtractionError("Original Ghidra pseudocode unavailable/oversized: " + label)
    flow = body.get("native_value_flow")
    if not isinstance(flow, dict) or not isinstance(flow.get("available"), bool):
        raise ExtractionError("Ghidra HighFunction availability missing: " + label)
    calls = list(dict.fromkeys(CALL.findall(code)))
    if len(calls) > MAX_CALLS:
        raise ExtractionError("Excessive decompiled call references: " + label)
    return {
        "label":label,
        "requestedAddress":query,
        "mustContainSourceInstructions":list(locations),
        "functionEntry":entry,
        "functionName":proc.get("name"),
        "functionBodyRanges":ranges["ranges"],
        "evidenceId":ev["evidence_id"],
        "highFunctionPcodeAvailable":flow["available"],
        "pseudocode":code,
        "observedCallSymbols":calls,
        "callbackTableProven":False,
        "protocolRegistrationProven":False,
        "runtimeRamBaseKnown":False,
    }


def audit(folder: Path) -> dict:
    parent = authenticate_parent(folder)
    records = [audit_one(folder, item) for item in TARGETS]
    return {
        "classification":"ORIGINAL_HXL1_ENV_DXE_VERIFIED_RAM_PROVIDER_FOLLOWUP_FUNCTIONS",
        "originalEnvDxeSha256":PE_SHA256,
        "parentSourceEvidenceIds":{
            x["label"]:x["evidenceId"] for x in parent["diagnostics"]
        },
        "parentInitEvidenceId":next(
            x["evidenceId"] for x in parent["startupFunctions"]
            if x["label"] == "env-initializer"),
        "functionDossiers":records,
        "protocolRegistrationSiteConfirmed":False,
        "getRamPartitionsCallbackConfirmed":False,
        "runtimeRamPartitionEntriesObserved":False,
        "kernelPhysicalLoadVerified":False,
        "deviceModified":False,
    }


def markdown(value: dict) -> str:
    lines = [
        "# HXL1 EnvDxe: targeted RAM provider control-flow dossiers", "",
        "Exact original EnvDxe PE SHA256: " + value["originalEnvDxeSha256"], "",
        "All entries, references and function bodies below are static Ghidra",
        "analysis coordinates; they are **not** numerical boot-time physical RAM.",
        "", "## Verified original parent evidence", "",
        "Initializer Ghidra evidence: "+value["parentInitEvidenceId"],
    ]
    for label,ev in value["parentSourceEvidenceIds"].items():
        lines.append("- " + label + ": " + ev)
    for fn in value["functionDossiers"]:
        lines += [
            "", "## " + fn["label"] + " at " + fn["requestedAddress"], "",
            "Original Ghidra evidence: "+fn["evidenceId"],
            "Function: "+str(fn["functionName"])+" "+fn["functionEntry"],
            "Verified instruction addresses within function: "+
            ", ".join(fn["mustContainSourceInstructions"]),
            "HighFunction p-code available: "+str(fn["highFunctionPcodeAvailable"]),
            "Observed call symbols: "+", ".join(fn["observedCallSymbols"]),
            "", "~~~c", fn["pseudocode"], "~~~", "",
        ]
    lines += [
        "## Unproven until directly corroborated", "",
        "The precise installed-protocol call and GetRamPartitions callback still",
        "require examination of the actual Ghidra control/data flow.",
        "Neither the source string xrefs nor nearby code alone demonstrates",
        "which RAM partitions the original firmware enumerated at boot.",
        "No live BaseMemory, KASLR slide, kernel physical entry or root established.",
        ""
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=REPORT_DIR)
    p.add_argument("--verify-single",choices=[x[0] for x in TARGETS])
    opts = p.parse_args()
    try:
        if opts.verify_single:
            target = next(q for q in TARGETS if q[0] == opts.verify_single)
            authenticate_parent(opts.out)
            item = audit_one(opts.out,target)
            print("[GHIDRA ORIGINAL FUNCTION VERIFIED]",item["label"],
                  item["functionEntry"],item["evidenceId"])
            return 0
        results=audit(opts.out)
        (opts.out/"rea-envdxe-provider-followup.json").write_text(
            json.dumps(results,indent=2)+"\n")
        (opts.out/"rea-envdxe-provider-followup.md").write_text(markdown(results))
    except (ExtractionError, OSError, ValueError, KeyError, StopIteration) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for item in results["functionDossiers"]:
        print("[VERIFIED]",item["label"],item["functionEntry"],
              "pcode",item["highFunctionPcodeAvailable"],
              "lines",len(item["pseudocode"].splitlines()))
        print("[CALL SYMBOLS]",", ".join(item["observedCallSymbols"][:30]))
    print("[REPORT]",opts.out/"rea-envdxe-provider-followup.md")
    print("[LIMIT] No dynamic RAM base, protocol installation or KernelSU yet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
