#!/usr/bin/env python3
"""Trace only authenticated original HXL1 EnvDxe RAM table input/installer leads.

Uses existing SHA256-pinned original EnvDxe/Ghidra source reports. Three
function dossiers: direct table supplier 0x53b0, startup protocol-setup
candidate 0x23b0, neighboring startup-services candidate 0x20ac. One
xref query targets previously VERIFIED table populator 0x5560. Neither
fallback constants nor a candidate EFI installer proves runtime DRAM layout.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_envdxe_provider_followup import audit as followup_audit
from tools.y2q_hxl1_envdxe_entry_strings import (
    evidence_json, contains, COORD, PE_SHA256, REPORT_DIR, ExtractionError
)

FUNCTION_TARGETS = (
    ("table-input-provider", "0x53b0", "ram-table-region-b"),
    ("init-protocol-candidate", "0x23b0", "initializer-dispatch"),
    ("init-services-candidate", "0x20ac", "initializer-dispatch"),
)
XREF_LABEL = "ram-table-populator"
XREF_TARGET = "0x5560"
MAX_CODE = 350000
MAX_REFS = 10000
CALL = re.compile(r"\b(?:thunk_)?FUN_[0-9a-fA-F]{6,16}\b")
MAX_CALLS = 300


def authenticated_parent(folder: Path) -> dict:
    parent = followup_audit(folder)
    if parent.get("originalEnvDxeSha256") != PE_SHA256:
        raise ExtractionError("Prior original EnvDxe SHA256 provenance mismatch")
    if (parent.get("protocolRegistrationSiteConfirmed") is not False or
        parent.get("runtimeRamPartitionEntriesObserved") is not False):
        raise ExtractionError("Prior static firmware data incorrectly promoted to runtime proof")
    funcs = {x["label"]: x for x in parent.get("functionDossiers", [])
             if isinstance(x, dict) and isinstance(x.get("label"), str)}
    required = {
        "initializer-dispatch": (
            "0x22b0", "FUN_000023b0(", "FUN_000020ac("
        ),
        "ram-table-region-a": (
            "0x5430", "mRamPartitionTableEntryCount <= 4",
            "FUN_00003c3c("
        ),
        "ram-table-region-b": (
            "0x5560", "FUN_000053b0(", "FUN_00005430(",
            "DAT_0000d700 = 0x60000000;",
            "DAT_0000d6f8 = 0x80000000;",
            "mRamPartitionTableEntryCount <= 4"
        ),
    }
    for label, patterns in required.items():
        f = funcs.get(label)
        if not isinstance(f, dict) or f.get("functionEntry") != patterns[0]:
            raise ExtractionError("Original EnvDxe parent function unknown: " + label)
        pseudo = f.get("pseudocode")
        if not isinstance(pseudo, str) or not all(x in pseudo for x in patterns[1:]):
            raise ExtractionError("Original EnvDxe data/callsite evidence changed: " + label)
        if not isinstance(f.get("evidenceId"), str) or not f["evidenceId"]:
            raise ExtractionError("No authenticated original Ghidra parent evidence ID")
    return parent


def audit_function(folder: Path, target: tuple[str, str, str]) -> dict:
    label, requested, _ = target
    ev = evidence_json(folder, "rea-envdxe-input-trace-"+label+".json")
    if (ev.get("operation") != "analyze_function" or
        ev.get("parameters", {}).get("procedure") != requested):
        raise ExtractionError("Wrong EnvDxe Ghidra input trace function query: "+label)
    value = ev.get("normalized_result")
    if not isinstance(value, dict):
        raise ExtractionError("Original EnvDxe function result missing: "+label)
    proc = value.get("procedure")
    if not isinstance(proc,dict):
        raise ExtractionError("Original Ghidra procedure identity missing: "+label)
    at, region = proc.get("address"), proc.get("body")
    if (not isinstance(at,str) or COORD.fullmatch(at) is None or
        not isinstance(region,dict) or region.get("available") is not True or
        region.get("provenance") != "ghidra-function-body-address-set" or
        not isinstance(region.get("ranges"),list) or
        not contains(requested,region["ranges"]) or
        not contains(at,region["ranges"])):
        raise ExtractionError("Original query is not inside verified Ghidra function body: "+label)
    code=value.get("pseudocode")
    if not isinstance(code,str) or not code.strip() or len(code)>MAX_CODE:
        raise ExtractionError("Ghidra function pseudocode missing/oversized: "+label)
    native=value.get("native_value_flow")
    if not isinstance(native,dict) or not isinstance(native.get("available"),bool):
        raise ExtractionError("Ghidra p-code availability not authenticated: "+label)
    symbols=list(dict.fromkeys(CALL.findall(code)))
    if len(symbols)>MAX_CALLS:
        raise ExtractionError("Unbounded Ghidra function calls: "+label)
    return {
        "label":label, "requestedAddress":requested,
        "functionEntry":at, "functionName":proc.get("name"),
        "functionBody":region["ranges"],
        "evidenceId":ev["evidence_id"],
        "highFunctionAvailable":native["available"],
        "pseudocode":code,"callSymbols":symbols,
        "registrationConfirmed":False,
        "rawRamPartitionTableObservedAtRuntime":False,
    }


def audit_xrefs(folder: Path) -> dict:
    ev=evidence_json(folder, "rea-envdxe-input-trace-"+XREF_LABEL+".json")
    if (ev.get("operation") != "xrefs" or
        ev.get("parameters",{}).get("address") != XREF_TARGET):
        raise ExtractionError("Ghidra xrefs not queried at verified 0x5560 function")
    result=ev.get("normalized_result")
    if not isinstance(result,list) or len(result)>MAX_REFS:
        raise ExtractionError("Original RAM table-populator xrefs malformed")
    for addr in result:
        if not isinstance(addr,str) or COORD.fullmatch(addr) is None:
            raise ExtractionError("Non-static Ghidra RAM table caller address")
    return {
        "label":XREF_LABEL,"requestedAddress":XREF_TARGET,
        "evidenceId":ev["evidence_id"],
        "count":len(result),"callsiteAddresses":list(dict.fromkeys(result)),
        "runtimeExecutionConfirmed":False,
    }


def audit(folder: Path) -> dict:
    parent=authenticated_parent(folder)
    bylabel={x["label"]:x for x in parent["functionDossiers"]}
    return {
        "classification":"ORIGINAL_HXL1_ENV_DXE_FIRMWARE_RAM_TABLE_PROVENANCE_STATIC",
        "originalEnvDxeSha256":PE_SHA256,
        "sourceFunctionEvidence":{
            x["label"]:x["evidenceId"] for x in parent["functionDossiers"]
        },
        "supplierAndSetupCandidates":[
            {"parentFunctionEvidence":bylabel[target[2]]["evidenceId"],
             **audit_function(folder,target)} for target in FUNCTION_TARGETS
        ],
        "ramTableCallerXrefs":audit_xrefs(folder),
        "observedFallbackOnly":{
            "conditionalErrorCode":"-0x7ffffffffffffffa",
            "fieldAtDAT_0000d6f8":"0x80000000",
            "fieldAtDAT_0000d700":"0x60000000",
            "interpretedAsActiveRuntimeBase":False,
        },
        "efiRamProtocolRegistrationProven":False,
        "getRamPartitionsCallbackProven":False,
        "numericRuntimeRamBaseMeasured":False,
        "kernelPhysicalEntryVerified":False,
        "phoneModified":False,
    }


def markdown(record: dict) -> str:
    rows=[
        "# HXL1 EnvDxe original RAM-table provider and init-service trace","",
        "Original PE SHA256: "+record["originalEnvDxeSha256"], "",
        "All addresses below are original Ghidra static PE coordinates,",
        "not boot-time physical RAM addresses.", "",
        "## Previously verified firmware RAM-table fallback", "",
        "On the original 0x5560 code's specific error branch:",
        "DAT_0000d6f8 = 0x80000000 and DAT_0000d700 = 0x60000000.",
        "This is a conditional fallback, NOT a measured RAM partition.",
        "",
        "## Direct original callers of the table-populator function", "",
    ]
    refs=record["ramTableCallerXrefs"]
    rows += [
        "Target: "+refs["requestedAddress"],
        "REA evidence: "+refs["evidenceId"],
        "References: "+str(refs["count"]),"",
    ]
    if not refs["count"]:
        rows+=["No Ghidra direct callers; this does not prove the routine unreachable.",""]
    for a in refs["callsiteAddresses"]:
        rows+=["- "+a]
    for fn in record["supplierAndSetupCandidates"]:
        rows += [
            "", "## "+fn["label"]+" at "+fn["requestedAddress"], "",
            "Ghidra function: "+fn["functionEntry"]+" "+str(fn["functionName"]),
            "Original REA Evidence: "+fn["evidenceId"],
            "Verified parent callsite source: "+fn["parentFunctionEvidence"],
            "HighFunction p-code available: "+str(fn["highFunctionAvailable"]),
            "Observed decompiled calls: "+", ".join(fn["callSymbols"]),
            "", "~~~c",fn["pseudocode"],"~~~","",
        ]
    rows+= [
        "## Next proof obligations","",
        "Determine whether any candidate actually calls UEFI",
        "InstallMultipleProtocolInterfaces with the exact original RAM GUID",
        "and publishes GetRamPartitions in a real protocol method table.",
        "Static module callbacks are not observed boot execution or a",
        "runtime DRAM partition table; no kernel physical load or root proved.",""
    ]
    return "\n".join(rows)


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=REPORT_DIR)
    p.add_argument("--verify-single",choices=[x[0] for x in FUNCTION_TARGETS]+[XREF_LABEL])
    opts=p.parse_args()
    try:
        if opts.verify_single:
            authenticated_parent(opts.out)
            if opts.verify_single == XREF_LABEL:
                x=audit_xrefs(opts.out)
                print("[XREFS VERIFIED]",x["requestedAddress"],x["count"],"refs")
            else:
                target=next(x for x in FUNCTION_TARGETS if x[0]==opts.verify_single)
                x=audit_function(opts.out,target)
                print("[FUNCTION VERIFIED]",x["label"],x["functionEntry"],
                      x["evidenceId"])
            return 0
        record=audit(opts.out)
        (opts.out/"rea-envdxe-ram-table-input-trace.json").write_text(
            json.dumps(record,indent=2)+"\n")
        (opts.out/"rea-envdxe-ram-table-input-trace.md").write_text(markdown(record))
    except (ExtractionError, OSError, ValueError, KeyError, StopIteration) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    for f in record["supplierAndSetupCandidates"]:
        print("[VERIFIED]",f["label"],f["functionEntry"],
              "pcode",f["highFunctionAvailable"],
              "lines",len(f["pseudocode"].splitlines()))
    refs=record["ramTableCallerXrefs"]
    print("[CALLER XREFS]",refs["count"],
          ",".join(refs["callsiteAddresses"][:24]))
    print("[REPORT]",opts.out/"rea-envdxe-ram-table-input-trace.md")
    print("[LIMIT] Original PE static data only; no runtime RAM/KernelSU")
    return 0


if __name__=="__main__":
    sys.exit(main())
