#!/usr/bin/env python3
"""Original SM-G986U1 HXL1 EnvDxe RAM protocol registration and callback audit.

Two independent, original-PE-gated evidence groups in one pass:
  A: the real 0x205c -> 0x5560 -> BootServices+0x148 registration branch.
  B: the protocol interface at 0xd1d0, GetRamPartitions slot +0x18,
     eight bounded Ghidra references and optional real callback function.

No device access. Ghidra static addresses are not boot-time RAM addresses.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_smem402_protocol import audit as prior_audit
from tools.y2q_hxl1_envdxe_entry_strings import (
    PE_SHA256, REPORT_DIR, evidence_json, COORD, contains, ExtractionError
)
from tools.y2q_hxl1_envdxe_callback_raw_proof import (
    original_code, imported_code_match, failure_record, CALLBACK_BYTES_EVIDENCE,
)

PROTOCOL_GUID_ADDR="0xd118"
PROTOCOL_INTERFACE_ADDR="0xd1d0"
SLOT_OFFSET=0x18
SLOT_ADDR="0xd1e8"
INTERFACE_LENGTH=48
POINTER_BYTES=8
READ_EVIDENCE="rea-envdxe-ram-protocol-interface-read.json"
CALLBACK_EVIDENCE="rea-envdxe-ram-protocol-callback-function.json"
XREF_TARGETS=(
    ("protocol-interface", "0xd1d0"),
    ("get-ram-partitions-slot", "0xd1e8"),
    ("registration-function", "0x205c"),
    ("smem402-table-supplier", "0x53b0"),
    ("ram-table-v1-parser", "0x5430"),
    ("ram-table-header-validator", "0x5288"),
    ("smem-generic-item-accessor", "0x7d08"),
    ("other-protocol-installer", "0x23b0"),
)
MAX_REFS=5000
MAX_CODE=350000
MAX_CALLS=200
CALL=re.compile(r"\b(?:thunk_)?FUN_[0-9a-fA-F]{6,16}\b")
HEX=re.compile(r"^[0-9a-fA-F]{96}$")
REGISTRATION_CALL=re.compile(
    r"\(\s*0xd2b8\s*,\s*0xd118\s*,\s*0xd1d0\s*,\s*0\s*,\s*0\s*\)"
)


def original_registration(folder: Path) -> dict:
    previous=prior_audit(folder)
    if previous.get("originalEnvDxeSha256") != PE_SHA256:
        raise ExtractionError("Original HXL1 EnvDxe SHA256 gate failed")
    # Require the ACTUAL output schema of y2q_hxl1_envdxe_smem402_protocol.audit.
    # numericRuntimeRamBaseMeasured belongs to the earlier input-trace stage,
    # not this direct parent's report. Missing fields must not silently pass.
    required_unverified = (
        "efiRamProtocolRegistrationProven",
        "ramProtocolImplementationRegistrationConfirmed",
        "physicalBaseMemoryMeasured",
        "runtimeSmemTableContentsObserved",
        "kernelPhysicalLoadVerified",
    )
    for field in required_unverified:
        if field not in previous:
            raise ExtractionError("Prior SMEM402 report schema missing field: " + field)
        if previous[field] is not False:
            raise ExtractionError(
                "Prior static evidence was promoted without runtime proof: " + field
            )
    code_sources=previous.get("originalSourceFunctions")
    if not isinstance(code_sources,list):
        raise ExtractionError("No verified original RAM initializer caller dossier")
    candidates=[
        f for f in code_sources if isinstance(f,dict) and
        f.get("label") == "ram-table-initializer-caller"
    ]
    if len(candidates)!=1:
        raise ExtractionError("Expected exactly one original 0x2064 owner function")
    fn=candidates[0]
    text=fn.get("originalPseudocode")
    if (fn.get("queriedAddress")!="0x2064" or
        fn.get("functionEntry")!="0x205c" or
        not isinstance(fn.get("originalEvidenceId"),str) or
        not fn["originalEvidenceId"] or
        not isinstance(text,str) or
        "FUN_00005560(" not in text or
        "if (lVar1 != 0)" not in text or
        "DAT_0000d328 + 0x148" not in text or
        REGISTRATION_CALL.search(text) is None):
        raise ExtractionError("Ghidra original EFI RAM registration callsite not corroborated")
    candidate=previous.get("originalCandidateInstallationGuid")
    if (not isinstance(candidate,dict) or
        candidate.get("staticAddress")!="0xd2e8" or
        candidate.get("originalBytesHex")!="00"*16 or
        candidate.get("matchesKnownRamPartitionGuid") is not False or
        not isinstance(candidate.get("readbackEvidenceId"),str)):
        raise ExtractionError("Distinct zero-GUID protocol candidate provenance missing")
    if previous.get("smemItemIdentifier",{}).get("decimal")!=402:
        raise ExtractionError("Known original Qualcomm RAM table SMEM 402 dependency changed")
    return {
        "originalCallerAt":"0x205c",
        "confirmedOriginalGhidraEvidenceId":fn["originalEvidenceId"],
        "bootServicesMethodOffset":"0x148",
        "guidSourceStaticAddress":PROTOCOL_GUID_ADDR,
        "interfaceStaticAddress":PROTOCOL_INTERFACE_ADDR,
        "handleLocation":"0xd2b8",
        "calledAfterTableInitReturnsSuccess":True,
        "uefiAbiConsistentInstallMultipleProtocolInterfaces":True,
        "bootServicesPointerProvenFromRuntime":False,
        "registeredSuccessfullyAtBoot":False,
        "zeroGuidOtherCallSite":"0xd2e8",
        "otherZeroGuidEvidenceId":candidate["readbackEvidenceId"],
        "originalPseudocode":text,
    }


def interface_readback(folder: Path) -> dict:
    ev=evidence_json(folder,READ_EVIDENCE)
    if (ev.get("operation")!="read_bytes" or
        ev.get("parameters",{}).get("address")!=PROTOCOL_INTERFACE_ADDR or
        ev.get("parameters",{}).get("length")!=INTERFACE_LENGTH):
        raise ExtractionError("Ghidra interface read did not target 0xd1d0/48 bytes")
    result=ev.get("normalized_result")
    if not isinstance(result,dict):
        raise ExtractionError("Missing original protocol interface byte result")
    raw=result.get("bytes_hex")
    if (result.get("address")!=PROTOCOL_INTERFACE_ADDR or
        result.get("requested_bytes")!=INTERFACE_LENGTH or
        result.get("returned_bytes")!=INTERFACE_LENGTH or
        result.get("complete") is not True or
        not isinstance(raw,str) or HEX.fullmatch(raw) is None):
        raise ExtractionError("Original protocol interface byte read incomplete or malformed")
    qwords=struct.unpack("<6Q",bytes.fromhex(raw))
    callback=qwords[SLOT_OFFSET//POINTER_BYTES]
    # The original Ghidra import uses PE preferred base zero. Only treat a
    # plain word-aligned, small nonzero value as a candidate code coordinate.
    # Relocated/constructed runtime callback values are outside this gate.
    candidate=hex(callback) if 0x1000<=callback<0x1000000 and callback%4==0 else None
    return {
        "sourceStaticAddress":PROTOCOL_INTERFACE_ADDR,
        "length":INTERFACE_LENGTH,
        "shaPinnedOriginalGhidraEvidenceId":ev["evidence_id"],
        "qwordsHex":[hex(v) for v in qwords],
        "getRamPartitionsOffset":hex(SLOT_OFFSET),
        "getRamPartitionsSlotStaticAddress":SLOT_ADDR,
        "getRamPartitionsSlotRawQword":hex(callback),
        "unrelocatedStaticFunctionCoordinateCandidate":candidate,
        "callbackMayRequireRelocationsOrRuntimeInitialization":candidate is None,
        "actualRuntimeCallbackPointerRead":False,
    }


def xref_evidence(folder:Path,label:str,address:str)->dict:
    ev=evidence_json(folder,"rea-envdxe-ram-protocol-xrefs-"+label+".json")
    if (ev.get("operation")!="xrefs" or
        ev.get("parameters",{}).get("address")!=address):
        raise ExtractionError("Wrong original EnvDxe Ghidra xref target: "+label)
    refs=ev.get("normalized_result")
    if not isinstance(refs,list) or len(refs)>MAX_REFS:
        raise ExtractionError("Invalid/unbounded original EnvDxe Ghidra xref list")
    for at in refs:
        if not isinstance(at,str) or COORD.fullmatch(at) is None:
            raise ExtractionError("Malformed original protocol xref instruction address")
    return {
        "label":label, "queriedStaticAddress":address,
        "originalEvidenceId":ev["evidence_id"],
        "referenceCount":len(refs),
        "sourceInstructionAddresses":list(dict.fromkeys(refs)),
        "actualBootExecutionObserved":False,
    }


def callback_function(folder:Path,at:str)->dict:
    if not isinstance(at,str) or COORD.fullmatch(at) is None:
        raise ExtractionError("Invalid callback analysis address")
    ev=evidence_json(folder,CALLBACK_EVIDENCE)
    if (ev.get("operation")!="analyze_function" or
        ev.get("parameters",{}).get("procedure")!=at):
        raise ExtractionError("Original EnvDxe Ghidra callback function request mismatch")
    dossier=ev.get("normalized_result")
    if not isinstance(dossier,dict) or not isinstance(dossier.get("procedure"),dict):
        raise ExtractionError("Original Ghidra callback function missing")
    proc=dossier["procedure"]; body=proc.get("body"); entry=proc.get("address")
    if (not isinstance(entry,str) or COORD.fullmatch(entry) is None or
        not isinstance(body,dict) or body.get("available") is not True or
        body.get("provenance")!="ghidra-function-body-address-set" or
        not isinstance(body.get("ranges"),list) or
        not contains(at,body["ranges"]) or not contains(entry,body["ranges"])):
        raise ExtractionError("Callback pointer is not inside authentic Ghidra function body")
    code=dossier.get("pseudocode")
    if not isinstance(code,str) or not code.strip() or len(code)>MAX_CODE:
        raise ExtractionError("Original Ghidra callback pseudocode absent/oversized")
    flow=dossier.get("native_value_flow")
    if not isinstance(flow,dict) or not isinstance(flow.get("available"),bool):
        raise ExtractionError("Original Ghidra callback p-code availability unverified")
    calls=list(dict.fromkeys(CALL.findall(code)))
    if len(calls)>MAX_CALLS:
        raise ExtractionError("Original callback contains unbounded symbol references")
    return {
        "queriedStaticAddress":at,
        "owningFunctionEntry":entry,
        "name":proc.get("name"),
        "bodyRanges":body["ranges"],
        "originalEvidenceId":ev["evidence_id"],
        "highFunctionPcodeAvailable":flow["available"],
        "pseudocode":code,"observedCallees":calls,
        "actualRuntimeCallbackExecutionObserved":False,
    }


def audit(folder:Path)->dict:
    registration=original_registration(folder)
    interface=interface_readback(folder)
    reference_checks=[xref_evidence(folder,name,address)
                      for name,address in XREF_TARGETS]
    callback=interface["unrelocatedStaticFunctionCoordinateCandidate"]
    # A valid pointer does not imply successful decompilation. The original
    # PE executable bytes are independently verified even if the existing
    # failed Ghidra function-analysis partial must be preserved.
    executable=original_code(folder,callback) if callback else None
    readfile=folder/CALLBACK_BYTES_EVIDENCE
    imported=(imported_code_match(folder,callback) if callback and
              readfile.is_file() else None)
    callback_file=folder/CALLBACK_EVIDENCE
    implementation=(callback_function(folder,callback) if callback and
                    callback_file.is_file() else None)
    failure=(failure_record(folder) if callback and implementation is None else None)
    return {
        "classification":"ORIGINAL_HXL1_ENV_DXE_RAM_PROTOCOL_REGISTRATION_AND_CALLBACK_CROSS_CHECK",
        "exactOriginalEnvDxeSha256":PE_SHA256,
        "conditionalRegistrationCallsite":registration,
        "protocolInterfaceStructure":interface,
        "targetedOriginalXrefs":reference_checks,
        "staticCallbackFunction":implementation,
        "originalCallbackExecutableBytes":executable,
        "originalCallbackGhidraReadback":imported,
        "ghidraFunctionAnalysisLimitation":failure,
        "staticRegistrationCallPatternVerified":True,
        "staticCallbackFunctionIdentified":implementation is not None,
        "runtimeRegistrationSuccessful":False,
        "runtimeRamPartitionTableMeasured":False,
        "kernelPhysicalLoadMeasured":False,
        "rootOrKernelSuAchieved":False,
        "deviceModified":False,
    }


def markdown(record:dict)->str:
    reg=record["conditionalRegistrationCallsite"]
    interface=record["protocolInterfaceStructure"]
    rows=[
        "# Original HXL1 EnvDxe: RAM protocol registration and callback", "",
        "Stock EnvDxe SHA256: "+record["exactOriginalEnvDxeSha256"], "",
        "## Registration: original firmware and verified ABI pattern", "",
        "Original function: "+reg["originalCallerAt"],
        "Ghidra evidence ID: "+reg["confirmedOriginalGhidraEvidenceId"],
        "UEFI BootServices method offset: "+reg["bootServicesMethodOffset"],
        "GUID static address: "+reg["guidSourceStaticAddress"],
        "Interface static address: "+reg["interfaceStaticAddress"],
        "Only called when RAM table initializer returned success: "+
        str(reg["calledAfterTableInitReturnsSuccess"]), "",
        "~~~c",reg["originalPseudocode"],"~~~","",
        "The code matches UEFI InstallMultipleProtocolInterfaces calling shape.",
        "The actual runtime EFI boot-service table and return status are NOT measured.",
        "The zero-GUID branch at 0xd2e8 is distinct from this genuine RAM GUID.", "",
        "## Protocol interface: static Ghidra 48-byte read", "",
        "Address: "+interface["sourceStaticAddress"],
        "REA evidence ID: "+interface["shaPinnedOriginalGhidraEvidenceId"],
        "Six little-endian qwords: "+", ".join(interface["qwordsHex"]),
        "GetRamPartitions ABI slot offset: "+interface["getRamPartitionsOffset"],
        "Slot Ghidra static address: "+interface["getRamPartitionsSlotStaticAddress"],
        "Raw slot pointer: "+interface["getRamPartitionsSlotRawQword"],
        "Candidate imported PE code address: "+
        str(interface["unrelocatedStaticFunctionCoordinateCandidate"]), "",
    ]
    if interface["callbackMayRequireRelocationsOrRuntimeInitialization"]:
        rows+=["No plain unrelocated code address could be established from",
               "this static slot. PE relocation or runtime initialization",
               "may explain the result; this is NOT proof of missing callback.",""]
    rows+=["## Eight original static xref checks", ""]
    for ref in record["targetedOriginalXrefs"]:
        rows+=["### "+ref["label"],"","Target: "+ref["queriedStaticAddress"],
               "Evidence: "+ref["originalEvidenceId"],
               "Reference count: "+str(ref["referenceCount"])]
        rows += ["- "+at for at in ref["sourceInstructionAddresses"]]
        rows+=[""]
    executable=record["originalCallbackExecutableBytes"]
    if executable is not None:
        rows+=["## Independently mapped original callback executable", "",
               "Original static coordinate: "+executable["coordinate"],
               "Original PE file offset: "+executable["fileOffset"],
               "Executable section: "+executable["sectionName"],
               "SHA256 of 64 original instruction bytes: "+executable["bytesSha256"],
               "Original code bytes: "+executable["bytesHex"],""]
    confirmed=record["originalCallbackGhidraReadback"]
    if confirmed is not None:
        rows+=["Ghidra imported bytes match original pinned PE: "+
               str(confirmed["importedBytesEqualOriginal"]),
               "REA byte evidence: "+confirmed["originalGhidraEvidenceId"],""]
    unresolved=record["ghidraFunctionAnalysisLimitation"]
    if unresolved is not None:
        rows+=["## Ghidra callback function analysis limitation","",
               "Status: "+unresolved["status"]]
        for saved in unresolved["files"]:
            rows+=["Original saved file: "+saved["filename"],
                   "SHA256: "+saved["sha256"],
                   "Diagnostic excerpt:", "~~~text",saved["excerpt"],"~~~",""]
        rows+=["The lack of a function dossier does not disprove the callback.",
               ""]
    cb=record["staticCallbackFunction"]
    if cb is not None:
        rows+=["## Callback function static decompilation","",
               "Function: "+cb["owningFunctionEntry"],
               "Ghidra evidence: "+cb["originalEvidenceId"],"",
               "~~~c",cb["pseudocode"],"~~~",""]
    rows+=["## Interpretation", "",
           "This establishes the original code's conditional RAM-protocol",
           "registration pattern. It does NOT demonstrate boot-time success,",
           "runtime RAM table entries, numerical BaseMemory/KASLR/kernel load,",
           "working exploit, privilege escalation or KernelSU.",""]
    return "\n".join(rows)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=REPORT_DIR)
    p.add_argument("--verify-single",choices=["registration","interface","callback","callback-bytes"]
                   +[a for a,_ in XREF_TARGETS])
    opts=p.parse_args()
    try:
        if opts.verify_single:
            if opts.verify_single=="registration":
                x=original_registration(opts.out)
                print("[VERIFIED ORIGINAL REGISTRATION]",x["originalCallerAt"],
                      x["confirmedOriginalGhidraEvidenceId"])
            elif opts.verify_single=="interface":
                x=interface_readback(opts.out)
                print("[VERIFIED ORIGINAL INTERFACE]",x["sourceStaticAddress"],
                      "callback-qword",x["getRamPartitionsSlotRawQword"])
            elif opts.verify_single=="callback-bytes":
                x=interface_readback(opts.out)
                at=x["unrelocatedStaticFunctionCoordinateCandidate"]
                if at is None:
                    raise ExtractionError("Callback PE address not statically usable")
                evidence=imported_code_match(opts.out,at)
                print("[VERIFIED ORIGINAL CALLBACK EXECUTABLE]",at,
                      evidence["bytesSha256"],evidence["originalGhidraEvidenceId"])
            elif opts.verify_single=="callback":
                x=interface_readback(opts.out)
                at=x["unrelocatedStaticFunctionCoordinateCandidate"]
                if at is None:
                    raise ExtractionError("No proven nonzero static callback coordinate to analyze")
                cb=callback_function(opts.out,at)
                print("[VERIFIED CALLBACK]",cb["owningFunctionEntry"])
            else:
                name,at=next(x for x in XREF_TARGETS if x[0]==opts.verify_single)
                refs=xref_evidence(opts.out,name,at)
                print("[VERIFIED XREFS]",name,refs["referenceCount"])
            return 0
        result=audit(opts.out)
        (opts.out/"rea-envdxe-ram-registration-callback.json").write_text(
            json.dumps(result,indent=2)+"\n")
        (opts.out/"rea-envdxe-ram-registration-callback.md").write_text(markdown(result))
    except (ExtractionError,ValueError,OSError,KeyError,StopIteration) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    reg=result["conditionalRegistrationCallsite"]
    table=result["protocolInterfaceStructure"]
    print("[REGISTRATION]",reg["originalCallerAt"],"conditional original BootServices+0x148")
    print("[RAM PROTOCOL]",reg["guidSourceStaticAddress"],reg["interfaceStaticAddress"])
    print("[CALLBACK SLOT]",table["getRamPartitionsSlotStaticAddress"],
          table["getRamPartitionsSlotRawQword"])
    for x in result["targetedOriginalXrefs"]:
        print("[XREFS]",x["label"],x["referenceCount"],
              ",".join(x["sourceInstructionAddresses"][:14]))
    print("[ORIGINAL EXECUTABLE CALLBACK BYTES]",
          result["originalCallbackExecutableBytes"] is not None)
    print("[GHIDRA CALLBACK BYTES MATCH ORIGINAL]",
          result["originalCallbackGhidraReadback"] is not None)
    print("[CALLBACK FUNCTION DECOMPILED]",result["staticCallbackFunctionIdentified"])
    if result["ghidraFunctionAnalysisLimitation"] is not None:
        limitation=result["ghidraFunctionAnalysisLimitation"]
        print("[CALLBACK ANALYSIS STATUS]",limitation["status"])
        for artifact in limitation["files"]:
            print("[GHIDRA ERROR]",artifact["filename"],artifact["excerpt"][:300])
    print("[REPORT]",opts.out/"rea-envdxe-ram-registration-callback.md")
    print("[LIMIT] No live DRAM table/physical kernel load/working Root My Galaxy payload")
    return 0


if __name__=="__main__":
    sys.exit(main())
