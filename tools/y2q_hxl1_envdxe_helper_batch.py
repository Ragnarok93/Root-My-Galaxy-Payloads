#!/usr/bin/env python3
"""Batch original-stock HXL1 EnvDxe callback-helper followups, no device I/O.

The exact RAM protocol's GetRamPartitions callback starts at 0x1f74 and calls
0x52cc. Its four neighboring entrypoints have distinct provisional method
regions: Ghidra's 128-byte windows overlap and must not be interpreted as
complete functions. This followup includes helper tail and three direct BL
leads, while never claiming runtime DRAM, physical kernel address, or root.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_method_arm64_trace import (
    report as method_audit, original_window, arm64_edges,
)
from tools.y2q_hxl1_envdxe_entry_strings import (
    PE_SHA256, REPORT_DIR, COORD, ExtractionError, evidence_json,
)

WINDOWS=(
    ("ram-helper-tail","0x52cc",224),
    ("ram-helper-copy-callee","0x3c3c",128),
    ("other-method-callee","0x5740",128),
    ("post-callback-callee","0x2618",128),
    ("ram-helper-branch-5388","0x5388",40),
    ("ram-helper-branch-5398","0x5398",24),
    ("post-callback-code","0x1fe8",96),
    ("additional-smem-caller","0x81f4",128),
)
XREFS=(
    ("ram-helper-copy-callee","0x3c3c"),
    ("other-method-callee","0x5740"),
    ("post-callback-callee","0x2618"),
    ("post-callback-code","0x1fe8"),
)
MAX_REFS=10000


def original_parent(folder:Path)->dict:
    parent=method_audit(folder,allow_missing=False)
    if parent.get("sha256PinnedEnvDxe")!=PE_SHA256:
        raise ExtractionError("Authenticated original EnvDxe parent digest mismatch")
    if (parent.get("livePhysicalMemoryObserved") is not False or
        parent.get("privilegeEscalationDemonstrated") is not False or
        parent.get("kernelSuInstalled") is not False):
        raise ExtractionError("Earlier static XBL evidence incorrectly promoted to root")
    methods={r.get("role"):r for r in parent.get("methods",[]) if isinstance(r,dict)}
    expect={
        "method-08":("0x1ee8","0x1f0c"),
        "method-10":("0x1f0c","0x1f28"),
        "method-20":("0x1f28","0x1f74"),
        "get-ram-partitions":("0x1f74","0x1fe8"),
    }
    if set(methods)!=set(expect):
        raise ExtractionError("Expected four distinct original RAM interface methods")
    for label,(start,end) in expect.items():
        record=methods[label]
        region=record.get("boundedInterpretation",{})
        if (record.get("originalCode",{}).get("staticAddress")!=start or
            not isinstance(record.get("ghidraCode"),dict) or
            record["ghidraCode"].get("originalBytesMatchImported") is not True or
            region.get("exclusiveUpperBound")!=end or
            region.get("boundaryIsVerifiedGhidraFunctionEnd") is not False):
            raise ExtractionError("Verified original method boundary/provenance changed: "+label)
    get=methods["get-ram-partitions"]
    other=methods["method-20"]
    def bl(record):
        return {e["instructionAddress"]:e["directBranchTarget"]
                for e in record["boundedInterpretation"]["inRegionControlFlow"]
                if e["mnemonicClass"]=="BL"}
    if bl(get).get("0x1fa4")!="0x52cc":
        raise ExtractionError("Original GetRamPartitions direct helper call not within method")
    if "0x1ff0" in bl(get):
        raise ExtractionError("Post-return BL 0x2618 incorrectly attributed to GetRamPartitions")
    if bl(other).get("0x1f40")!="0x5740":
        raise ExtractionError("Original other method's 0x5740 callee unverified")
    if "0x1fa4" in bl(other):
        raise ExtractionError("Other method incorrectly owns GetRamPartitions BL 0x52cc")
    extra=parent.get("directCalleeCode",[])
    if len(extra)!=1 or extra[0].get("code",{}).get("staticAddress")!="0x52cc" or (
        not isinstance(extra[0].get("ghidraCode"),dict) or
        extra[0]["ghidraCode"].get("originalBytesMatchImported") is not True):
        raise ExtractionError("Original 0x52cc callback BL target bytes not authenticated")
    code=extra[0]["code"]
    observed={e["instructionAddress"]:e["directBranchTarget"]
              for e in code.get("edges",[])}
    required={"0x52f4":"0x5398","0x532c":"0x5388","0x5340":"0x3c3c"}
    if any(observed.get(at)!=dest for at,dest in required.items()):
        raise ExtractionError("Original helper branching/control flow changed")
    return parent


def imported_code(folder:Path,label:str,addr:str,size:int,original:dict)->dict:
    ev=evidence_json(folder,"rea-envdxe-helper-window-"+label+".json")
    if (ev.get("operation")!="read_bytes" or
        ev.get("parameters",{}).get("address")!=addr or
        ev.get("parameters",{}).get("length")!=size):
        raise ExtractionError("Wrong Ghidra helper code-window operation/coordinates: "+label)
    result=ev.get("normalized_result")
    if (not isinstance(result,dict) or
        result.get("address")!=addr or
        result.get("requested_bytes")!=size or
        result.get("returned_bytes")!=size or
        result.get("complete") is not True or
        not isinstance(result.get("bytes_hex"),str) or
        re.fullmatch(r"[0-9a-fA-F]{%d}"%(size*2),result["bytes_hex"]) is None):
        raise ExtractionError("Incomplete original Ghidra helper code-window result: "+label)
    if result["bytes_hex"].lower()!=original["bytesHex"]:
        raise ExtractionError("Ghidra imported helper bytes differ from SHA-pinned original PE: "+label)
    return {"evidenceId":ev["evidence_id"],"address":addr,
            "size":size,"originalBytesMatch":True}


def original_refs(folder:Path,label:str,addr:str)->dict:
    ev=evidence_json(folder,"rea-envdxe-helper-xrefs-"+label+".json")
    if (ev.get("operation")!="xrefs" or ev.get("parameters",{}).get("address")!=addr):
        raise ExtractionError("Wrong original Ghidra helper xref query: "+label)
    refs=ev.get("normalized_result")
    if not isinstance(refs,list) or len(refs)>MAX_REFS or not all(
        isinstance(v,str) and COORD.fullmatch(v) for v in refs
    ):
        raise ExtractionError("Unbounded or malformed original helper reference list")
    return {"label":label,"target":addr,"references":list(dict.fromkeys(refs)),
            "count":len(refs),"evidenceId":ev["evidence_id"],
            "runtimeReachabilityConfirmed":False}


def report(folder:Path,strict:bool=False)->dict:
    previous=original_parent(folder)
    entries=[]
    for label,addr,size in WINDOWS:
        pe=original_window(folder,addr,size)
        file=folder/("rea-envdxe-helper-window-"+label+".json")
        ghidra=imported_code(folder,label,addr,size,pe) if file.exists() or file.is_symlink() else None
        if strict and ghidra is None:
            raise ExtractionError("Missing Ghidra helper evidence for "+label)
        entries.append({"label":label,"queryStaticAddress":addr,
                        "size":size,"originalPe":pe,"ghidraImported":ghidra,
                        "inferredFullFunction":False,
                        "liveExecutionObserved":False})
    helper=entries[0]
    original128=previous["directCalleeCode"][0]["code"]["bytesHex"]
    if not helper["originalPe"]["bytesHex"].startswith(original128):
        raise ExtractionError("Extended helper code differs from previously verified 128 bytes")
    helper_edges=helper["originalPe"]["edges"]
    if not any(x["instructionAddress"]=="0x5340" and x["mnemonicClass"]=="BL"
               and x["directBranchTarget"]=="0x3c3c" for x in helper_edges):
        raise ExtractionError("Extended helper 0x5340 direct BL target no longer 0x3c3c")
    refs=[]
    for label,addr in XREFS:
        path=folder/("rea-envdxe-helper-xrefs-"+label+".json")
        if path.exists() or path.is_symlink():
            refs.append(original_refs(folder,label,addr))
        elif strict:
            raise ExtractionError("Missing original Ghidra helper xrefs "+label)
    return {
        "classification":"ORIGINAL_HXL1_ENV_DXE_EIGHT_TARGET_HELPER_STATIC_FOLLOWUP",
        "originalEnvDxeSha256":PE_SHA256,
        "parentCallbackEvidence":
            previous["originalInterfaceEvidenceId"],
        "eightCodeWindows":entries,
        "targetedXrefs":refs,
        "methodOwnershipCorrected":True,
        "getRamPartitionsIndirectMethodOffset":"0x18",
        "originalHelperDirectBranch":"0x5340 -> 0x3c3c",
        "bootTimeRamTableValuesMeasured":False,
        "kernelPhysicalEntryObserved":False,
        "rootPrivilegeDemonstrated":False,
        "kernelSuInstalled":False,
    }


def render(value:dict)->str:
    rows=[
        "# Original HXL1 EnvDxe: eight static helper/callback followups","",
        "Original PE SHA256: "+value["originalEnvDxeSha256"],"",
        "GetRamPartitions at 0x1f74 -> helper 0x52cc.",
        "Helper 0x5340 -> 0x3c3c. The other EFI interface method",
        "at 0x1f28 -> 0x5740 via BL at 0x1f40.",
        "The instruction at 0x1ff0 -> 0x2618 occurs AFTER the",
        "observed callback RET at 0x1fe4 and is not attributed to GetRamPartitions.",
        "All coordinates are ORIGINAL STATIC PE code addresses, never runtime",
        "DRAM partition bases or physical Linux kernel load addresses.",
        "Raw code windows are NOT complete Ghidra functions.","",
    ]
    for record in value["eightCodeWindows"]:
        pe=record["originalPe"]
        rows += ["## "+record["label"]+" at "+record["queryStaticAddress"],"",
                 "Window bytes: "+str(record["size"]),
                 "PE file offset: "+pe["peFileOffset"],
                 "Executable section: "+pe["sectionName"],
                 "Original SHA256: "+pe["sha256"],
                 "Ghidra agreement: "+str(record["ghidraImported"] is not None)]
        if record["ghidraImported"] is not None:
            rows+=["REA evidence: "+record["ghidraImported"]["evidenceId"]]
        rows += ["Original bytes: "+pe["bytesHex"],"",
                 "| Static instruction | Control flow | Static target |",
                 "|---|---|---|"]
        for edge in pe["edges"]:
            rows += ["| "+edge["instructionAddress"]+" | "+
                     edge["mnemonicClass"]+" | "+
                     str(edge["directBranchTarget"])+" |"]
        rows += [""]
    rows += ["## Four additional Ghidra xref queries",""]
    for ref in value["targetedXrefs"]:
        rows += ["- "+ref["label"]+" at "+ref["target"]+": "+
                 str(ref["count"])+" refs; "+ref["evidenceId"]]
        rows += ["  - "+a for a in ref["references"]]
    rows += ["","## Remaining proof obligations","",
             "Explain original GetRamPartitions count/buffer validation",
             "and interaction with SMEM 402, using recovered original",
             "AArch64 code, and establish any required relocations.",
             "Do NOT treat static symbols as boot-time DRAM values.",
             "No Root My Galaxy privilege escalation or KernelSU verified.",""]
    return "\n".join(rows)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out",type=Path,default=REPORT_DIR)
    ap.add_argument("--verify",choices=[x[0] for x in WINDOWS]+[x[0] for x in XREFS])
    # Some labels appear in both groups; prefer window for --verify,
    # caller may explicitly pass --kind xrefs.
    ap.add_argument("--kind",choices=["window","xrefs"],default="window")
    ap.add_argument("--strict",action="store_true")
    args=ap.parse_args()
    try:
        if args.verify:
            original_parent(args.out)
            if args.kind=="window":
                label,addr,size=next(x for x in WINDOWS if x[0]==args.verify)
                original=original_window(args.out,addr,size)
                value=imported_code(args.out,label,addr,size,original)
                print("[WINDOW VERIFIED]",label,addr,value["evidenceId"])
            else:
                label,addr=next(x for x in XREFS if x[0]==args.verify)
                value=original_refs(args.out,label,addr)
                print("[XREFS VERIFIED]",label,addr,value["count"])
            return 0
        value=report(args.out,strict=args.strict)
        (args.out/"rea-envdxe-helper-batch.json").write_text(
            json.dumps(value,indent=2)+"\n")
        (args.out/"rea-envdxe-helper-batch.md").write_text(render(value))
    except (ExtractionError,OSError,ValueError,KeyError,StopIteration) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for item in value["eightCodeWindows"]:
        print("[HELPER]",item["label"],item["queryStaticAddress"],
              "Ghidra match",item["ghidraImported"] is not None,
              "static branches",len(item["originalPe"]["edges"]))
    for item in value["targetedXrefs"]:
        print("[XREFS]",item["label"],item["count"])
    print("[REPORT]",args.out/"rea-envdxe-helper-batch.md")
    print("[LIMIT] Original static ARM64 only; no live DRAM/kernel/root measurement")
    return 0


if __name__=="__main__":
    sys.exit(main())
