#!/usr/bin/env python3
"""Static HXL1 GetRamPartitions callee audit: allocation/record helper leads.

This pass extends the now-authenticated complete bounded callback CFG with
three target-specific original executable + independent Ghidra byte reads:
  0x26bc: reachable callback BL at 0x2050
  0x25d8: secondary helper referenced at 0x2638 by caller 0x2618
  0x3d04: copy helper referenced at 0x3c60 and 0x3c74 by 0x3c3c
Their semantics remain provisional until original instructions are inspected.
No on-device calls, RAM readings, physical kernel address or root claim.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_callback_cfg import analyze as callback_audit
from tools.y2q_hxl1_envdxe_helper_batch import report as helper_audit
from tools.y2q_hxl1_envdxe_method_arm64_trace import original_window
from tools.y2q_hxl1_envdxe_entry_strings import (
    PE_SHA256, REPORT_DIR, COORD, ExtractionError, evidence_json
)

# Windows have distinct start addresses. Never label them full functions.
WINDOWS=(
    ("callback-tail-callee","0x26bc",192,
     ("0x2050",)),
    ("secondary-ram-helper","0x25d8",160,
     ("0x2638",)),
    ("record-copy-subroutine","0x3d04",160,
     ("0x3c60","0x3c74")),
)
MAX_XREFS=8000
NAME="rea-envdxe-callee-provenance"


def previous(folder:Path)->tuple[dict,dict]:
    cb=callback_audit(folder)
    other=helper_audit(folder,strict=True)
    if (cb.get("originalEnvDxeSha256")!=PE_SHA256 or
        other.get("originalEnvDxeSha256")!=PE_SHA256 or
        cb.get("runtimePhysicalRamKnown") is not False or
        cb.get("kernelPhysicalLoadKnown") is not False or
        cb.get("exploitOrRootAchieved") is not False or
        other.get("rootPrivilegeDemonstrated") is not False):
        raise ExtractionError("Prior HXL1 source identity/proof boundary changed")

    reachable={c["pc"]:c["target"]
               for c in cb["cfg"]["reachableCalls"]}
    if (reachable.get("0x1fa4")!="0x52cc" or
        reachable.get("0x1ff0")!="0x2618" or
        reachable.get("0x2004")!="0x52cc" or
        reachable.get("0x2050")!="0x26bc" or
        cb["cfg"].get("outOfWindowSuccessors")!=[]):
        raise ExtractionError("Exact callback four-reachable-call evidence changed")

    sources={x["label"]:x for x in other.get("eightCodeWindows",[])}
    required={
        "post-callback-callee":{"0x2638":"0x25d8"},
        "ram-helper-copy-callee":{"0x3c60":"0x3d04","0x3c74":"0x3d04"},
    }
    for label,expected in required.items():
        source=sources.get(label)
        if not source or not isinstance(source.get("ghidraImported"),dict) or (
            source["ghidraImported"].get("originalBytesMatch") is not True):
            raise ExtractionError("Required original Ghidra caller code not authenticated: "+label)
        branches={e["instructionAddress"]:e["directBranchTarget"]
                  for e in source["originalPe"]["edges"]
                  if e["mnemonicClass"]=="BL"}
        if any(branches.get(at)!=target for at,target in expected.items()):
            raise ExtractionError("Original caller direct branches differ: "+label)
    return cb,other


def imported(folder:Path,label:str,addr:str,size:int,original:dict)->dict:
    ev=evidence_json(folder,f"{NAME}-bytes-{label}.json")
    value=ev.get("normalized_result")
    if (ev.get("operation")!="read_bytes" or
        ev.get("parameters",{}).get("address")!=addr or
        ev.get("parameters",{}).get("length")!=size):
        raise ExtractionError("Ghidra callee byte-read request identity differs: "+label)
    if (not isinstance(value,dict) or
        value.get("address")!=addr or
        value.get("requested_bytes")!=size or
        value.get("returned_bytes")!=size or
        value.get("complete") is not True or
        not isinstance(value.get("bytes_hex"),str) or
        re.fullmatch(r"[a-fA-F0-9]{%s}" % (2*size),value["bytes_hex"]) is None):
        raise ExtractionError("Ghidra callee byte-read incomplete: "+label)
    if value["bytes_hex"].lower()!=original["bytesHex"]:
        raise ExtractionError("Original executable bytes disagree with Ghidra: "+label)
    return {"evidenceId":ev["evidence_id"],"match":True,
            "originalBytesSha256":original["sha256"],
            "readBytes":size}


def xrefs(folder:Path,label:str,addr:str,mandatory:tuple[str,...])->dict:
    ev=evidence_json(folder,f"{NAME}-refs-{label}.json")
    if (ev.get("operation")!="xrefs" or
        ev.get("parameters",{}).get("address")!=addr):
        raise ExtractionError("Ghidra callee xrefs request identity differs: "+label)
    refs=ev.get("normalized_result")
    if (not isinstance(refs,list) or len(refs)>MAX_XREFS or
        any(not isinstance(v,str) or COORD.fullmatch(v) is None for v in refs)):
        raise ExtractionError("Malformed Ghidra callee xrefs: "+label)
    missing=set(mandatory)-set(refs)
    if missing:
        raise ExtractionError("Required known static callers absent from Ghidra xrefs: "+
                              label+" "+",".join(sorted(missing)))
    return {"evidenceId":ev["evidence_id"],"sources":sorted(set(refs)),
            "sourceCount":len(refs),"expectedSources":list(mandatory),
            "dynamicExecutionVerified":False}


def report(folder:Path,strict:bool=False)->dict:
    cb,_=previous(folder)
    results=[]
    for label,addr,size,expected_refs in WINDOWS:
        src=original_window(folder,addr,size)
        f=folder/f"{NAME}-bytes-{label}.json"
        imported_value=(imported(folder,label,addr,size,src)
                        if f.exists() or f.is_symlink() else None)
        g=folder/f"{NAME}-refs-{label}.json"
        refs=(xrefs(folder,label,addr,expected_refs)
              if g.exists() or g.is_symlink() else None)
        if strict and (imported_value is None or refs is None):
            raise ExtractionError("Missing original Ghidra callee proof: "+label)
        results.append({
            "role":label,"originalExecutable":src,
            "importedOriginalGhidraCode":imported_value,
            "staticXrefs":refs,
            "boundaryGhidraVerified":False,
            "semanticsInferredFromName":False,
        })
    return {
        "classification":"HXL1_STATIC_RAM_PROTOCOL_OUTPUT_HELPER_CALLEES",
        "originalEnvDxeSha256":PE_SHA256,
        "boundedCallbackEvidenceSha256":
            cb["threeOriginalGhidraReadbacks"]["originalSha256"],
        "callbackCompleteReachableStaticCallsites":cb["cfg"]["reachableCalls"],
        "additionalOriginalTargetReadbacks":results,
        "liveRamPartitionsMeasured":False,
        "runtimeBootBranchKnown":False,
        "kernelPhysicalBaseKnown":False,
        "rootOrKernelSuDemonstrated":False,
    }


def markdown(x:dict)->str:
    rows=[
        "# HXL1 EnvDxe — reachable RAM-partition callback helper targets",
        "",
        "Authenticated original EnvDxe SHA256: "+x["originalEnvDxeSha256"],
        "Authenticated previous callback window SHA256: "+
            x["boundedCallbackEvidenceSha256"],
        "",
        "Three targets follow independently verified *static* BL callsites.",
        "Code windows are not validated complete function extents and a",
        "symbolic target name must not be treated as a confirmed allocator.",
        "",
    ]
    for r in x["additionalOriginalTargetReadbacks"]:
        src=r["originalExecutable"]
        rows+=["## "+r["role"]+" "+src["staticAddress"],"",
               "Read length: "+str(src["size"])+" bytes",
               "Section: "+src["sectionName"],
               "Original file offset: "+src["peFileOffset"],
               "Original SHA256: "+src["sha256"],
               "Original bytes: "+src["bytesHex"],
               "Ghidra import checked: "+str(r["importedOriginalGhidraCode"] is not None),
               "Ghidra references checked: "+str(r["staticXrefs"] is not None),""]
        if r["importedOriginalGhidraCode"] is not None:
            rows+=["Ghidra byte-read evidence: "+
                   r["importedOriginalGhidraCode"]["evidenceId"]]
        if r["staticXrefs"] is not None:
            refs=r["staticXrefs"]
            rows+=["Ghidra xref evidence: "+refs["evidenceId"],
                   "Observed caller sites: "+", ".join(refs["sources"])]
        rows+=["","| Original instruction | Kind | Static destination |",
               "|---|---|---|"]
        rows+=["| "+e["instructionAddress"]+" | "+e["mnemonicClass"]+
               " | "+str(e["directBranchTarget"])+" |" for e in src["edges"]]
        rows+=[""]
    rows+=["## Limits","",
           "This is only authenticated original stock firmware code and static",
           "references. No actual output allocation was traced at runtime.",
           "No SMEM 402 table contents, BaseMemory, kernel physical destination,",
           "live KASLR value, exploit, root or KernelSU were established.",""]
    return "\n".join(rows)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out",type=Path,default=REPORT_DIR)
    ap.add_argument("--verify",choices=[x[0] for x in WINDOWS])
    ap.add_argument("--kind",choices=["bytes","xrefs"],default="bytes")
    args=ap.parse_args()
    try:
        if args.verify:
            label,at,size,required=next(x for x in WINDOWS if x[0]==args.verify)
            if args.kind=="bytes":
                orig=original_window(args.out,at,size)
                result=imported(args.out,label,at,size,orig)
                print("[VERIFIED CALLEE BYTES]",label,at,result["evidenceId"])
            else:
                result=xrefs(args.out,label,at,required)
                print("[VERIFIED CALLEE XREFS]",label,at,result["evidenceId"],
                      "sources",result["sourceCount"])
            return 0
        data=report(args.out,strict=False)
        (args.out/"rea-envdxe-callee-provenance.md").write_text(markdown(data))
        (args.out/"rea-envdxe-callee-provenance.json").write_text(
            json.dumps(data,indent=2)+"\n")
        for item in data["additionalOriginalTargetReadbacks"]:
            print("[STATIC CALLEE]",item["role"],item["originalExecutable"]["staticAddress"],
                  "original and Ghidra matched",item["importedOriginalGhidraCode"] is not None,
                  "Ghidra xrefs verified",item["staticXrefs"] is not None)
        print("[REPORT]",args.out/"rea-envdxe-callee-provenance.md")
        print("[LIMIT] No live SMEM/physical kernel load/root observed")
        return 0
    except (ExtractionError,OSError,ValueError,KeyError,StopIteration) as e:
        print("[STOP]",str(e),file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
