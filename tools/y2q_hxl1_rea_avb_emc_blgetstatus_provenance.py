#!/usr/bin/env python3
"""Static HXL1 EMC BLGetStatus response-source and status-return provenance.

Chain-attests pinned original HXL1 LinuxLoader and completed bit-2
producer evidence. Native FUN_00068810 preserves request arguments,
builds an EMC request and reads status result DAT_00365234 after
FUN_0006d820. This does not prove the status origin, authenticity or
that status 1 authorizes secure boot.

NEW read-only original Ghidra requests: at most SEVEN:
  xrefs 0x365234 (status result);
  function + native of 0x712b8 (request initialization),
  0x715e8 (request element builder),
  0x6d820 (response/status transfer).
No phone communication, binary patching, flashing or bypass operation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256,TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner,choose_targets,evidence,function_record,reference_sources,safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_writers import exact_instruction
from tools.y2q_hxl1_rea_avb_unlock_bitmask_clusters import full_native
from tools.y2q_hxl1_rea_avb_bit2_writer_origin import audit as verify_bit2

ROOT="0x68810"
STATUS="0x365234"
FUNCTIONS=(
    ("0x712b8","emc-request-preparation"),
    ("0x715e8","emc-request-element-builder"),
    ("0x6d820","emc-status-response-transfer"),
)
BL_NATIVE=(
    ("0x68828","mov","w20,w0"),
    ("0x68834","stp","w1,w0,[sp]"),
    ("0x68838","bl","0x00067e20"),
    ("0x68870","orr","w0,wzr,#0x6"),
    ("0x68874","mov","x1,x19"),
    ("0x68878","bl","0x000712b8"),
    ("0x68a14","ldr","x0,[x19,#0x18]"),
    ("0x68a18","mov","w1,#0x1"),
    ("0x68a1c","add","x2,sp,#0x4"),
    ("0x68a20","mov","w3,#0x2"),
    ("0x68a24","bl","0x000715e8"),
    ("0x68a34","ldr","x0,[x19,#0x18]"),
    ("0x68a38","mov","w1,#0x15"),
    ("0x68a3c","mov","x2,sp"),
    ("0x68a40","mov","w3,#0x4"),
    ("0x68a44","bl","0x000715e8"),
    ("0x68a54","adrp","x20,0x365000"),
    ("0x68a58","add","x20,x20,#0x230"),
    ("0x68a5c","mov","w1,#0x20"),
    ("0x68a60","mov","x0,x19"),
    ("0x68a64","mov","x2,x20"),
    ("0x68a68","bl","0x0006d820"),
)
SOURCE_MARKERS=(
    r"FUN_00067e20\s*\(",
    r"FUN_000712b8\s*\(",
    r"FUN_000715e8\s*\(",
    r"FUN_0006d820\s*\(",
    r"DAT_00365234",
    r"if\s*\(\s*DAT_00365234\s*==\s*0\s*\)",
    r"iVar4\s*=\s*1\s*;",
    r"return\s+iVar4",
)
MAX_NATIVE=5000
MAX_SOURCE_LINES=7000


def verify_prior(prior:dict)->dict:
    if prior.get("sourceAttested") is not True:
        raise TriageError("HXL1 original bit-2 source chain unauthenticated")
    bit=prior.get("bit2NativeMerge") or {}
    if (bit.get("exactLocalBit2AndBit3MergeVerified") is not True
            or bit.get("effectiveAddressFromPinnedX19")!="0x3651ec"):
        raise TriageError("Original bit-2/bit-3 merge provenance changed")
    items=prior.get("remainingAndProvider")
    if not isinstance(items,list) or len(items)!=3:
        raise TriageError("Original BLGetStatus and final xref dossiers incomplete")
    by_site={item.get("site"):item for item in items if isinstance(item,dict)}
    if len(by_site)!=3 or set(by_site)!={ROOT,"0x68160","0x69834"}:
        raise TriageError("Original BLGetStatus dossier inventory changed")
    for site,expected_owner in ((ROOT,ROOT),("0x68160","0x68148"),("0x69834","0x69780")):
        row=by_site[site]
        if not (row.get("source",{}).get("owner")==expected_owner
                and row.get("native",{}).get("owner")==expected_owner
                and isinstance(row["source"].get("evidenceId"),str)
                and isinstance(row["native"].get("nativeEvidenceId"),str)):
            raise TriageError(f"Original 22 xref source-owner evidence changed at {site}")
    return by_site


def verify_original_BLGetStatus(fn:dict, native:dict, prior:dict)->dict:
    if (fn["evidence_id"]!=prior["source"]["evidenceId"]
            or native["evidence_id"]!=prior["native"]["nativeEvidenceId"]):
        raise TriageError("Original saved BLGetStatus source/native Evidence identity changed")
    if function_record(fn,ROOT)["entry"]!=ROOT:
        raise TriageError("Original BLGetStatus function owner changed")
    pseudo=fn["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not 20<=len(pseudo.splitlines())<=5000:
        raise TriageError("Original BLGetStatus Ghidra pseudocode unavailable/oversized")
    for pat in SOURCE_MARKERS:
        if re.search(pat,pseudo) is None:
            raise TriageError(f"Original BLGetStatus source marker differs: {pat}")
    ops=full_native(native,ROOT)
    if len(ops)!=318:
        raise TriageError("Original BLGetStatus native 318-instruction inventory changed")
    for a,m,o in BL_NATIVE:
        exact_instruction(ops,a,m,o)
    def interval(start,end,required):
        got=sorted((a for a in ops if int(start,16)<=int(a,16)<=int(end,16)),
                   key=lambda a:int(a,16))
        if got!=list(required):
            raise TriageError(f"Original BLGetStatus request argument interval differs {start}")
    interval("0x68a14","0x68a24",("0x68a14","0x68a18","0x68a1c","0x68a20","0x68a24"))
    interval("0x68a34","0x68a44",("0x68a34","0x68a38","0x68a3c","0x68a40","0x68a44"))
    interval("0x68a54","0x68a68",("0x68a54","0x68a58","0x68a5c","0x68a60","0x68a64","0x68a68"))
    return {
        "entry":ROOT,"sourceEvidenceId":fn["evidence_id"],
        "nativeEvidenceId":native["evidence_id"],
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "nativeInstructionCount":len(ops),
        "normalPseudocodeStatusExpression":"DAT_00365234 != 0 ? DAT_00365234 : 1",
        "originalStatusGlobal":STATUS,
        "requestArgumentSourcesPinned":True,
        "originalNativePins":[a+": "+ops[a][0]+" "+ops[a][1] for a,_,_ in BL_NATIVE],
        "returnedStatusNativeW0Proof":False,
        "authenticatedResponseOrSecureAuthorizationProven":False,
        "status1IsEquivalentToOEMUnlockProven":False,
    }


def bounded_function(ev:dict,entry:str,kind:str)->dict:
    if function_record(ev,entry)["entry"]!=entry:
        raise TriageError("Original EMC helper function owner changed")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>330000:
        raise TriageError("Original EMC helper function source invalid")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=MAX_SOURCE_LINES:
        raise TriageError("Original EMC helper exceeds source budget")
    needle=re.compile(r"65234|712b8|715e8|6d820|714b0|response|result|status|token|"
                      r"FUN_|DAT_|if\s*\(|return|secure|payload",re.I)
    matches=[i for i,line in enumerate(lines) if needle.search(line)]
    indices=set(range(min(10,len(lines))))
    for i in matches[:80]:
        indices.update(range(max(0,i-3),min(len(lines),i+5)))
    chosen=sorted(indices)[:230]
    return {
        "entry":entry,"kind":kind,"sourceEvidenceId":ev["evidence_id"],
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "totalLines":len(lines),
        "excerpt":[{"line":i+1,"text":lines[i][:790]} for i in chosen],
        "truncated":len(indices)>len(chosen) or len(matches)>80,
        "globalRefs":sorted(set(re.findall(r"\bDAT_[0-9a-fA-F]{8}\b",pseudo)))[:150],
        "functionRefs":sorted(set(re.findall(r"\bFUN_[0-9a-fA-F]{8}\b",pseudo)))[:150],
        "trustedResponseSourceVerified":False,
    }


def bounded_native(ev:dict,entry:str)->dict:
    ops=full_native(ev,entry)
    if not 6<=len(ops)<=MAX_NATIVE:
        raise TriageError("Original EMC helper native list out of bounds")
    keys=sorted(ops,key=lambda x:int(x,16))
    return {
        "entry":entry,"nativeEvidenceId":ev["evidence_id"],
        "instructionCount":len(ops),
        "excerpt":[a+": "+ops[a][0]+(" "+ops[a][1] if ops[a][1] else "")
                   for a in keys[:205]],
        "truncated":len(keys)>205,"secureMessageIntegrityEstablished":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prev=verify_bit2(root)
    sites=verify_prior(prev)
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    f=evidence(folder/"function-bitmask-bit2-0x68810.json",
               sha=target.sha256,operation="analyze_function",
               parameter="procedure",value=ROOT)
    n=evidence(folder/"instructions-bitmask-bit2-owner-0x68810.json",
               sha=target.sha256,operation="read_function_instructions",
               parameter="procedure",value=ROOT)
    pinned=verify_original_BLGetStatus(f,n,sites[ROOT])
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA host file unavailable or symlinked")
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    e=runner.obtain(
        target,["xrefs",str(target.path),STATUS],
        folder/("xrefs-emc-status-"+safe_segment(STATUS)+".json"),
        operation="xrefs",parameter="address",value=STATUS)
    status_xrefs=reference_sources(e) if e is not None else []
    helpers=[]
    for entry,kind in FUNCTIONS:
        fn=runner.obtain(
            target,["function",str(target.path),entry],
            folder/("function-emc-status-"+safe_segment(entry)+".json"),
            operation="analyze_function",parameter="procedure",value=entry)
        native=runner.obtain(
            target,["instructions",str(target.path),entry],
            folder/("instructions-emc-status-"+safe_segment(entry)+".json"),
            operation="read_function_instructions",parameter="procedure",value=entry)
        helpers.append({
            "entry":entry,"kind":kind,
            "source":bounded_function(fn,entry,kind) if fn else None,
            "native":bounded_native(native,entry) if native else None,
        })
    return {
        "schemaVersion":1,"originalBlArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"READ_ONLY_ORIGINAL_GHIDRA" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),
        "requestAndStatus":pinned,
        "statusReferences":{
            "global":STATUS,"sourceEvidenceId":e["evidence_id"] if e else None,
            "total":len(status_xrefs),"coordinates":status_xrefs[:200],
            "displayTruncated":len(status_xrefs)>200,
            "writesOrTrustedOwnershipProven":False,
        },
        "helpers":helpers,
        "responseAuthenticationProven":False,
        "bit2OEMAuthorizationProven":False,
        "signedImageOrOdinBypassProven":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    p=r["requestAndStatus"]
    lines=[
        "# HXL1 original EMC BLGetStatus response and bit-2 producer provenance",
        "",
        "**Only source-pinned stock HXL1 native/Ghidra; no device changes.**",
        "","Original BL archive SHA256: "+r["originalBlArchiveSha256"],
        "New read-only Ghidra queries: "+str(r["newQueries"]),
        "",
        "## Native BLGetStatus request construction","",
        "Original native Evidence: "+p["nativeEvidenceId"],
        "Original source Evidence: "+p["sourceEvidenceId"],
        "- Preserve request arguments W0/W1, initialize via 0x67e20.",
        "- Create transaction structure via 0x712b8, add request",
        "  items through 0x715e8 and transfer/parse via 0x6d820.",
        "- Original pseudocode returns DAT_00365234, or 1 if zero.",
        "  Exact native returned W0 and status origin require separate proof.",
        "- Status '1' may be a generic success; it is NOT proof",
        "  of privileged boot-unlock authorization.",
        "","~~~asm",*p["originalNativePins"],"~~~","",
    ]
    x=r["statusReferences"]
    lines += [
        "## Original DAT_00365234 cross-references","",
        "- Global: "+x["global"],"- Evidence: "+str(x["sourceEvidenceId"]),
        "- Source-coordinate count: "+str(x["total"]),
        "- Coordinates: "+str(x["coordinates"]),
        "- Xrefs are unclassified; stores, effective addresses and",
        "  security authority have not been proven.","",
        "## Original EMC request/response helper dossiers","",
    ]
    for item in r["helpers"]:
        lines += ["### "+item["entry"]+" — "+item["kind"],""]
        f=item["source"]
        if f:
            lines += [
                "- Original source Evidence: "+f["sourceEvidenceId"],
                "- Function candidates: "+str(f["functionRefs"]),
                "- Data globals: "+str(f["globalRefs"]),
                "","~~~c",
            ]
            lines += [str(x["line"])+": "+x["text"] for x in f["excerpt"]]
            lines += ["~~~",""]
        else:
            lines += ["- Original source query pending.",""]
        n=item["native"]
        if n:
            lines += [
                "- Original native Evidence: "+n["nativeEvidenceId"],
                "- Native instruction count: "+str(n["instructionCount"]),
                "","~~~asm",*n["excerpt"],"~~~","",
            ]
    lines += [
        "## Remaining proof gates","",
        "1. Prove which native instructions write DAT_00365234,",
        "   and whether the value is a transport result or token status.",
        "2. Identify authenticated origin, if any, of EMC token/core",
        "   data returned through request builder and response helpers.",
        "3. Reconstruct native reaching definitions for FUN_00068810",
        "   returned W0. Ghidra's default-zero->one normalization",
        "   alone cannot establish a policy Boolean.",
        "4. Separately determine how Qualcomm/Samsung boot and",
        "   Odin verification interpret bit-2 software state.",
        "5. No handset/flash changes or working bypass demonstrated.","",
    ]
    return "\n".join(lines)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir",type=Path,default=Path.home()/
                    "s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    ap.add_argument("--node",default="node")
    ap.add_argument("--execute",action="store_true")
    ap.add_argument("--recover-partials",action="store_true")
    ap.add_argument("--timeout",type=int,default=240)
    a=ap.parse_args()
    if not 30<=a.timeout<=1200:
        ap.error("timeout outside safe bounds")
    try:
        root=a.input_dir.expanduser().resolve()
        r=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-emc-blgetstatus-provenance.json").write_text(json.dumps(r,indent=2)+"\n")
        (out/"avb-emc-blgetstatus-provenance.md").write_text(markdown(r))
    except (TriageError,OSError,TypeError,ValueError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[STATUS]",STATUS,"xrefs",r["statusReferences"]["total"])
    for h in r["helpers"]:
        print("[HELPER]",h["entry"],h["kind"],
              "ATTESTED" if h["source"] and h["native"] else "PENDING")
    print("[REPORT]",out/"avb-emc-blgetstatus-provenance.md")
    print("[LIMIT] No secure authorization, unsigned boot or device unlock proven")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
