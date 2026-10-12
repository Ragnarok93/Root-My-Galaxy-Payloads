#!/usr/bin/env python3
"""Source-attested HXL1 bit-2 producer and remaining native xref owners.

Reattest the prior original 22-xref audit, including owner 0x68d08's
cached *full* native instructions. Verify X19 page origin at 0x68d90
and all seven STR W8,[X19,#0x1ec] targets. Pin the two alternatives
that merge at 0x68e1c, adding either 0x4 (bit 2) or 0x8 (bit 3),
without claiming branch dominance or secure-world permission.

Read-only original Ghidra queries: function+instructions at 0x68810,
plus function+instructions for two uncovered xrefs 0x68160, 0x69834.
At most six new queries, no handset, flash, patch or image unlock.
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
    Runner,choose_targets,evidence,function_record,safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions,exact_instruction
from tools.y2q_hxl1_rea_avb_unlock_bitmask_clusters import (
    audit as verify_clusters, full_native, site_evidence,
)

ROOT_GLOBAL="0x3651ec"
ROOT_OWNER="0x68d08"
CALL="0x68810"
REMAINING=("0x68160","0x69834")
STORE_SITES=(
    "0x68e24","0x68e44","0x68e64","0x68e84",
    "0x68ea4","0x68ec4","0x68ef0",
)
PINNED=(
    ("0x68d90","adrp","x19,0x365000"),
    ("0x68d94","ldr","w8,[x19,#0x1ec]"),
    ("0x68df4","cmp","w0,#0x1"),
    ("0x68df8","b.ne","0x00068e04"),
    ("0x68dfc","mov","w8,#0x4"),
    ("0x68e00","b","0x00068e1c"),
    ("0x68e04","mov","w0,#0x4"),
    ("0x68e08","mov","w1,wzr"),
    ("0x68e0c","bl","0x00068810"),
    ("0x68e10","cmp","w0,#0x1"),
    ("0x68e14","b.ne","0x00068e28"),
    ("0x68e18","mov","w8,#0x8"),
    ("0x68e1c","ldr","w9,[x19,#0x1ec]"),
    ("0x68e20","orr","w8,w9,w8"),
    ("0x68e24","str","w8,[x19,#0x1ec]"),
    ("0x68e40","orr","w8,w8,#0x40"),
    ("0x68e60","orr","w8,w8,#0x20"),
    ("0x68e80","orr","w8,w8,#0x80"),
    ("0x68ea0","orr","w8,w8,#0x100"),
    ("0x68ec0","orr","w8,w8,#0x400"),
    ("0x68eec","orr","w8,w8,#0x800"),
)
MAX_FUNC_NATIVE=5500


def check_prior(prior:dict)->dict:
    if prior.get("sourceAttested") is not True:
        raise TriageError("Original global cluster evidence unauthenticated")
    records=prior.get("classifiedXrefs")
    if not isinstance(records,list) or len(records)!=22 or prior.get("classifiedCount")!=20:
        raise TriageError("Original classified native xref inventory must be 20/22")
    known={row.get("site"):row for row in records}
    if len(known)!=22 or set(known)!={
        "0x67df8","0x6811c","0x68160","0x68d94","0x68e1c","0x68e24",
        "0x68e3c","0x68e44","0x68e5c","0x68e64","0x68e7c","0x68e84",
        "0x68e9c","0x68ea4","0x68ebc","0x68ec4","0x68ee4","0x68ef0",
        "0x6967c","0x696b8","0x69700","0x69834",
    }:
        raise TriageError("Original complete 22 native-site inventory differs")
    for site in REMAINING:
        if (known[site].get("nativeOwner") is not None or
            known[site].get("opcodeClass")!="NOT_YET_NATIVE_CLASSIFIED"):
            raise TriageError("Original missing native owner inventory changed")
    for site in STORE_SITES:
        obj=known[site]
        if (obj.get("nativeOwner")!=ROOT_OWNER
            or obj.get("nativeOpcode")!="str"
            or obj.get("operands")!="w8,[x19,#0x1ec]"
            or obj.get("opcodeClass")!="store-opcode-unattributed"):
            raise TriageError("Original ARM64 candidate bitmask STR sites changed")
    rows=[item for item in prior.get("nativeOwnerEvidence",[])
          if item.get("owner")==ROOT_OWNER]
    if len(rows)!=1 or not isinstance(rows[0].get("evidenceId"),str):
        raise TriageError("Original 0x68d08 native owner evidence missing")
    for site in ("0x6811c","0x68d94","0x6967c"):
        if known[site].get("nativeOwner") not in (
            "0x680d8","0x68d08","0x69628"
        ):
            raise TriageError("Unexpected original bitmask cluster source owner")
    return {"originalNativeEvidence":rows[0]["evidenceId"],
            "sites":known}


def native_bit2_merge(ev:dict,expected:str)->dict:
    if ev["evidence_id"]!=expected:
        raise TriageError("Original 0x68d08 native Evidence ID mismatch")
    ops=full_native(ev,ROOT_OWNER)
    for a,m,o in PINNED:
        exact_instruction(ops,a,m,o)
    for a in STORE_SITES:
        exact_instruction(ops,a,"str","w8,[x19,#0x1ec]")
    page_base=0x365000
    offset=0x1ec
    if hex(page_base+offset)!=ROOT_GLOBAL:
        raise TriageError("Native ADRP+STR global effective address mismatch")
    # No explicit W19/X19 redeclaration between the pinned ADRP and
    # the latest store. ARM64 BL normally preserves callee-saved X19,
    # but this check is NOT an interprocedural ABI or CFG proof.
    clobbers=[]
    for a,(mnemonic,operand) in ops.items():
        if not 0x68d90<int(a,16)<=0x68ef0:
            continue
        if mnemonic in ("str","strb","strh","stp","stur","stlr",
                        "cmp","cmn","tst","b","bl","blr","ret"):
            continue
        dest=operand.split(",",1)[0]
        if dest in ("x19","w19"):
            clobbers.append(a)
    if clobbers:
        raise TriageError("Original X19 bitmask-page base overwritten at "+str(clobbers))
    seq=("0x68df4","0x68df8","0x68dfc","0x68e00",
         "0x68e04","0x68e08","0x68e0c","0x68e10","0x68e14",
         "0x68e18","0x68e1c","0x68e20","0x68e24")
    actual=sorted((a for a in ops if int(seq[0],16)<=int(a,16)<=int(seq[-1],16)),
                  key=lambda x:int(x,16))
    if actual!=list(seq):
        raise TriageError("Unknown instruction in original bit 2/3 write merge")
    return {
        "nativeEvidenceId":ev["evidence_id"],
        "owner":ROOT_OWNER,
        "originalNativeCount":len(ops),
        "addressExpression":"0x365000 + 0x1ec = 0x3651ec",
        "effectiveAddressFromPinnedX19":ROOT_GLOBAL,
        "storeOpcodeSites":list(STORE_SITES),
        "x19OverwritesBetweenBaseAndLastStore":[],
        "firstWriteMode":"W8=old_global | 0x4 after 0x68dfc",
        "alternativeWriteMode":"W8=old_global | 0x8 after 0x68810(4,0)==1",
        "exactLocalBit2AndBit3MergeVerified":True,
        "wholeFunctionDominanceVerified":False,
        "interproceduralX19PreservationVerified":False,
        "functionMayReturnWithoutSettingBit2":True,
        "authorityOfDecisionSourceVerified":False,
        "hardwareBootUnlockProven":False,
    }


def source_report(ev:dict,site:str)->dict:
    rec=function_record(ev,site)
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>300000:
        raise TriageError("Original Ghidra source not present or oversized")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=6000:
        raise TriageError("Ghidra original source line budget exceeded")
    includes=set(range(min(12,len(lines))))
    interesting=re.compile("68810|3651ec|OEM|unlock|bit|flag|token|status|param|if\\s*\\(",re.I)
    hits=[i for i,line in enumerate(lines) if interesting.search(line)]
    for index in hits[:50]:
        includes.update(range(max(0,index-3),min(len(lines),index+5)))
    chosen=sorted(includes)[:190]
    return {
        "site":site,"owner":rec["entry"],
        "evidenceId":ev["evidence_id"],
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "pseudocodeLines":len(lines),
        "source":[{"line":i+1,"code":lines[i][:800]} for i in chosen],
        "excerptTruncated":len(includes)>len(chosen),
        "provesTrustedAuthorization":False,
    }


def original_native_dossier(ev:dict,entry:str,site:str)->dict:
    ops=full_native(ev,entry)
    if site not in ops:
        raise TriageError(f"Original function {entry} does not contain required {site}")
    return {
        "owner":entry,"sourceSite":site,"nativeEvidenceId":ev["evidence_id"],
        "originalInstructionCount":len(ops),
        "site":site_evidence(ops,site,entry,ev["evidence_id"]),
        "nativeExcerpt":[
            a+": "+ops[a][0]+(" "+ops[a][1] if ops[a][1] else "")
            for a in sorted(ops,key=lambda s:int(s,16))[:175]
        ],
        "originalControlFlowProven":False,
        "trustedBootStateProven":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_clusters(root)
    expected=check_prior(prior)
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    original=evidence(
        folder/"instructions-bitmask-owner-0x68d08.json",
        sha=target.sha256,operation="read_function_instructions",
        parameter="procedure",value=ROOT_OWNER)
    bit= native_bit2_merge(original,expected["originalNativeEvidence"])
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA host script missing/unsafe")
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    cases=[]
    for site in (CALL,*REMAINING):
        f=runner.obtain(
            target,["function",str(target.path),site],
            folder/("function-bitmask-bit2-"+safe_segment(site)+".json"),
            operation="analyze_function",parameter="procedure",value=site)
        info=source_report(f,site) if f else None
        n=None
        if info:
            n=runner.obtain(
                target,["instructions",str(target.path),info["owner"]],
                folder/("instructions-bitmask-bit2-owner-"+
                        safe_segment(info["owner"])+".json"),
                operation="read_function_instructions",parameter="procedure",value=info["owner"])
        native=original_native_dossier(n,info["owner"],site) if n is not None else None
        cases.append({
            "site":site,"source":info,"native":native,
            "originalReadOnly":True,"deviceModified":False,
        })
    return {
        "schemaVersion":1,"originalBlArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"READ_ONLY_ORIGINAL_GHIDRA" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),
        "bit2NativeMerge":bit,
        "remainingAndProvider":cases,
        "bit2SourceAuthorityProven":False,
        "bootloaderUnlockOrOdinBypassProven":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    b=r["bit2NativeMerge"]
    lines=[
        "# HXL1 original bit-2 and bit-3 write merge — provider provenance",
        "",
        "**Original SHA-attested static ARM64 source. No phone/firmware operation.**",
        "","HXL1 BL archive SHA256: "+r["originalBlArchiveSha256"],
        "New original Ghidra queries: "+str(r["newQueries"]),
        "",
        "## Source-pinned X19 effective address and bit-2 path","",
        "- Original owner: "+b["owner"],
        "- Native Evidence: "+b["nativeEvidenceId"],
        "- ADRP X19 at 0x68d90 forms 0x365000.",
        "- Seven original STR W8,[X19,#0x1ec] operations",
        "  address 0x3651ec if callee-saved X19 is preserved.",
        "- At 0x68dfc, W8 <- 0x4 (bit 2).",
        "- Alternative 0x68e0c calls FUN_00068810(4,0); if",
        "  W0 == 1, W8 <- 0x8 (bit 3).",
        "- 0x68e1c loads the previous global value,",
        "  0x68e20 ORs W8 with it and 0x68e24 stores.",
        "- These are locally verified instructions and addressing;",
        "  full reaching-definitions, CFG dominance and trusted",
        "  source semantics remain UNPROVEN.",
        "- Original store sites: "+str(b["storeOpcodeSites"]),
        "","~~~asm",
        "0x68d90: adrp x19,0x365000",
        "0x68df4: cmp w0,#0x1",
        "0x68df8: b.ne 0x00068e04",
        "0x68dfc: mov w8,#0x4",
        "0x68e00: b 0x00068e1c",
        "0x68e04: mov w0,#0x4",
        "0x68e08: mov w1,wzr",
        "0x68e0c: bl 0x00068810",
        "0x68e10: cmp w0,#0x1",
        "0x68e14: b.ne 0x00068e28",
        "0x68e18: mov w8,#0x8",
        "0x68e1c: ldr w9,[x19,#0x1ec]",
        "0x68e20: orr w8,w9,w8",
        "0x68e24: str w8,[x19,#0x1ec]",
        "~~~","",
        "## OEM/token query provider and two unclassified xrefs","",
    ]
    for case in r["remainingAndProvider"]:
        src=case["source"]
        lines += [
            "### "+case["site"]+
              (" -> "+src["owner"] if src else " -> NOT YET QUERIED"),"",
        ]
        if src:
            lines += [
                "- Original source Evidence: "+src["evidenceId"],
                "- Pseudocode lines: "+str(src["pseudocodeLines"]),
                "","~~~c",
            ]
            for row in src["source"]:
                lines.append(f"{row['line']:5d} | {row['code']}")
            lines += ["~~~",""]
        data=case["native"]
        if data:
            lines += [
                "- Original native Evidence: "+data["nativeEvidenceId"],
                "- Native instructions: "+str(data["originalInstructionCount"]),
                "- Target instruction: "+data["site"]["nativeOpcode"]+
                  " "+data["site"]["operands"],
                "- Opcode class: "+data["site"]["opcodeClass"],
                "- Global alias/security authorization NOT YET VERIFIED.",
                "","~~~asm",*data["nativeExcerpt"],"~~~","",
            ]
    lines += [
        "## Remaining security gates","",
        "1. Read FUN_00068810 input-index and its state/source",
        "   semantics (particularly [0,0], [3,0], [4,0]).",
        "2. Determine origin of 0x68d08 result W0 preceding",
        "   0x68df4; distinguish bit 2 versus bit 3.",
        "3. Assess whether this cached token-mask determines actual",
        "   signed-image authorization independently of user-visible",
        "   OEM/FRP values. Do not infer trust from a STR instruction.",
        "4. No working OEM bootloader unlock or signature bypass",
        "   is established from this static dossier.","",
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
        ap.error("Timeout out of bounded range")
    try:
        root=a.input_dir.expanduser().resolve()
        r=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-bit2-writer-origin.json").write_text(json.dumps(r,indent=2)+"\n")
        (out/"avb-bit2-writer-origin.md").write_text(markdown(r))
    except (TriageError,OSError,TypeError,ValueError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[BIT2]",r["bit2NativeMerge"]["effectiveAddressFromPinnedX19"],
          "local bit2/bit3 merge attested")
    for case in r["remainingAndProvider"]:
        print("[OWNER]",case["site"],
              case["source"]["owner"] if case["source"] else "PENDING")
    print("[REPORT]",out/"avb-bit2-writer-origin.md")
    print("[LIMIT] No hardware unlock authorization or signature bypass proven")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
