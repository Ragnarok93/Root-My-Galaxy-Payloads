#!/usr/bin/env python3
"""HXL1 original 0x3651ec bitmask reference-cluster source audit.

Read-only SHA-pinned original LinuxLoader evidence. Revalidate exactly
22 original 0x3651ec Ghidra xref coordinates (one reader and 21 other
unclassified xrefs) and three distinct representative seed locations:
  0x6811c, 0x68d94, 0x6967c.
Obtain up to six new original Ghidra queries, function and native
instructions for each seed's actual Ghidra owner, collapsing repeated
owner lookups. Classify only sites present in FULL native owner bodies;
do not infer that a Ghidra xref is a store or that a bit is trusted.

This is static source analysis; never access handset, flash, bypass,
patch the original image or make a signed-boot authorization claim.
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
from tools.y2q_hxl1_rea_avb_unlock_bitmask_producers import audit as verify_bitmask_producers
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions

GLOBAL="0x3651ec"
SEEDS=("0x6811c","0x68d94","0x6967c")
SITES=(
    "0x67df8","0x6811c","0x68160","0x68d94","0x68e1c","0x68e24",
    "0x68e3c","0x68e44","0x68e5c","0x68e64","0x68e7c","0x68e84",
    "0x68e9c","0x68ea4","0x68ebc","0x68ec4","0x68ee4","0x68ef0",
    "0x6967c","0x696b8","0x69700","0x69834",
)
MAX_INSTRUCTIONS=5000
MAX_SOURCE_LINES=6000
OPERAND_MEMORY=re.compile(r"\[\s*(x(?:[12]?\d|30)|sp)\s*(?:,\s*#(0x[0-9a-f]+|\d+))?\s*\]",re.I)
ADDR_LOAD=re.compile(r"^adrp\s+(x\d+),\s*0x([0-9a-f]+)$",re.I)


def verify_inventory(prior:dict)->dict:
    if prior.get("sourceAttested") is not True:
        raise TriageError("Original Ghidra bitmask producer source not attested")
    sel=prior.get("nativeBitmaskSelector") or {}
    if sel.get("globalAddress")!=GLOBAL or sel.get("callerInputMask")!=4 or \
       sel.get("normalReturnFlowVerified") is not True:
        raise TriageError("Original bitmask Boolean/entry mask changed")
    xrefs=[x for x in prior.get("sourceXrefs",[]) if x.get("address")==GLOBAL]
    if len(xrefs)!=1:
        raise TriageError("Original bitmask xref Evidence not unique")
    inv=xrefs[0]
    sites=inv.get("sites")
    if (inv.get("xrefCount")!=len(SITES) or inv.get("displayTruncated") is not False
        or not isinstance(sites,list) or len(sites)!=len(SITES)
        or set(sites)!=set(SITES) or not isinstance(inv.get("originalEvidenceId"),str)):
        raise TriageError("Original bitmask global 22-address reference inventory changed")
    return inv


def original_xref_audit(ev:dict,prior_row:dict)->dict:
    addresses=reference_sources(ev)
    if (len(addresses)!=len(SITES) or set(addresses)!=set(SITES)
        or ev["evidence_id"]!=prior_row["originalEvidenceId"]):
        raise TriageError("Original SHA-bound 0x3651ec Ghidra references changed")
    return {"evidenceId":ev["evidence_id"],"global":GLOBAL,
            "total":len(addresses),"sourceCoordinates":addresses}


def original_function(ev:dict,seed:str)->dict:
    owner=function_record(ev,seed)
    pseudo=ev["normalized_result"].get("pseudocode")
    if (not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>300000):
        raise TriageError("Original bitmask cluster pseudocode missing/oversized")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=MAX_SOURCE_LINES:
        raise TriageError("Original owner pseudocode not bounded")
    hits=[i for i,l in enumerate(lines)
          if re.search(r"DAT_003651ec|FUN_00067dd8|FUN_00067e20|0x3651ec|bit|flag|switch|mode",l,re.I)]
    select=set(range(min(15,len(lines))))
    for i in hits[:80]:
        select.update(range(max(0,i-4),min(len(lines),i+5)))
    excerpts=sorted(select)[:220]
    return {
        "seed":seed,"owner":owner["entry"],"evidenceId":ev["evidence_id"],
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "lines":len(lines),
        "selectedLines":[{"line":i+1,"source":lines[i][:800]} for i in excerpts],
        "sourceTruncated":len(select)>len(excerpts) or len(hits)>80,
        "nativeOwnershipVerified":False,"globalWriterVerified":False,
    }


def full_native(ev:dict,entry:str)->dict:
    data=ev.get("normalized_result")
    rows=data if isinstance(data,list) else data.get("instructions") if isinstance(data,dict) else None
    if not isinstance(rows,list) or not 6<=len(rows)<=MAX_INSTRUCTIONS:
        raise TriageError("Original bitmask cluster native listing missing/beyond limit")
    # Use the strict original parser unless the owner exceeds the helper
    # reader's 2000-instruction safe limit. Do not silently truncate.
    if len(rows)<=2000:
        ops=parse_instructions(ev,entry)
    else:
        from tools.y2q_hxl1_rea_avb_oem_providers_entry import parse_large_main_instructions
        ops=parse_large_main_instructions(ev)
    if len(ops)!=len(rows):
        raise TriageError("Original full-native cluster instruction count differs")
    return ops


def site_evidence(ops:dict,site:str,owner:str,evidence_id:str)->dict:
    if site not in ops:
        raise TriageError("Original xref not in collected owner native listing")
    addresses=sorted(ops,key=lambda x:int(x,16))
    i=addresses.index(site)
    region=addresses[max(0,i-10):min(len(addresses),i+13)]
    opcode,operands=ops[site]
    mnem=opcode.lower()
    # Any store below is an *opcode* classification only, not a
    # proven store to 0x3651ec. ADRP may be an xref to a PAGE rather
    # than a unique byte/word, and intervening register clobbers or
    # branches can change the effective address.
    if mnem.startswith(("str","stp","stur","stlr","stxr")):
        kind="store-opcode-unattributed"
    elif mnem.startswith(("ldr","ldp","ldur","ldar","ldxr")):
        kind="load-opcode-unattributed"
    elif mnem in ("adrp","adr","add"):
        kind="address-computation-not-memory-write"
    else:
        kind="other-native-xref"
    snippets=[a+": "+ops[a][0]+(" "+ops[a][1] if ops[a][1] else "")
              for a in region]
    # Native snippets describe a lexical region; do not assert global
    # write direction until register alias / effective address and
    # path feasibility are source-proven separately.
    return {
        "site":site,"nativeOwner":owner,"nativeEvidenceId":evidence_id,
        "nativeOpcode":mnem,"operands":operands,"opcodeClass":kind,
        "nativeWindow":snippets,
        "effectiveAddress0x3651ecVerified":False,
        "reachableStoreToGlobalVerified":False,
        "sourceOfStoredValueVerified":False,
        "securityPermissionMeaningVerified":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_bitmask_producers(root)
    expected=verify_inventory(prior)
    target={x.name:x for x in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    original_ref=evidence(
        folder/"xrefs-selector-root-0x3651ec.json",
        sha=target.sha256,operation="xrefs",parameter="address",value=GLOBAL)
    inventory=original_xref_audit(original_ref,expected)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA entrypoint missing or symlinked")
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    owner_records={}
    native_records={}
    for seed in SEEDS:
        f=runner.obtain(
            target,["function",str(target.path),seed],
            folder/("function-bitmask-cluster-"+safe_segment(seed)+".json"),
            operation="analyze_function",parameter="procedure",value=seed)
        if f is None:
            continue
        info=original_function(f,seed)
        owner=info["owner"]
        owner_records[seed]=info
        if owner not in native_records:
            n=runner.obtain(
                target,["instructions",str(target.path),owner],
                folder/("instructions-bitmask-owner-"+safe_segment(owner)+".json"),
                operation="read_function_instructions",parameter="procedure",value=owner)
            if n is not None:
                ops=full_native(n,owner)
                native_records[owner]=(n["evidence_id"],ops)
    rows=[]
    for site in SITES:
        match=[(owner,eid,ops) for owner,(eid,ops) in native_records.items() if site in ops]
        if len(match)>1:
            raise TriageError("One original xref unexpectedly owned by multiple native function bodies")
        if match:
            owner,eid,ops=match[0]
            rows.append(site_evidence(ops,site,owner,eid))
        else:
            rows.append({
                "site":site,"nativeOwner":None,"nativeEvidenceId":None,
                "opcodeClass":"NOT_YET_NATIVE_CLASSIFIED",
                "effectiveAddress0x3651ecVerified":False,
                "reachableStoreToGlobalVerified":False,
                "sourceOfStoredValueVerified":False,
                "securityPermissionMeaningVerified":False,
            })
    return {
        "schemaVersion":1,"originalBlArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"READ_ONLY_ORIGINAL_GHIDRA" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),
        "globalInventory":inventory,
        "sourceOwners":list(owner_records.values()),
        "nativeOwnerEvidence":[{"owner":owner,"evidenceId":pair[0],
                                "instructionCount":len(pair[1])}
                               for owner,pair in native_records.items()],
        "classifiedXrefs":rows,
        "classifiedCount":sum(row["nativeOwner"] is not None for row in rows),
        "globalWriteProven":False,
        "bit2ProducerAndTrustProven":False,
        "hardwareUnlockOrImageSignatureBypassProven":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    lines=[
        "# HXL1 original 0x3651ec bitmask xrefs — source-verified native owner clusters",
        "",
        "**SHA-pinned original Ghidra, host read-only. No security bypass or device changes.**",
        "","BL archive SHA256: "+r["originalBlArchiveSha256"],
        "Original xref Evidence: "+r["globalInventory"]["evidenceId"],
        "Original xref total: "+str(r["globalInventory"]["total"]),
        "New read-only REA queries: "+str(r["newQueries"]),
        "Native classified coordinates: "+str(r["classifiedCount"])+
          " / "+str(len(r["classifiedXrefs"])),
        "","## Original three representative Ghidra functions","",
    ]
    for owner in r["sourceOwners"]:
        lines += [
            "### Seed "+owner["seed"]+" -> owner "+owner["owner"],"",
            "- Original Ghidra Evidence: "+owner["evidenceId"],
            "- Source lines: "+str(owner["lines"]),
            "","~~~c",
        ]
        for p in owner["selectedLines"]:
            lines.append(f"{p['line']:5d} | {p['source']}")
        lines += ["~~~",""]
    lines += ["## Original native xref coordinate classification",""]
    for x in r["classifiedXrefs"]:
        lines += [
            "### "+x["site"],"",
            "- Native owner: "+str(x["nativeOwner"]),
            "- Original native Evidence: "+str(x["nativeEvidenceId"]),
            "- Instruction category: "+x["opcodeClass"],
        ]
        if x["nativeOwner"]:
            lines += [
                "- Opcode: "+str(x["nativeOpcode"])+" "+str(x["operands"]),
                "- **Not proof of memory write at 0x3651ec.**",
                "","~~~asm",*x["nativeWindow"],"~~~","",
            ]
        else:
            lines += ["- Full original native owner has not yet been collected.",""]
    lines += [
        "## Remaining evidence requirements","",
        "1. Identify all original xref owner functions that were not covered",
        "   by representative native bodies, without assuming code similarity.",
        "2. For candidate memory writes, prove effective 0x3651ec address",
        "   through registers/offsets, relevant conditional branches and",
        "   stored-value origins. An ADRP xref is not a store.",
        "3. Compare confirmed writes against original 0x67dd8 bit-2 reader",
        "   and the immediately preceding 0x68f18 token initialization.",
        "4. Establish whether any decision is trusted by the secure boot",
        "   chain independently of cached OEM, FRP and AVB diagnostics.",
        "5. Nothing proves a working unlock, unsigned boot or Odin bypass.","",
    ]
    return "\n".join(lines)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path,default=Path.home()/
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    p.add_argument("--node",default="node")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--recover-partials",action="store_true")
    p.add_argument("--timeout",type=int,default=240)
    a=p.parse_args()
    if not 30<=a.timeout<=1200:
        p.error("timeout outside bounded range")
    try:
        root=a.input_dir.expanduser().resolve()
        report=audit(root,execute=a.execute,rea=a.rea,
                     node=a.node,timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-unlock-bitmask-clusters.json").write_text(json.dumps(report,indent=2)+"\n")
        (out/"avb-unlock-bitmask-clusters.md").write_text(markdown(report))
    except (TriageError,OSError,TypeError,ValueError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[XREFS]",report["globalInventory"]["total"],
          "original source-attested; classified",report["classifiedCount"])
    for item in report["sourceOwners"]:
        print("[OWNER]",item["seed"],"->",item["owner"])
    print("[REPORT]",out/"avb-unlock-bitmask-clusters.md")
    print("[LIMIT] No confirmed bitmask writer or secure unlock authority")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
