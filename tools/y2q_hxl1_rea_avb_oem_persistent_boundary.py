#!/usr/bin/env python3
"""HXL1 original OEM persistent-byte reader and unlock-mode dispatch boundary.

Chain-reattest SHA-pinned owner Ghidra evidence through the 0x17d8 main
entry and both 0x60790/0x60918 provider native listings, proving:
* OEM byte source: last byte of a partition located as "persistent",
  copied into zero-initialized local 4-byte result.
* FRP-related size field: 4 bytes at buffered offset +0x24,
  byte-swapped with ARM64 REV (not the OEM unlock byte).
* main boot entry tests result of 0x67dd8(4) before direct
  unlock or relock, and separately dispatches boot modes via 0x182d0.

Collects only SIX new read-only, bounded original Ghidra queries:
function/instructions for 0x67dd8, 0x1e5f0, and 0x182d0.
The actual secure authorization, trust of the persistent contents
and firmware/Odin signature acceptance are NOT proven.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, function_record, safe_segment
)
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions, exact_instruction
from tools.y2q_hxl1_rea_avb_oem_providers_entry import (
    audit as verify_providers,
    parse_large_main_instructions,
)

MAIN="0x17d8"
OEM="0x60790"
FRP="0x60918"
DECISION="0x67dd8"
PARTITION="0x1e5f0"
BOOT_DISPATCH="0x182d0"
QUERY=(("0x67dd8","unlock-selector"),("0x1e5f0","persistent-partition-resolver"),
       ("0x182d0","boot-mode-selector"))
OEM_NATIVE_PINS=(
    ("0x607a4","adrp","x0,0xc9000"),
    ("0x607a8","add","x0,x0,#0xf54"),
    ("0x607c4","str","wzr,[sp,#0x4]"),
    ("0x607c8","bl","0x0001e5f0"),
    ("0x607cc","cbnz","w0,0x00060868"),
    ("0x607d8","ldrsw","x21,[x8,#0xc]"),
    ("0x607dc","ldr","x22,[x8,#0x18]"),
    ("0x60814","blr","x9"),
    ("0x60818","add","x8,x20,x21"),
    ("0x6081c","sub","x1,x8,#0x1"),
    ("0x60820","add","x0,sp,#0x4"),
    ("0x60824","mov","w2,#0x1"),
    ("0x60828","bl","0x0000f9d8"),
    ("0x60864","ldr","w19,[sp,#0x4]"),
    ("0x6087c","mov","w0,w19"),
    ("0x60890","ret",""),
)
FRP_NATIVE_PINS=(
    ("0x60928","adrp","x0,0xc9000"),
    ("0x6092c","add","x0,x0,#0xf54"),
    ("0x60944","bl","0x0001e5f0"),
    ("0x60980","ldr","x8,[sp,#0x10]"),
    ("0x60988","ldrsw","x20,[x8,#0xc]"),
    ("0x609c0","blr","x9"),
    ("0x609cc","add","x1,x19,#0x24"),
    ("0x609d0","mov","w2,#0x4"),
    ("0x609d4","mov","x0,x20"),
    ("0x609d8","bl","0x0000f9d8"),
    ("0x609dc","ldr","w8,[x20]"),
    ("0x609e0","rev","w8,w8"),
    ("0x609e4","str","w8,[x20]"),
    ("0x60a44","mov","w0,w19"),
    ("0x60a54","ret",""),
)
MAIN_NATIVE_PINS=(
    ("0x1b34","bl","0x00068f18"),
    ("0x1b38","mov","w0,#0x4"),
    ("0x1b3c","bl","0x00067dd8"),
    ("0x1b40","tst","w0,#0xff"),
    ("0x1b44","b.eq","0x00001db0"),
    ("0x1b48","bl","0x00034238"),
    ("0x1db0","bl","0x00034370"),
    ("0x1cd4","bl","0x000182d0"),
    ("0x1cdc","sub","w8,w21,#0x1"),
    ("0x1ce0","cmp","w8,#0xb"),
    ("0x1ce4","b.hi","0x00001ac0"),
    ("0x1cf8","ldrh","w11,[x9,x8,lsl#0x1]"),
    ("0x1d00","br","x10"),
)
OEM_SOURCE=(
    r'FUN_0001e5f0\s*\(\s*"persistent"\s*,',
    r"FUN_0000f9d8\s*\(\s*&local_4c\s*,\s*lVar3\s*\+\s*lVar5\s*\+\s*-1\s*,\s*1\s*\)",
    r"\blocal_4c\s*=\s*0\s*;",
    r"\breturn\s+uVar4\s*;",
)
FRP_SOURCE=(
    r'FUN_0001e5f0\s*\(\s*"persistent"\s*,',
    r"FUN_0000f9d8\s*\(\s*&DAT_0035cb14\s*,\s*lVar3\s*\+\s*0x24\s*,\s*4\s*\)",
    r"DAT_0035cb14\s*=\s*uVar5\s*>>\s*0x10\s*\|\s*uVar5\s*<<\s*0x10",
)
MAX_HELPER_LINES=3500
MAX_HELPER_NATIVE=2000


def validated_prior(prior:dict)->dict:
    if prior.get("sourceAttested") is not True:
        raise TriageError("Original HXL1 provider audit not source-attested")
    if prior.get("mainNative",{}).get("entry") != MAIN:
        raise TriageError("Original 0x17d8 native entry dossier absent")
    providers=prior.get("stateProviders")
    if not isinstance(providers,list) or len(providers)!=2:
        raise TriageError("Expected exactly two original partition provider dossiers")
    got={}
    for row in providers:
        entry=row.get("entry")
        if entry in got or entry not in (OEM,FRP):
            raise TriageError("Original OEM/FRP provider inventory changed")
        if (not isinstance(row.get("function"),dict)
                or not isinstance(row.get("native"),dict)
                or not isinstance(row["function"].get("evidenceId"),str)
                or not isinstance(row["native"].get("evidenceId"),str)):
            raise TriageError("Original provider source/native evidence incomplete")
        got[entry]=row
    if len(got)!=2:
        raise TriageError("Original OEM and FRP providers incomplete")
    return got


def saved_provider_evidence(root:Path,target_sha:str,prior:dict)->dict:
    folder=root/"rea-security-audit"/"LinuxLoader"
    sources={}
    for entry,pins,patterns,expected_len in (
        (OEM,OEM_NATIVE_PINS,OEM_SOURCE,78),
        (FRP,FRP_NATIVE_PINS,FRP_SOURCE,92),
    ):
        f=evidence(folder/("function-oem-provider-"+safe_segment(entry)+".json"),
                   sha=target_sha,operation="analyze_function",
                   parameter="procedure",value=entry)
        n=evidence(folder/("instructions-oem-provider-"+safe_segment(entry)+".json"),
                   sha=target_sha,operation="read_function_instructions",
                   parameter="procedure",value=entry)
        if (f["evidence_id"]!=prior[entry]["function"]["evidenceId"]
                or n["evidence_id"]!=prior[entry]["native"]["evidenceId"]):
            raise TriageError("Original source/native provider Evidence IDs changed")
        if function_record(f,entry)["entry"]!=entry:
            raise TriageError("Original OEM/FRP provider Ghidra owner changed")
        pseudo=f["normalized_result"].get("pseudocode")
        if not isinstance(pseudo,str) or len(pseudo)>260000:
            raise TriageError("Original partition provider pseudocode unavailable/oversized")
        for pattern in patterns:
            if not re.search(pattern,pseudo):
                raise TriageError(f"Original {entry} partition source semantics differ: {pattern}")
        instructions=parse_instructions(n,entry)
        if len(instructions)!=expected_len:
            raise TriageError(f"Original {entry} native instruction count changed")
        for a,m,o in pins:
            exact_instruction(instructions,a,m,o)
        sources[entry]={
            "entry":entry,"pseudocodeEvidenceId":f["evidence_id"],
            "nativeEvidenceId":n["evidence_id"],
            "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
            "fullNativeInstructionCount":len(instructions),
            "originalNativePins":[{"address":a,"opcode":instructions[a][0]+" "+instructions[a][1]}
                                  for a,_,_ in pins],
            "partitionLocatorString":"persistent",
            "sourceDataLocation":"last byte of allocated partition buffer"
                                  if entry==OEM else "4 bytes at buffer+0x24",
            "readMethodStatusVerified":False,
            "partitionContentsCryptographicallyAuthenticatedProven":False,
            "secureMonitorDelegationProven":False,
            "samePartitionDeviceAsVBDeviceProven":False,
        }
    return sources


def verify_main_selection(ev:dict,expected_id:str)->dict:
    if ev["evidence_id"]!=expected_id:
        raise TriageError("Original main owner native Evidence ID changed")
    ops=parse_large_main_instructions(ev)
    if len(ops)!=569:
        raise TriageError("Original main 0x17d8 instruction count changed")
    for a,m,o in MAIN_NATIVE_PINS:
        exact_instruction(ops,a,m,o)
    keys=("0x1b34","0x1b38","0x1b3c","0x1b40","0x1b44","0x1b48")
    observed=sorted((a for a in ops if int(keys[0],16)<=int(a,16)<=int(keys[-1],16)),
                    key=lambda a:int(a,16))
    if observed!=list(keys):
        raise TriageError("Unknown original instruction in unlock/relock condition")
    return {
        "entry":MAIN,"nativeEvidenceId":ev["evidence_id"],
        "exactNativeBranchSequence":[a+": "+ops[a][0]+" "+ops[a][1] for a in keys],
        "zeroResultBranchDestination":"0x1db0",
        "nonzeroResultDirectTarget":"0x34238",
        "zeroResultDirectTarget":"0x34370",
        "inputToSelector":"0x4","selectorFunction":DECISION,
        "bootModeSubdispatchFunction":BOOT_DISPATCH,
        "originalBootModeJumpTableSite":"0x1d00",
        "nativeSelectorBranchVerified":True,
        "selectorSemanticsOrAuthorityProven":False,
        "bootModeJumpTargetsFullyProven":False,
        "secureBootAuthorizationProven":False,
    }


def helper_source(ev:dict,entry:str,kind:str)->dict:
    info=function_record(ev,entry)
    if info["entry"]!=entry:
        raise TriageError("Unexpected original HXL1 helper owner")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>240000:
        raise TriageError("Missing original HXL1 helper decompilation")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=MAX_HELPER_LINES:
        raise TriageError("Bounded original HXL1 helper pseudocode invalid")
    callees=sorted(set(re.findall(r"\bFUN_([0-9a-fA-F]{8})\s*\(",pseudo)))
    globals_=sorted(set(re.findall(r"\bDAT_([0-9a-fA-F]{8})\b",pseudo)))
    return {
        "entry":entry,"kind":kind,
        "sourceEvidenceId":ev["evidence_id"],
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "originalSourceLines":len(lines),
        "sourceExcerpt":[{"line":i+1,"text":line[:800]} for i,line in enumerate(lines[:190])],
        "excerptTruncated":len(lines)>190,
        "calleeCoordinates":["0x"+s.lower().lstrip("0") for s in callees if int(s,16)>0][:80],
        "globalReferences":["0x"+s.lower().lstrip("0") for s in globals_ if int(s,16)>0][:80],
        "securityAuthorityOrInputTrustVerified":False,
    }


def helper_native(ev:dict,entry:str)->dict:
    ops=parse_instructions(ev,entry)
    if not 6<=len(ops)<=MAX_HELPER_NATIVE:
        raise TriageError("Invalid original HXL1 helper native listing")
    addr=sorted(ops,key=lambda a:int(a,16))
    return {
        "entry":entry,"nativeEvidenceId":ev["evidence_id"],
        "nativeCount":len(ops),
        "instructionExcerpt":[a+": "+ops[a][0]+" "+ops[a][1] for a in addr[:175]],
        "excerptTruncated":len(addr)>175,
        "nativeW0ReturnAuthorityProven":False,
        "nativeControlFlowProven":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_providers(root)
    known=validated_prior(prior)
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    p=saved_provider_evidence(root,target.sha256,known)
    main_evidence=evidence(
        folder/"instructions-route-owner-0x17d8.json",
        sha=target.sha256,operation="read_function_instructions",
        parameter="procedure",value=MAIN)
    main=verify_main_selection(main_evidence,prior["mainNative"]["evidenceId"])
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing/unsafe")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    helpers=[]
    for entry,kind in QUERY:
        fun=runner.obtain(
            target,["function",str(target.path),entry],
            folder/("function-state-boundary-"+safe_segment(entry)+".json"),
            operation="analyze_function",parameter="procedure",value=entry)
        native=runner.obtain(
            target,["instructions",str(target.path),entry],
            folder/("instructions-state-boundary-"+safe_segment(entry)+".json"),
            operation="read_function_instructions",parameter="procedure",value=entry)
        helpers.append({
            "entry":entry,"kind":kind,
            "function":helper_source(fun,entry,kind) if fun else None,
            "native":helper_native(native,entry) if native else None,
        })
    return {
        "schemaVersion":1,"originalBlArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"READ_ONLY_ORIGINAL_GHIDRA" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),
        "oemAndFrpSources":p,
        "mainUnlockSelection":main,
        "boundaryHelpers":helpers,
        "persistentPartitionTrustedAndAuthenticatedProven":False,
        "onDeviceUnlockAuthorizationOrImageBypassProven":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    lines=[
        "# HXL1 — persistent partition OEM byte and unlock selection boundary",
        "",
        "**SHA-attested original Ghidra source only, no device modification or unlock.**",
        "","Original archive SHA256: "+r["originalBlArchiveSha256"],
        "New read-only Ghidra queries: "+str(r["newQueries"]),
        "","## OEM/FRP original persistent partition reads","",
    ]
    for entry,title in ((OEM,"OEM"),(FRP,"FRP-related")):
        f=r["oemAndFrpSources"][entry]
        lines += [
            "### "+title+" provider "+entry,"",
            "- Original native Evidence: "+f["nativeEvidenceId"],
            "- Original decompilation Evidence: "+f["pseudocodeEvidenceId"],
            "- Partition name: "+f["partitionLocatorString"],
            "- Data location: "+f["sourceDataLocation"],
            "- Partition read method and status semantics: UNVERIFIED",
            "- Cryptographic authentication / secure ownership: UNKNOWN",
            "","~~~asm",
        ]
        for row in f["originalNativePins"]:
            lines.append(row["address"]+": "+row["opcode"])
        lines += ["~~~",""]
    main=r["mainUnlockSelection"]
    lines += [
        "## 0x17d8 direct unlock/relock selection","",
        "- Original native Evidence: "+main["nativeEvidenceId"],
        "- Call selector: 0x67dd8(W0=4)",
        "- Result W0 low byte nonzero: call 0x34238 (unlock request)",
        "- Result W0 low byte zero: branch 0x1db0 -> 0x34370 (relock request)",
        "- Unverified: 0x67dd8 semantics, input trust, firmware/flash policy",
        "","~~~asm",*main["exactNativeBranchSequence"],"~~~","",
        "- Another original entry call 0x182d0 participates in",
        "  a bounded boot-mode jump table at 0x1d00.",
        "  Jump table targets and permissions not verified.","",
        "## Next original HXL1 source-boundary dossiers","",
    ]
    for row in r["boundaryHelpers"]:
        lines += ["### "+row["entry"]+" — "+row["kind"],""]
        f=row["function"]
        if f is None:
            lines += ["- Original Ghidra function query planned.",""]
        else:
            lines += [
                "- Ghidra source Evidence: "+f["sourceEvidenceId"],
                "- Original source line count: "+str(f["originalSourceLines"]),
                "- Lexical callee coordinates: "+str(f["calleeCoordinates"]),
                "- Original global refs: "+str(f["globalReferences"]),
                "","~~~c",
            ]
            for x in f["sourceExcerpt"]:
                lines.append(f"{x['line']:5d} | {x['text']}")
            lines += ["~~~",""]
        native=row["native"]
        if native is not None:
            lines += [
                "- Ghidra native Evidence: "+native["nativeEvidenceId"],
                "- Original native instruction count: "+str(native["nativeCount"]),
                "","~~~asm",*native["instructionExcerpt"],"~~~","",
            ]
    lines += [
        "## Remaining security research gates","",
        "1. Determine how 0x67dd8 handles key/option 4 and whether",
        "   its result is an authorization decision or a mode selector.",
        "2. Establish how 0x1e5f0 resolves persistent partition data",
        "   and whether validation/authentication applies.",
        "3. Reconstruct 0x182d0 and 0x17d8 boot-mode case dispatch",
        "   to distinguish entry reachability from security authority.",
        "4. Nothing here proves that the cached OEM byte or AVB device",
        "   state governs Qualcomm secure boot or Odin image signing.",
        "5. No handset/firmware writes or bypass occurred.","",
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
    x=p.parse_args()
    if not 30<=x.timeout<=1200:
        p.error("Timeout out of bounds")
    try:
        root=x.input_dir.expanduser().resolve()
        r=audit(root,execute=x.execute,rea=x.rea,
                node=x.node,timeout=x.timeout,
                recover_partials=x.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-oem-persistent-selector-boundary.json").write_text(
            json.dumps(r,indent=2)+"\n")
        (out/"avb-oem-persistent-selector-boundary.md").write_text(markdown(r))
    except (TriageError,OSError,ValueError,TypeError,KeyError) as exc:
        print("[STOP]",str(exc),file=sys.stderr)
        return 2
    for row in r["boundaryHelpers"]:
        print("[BOUNDARY]",row["entry"],row["kind"],
              "SOURCE_VERIFIED" if row["function"] and row["native"] else "PENDING")
    print("[SELECTOR] 0x67dd8(4) branches to unlock/relock request")
    print("[REPORT]",out/"avb-oem-persistent-selector-boundary.md")
    print("[LIMIT] OEM authority, secure boot and bootloader unlock remain UNKNOWN")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
