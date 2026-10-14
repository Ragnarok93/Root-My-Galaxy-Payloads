#!/usr/bin/env python3
"""HXL1 offline verified sendmsg callsite inventory, not object-layout proof.

Uses owner's independently rehashed original Image frame audit and its
validated raw-code/disassembly siblings. No device, REA or exploit execution.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_ghostlock_sendmsg_frame_attest as original

EXPECTED_FRAME_SHA = "a0426c036e614611c368338c9f80e298f13b23bc238e1b3dc67aa1a3c20dcc10"
EXPECTED_WINDOWS_SHA = "8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8"
BASE = Path.home()/"s20-artifacts/hxl1-research"
REPO = Path(__file__).resolve().parents[1]
STOCK_SOURCE = Path.home()/"src/samsung-y2q-hxl1-stock"
HEX = re.compile(r"^\s*(?:0x)?([0-9a-f]+)\b", re.I)
CONTROL = {"b", "bl", "br", "blr", "ret", "eret", "cbz", "cbnz", "tbz", "tbnz"}

class EvidenceError(ValueError):
    pass

def require(value, reason):
    if not value:
        raise EvidenceError(reason)

def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def read(path:Path, limit:int)->bytes:
    require(path.is_file() and not path.is_symlink() and
            0<path.stat().st_size<=limit, "Missing/unsafe input: "+str(path))
    return path.read_bytes()

def find_unique(root:Path, pattern:str, expected_hash:str, limit:int)->Path:
    matches=[]
    for candidate in root.glob(pattern):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        if candidate.stat().st_size>limit:
            continue
        if sha(candidate.read_bytes())==expected_hash:
            matches.append(candidate)
    require(len(matches)==1, "Expected one exact hash-pinned report: "+pattern+
            " (found "+str(len(matches))+")")
    return matches[0]

def callsite_summary(rows:list[tuple[int,str,str]], feature:dict)->dict:
    original_sp=feature.get("spRelativeAddressConstructs",[])
    sp_addresses={int(x["staticImageVA"],16):x["instruction"] for x in original_sp}
    calls=[]
    control_count=0
    returns=0
    for i,(address,opcode,operands) in enumerate(rows):
        if opcode=="ret":
            returns+=1
        if opcode in CONTROL or opcode.startswith("b."):
            control_count+=1
        if opcode not in ("bl","blr"):
            continue
        nearby=[]
        for j in range(max(0,i-12),i):
            ptr_addr=rows[j][0]
            if ptr_addr in sp_addresses:
                nearby.append({
                    "staticImageVA":hex(ptr_addr),
                    "syntacticSpConstruction":sp_addresses[ptr_addr],
                    "linearInstructionDistance":i-j})
        crossed=any(rows[j][1] in CONTROL or rows[j][1].startswith("b.")
                    for j in range(max(0,i-12),i))
        target=HEX.match(operands) if opcode=="bl" else None
        calls.append({
            "staticImageVA":hex(address), "opcode":opcode,
            "directTargetText":("0x"+target.group(1).lower() if target else None),
            "indirectCallRegister":operands if opcode=="blr" else None,
            "nearbySpConstructionTextualOnly":nearby[:12],
            "interveningBranchInTwelveInstructionWindow":crossed,
            "calleeArgumentIdentityProved":False,
            "pointerEscapeProved":False,
        })
    return {"calls":calls,"totalCalls":len(calls),
            "directCalls":sum(x["opcode"]=="bl" for x in calls),
            "indirectCalls":sum(x["opcode"]=="blr" for x in calls),
            "controlTransferInstructions":control_count,
            "retInstructions":returns,
            "sourceLocalVariableAttributionVerified":False,
            "interproceduralDataflowVerified":False,
            "runtimeCarrierWindowVerified":False}

def audit(frame:dict, windows:dict, directory:Path)->dict:
    require(frame.get("target")=="SM-G986U1/G986U1UESCHXL1" and
            frame.get("status")=="ORIGINAL_CODE_ATTESTED_STACK_RELATIONSHIP_UNPROVEN" and
            frame.get("originalImageIndependentlyRehashedByThisTool") is True and
            frame.get("upstreamWindowManifestSha256")==EXPECTED_WINDOWS_SHA and
            frame.get("codeWindowsVerified")==6 and frame.get("requestedSymbols")==8,
            "Original frame report identity/count mismatch")
    require(windows.get("target")==frame["target"] and
            windows.get("status")=="BOUNDED_STOCK_NATIVE_CODE_WINDOWS_NOT_STACK_GEOMETRY" and
            windows.get("originalKernelSha256")==frame["originalKernelSha256"] and
            windows.get("recoveredNmSha256")==frame["recoveredNmSha256"],
            "Upstream original code-window provenance mismatch")
    for flag in ("exactOriginalCompilerStackObjectsKnown",
                 "danglingWaiterToSendmsgAliasVerified",
                 "runtimeKernelStackReuseVerified","ghostLockPrimitiveVerified",
                 "temporaryRootVerified","kernelSuLoaded"):
        require(frame.get(flag) is False,"Unproven positive claim: "+flag)
    frames=frame.get("functions",[])
    windows_items=windows.get("functions",[])
    require(isinstance(frames,list) and isinstance(windows_items,list) and
            len(frames)==8 and len(windows_items)==8 and
            [x.get("symbol") for x in frames]==[x.get("symbol") for x in windows_items] and
            [x.get("symbol") for x in frames]==list(original.prior.NAMES),
            "Function inventory mismatch")
    details=[]
    instruction_count=0
    for rec,w in zip(frames,windows_items):
        name=rec["symbol"]
        if rec.get("status")=="NOT_FOUND_IN_RECOVERED_NM":
            require(w.get("status")=="NOT_FOUND_IN_RECOVERED_NM" and
                    rec.get("compiledFunctionAbsent") is False,
                    "Unsubstantiated symbol absence: "+name)
            details.append({"symbol":name,"status":"NAME_NOT_RECOVERED",
                            "compilerEmittedFunctionAbsent":False})
            continue
        require(rec.get("status")=="CODE_BYTES_AND_DISASSEMBLY_INDEPENDENTLY_VERIFIED" and
                w.get("status")=="ORIGINAL_IMAGE_CODE_WINDOW" and
                w.get("sliceSha256")==rec.get("originalCodeSha256") and
                w.get("disassembly",{}).get("sha256")==rec.get("savedDisassemblySha256") and
                w.get("staticImageVA")==rec.get("staticImageVA"),
                "Original window/disassembly cross-reference mismatch: "+name)
        raw=read(directory/(name+".bin"),4096)
        disasm=read(directory/(name+".disasm.txt"),200000)
        require(len(raw)==w["sampledBytes"] and sha(raw)==rec["originalCodeSha256"] and
                sha(disasm)==rec["savedDisassemblySha256"],
                "Cached original bytes/disassembly mismatch: "+name)
        rows=original.parse_disasm(disasm,raw,int(rec["staticImageVA"],16))
        require(original.structural_features(rows)==rec["features"],
                "Recomputed static frame features disagree: "+name)
        calls=callsite_summary(rows,rec["features"])
        details.append({
            "symbol":name,"status":"ORIGINAL_CALLSITES_REVIEWED",
            "staticEntryBytesFromReport":
                rec["features"]["literalSpAdjustments"]["staticEntryBytes"],
            "staticFrameEntryAndRestoreTextuallyBalanced":
                rec["features"]["literalSpAdjustments"]["literalRestorationsBalanceEntry"],
            "instructionSlotsVerified":len(rows),"callsiteInventory":calls})
        instruction_count+=len(rows)
    require(instruction_count==746,"Original six-window instruction count mismatch")
    return {
        "schemaVersion":1,"target":frame["target"],
        "scope":"STATIC_ORIGINAL_AARCH64_CALLSITES_AND_SP_PROXIMITY_ONLY",
        "originalKernelImageHashReportedAndVerifiedByPriorTool":frame["originalKernelSha256"],
        "recoveredNmSha256":frame["recoveredNmSha256"],
        "verifiedOriginalInstructionSlots":instruction_count,
        "functions":details,
        "originalFutexWaiterLocalFrameVerified":False,
        "sourceCObjectIdentityVerified":False,
        "sendmsgWaiterStackOverlapVerified":False,
        "sendmsgRuntimeBlockingLifetimeVerified":False,
        "kernelPhysicalLoadOrKaslrVerified":False,
        "ghostLockExploitVerified":False,
        "temporaryRootVerified":False,
        "kernelSuLoaded":False,
        "deviceModified":False,
        "interpretation":"All callsites are original static code. SP/call proximity is lexical, not established register dataflow, source-local ownership, waiter lifetime or exploitable stack overlap."}

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir",type=Path,default=BASE)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        evidence=args.evidence_dir.expanduser().resolve()
        frame_path=find_unique(evidence,"ghostlock-sendmsg-frame-*.json",EXPECTED_FRAME_SHA,200000)
        manifest_path=find_unique(evidence,
            "ghostlock-original-sendmsg-*/original-sendmsg-windows.json",
            EXPECTED_WINDOWS_SHA,200000)
        out=args.output.expanduser().resolve()
        require(not args.output.expanduser().is_symlink() and
                not out.exists() and not out.is_symlink() and
                out!=REPO and REPO not in out.parents and
                out!=STOCK_SOURCE and STOCK_SOURCE not in out.parents,
                "Output must be new and outside source trees")
        frame=json.loads(read(frame_path,200000))
        windows=json.loads(read(manifest_path,200000))
        result=audit(frame,windows,manifest_path.parent)
        result["frameReportSha256"]=EXPECTED_FRAME_SHA
        result["originalWindowsManifestSha256"]=EXPECTED_WINDOWS_SHA
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        print("[ORIGINAL CALLSITE INVENTORY]",
              sum(x.get("callsiteInventory",{}).get("totalCalls",0)
                  for x in result["functions"]))
        print("[ORIGINAL INSTRUCTION SLOTS VERIFIED]",
              result["verifiedOriginalInstructionSlots"])
        print("[C LOCAL / WAITER STACK REUSE / ROOT / KERNELSU] NOT VERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
