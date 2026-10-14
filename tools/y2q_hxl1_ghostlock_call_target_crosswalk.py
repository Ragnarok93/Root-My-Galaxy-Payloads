#!/usr/bin/env python3
"""Read-only recovered-symbol crosswalk for HXL1 original sendmsg callsites.

Does NOT infer register flow, stack pointer aliasing, futex waiter lifetime,
dynamic kernel addresses, exploitable overlaps, or privilege escalation.
Original full Image need not be extracted again.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_ghostlock_stack_gate as stock
from tools import y2q_hxl1_ghostlock_original_sendmsg_windows as windows

ORIGINAL_NM_SHA="c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f"
FRAME_SHA="a0426c036e614611c368338c9f80e298f13b23bc238e1b3dc67aa1a3c20dcc10"
WINDOWS_SHA="8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8"
ROOT=Path(__file__).resolve().parents[1]
STOCK_SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
RESEARCH=Path.home()/"s20-artifacts/hxl1-research"
NM_LINE=re.compile(r"^([0-9a-fA-F]{8,16})\s+([tT])\s+([A-Za-z_.$][\w.$]*)$")
EXPECTED_COUNTS={"__sys_sendmsg":4,"___sys_sendmsg":15,"____sys_sendmsg":0,
                 "__sys_sendto":7,"__sys_sendmmsg":6,"rw_copy_check_uvector":4,
                 "copy_msghdr_from_user":5,"futex_wait_requeue_pi":0}
REQUIRED_EDGES={
    ("__sys_sendmsg","0xffffff800966f248","0xffffff800966f2a4"),
    ("__sys_sendmmsg","0xffffff800966f750","0xffffff800966f2a4"),
    ("__sys_sendmmsg","0xffffff800966f7d4","0xffffff800966f2a4"),
    ("___sys_sendmsg","0xffffff800966f304","0xffffff800967357c"),
}

class CrosswalkError(ValueError):
    pass

def require(condition,why):
    if not condition:raise CrosswalkError(why)

def sha(blob):
    return hashlib.sha256(blob).hexdigest()

def safe_read(path:Path,max_bytes:int):
    require(path.is_file() and not path.is_symlink()
            and 0<path.stat().st_size<=max_bytes,"Missing/unsafe input: "+str(path))
    return path.read_bytes()

def read_symbols(raw:bytes,expected_hash:str=ORIGINAL_NM_SHA):
    require(sha(raw)==expected_hash,"Original recovered NM SHA256 mismatch")
    parsed=stock.parse_nm(raw.decode("utf-8","strict"))
    require(parsed.get("_text",(-1,))[0]==stock.IMAGE_VA,
            "Original recovered NM text address mismatch")
    by_address={}
    for line in raw.decode("utf-8","strict").splitlines():
        m=NM_LINE.fullmatch(line.strip())
        if not m:continue
        va=int(m.group(1),16)
        by_address.setdefault(va,set()).add(m.group(3))
    return {a:sorted(names) for a,names in by_address.items()},sorted(by_address)

def validate_owner_report(d):
    require(isinstance(d,dict) and d.get("schemaVersion")==1 and
        d.get("target")=="SM-G986U1/G986U1UESCHXL1" and
        d.get("scope")=="STATIC_ORIGINAL_AARCH64_CALLSITES_AND_SP_PROXIMITY_ONLY" and
        d.get("verifiedOriginalInstructionSlots")==746 and
        d.get("frameReportSha256")==FRAME_SHA and
        d.get("originalWindowsManifestSha256")==WINDOWS_SHA and
        d.get("originalKernelImageHashReportedAndVerifiedByPriorTool")==stock.STOCK_SHA and
        d.get("recoveredNmSha256")==ORIGINAL_NM_SHA,
        "Owner callsite report identity/fingerprint mismatch")
    rows=d.get("functions")
    require(isinstance(rows,list) and len(rows)==len(windows.NAMES) and
            [x.get("symbol") for x in rows]==list(windows.NAMES),
            "Original function inventory mismatch")
    seen=set(); count=0; proximity=0
    for f in rows:
        name=f["symbol"]; expected=EXPECTED_COUNTS[name]
        if expected==0:
            require(f.get("status")=="NAME_NOT_RECOVERED" and
                    f.get("compilerEmittedFunctionAbsent") is False,
                    "Missing original name incorrectly promoted to absent")
            continue
        c=f.get("callsiteInventory",{})
        calls=c.get("calls")
        require(f.get("status")=="ORIGINAL_CALLSITES_REVIEWED" and
                isinstance(calls,list) and len(calls)==expected and
                c.get("totalCalls")==expected and
                c.get("directCalls")==expected and c.get("indirectCalls")==0 and
                c.get("sourceLocalVariableAttributionVerified") is False and
                c.get("interproceduralDataflowVerified") is False and
                c.get("runtimeCarrierWindowVerified") is False,
                "Untrusted or changed original callsite count/claims: "+name)
        for call in calls:
            require(call.get("opcode")=="bl" and
                    call.get("calleeArgumentIdentityProved") is False and
                    call.get("pointerEscapeProved") is False and
                    isinstance(call.get("nearbySpConstructionTextualOnly"),list),
                    "Callsite incorrectly promotes dataflow: "+name)
            origin=call.get("staticImageVA","")
            dest=call.get("directTargetText","")
            require(re.fullmatch(r"0x[0-9a-f]{16}",origin or "") and
                    re.fullmatch(r"0x[0-9a-f]{16}",dest or "") and
                    int(origin,16)%4==0 and int(dest,16)%4==0,
                    "Invalid static original call address")
            key=(name,origin,dest)
            require(key not in seen,"Duplicate original callsite")
            seen.add(key)
            proximity+=bool(call["nearbySpConstructionTextualOnly"])
            count+=1
    require(count==41 and len({t for _,_,t in seen})==21 and
            proximity==19 and REQUIRED_EDGES.issubset(seen),
            "Owner 41-call/21-destination provenance or known direct edges changed")
    return seen

def symbol_match(target,by_address,addresses):
    va=int(target,16)
    if va in by_address:
        return {"status":"EXACT_RECOVERED_TEXT_LABEL",
                "labels":by_address[va], "staticRecoveredTextVA":target,
                "calleeCompilerFunctionIdentityVerified":False}
    i=bisect.bisect_right(addresses,va)
    if 0<i<len(addresses) and addresses[i-1]<va<addresses[i]:
        return {"status":"INTERIOR_OF_RECOVERED_TEXT_INTERVAL_UNPROVEN",
                "lowerLabels":by_address[addresses[i-1]],
                "lowerStaticTextVA":hex(addresses[i-1]),
                "upperStaticTextVA":hex(addresses[i]),
                "offsetFromLowerLabel":va-addresses[i-1],
                "calleeCompilerFunctionIdentityVerified":False}
    return {"status":"NO_SAFE_TEXT_SYMBOL_BOUND",
            "calleeCompilerFunctionIdentityVerified":False}

def crosswalk(report:dict,raw_nm:bytes):
    triples=validate_owner_report(report)
    by_address,addresses=read_symbols(raw_nm)
    targets=sorted({target for _,_,target in triples},key=lambda x:int(x,16))
    items=[{"targetStaticVA":t,"totalIncomingCalls":sum(a==t for _,_,a in triples),
            **symbol_match(t,by_address,addresses)} for t in targets]
    by_target={x["targetStaticVA"]:x for x in items}
    edges=[{"caller":caller,"callStaticVA":site,"targetStaticVA":target,
            "targetLabelMatch":by_target[target]["status"],
            "targetLabels":by_target[target].get("labels",[]),
            "registerArgumentsTraced":False}
           for caller,site,target in sorted(triples)]
    return {"schemaVersion":1,"target":"SM-G986U1/G986U1UESCHXL1",
            "scope":"STATIC_ORIGINAL_SENDMSG_CALLS_TO_RECOVERED_NM_LABELS_ONLY",
            "nmSha256":sha(raw_nm),
            "stockImageSha256ReportedByEarlierAttestor":stock.STOCK_SHA,
            "callsites":len(edges),"uniqueDestinations":len(items),
            "directTargets":items,"callEdges":edges,
            "exactSymbolDestinations":sum(x["status"]=="EXACT_RECOVERED_TEXT_LABEL" for x in items),
            "uncertainInteriorDestinations":sum(x["status"]=="INTERIOR_OF_RECOVERED_TEXT_INTERVAL_UNPROVEN" for x in items),
            "knownDirectChainsObserved":[
              "__sys_sendmsg -> ___sys_sendmsg",
              "__sys_sendmmsg -> ___sys_sendmsg (two callsites)",
              "___sys_sendmsg -> copy_msghdr_from_user"],
            "calleeSourceFunctionIdentityVerified":False,
            "callArgumentPointerDataflowVerified":False,
            "sendmsgFutexWaiterLifetimeOverlapVerified":False,
            "originalKernelPhysicalLoadBaseVerified":False,
            "liveGhostLockExploitVerified":False,
            "rootOrKernelSuVerified":False,
            "deviceModified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report",required=True,type=Path)
    p.add_argument("--nm",type=Path,default=RESEARCH/"vmlinux-stock.nm")
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    try:
        out=a.output.expanduser().resolve()
        require(not a.output.expanduser().is_symlink() and
                not out.exists() and out!=ROOT and ROOT not in out.parents and
                out!=STOCK_SOURCE and STOCK_SOURCE not in out.parents,
                "Refusing output overwrite or source-tree modification")
        d=json.loads(safe_read(a.report,300000))
        nm=safe_read(a.nm,stock.MAX_NM_BYTES)
        result=crosswalk(d,nm)
        result["ownerCallsiteReportSha256"]=sha(safe_read(a.report,300000))
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x",encoding="utf-8") as fp:
            json.dump(result,fp,indent=2)
            fp.write("\n")
        print("[ORIGINAL DIRECT CALLS]",result["callsites"])
        print("[DISTINCT DESTINATIONS]",result["uniqueDestinations"])
        print("[EXACT RECOVERED LABEL DESTINATIONS]",result["exactSymbolDestinations"])
        print("[CALL ARGUMENTS/WAITER LIFETIME/ROOT] NOT VERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,UnicodeError,KeyError,TypeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
