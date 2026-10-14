#!/usr/bin/env python3
"""Read-only HXL1 waiter-pointer store/load CFG consistency audit.

Matches pinned original Samsung source and 1766-instruction do_futex
disassembly. Static graph reachability is an overapproximation, not
proof of live waiter object identity, memory aliasing, GhostLock or root.
"""
from __future__ import annotations
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

PIN_SOURCE="deac172780286aeca1d3b1d9ab7f036e84532a6d087cc89721fd5cc7d16fe1a3"
PIN_DISASM="20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997"
PIN_FUTEX="493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5"
PIN_TEXT="56286516ae9e6a873beab22b16af3ab330a768dc1b02f901854eb96f193789a5"
BASE=0xffffff800818e52c
LINE=re.compile(r"^([0-9a-fA-F]{16}):\s+([0-9a-fA-F]{8})\s+(\S+)(?:\s+(.*))?$")
TARGET=re.compile(r"0x[0-9a-fA-F]+")
REQUIRED={
 0x1194:("910303f9","add","x25, sp, #0xc0"),
 0x11b4:("35004ac0","cbnz","w0, 0xffffff8008190038"),
 0x11d0:("a90a6ff9","stp","x25, x27, [sp, #160]"),
 0x12ec:("a949a7e8","ldp","x8, x9, [sp, #152]"),
 0x12f0:("b4000e29","cbz","x9, 0xffffff800818f9e0"),
 0x12f4:("b40042c8","cbz","x8, 0xffffff8008190078"),
 0x12fc:("910303e2","add","x2, sp, #0xc0"),
 0x1308:("97fee1fc","bl","0xffffff8008148024"),
 0x131c:("340000d5","cbz","w21, 0xffffff800818f860"),
 0x1320:("910303e1","add","x1, sp, #0xc0"),
 0x1328:("97fee218","bl","0xffffff80081480b4"),
}
class AuditError(ValueError): pass

def need(value,why):
    if not value: raise AuditError(why)

def sha(blob):
    return hashlib.sha256(blob).hexdigest()

def member(archive:Path,expected_archive:str,name:str,expected_member:str)->bytes:
    need(archive.is_file() and not archive.is_symlink() and
         0<archive.stat().st_size<4000000,"Missing/unsafe original archive")
    need(sha(archive.read_bytes())==expected_archive,"Original archive SHA mismatch")
    with tarfile.open(archive,"r:gz") as tf:
        listings=tf.getmembers()
        need(len(listings)<=10 and all(x.isfile() and 0<x.size<300000 for x in listings),
             "Unexpected original archive member inventory")
        matches=[x for x in listings if x.name==name]
        need(len(matches)==1,"Missing or duplicate original archive member")
        raw=tf.extractfile(matches[0]).read()
        need(sha(raw)==expected_member,"Original member SHA mismatch")
        return raw

def parse(disasm:bytes)->dict[int,tuple[str,str,str]]:
    instructions={}
    for line in disasm.decode("utf-8","strict").splitlines():
        m=LINE.match(line)
        if m:
            addr=int(m.group(1),16)
            need(addr not in instructions,"Duplicate original instruction location")
            instructions[addr]=(m.group(2).lower(),m.group(3).lower(),
                                (m.group(4) or "").split("//",1)[0].strip())
    need(len(instructions)==1766 and
         all(BASE+4*i in instructions for i in range(1766)),
         "Original do_futex instruction window changed")
    return instructions

def validate_sites(instructions):
    for off,expected in REQUIRED.items():
        need(instructions.get(BASE+off)==expected,
             "Original instruction word/register drift at "+hex(off))
    return True

def successors(instructions,addr:int)->list[int]:
    _,op,args=instructions[addr]
    targets=TARGET.findall(args)
    target=int(targets[-1],16) if targets else None
    next_addr=addr+4
    if op in ("ret","eret","brk","hlt","br","blr"): return []
    if op=="b": return [target] if target in instructions else []
    if op.startswith("b.") or op in ("cbz","cbnz","tbz","tbnz"):
        return [p for p in (next_addr,target) if p in instructions]
    return [next_addr] if next_addr in instructions else []

def shortest_static_path(instructions,start:int,end:int,cap:int=4096):
    need(start in instructions and end in instructions,"Static CFG endpoints missing")
    pending=deque([start]);previous={start:None}
    while pending and len(previous)<=cap:
        pc=pending.popleft()
        if pc==end: break
        for nxt in successors(instructions,pc):
            if nxt not in previous:
                previous[nxt]=pc
                pending.append(nxt)
    need(end in previous,"No bounded original static CFG path")
    path=[]
    pc=end
    while pc is not None:
        path.append(pc);pc=previous[pc]
    return path[::-1]

def source_anchors(raw:bytes):
    source=raw.decode("utf-8","strict")
    anchors={
      "layout_marker":"struct futex_q {",
      "layout_randomization_annotation":"} __randomize_layout;",
      "source_waiter_assignment":"q.rt_waiter = &rt_waiter;",
      "source_waiter_test":"if (!q.rt_waiter) {",
      "source_proxy_wait":"ret = rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);",
      "source_cleanup":"if (ret && !rt_mutex_cleanup_proxy_lock(pi_mutex, &rt_waiter))",
    }
    need(all(source.count(value)==1 for key,value in anchors.items()
             if key!="layout_randomization_annotation"),
         "Original futex source anchors changed")
    start=source.index(anchors["layout_marker"])
    layout_end=source.index(anchors["layout_randomization_annotation"],start)
    need(layout_end-start<1000,"futex_q source layout annotation not adjacent")
    return {key:source[:layout_end if key=="layout_randomization_annotation"
                         else source.index(value)].count("\n")+1
            for key,value in anchors.items()}

def audit(original_source:bytes,original_disasm:bytes):
    anchors=source_anchors(original_source)
    instructions=parse(original_disasm)
    validate_sites(instructions)
    store=BASE+0x11d0
    load=BASE+0x12ec
    path=shortest_static_path(instructions,store,load)
    subsequent=shortest_static_path(instructions,BASE+0x12f0,BASE+0x1308)
    cleanup=shortest_static_path(instructions,BASE+0x131c,BASE+0x1328)
    need(BASE+0x12f4 in subsequent and BASE+0x12fc in subsequent and
         BASE+0x1320 in cleanup,"Original conditional fall-through changed")
    return {
     "schemaVersion":1,"target":"SM-G986U1/G986U1UESCHXL1",
     "scope":"ORIGINAL_DOFUTEX_STATIC_STORE_LOAD_AND_NULL_TEST_CROSSCHECK",
     "originalSourceArchiveSha256":PIN_SOURCE,
     "originalDisassemblyArchiveSha256":PIN_DISASM,
     "originalFutexSourceSha256":PIN_FUTEX,
     "originalDoFutexDisassemblySha256":PIN_TEXT,
     "originalInstructionSlots":len(instructions),"sourceAnchors":anchors,
     "sourceFutexQHasRandomizeLayoutAnnotation":True,
     "stockCompilerActualRandstructReorderingVerified":False,
     "firstStoreRelativeOffset":"0x11d0",
     "storedPointerExpression":"x25 (previously SP + 0xc0)",
     "storeFirstMemorySlot":"SP + 0xa0",
     "laterLoadRelativeOffset":"0x12ec","laterLoadedSecondRegister":"x9",
     "laterLoadedRegisterOrigin":"second element of ldp x8, x9, [SP + 0x98] = SP + 0xa0",
     "nullCheckRelativeOffset":"0x12f0",
     "nullCheckInstruction":"cbz x9, 0xffffff800818f9e0",
     "staticControlFlowPathStoreToLoadFound":True,
     "shortestStoreToLoadPathInstructions":len(path),
     "shortestStoreToLoadConditionalBranchOffsets":[
        hex(pc-BASE) for pc in path
        if instructions[pc][1] in ("cbz","cbnz","tbz","tbnz") or
        instructions[pc][1].startswith("b.")],
     "proxyWaitFallthroughStaticReachable":True,
     "cleanupConditionalFallthroughStaticReachable":True,
     "calleeSourceFieldQrtWaiterMapping":
          "CANDIDATE_CORROBORATED_NOT_FACTORY_LAYOUT_CERTIFIED",
     "aliasAnalysisAcrossIndirectMemoryWritesComplete":False,
     "runtimeBranchConditionsFeasibleProven":False,
     "samePhysicalPointerLiveAcrossAllCallsProven":False,
     "compiledWaiterCObjectBoundsCertified":False,
     "stackOverlapAcrossSyscallsProven":False,
     "ghostLockExploitOrRootVerified":False,
     "kernelSuLoaded":False,"deviceModified":False,
     "limits":"CFG path existence overapproximates execution. The C struct has a "
              "__randomize_layout annotation; source field correspondence "
              "is a candidate without OEM layout and memory alias analysis. "
              "Object lifetime, runtime feasibility, exploit and root are unproved."
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive",type=Path,required=True)
    parser.add_argument("--disassembly-archive",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        out=args.output.expanduser().resolve()
        need(not args.output.expanduser().is_symlink() and not out.exists(),
             "Output already exists or is symlink")
        need("/src/" not in str(out) and
             "/Root-My-Galaxy-Payloads/" not in str(out),
             "Refusing write into stock source/research repository")
        source=member(args.source_archive,PIN_SOURCE,"kernel/futex.c",PIN_FUTEX)
        disasm=member(args.disassembly_archive,PIN_DISASM,
                      "do_futex.disasm.txt",PIN_TEXT)
        result=audit(source,disasm)
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x",encoding="utf-8") as fp:
            json.dump(result,fp,indent=2)
            fp.write("\n")
        print("[ORIGINAL STATIC STORE-LOAD PATH]",result["staticControlFlowPathStoreToLoadFound"])
        print("[SHORTEST STATIC PATH INSTRUCTIONS]",result["shortestStoreToLoadPathInstructions"])
        print("[OEM FIELD LAYOUT / WAITER LIFETIME / ROOT] UNVERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,UnicodeError,tarfile.TarError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
