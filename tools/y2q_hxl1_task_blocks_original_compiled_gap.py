#!/usr/bin/env python3
"""HXL1 missing evidence ONLY: stock task_blocks_on_rt_mutex compiled paths.

No source, kernel rebuild, runtime fault triggering, payload, phone operation, or
repeat of previously completed rtmutex/stack audit stages. Authenticates the
owner's existing original ELF and recovered NM, then disassembles just this
single previously unexamined function to inventory publication/chainwalk/return.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_ghostlock_call_target_crosswalk as symbols
from tools import y2q_hxl1_static_cfg_audit as graphlib

ELF_SHA="e15f67e8253396d9e6463e5dfd78d67e324a7149842a7fbccb973ec0fd36ecdb"
NAME="task_blocks_on_rt_mutex"
EXPECTED_ENTRY=0xffffff80081479d4   # Original HXL1 proxy helper branch destination
MAX_FUNCTION_BYTES=0x3000
PC_LINE=re.compile(r"^\s*([0-9a-fA-F]{16}):\s+([0-9a-fA-F]{8})\s+(\S+)(?:\s+(.*?))?\s*$")
IMM=re.compile(r"0x[0-9a-fA-F]{16}$")
OBJ_HEX=re.compile(r"(?:0x)?[0-9a-fA-F]{16}$")
BRANCH_OPS={"b","bl","cbz","cbnz","tbz","tbnz"}

def normalize_objdump_control_target(op:str,operands:str)->str:
    """GNU ARM64 objdump writes branch VAs without 0x; normalise only VAs.

    Never change non-branch immediate operands, data offsets or register names.
    Unknown branch syntax stays unknown, rather than constructing an edge.
    """
    if op not in BRANCH_OPS and not op.startswith("b."):
        return operands
    prefix,sep,last=operands.rpartition(",")
    field=(last if sep else operands).strip()
    if not OBJ_HEX.fullmatch(field):
        return operands
    resolved="0x"+field.removeprefix("0x").lower()
    return (prefix+", "+resolved) if sep else resolved
SP_OFF=re.compile(r"\[\s*x\d+,\s*#(?:2296|0x8f8)\s*\]")
class EvidenceGap(ValueError):pass

def need(test,message):
    if not test:raise EvidenceGap(message)

def pin(path:Path,expected:str,limit:int)->bytes:
    need(path.is_file() and not path.is_symlink() and
         0<path.stat().st_size<limit,
         "Missing or unsafe already-saved original evidence "+str(path))
    raw=path.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==expected,
         "Original evidence bytes differ from owner pin "+str(path))
    return raw

def function_bounds(nm:bytes):
    by_address,addrs=symbols.read_symbols(nm)
    need(NAME in by_address.get(EXPECTED_ENTRY,[]),
         "Recovered original task_blocks_on_rt_mutex label/VA unavailable")
    idx=bisect.bisect_right(addrs,EXPECTED_ENTRY)
    need(idx<len(addrs),"Missing original next-text boundary")
    end=addrs[idx]
    need(32<=end-EXPECTED_ENTRY<=MAX_FUNCTION_BYTES and
         (end-EXPECTED_ENTRY)%4==0,
         "Unbounded or misaligned recovered function extent")
    return end,by_address,addrs

def disassemble(elf:Path,end:int,program:str)->dict:
    result=subprocess.run([
        program,"-d",
        "--start-address="+hex(EXPECTED_ENTRY),
        "--stop-address="+hex(end),str(elf)
    ],capture_output=True,text=True,errors="replace",timeout=30)
    need(result.returncode==0 and len(result.stdout)<1_000_000,
         "Original function objdump failed: "+result.stderr[:400])
    rows={}
    for line in result.stdout.splitlines():
        m=PC_LINE.match(line)
        if not m:continue
        va=int(m.group(1),16)
        if EXPECTED_ENTRY<=va<end:
            need(va not in rows,"Duplicated original instruction location")
            rows[va]={"relative":hex(va-EXPECTED_ENTRY),
                      "pc":hex(va),"word":m.group(2).lower(),
                      "op":m.group(3).lower(),
                      "args":normalize_objdump_control_target(
                          m.group(3).lower(),
                          (m.group(4) or "").split("//",1)[0].split(" <",1)[0].strip())}
    need(len(rows)==(end-EXPECTED_ENTRY)//4 and
         all(EXPECTED_ENTRY+4*i in rows for i in range(len(rows))),
         "Original compiler function text incomplete; do not infer control flow")
    return rows

def can_reach(edges,start,goal,exclude=frozenset()):
    if start in exclude or goal in exclude:return False
    seen=set();work=[start]
    while work:
        pc=work.pop()
        if pc==goal:return True
        if pc not in seen:
            seen.add(pc)
            work.extend(x for x in edges.get(pc,()) if x not in seen and x not in exclude)
    return False

def bounded_path_avoiding_register_writes(edges,rows,start,end,register):
    """One conservative path; no claim that its branch predicates are feasible."""
    pending=[(start,[start])]
    seen=set()
    store_ops={"str","stp","stur","stnp","stxr","stlxr","stlr","sttr"}
    while pending and len(seen)<len(rows):
        pc,path=pending.pop(0)
        if pc in seen or pc not in rows:
            continue
        seen.add(pc)
        if pc==end:
            return [hex(x-EXPECTED_ENTRY) for x in path]
        row=rows[pc]
        first=row["args"].split(",",1)[0].strip().lower()
        second=(row["args"].split(",",2)[1].strip().lower()
                if "," in row["args"] else "")
        writes=(row["op"] not in store_ops and
                (first in ("x"+register,"w"+register) or
                 (row["op"]=="ldp" and
                  second in ("x"+register,"w"+register))))
        if writes:
            continue
        for dest in edges.get(pc,()):
            if dest not in seen:
                pending.append((dest,path+[dest]))
    return None


def compiled_chainwalk_return_capture(rows,edges,returns):
    """Identify only captured-result-to-return-copy *static candidate* paths."""
    call_pc=EXPECTED_ENTRY+0x18c
    capture_pc=call_pc+4
    capture=rows.get(capture_pc)
    need(capture is not None and capture["word"]=="2a0003f4" and
         capture["op"]=="mov" and capture["args"]=="w20, w0",
         "Original post-chainwalk w20 return-value capture changed")
    matches=[]
    for pc,row in sorted(rows.items()):
        if (row["op"]=="mov" and row["args"]=="w0, w20") or (
             row["op"]=="orr" and
             row["args"] in ("w0, wzr, w20","w0, w20, wzr")):
            path=bounded_path_avoiding_register_writes(
                edges,rows,capture_pc+4,pc,"20")
            matches.append({
                "returnCopyRelativeVA":row["relative"],
                "originalOpcodeWord":row["word"],
                "instruction":row["op"]+" "+row["args"],
                "w20NotSyntacticallyOverwrittenAlongAConservativePath":bool(path),
                "conservativeWitnessFromCapture":path,
                "returnStaticReachableAfterCopy":any(
                    can_reach(edges,pc,ret) for ret in returns),
                "branchPredicatesJointlyFeasibleVerified":False,
                "fullReturnValuePropagationProven":False,
            })
    return {
       "chainwalkCallRelativeVA":"0x18c",
       "immediateReturnResultCaptureRelativeVA":"0x190",
       "captureInstruction":"mov w20, w0",
       "captureMachineWordVerified":"2a0003f4",
       "compiledReturnCopyCandidates":matches,
       "candidateCopiesFound":len(matches),
       "runtimeNonzeroChainwalkErrorProven":False,
       "pathSensitiveRuntimeValuePropagationProven":False,
    }


def inspect(rows,by_address,addresses):
    code={pc:(r["op"],r["args"]) for pc,r in rows.items()}
    edges,_,_,_=graphlib.edges_for(code)
    store_candidates=[
        pc for pc,r in rows.items()
        if r["op"] in ("str","stur","stp","stnp") and SP_OFF.search(r["args"])
    ]
    callsites=[]
    for pc,r in sorted(rows.items()):
        if r["op"]=="bl":
            args=r["args"]
            name=(symbols.symbol_match(args,by_address,addresses)
                  if IMM.fullmatch(args)
                  else {"status":"NON_LITERAL_TARGET_UNKNOWN"})
            callsites.append({"relativeVA":r["relative"],"staticVA":r["pc"],
                              "target":args,"recoveredLabel":name,
                              "sourceArgumentIdentityCertified":False})
    chainwalk=[c for c in callsites
               if "rt_mutex_adjust_prio_chain" in
               c["recoveredLabel"].get("labels",[])]
    returns=[pc for pc,r in rows.items() if r["op"]=="ret"]
    need(bool(returns),"Original task_blocks_on_rt_mutex return not found")
    entry=EXPECTED_ENTRY
    candidates=[]
    for pc in store_candidates:
        publicationToChain=[
            {
              "call":call,
              "staticEntryMayReachPublication":can_reach(edges,entry,pc),
              "staticPublicationMayReachChainwalk":can_reach(
                  edges,pc,int(call["staticVA"],16)),
              "staticChainwalkMayReachReturn":any(can_reach(
                  edges,int(call["staticVA"],16),ret) for ret in returns),
              "callReturnContext":[rows[a] for a in sorted(rows)
                                   if abs(a-int(call["staticVA"],16))<=48],
              "postPublicationErrorResultProven":False,
            } for call in chainwalk
        ]
        candidates.append({
           "chainwalkCandidatesFromPublication":publicationToChain,
           "staticEntryMayReachPublication":can_reach(edges,entry,pc),
           "site":rows[pc],
           "possibleReturnReachableAfterStoreUnderConservativeGraph":
               any(can_reach(edges,pc,x) for x in returns),
           "possibleEarlyReturnAvoidingThisStoreUnderConservativeGraph":
               any(can_reach(edges,entry,x,{pc}) for x in returns),
           "candidateStoreContext":[rows[k] for k in sorted(rows)
                                    if abs(k-pc)<=28],
           "taskRegisterAndWaiterValueDataflowCertified":False,
           "lateChainwalkErrorReturnProven":False,
        })
    chain=chainwalk
    returnFlow=compiled_chainwalk_return_capture(rows,edges,returns)
    return {
      "compiledChainwalkReturnCapture":returnFlow,
      "target":"SM-G986U1/G986U1UESCHXL1",
      "scope":"STOCK_TASK_BLOCKS_ON_RT_MUTEX_COMPILER_PUBLICATION_RETURN_GAP",
      "originalStockElfSha256":ELF_SHA,
      "originalNmSha256":symbols.ORIGINAL_NM_SHA,
      "originalTaskBlocksEntryVA":hex(entry),
      "originalFunctionEndRecoveredSymbolVA":hex(max(rows)+4),
      "originalInstructionCount":len(rows),
      "candidatePiBlockedOnStoreDisplacements":candidates,
      "candidateStoresCount":len(candidates),
      "returns":[rows[x] for x in sorted(returns)],
      "callsiteLedger":callsites,
      "exactRtMutexAdjustPrioChainCallCount":len(chain),
      "symbolizedBlCallCount":sum(
          x["recoveredLabel"].get("status")=="EXACT_RECOVERED_TEXT_LABEL"
          for x in callsites),
      "normalizedObjdumpBranchAndCallOperands":True,
      "conservativeCfgUnresolvedEdges":graphlib.edges_for(code)[3],
      "meaningOfPositiveReachability":"Potential path under overapproximated branches, not path predicate feasibility",
      "actualRuntimeLateErrorConditionProven":False,
      "compilerOriginalChainwalkCalls":chain,
      "branchAndStoreRelationshipsConservativeOnly":True,
      "factoryOriginalCallSequenceRuntimeFeasibleProven":False,
      "actualTaskPointerDataflowProven":False,
      "lateErrorPostPublicationObservedAtRuntime":False,
      "staleTaskPiBlockedOnAfterSyscallReturnObserved":False,
      "rootOrKernelSuObserved":False,
      "deviceModified":False,
      "meaning":"Original compiled publication/return candidates only. The CVE "
       "wrong-task cleanup in remove_waiter is already known and NOT "
       "re-verified or re-scored by this instrument. An individual return "
       "or store reachable in conservative CFG does not prove simultaneous "
       "branch predicates, source field identity, or a dangling pointer."
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf",type=Path,required=True,
                        help="Already saved, pinned original stock-vmlinux.elf")
    parser.add_argument("--nm",type=Path,required=True,
                        help="Already saved, pinned recovered original vmlinux-stock.nm")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        output=args.output.expanduser().resolve()
        need(not args.output.expanduser().is_symlink()
             and not output.exists()
             and "/src/" not in str(output)
             and "/Root-My-Galaxy-Payloads/" not in str(output),
             "Refusing overwrite or source/repository output")
        pin(args.elf,ELF_SHA,256_000_000)
        nm=pin(args.nm,symbols.ORIGINAL_NM_SHA,20_000_000)
        end,labels,addrs=function_bounds(nm)
        exe=shutil.which("aarch64-linux-gnu-objdump")
        need(bool(exe),"Install binutils-aarch64-linux-gnu to analyze original ELF")
        rows=disassemble(args.elf,end,exe)
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x",encoding="utf-8") as fp:
            result=inspect(rows,labels,addrs)
            json.dump(result,fp,indent=2);fp.write("\n")
        print("[NEW FACTORY FUNCTION]",NAME)
        print("[INSTRUCTIONS]",result["originalInstructionCount"])
        print("[CANDIDATE BLOCKED-ON STORES]",result["candidateStoresCount"])
        print("[RESOLVED ORIGINAL CALLS]",result["symbolizedBlCallCount"],"/",len(result["callsiteLedger"]))
        print("[CFG UNRESOLVED BRANCHES]",result["conservativeCfgUnresolvedEdges"])
        print("[COMPILED CHAINWALK CALLS]",len(result["compilerOriginalChainwalkCalls"]))
        for s in result["candidatePiBlockedOnStoreDisplacements"]:
            print("[PUBLICATION]",s["site"]["relative"],"entry->store",s["staticEntryMayReachPublication"],
                  "store->ret",s["possibleReturnReachableAfterStoreUnderConservativeGraph"],
                  "early ret without store",s["possibleEarlyReturnAvoidingThisStoreUnderConservativeGraph"])
            for c in s["chainwalkCandidatesFromPublication"]:
                print("[CHAINWALK PATH]",c["call"]["relativeVA"],
                      "publication->call",c["staticPublicationMayReachChainwalk"],
                      "call->ret",c["staticChainwalkMayReachReturn"],
                      "late error UNVERIFIED")
        print("[RETURN POINTS]",len(result["returns"]))
        f=result["compiledChainwalkReturnCapture"]
        print("[ORIGINAL CHAINWALK RETURN CAPTURE]",f["immediateReturnResultCaptureRelativeVA"],
              f["captureInstruction"])
        print("[POSSIBLE W20 RETURN COPIES]",f["candidateCopiesFound"])
        for r in f["compiledReturnCopyCandidates"]:
            print("[RETURN COPY CANDIDATE]",r["returnCopyRelativeVA"],r["instruction"],
                  "no-clobber witness",r["w20NotSyntacticallyOverwrittenAlongAConservativePath"],
                  "may reach ret",r["returnStaticReachableAfterCopy"])
        print("[LATE ERROR / LIVE STALE REFERENCE] NOT VERIFIED")
        print("[REPORT]",output)
        return 0
    except (OSError,ValueError,subprocess.TimeoutExpired) as ex:
        print("[STOP]",ex,file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
