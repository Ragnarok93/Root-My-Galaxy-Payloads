#!/usr/bin/env python3
"""Bounded original HXL1 do_futex operation-11 compiled basic-block audit.

Reuse the previously SHA-authenticated Samsung Image-derived disassembly
archive and recovered text-symbol listing. Do not infer C-local waiter slots,
compiler inlining, stack reuse, live addresses or CVE exploitability.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_static_cfg_audit as cfg
from tools import y2q_hxl1_ghostlock_call_target_crosswalk as names

ARCHIVE_SHA="20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997"
EXPECTED_NM=names.ORIGINAL_NM_SHA
REPO=Path(__file__).resolve().parents[1]
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
MAX_BLOCK_INSTRUCTIONS=128
MAX_SUCCESSOR_BLOCKS=2
MAX_SUCCESSOR_INSTRUCTIONS=64
MAX_SECOND_HOP_BLOCKS=4
STOP={"b","br","ret","eret","brk","hlt","cbz","cbnz","tbz","tbnz"}
VA=re.compile(r"0x[0-9a-fA-F]+$")
class Stop(ValueError):
    pass

def need(test,why):
    if not test: raise Stop(why)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def examine_op11(code:dict,entry:int,labels:dict,addresses:list)->dict:
    """Inspection of one branch-target linear block, NOT path-sensitive CFG."""
    need(code.get(entry+0xb14)==("cmp","w8, #0xb"),
         "Expected original operation-11 compare missing")
    jump,raw=code.get(entry+0xb18,("",""))
    need(jump=="b.eq" and bool(VA.fullmatch(raw)),
         "Expected original operation-11 dispatcher branch missing")
    target=int(raw,16)
    need(target in code and target%4==0,
         "Original operation-11 branch target outside bounded do_futex")
    observed=[]
    calls=[]
    reason="MAX_LINEAR_WINDOW_REACHED"
    for ix in range(MAX_BLOCK_INSTRUCTIONS):
        addr=target+ix*4
        if addr not in code:
            reason="STOPPED_AT_RECOVERED_FUNCTION_WINDOW_BOUNDARY"
            break
        op,args=code[addr]
        observed.append({"relativeToDoFutexEntry":hex(addr-entry),
                         "opcode":op,
                         "operands":args[:120],
                         "directBranchOrCallTarget":args if op in ("bl","b","b.eq") and VA.fullmatch(args) else None})
        if op=="bl":
            label=(names.symbol_match(args,labels,addresses)
                   if VA.fullmatch(args) else {"status":"NO_DIRECT_TARGET_IMMEDIATE"})
            calls.append({
              "relativeToDoFutexEntry":hex(addr-entry),
              "directCallTargetStaticVA":args if VA.fullmatch(args) else None,
              "recoveredTextTarget":label,
              "effectiveCalleeOrSourceIdentityVerified":False,
            })
        if op in STOP or op.startswith("b."):
            reason="STOPPED_AT_EXPLICIT_CONTROL_TRANSFER"
            break
    need(observed,"Empty original operation-11 block")
    last=target+(len(observed)-1)*4
    terminal_op,terminal_args=code[last]
    terminal=terminal_op in STOP or terminal_op.startswith("b.")
    successors=[]
    successor_calls=0
    if terminal:
        # Reuse the previously validated conservative branch-edge model.
        # Examine ONE following block per explicit original successor only.
        graph,_,_,_=cfg.edges_for(code)
        for start in sorted(set(graph.get(last,[])))[:MAX_SUCCESSOR_BLOCKS]:
            if start==target:
                successors.append({"relativeToDoFutexEntry":hex(start-entry),
                                   "status":"CYCLE_TO_FIRST_BLOCK_NOT_FOLLOWED",
                                   "dynamicPathFeasibilityVerified":False})
                continue
            next_rows=[]
            next_calls=[]
            halt="MAX_SUCCESSOR_BOUND"
            for j in range(MAX_SUCCESSOR_INSTRUCTIONS):
                va=start+j*4
                if va not in code:
                    halt="STOPPED_AT_VERIFIED_WINDOW_BOUNDARY"
                    break
                operation,operand=code[va]
                next_rows.append({"relativeToDoFutexEntry":hex(va-entry),
                                  "opcode":operation,"operands":operand[:120]})
                if operation=="bl":
                    source=names.symbol_match(operand,labels,addresses) if VA.fullmatch(operand) else {
                        "status":"DIRECT_CALL_IMMEDIATE_NOT_RESOLVED"}
                    next_calls.append({"relativeToDoFutexEntry":hex(va-entry),
                                       "recoveredTarget":source,
                                       "calleeSourceIdentityProven":False})
                if operation in STOP or operation.startswith("b."):
                    halt="STOPPED_AT_CONTROL_TRANSFER"
                    break
            successors.append({
                "relativeToDoFutexEntry":hex(start-entry),
                "status":"ONE_HOP_STATIC_WINDOW_ONLY",
                "instructionSlots":len(next_rows),
                "instructions":next_rows,
                "directCalls":next_calls,
                "stopReason":halt,
                "dynamicPathFeasibilityVerified":False,
                "waiterLocalSourceMappingProven":False,
            })
            successor_calls+=len(next_calls)
    # Follow only a second bounded control-transfer edge from the original
    # operation-11 entry. Do not treat graph edges as dynamically feasible.
    two_hop=[]
    two_hop_calls=0
    if terminal:
        seen={target}
        seen.update(entry+int(b["relativeToDoFutexEntry"],16) for b in successors)
        destinations=set()
        for b in successors:
            if b.get("status")!="ONE_HOP_STATIC_WINDOW_ONLY":
                continue
            begin=entry+int(b["relativeToDoFutexEntry"],16)
            n=b["instructionSlots"]
            if not n:
                continue
            last_addr=begin+(n-1)*4
            op=code[last_addr][0]
            if op not in STOP and not op.startswith("b."):
                continue
            destinations.update(x for x in graph.get(last_addr,[])
                                if x in code and x not in seen)
        for begin in sorted(destinations)[:MAX_SECOND_HOP_BLOCKS]:
            rows=[]
            calls2=[]
            reason="MAX_TWO_HOP_LINEAR_WINDOW_REACHED"
            for j in range(MAX_SUCCESSOR_INSTRUCTIONS):
                va=begin+4*j
                if va not in code:
                    reason="STOPPED_AT_VERIFIED_WINDOW_BOUNDARY"
                    break
                op,args=code[va]
                rows.append({"relativeToDoFutexEntry":hex(va-entry),
                             "opcode":op,"operands":args[:120]})
                if op=="bl":
                    match=(names.symbol_match(args,labels,addresses)
                           if VA.fullmatch(args) else
                           {"status":"DIRECT_CALL_IMMEDIATE_NOT_RESOLVED"})
                    calls2.append({
                        "relativeToDoFutexEntry":hex(va-entry),
                        "directCallTargetStaticVA":args if VA.fullmatch(args) else None,
                        "recoveredTarget":match,
                        "effectiveCalleeOrWaiterSourceIdentityVerified":False,
                    })
                if op in STOP or op.startswith("b."):
                    reason="STOPPED_AT_EXPLICIT_CONTROL_TRANSFER"
                    break
            two_hop.append({
                "relativeToDoFutexEntry":hex(begin-entry),
                "status":"SECOND_HOP_BOUNDED_STATIC_WINDOW_ONLY",
                "instructionSlots":len(rows),
                "instructions":rows,
                "directCalls":calls2,
                "stopReason":reason,
                "dynamicPathFeasibilityVerified":False,
                "sourceLocalWaiterIdentityVerified":False,
            })
            two_hop_calls+=len(calls2)
    return {
      "dispatcherCompareRelativeOffset":"0xb14",
      "dispatcherBranchRelativeOffset":"0xb18",
      "case11BlockStartRelativeToDoFutexEntry":hex(target-entry),
      "originalLinearInstructionSlotsReviewed":len(observed),
      "firstBlock":observed,
      "callTargetsInFirstBlock":calls,
      "stopReason":reason,
      "terminalControlTransfer":{
          "relativeToDoFutexEntry":hex(last-entry),
          "opcode":terminal_op,
          "operands":terminal_args[:120],
          "observedTerminator":terminal,
      },
      "immediateSuccessorBlocks":successors,
      "oneHopSuccessorDirectCalls":successor_calls,
      "twoHopSuccessorBlocks":two_hop,
      "twoHopDirectCalls":two_hop_calls,
      "maxOriginalBranchHopsInspected":2,
      "allRuntimePathsVerified":False,
      "interproceduralPointerDataflowVerified":False,
      "compilerInlinedFutexWaitRequeuePiProven":False,
      "waiterSourceLocalMachineSlotIdentified":False,
      "branchTakenDynamicallyObserved":False,
    }

def review(archive:Path,nm:Path)->dict:
    need(archive.is_file() and not archive.is_symlink() and
         0<archive.stat().st_size<4_000_000,
         "Missing/unsafe original disassembly archive")
    need(digest(archive.read_bytes())==ARCHIVE_SHA,
         "Original HXL1 5-function disassembly archive SHA256 mismatch")
    all_windows=cfg.read_archive(archive)
    old=cfg.analyze(all_windows)
    need(old.get("instructionsChecked")==4102 and
         old.get("operation11Branch",{}).get("canReachBranchFromEntry") is True,
         "Previous original op-11 CFG provenance not reproduced")
    need(nm.is_file() and not nm.is_symlink() and
         0<nm.stat().st_size<16_000_000,
         "Missing/unsafe recovered HXL1 nm")
    sym,addr=names.read_symbols(nm.read_bytes(),EXPECTED_NM)
    function=all_windows["do_futex"]
    branch=examine_op11(function["instructions"],function["start"],sym,addr)
    expected=[("0xc34",16,3),("0x118c",11,2),("0x128c",2,0)]
    actual=[(b["relativeToDoFutexEntry"],b["instructionSlots"],len(b["directCalls"]))
            for b in branch["twoHopSuccessorBlocks"]]
    need(branch["case11BlockStartRelativeToDoFutexEntry"]=="0xbd0" and
         branch["originalLinearInstructionSlotsReviewed"]==24 and
         len(branch["immediateSuccessorBlocks"])==2 and
         actual==expected and branch["twoHopDirectCalls"]==5,
         "Pinned original operation-11 two-hop block inventory mismatch")
    return {
      "schemaVersion":1,
      "target":"SM-G986U1/G986U1UESCHXL1",
      "scope":"EXISTING_ORIGINAL_DOFUTEX_OP11_SINGLE_STATIC_BASIC_BLOCK",
      "originalDisassemblyArchiveSha256":ARCHIVE_SHA,
      "originalNmSha256":EXPECTED_NM,
      "originalKernelImageRehashedByThisAudit":False,
      "originalArchiveCodeFunctionCount":5,
      "originalArchiveInstructionSlotsVerified":4102,
      "operation11StaticallyReachableUnderConservativeCFG":True,
      "operation11LinearBlock":branch,
      "exactFutexWaiterCompilerLocalProven":False,
      "originalWaiterLifetimeOrStackAliasProven":False,
      "usableGhostLockPrivilegeEscalationProven":False,
      "kernelSuLoaded":False,
      "deviceModified":False,
      "limits":"Bounded original opcode inspection only. Source-to-binary C-local identity, compiler inlining, loop lifetimes and dynamic taken paths are not established.",
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--nm",type=Path,default=Path.home()/"s20-artifacts/hxl1-research/vmlinux-stock.nm")
    p.add_argument("--output",type=Path,required=True)
    opts=p.parse_args()
    try:
        out=opts.output.expanduser().resolve()
        need(not opts.output.expanduser().is_symlink() and
             not out.exists() and out!=REPO and REPO not in out.parents and
             out!=SOURCE and SOURCE not in out.parents and
             out!=opts.archive.expanduser().resolve() and
             out!=opts.nm.expanduser().resolve(),
             "Output must be fresh and outside original evidence/source trees")
        result=review(opts.archive.expanduser().resolve(),
                      opts.nm.expanduser().resolve())
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x",encoding="utf-8") as f:
            json.dump(result,f,indent=2)
            f.write("\n")
        b=result["operation11LinearBlock"]
        print("[ORIGINAL OPERATION-11 BRANCH] VERIFIED")
        print("[SINGLE BASIC BLOCK INSTRUCTIONS]",b["originalLinearInstructionSlotsReviewed"])
        print("[DIRECT CALLS IN FIRST BLOCK]",len(b["callTargetsInFirstBlock"]))
        print("[TERMINAL CONTROL TRANSFER]",b["terminalControlTransfer"]["opcode"],
              b["terminalControlTransfer"]["operands"])
        print("[IMMEDIATE SUCCESSOR BLOCKS]",len(b["immediateSuccessorBlocks"]))
        print("[ONE-HOP SUCCESSOR DIRECT CALLS]",b["oneHopSuccessorDirectCalls"])
        print("[SECOND-HOP BLOCKS]",len(b["twoHopSuccessorBlocks"]))
        for sub in b["twoHopSuccessorBlocks"]:
            print("[SECOND-HOP]",sub["relativeToDoFutexEntry"],
                  "instructions=",sub["instructionSlots"],
                  "direct BL calls=",len(sub["directCalls"]))
        print("[SECOND-HOP DIRECT CALLS]",b["twoHopDirectCalls"])
        print("[COMPILER WAITER-LOCAL, STACK REUSE, ROOT] UNVERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,KeyError,TypeError,UnicodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
