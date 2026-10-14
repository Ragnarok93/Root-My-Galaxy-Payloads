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
    return {
      "dispatcherCompareRelativeOffset":"0xb14",
      "dispatcherBranchRelativeOffset":"0xb18",
      "case11BlockStartRelativeToDoFutexEntry":hex(target-entry),
      "originalLinearInstructionSlotsReviewed":len(observed),
      "firstBlock":observed,
      "callTargetsInFirstBlock":calls,
      "stopReason":reason,
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
        print("[COMPILER WAITER-LOCAL, STACK REUSE, ROOT] UNVERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,KeyError,TypeError,UnicodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
