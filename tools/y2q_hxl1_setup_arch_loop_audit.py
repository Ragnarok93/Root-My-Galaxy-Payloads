#!/usr/bin/env python3
"""Offline original HXL1 setup_arch yield/B loop, call, and string attribution.

Uses only previously owner-observed QMP PC evidence, exact SHA-pinned factory
Image and the independently reconstructed (unverified) symbol map. No QEMU
guest execution, new FDT, kernel write, mobile device, or root action.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_pc_attribution as prev
from tools import y2q_hxl1_qemu_fault_sites as stock

LOOP_PC=0xffffff800a60514c
YIELD_WORD=0xd503203f
B_PREV_WORD=0x17ffffff
VM_BASE=gate.VM_BASE

class LoopAuditError(ValueError):
    pass

def get_word(image:bytes,virtual_address:int)->int:
    offset=virtual_address-VM_BASE
    if offset<0 or offset%4 or offset+4>len(image):
        raise LoopAuditError("Instruction not backed by original factory Image")
    return int.from_bytes(image[offset:offset+4],"little")

def decode_adrp(opcode:int,pc:int)->dict:
    if opcode&0x9f000000!=0x90000000:
        return {"status":"NOT_ADRP"}
    immlo=(opcode>>29)&3
    immhi=(opcode>>5)&0x7ffff
    imm=(immhi<<2)|immlo
    if imm&(1<<20):
        imm-=1<<21
    return {"status":"ADRP","reg":opcode&31,
            "address":(pc&~0xfff)+(imm<<12)}

def decode_add_imm(opcode:int)->dict:
    if opcode&0xff000000!=0x91000000:
        return {"status":"NOT_ADD64_IMMEDIATE"}
    shift=(opcode>>22)&3
    if shift not in (0,1):
        return {"status":"UNSUPPORTED_ADD_IMMEDIATE_SHIFT"}
    return {"status":"ADD64_IMMEDIATE",
            "rd":opcode&31,"rn":(opcode>>5)&31,
            "immediate":((opcode>>10)&0xfff)<<(12 if shift else 0)}

def candidate_printable_string(image:bytes,va:int,max_bytes:int=256)->dict:
    off=va-VM_BASE
    if off<0 or off>=len(image):
        return {"status":"POINTER_OUTSIDE_FACTORY_IMAGE","address":hex(va)}
    raw=image[off:off+max_bytes+1]
    end=raw.find(b"\0")
    if end<0 or end>max_bytes:
        return {"status":"STRING_NOT_TERMINATED_WITHIN_BOUND","address":hex(va)}
    data=raw[:end]
    if not data or any(c<0x20 or c>0x7e for c in data):
        return {"status":"NO_PLAUSIBLE_PRINTABLE_STRING","address":hex(va)}
    return {"status":"CANDIDATE_STATIC_ASCII",
            "address":hex(va),"imageOffset":hex(off),
            "value":data.decode("ascii"),"length":len(data),
            "proof":"ORIGINAL_IMAGE_BYTES_ONLY_NOT_RUNTIME_GUEST_CONTENT"}

def interpret(image:bytes,pc:int,symbols:dict)->dict:
    # Matched source bytes independently; never infer behavior from the
    # reconstructed symbol *name* without verifying the original opcodes.
    b=get_word(image,pc)
    y=get_word(image,pc-4)
    c=get_word(image,pc-8)
    br=prev.aarch64_unconditional_branch(b,pc)
    call=prev.aarch64_unconditional_branch(c,pc-8)
    loop=(y==YIELD_WORD and br.get("status")=="A64_B_OR_BL_IMM26"
          and br.get("kind")=="B" and br.get("target")==hex(pc-4))
    result={
        "sampledPc":hex(pc),
        "sampledPcOriginalImageOffset":hex(pc-VM_BASE),
        "yieldAddress":hex(pc-4),"yieldOpcode":f"{y:08x}",
        "branchOpcode":f"{b:08x}",
        "branch":br,
        "priorCallAddress":hex(pc-8),
        "priorCallOpcode":f"{c:08x}",
        "priorCall":call,
        "sourceContainsYieldBackwardBranchLoop":loop,
        "guestLiveBytesAtLoopCorrelated":False,
        "loopRunningIndefinitelyProven":False,
        "kernelBootsUserspace":False,
        "memblockAllocatorReservationVerified":False,
        "secureRkpPoolReserved":False,
        "nearestSourceTextSymbol":stock.nearest_symbol(symbols,pc),
    }
    if not loop:
        result["classification"]="NO_VERIFIED_FACTORY_YIELD_LOOP_AT_SAMPLED_PC"
        return result
    result["classification"]="PINNED_FACTORY_SOURCE_YIELD_LOOP_MATCHES_REPEATED_QMP_PC"
    if call.get("kind")=="BL" and call.get("target"):
        target=int(call["target"],16)
        result["callee"]={
            "target":hex(target),
            "factoryImageOffset":hex(target-VM_BASE),
            "nearestRecoveredSymbol":stock.nearest_symbol(symbols,target),
            "firstOpcode":f"{get_word(image,target):08x}" if 0<=target-VM_BASE<len(image)-4 else None,
            "symbolNameValidatedByExecution":False,
        }
    # The observed source sequence at PC-0x18 and PC-0x10 builds x0:
    # adrp x0, page / add x0, x0, #imm12. A different opcode must fail
    # attribution instead of guessing a format-message address.
    adrp_pc=pc-0x18
    adrp=decode_adrp(get_word(image,adrp_pc),adrp_pc)
    add=decode_add_imm(get_word(image,pc-0x10))
    result["staticAddressSequence"]={
        "adrpInstructionAddress":hex(adrp_pc),
        "adrp":{k:hex(v) if isinstance(v,int) and k=="address" else v for k,v in adrp.items()},
        "addInstructionAddress":hex(pc-0x10),
        "add":add,
        "candidateAddressEstablished":False,
    }
    if (adrp.get("status")=="ADRP" and add.get("status")=="ADD64_IMMEDIATE"
            and adrp["reg"]==add["rn"]==add["rd"]==0):
        va=adrp["address"]+add["immediate"]
        result["staticAddressSequence"]["candidateAddressEstablished"]=True
        result["staticAddressSequence"]["candidateX0Address"]=hex(va)
        result["staticAddressSequence"]["candidateImageString"]=candidate_printable_string(image,va)
    # Independent branch from prior non-fatal path: B at PC-0x1c can
    # skip this ADRP/BL/loop block. Predecessor branch conditions are
    # NOT established by this short window.
    skip_pc=pc-0x1c
    skip=prev.aarch64_unconditional_branch(get_word(image,skip_pc),skip_pc)
    result["skipOverLoopBranch"]={
        "instructionAddress":hex(skip_pc),
        "sourceBranch":skip,
        "skipsLoopBlock":skip.get("kind")=="B" and (
            int(skip["target"],16)>pc) if skip.get("target") else False,
        "branchPredecessorConditionProven":False,
    }
    return result

def read_prior_report(prior:dict,image:bytes,symbols:dict)->dict:
    if prior.get("target")!=prev.TARGET or prior.get("factoryImageSha256")!=gate.KERNEL_SHA:
        raise LoopAuditError("Original PC attribution evidence not from exact factory HXL1 Image")
    if prior.get("sampledPc")!=hex(LOOP_PC) or prior.get("originalImage",{}).get("originalOpcode")!="17ffffff":
        raise LoopAuditError("Owner prior sample/branch opcode is not the validated setup_arch site")
    if prior.get("sourceQmpMode")!="v3-canary" or prior.get("sampleCount")!=4:
        raise LoopAuditError("Original owner QMP four-sample source context differs")
    return interpret(image,LOOP_PC,symbols)

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    report=root/"qemu-memblock-pc-samples-v3-20261012"
    p.add_argument("--prior",type=Path,default=report/"original-pc-attribution.json")
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,default=report/"setup-arch-loop-callee-audit.json")
    a=p.parse_args()
    try:
        output=a.output.expanduser().absolute()
        source=[x.expanduser().absolute() for x in (a.prior,a.kernel,a.nm)]
        if output.suffix!=".json" or output.exists() or output.is_symlink() or output in source:
            raise LoopAuditError("Use a fresh .json output; no original evidence overwritten")
        prior=json.loads(gate.checked_file(a.prior,320*1024))
        image=gate.checked_file(a.kernel)
        gate.valid_source(image)
        symbols=stock.load_recovered_symbols(a.nm)
        if symbols["status"]!="RECOVERED_NM_SYMBOLS_UNVERIFIED":
            raise LoopAuditError("Recovered original symbol map unavailable")
        r=read_prior_report(prior,image,symbols)
        if not r["sourceContainsYieldBackwardBranchLoop"]:
            raise LoopAuditError("Original factory yield/branch loop did not match evidence")
        r["sourceFactoryImageSha256"]=gate.KERNEL_SHA
        r["symbolMapSha256"]=symbols["sourceSha256"]
        r["guestMemoryOrPhoneChanged"]=False
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(r,indent=2)+"\n")
        print("[FACTORY LOOP]",r["classification"])
        print("[CALL TARGET]",r.get("callee",{}).get("target"))
        print("[RECOVERED CALLEE]",r.get("callee",{}).get("nearestRecoveredSymbol",{}).get("name"))
        address=r.get("staticAddressSequence",{})
        print("[STATIC X0 POINTER]",address.get("candidateX0Address","[not established]"))
        print("[SOURCE STRING]",address.get("candidateImageString",{}))
        print("[SKIP OVER LOOP BRANCH]",r.get("skipOverLoopBranch",{}))
        print("[LIVE GUEST OPCODE COMPARED] NO")
        print("[MEMBLOCK/RKP VERIFIED] NO")
        print("[REPORT]",output)
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
