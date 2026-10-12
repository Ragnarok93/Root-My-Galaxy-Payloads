#!/usr/bin/env python3
"""Offline audit of actual compact-HXL1 producer/fault GDB traces and branch paths.

Cross-checks previously saved raw GDB logs with their JSON reports, immutable
OEM kernel opcodes and the exact compact DTB/35,168-byte guest FDT provenance.
Scans bounded source-only AArch64 direct branches near the *first* fault to
find candidate incoming edges. Does not infer executed branches from code
presence, or source contents if an original GDB memory read was missing.

No guest execution, memory writes, fabricated UH, device, root or unlock.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_compact_register_provenance as owner
from tools import y2q_hxl1_qemu_compact_smc_registers as smc
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_fault_sites as sites

ROOT=Path.home()/"s20-artifacts/hxl1-research"
SOURCE_FOLDERS={
    "x21":"qemu-compact-regorigin-x21-v1-20261012",
    "x10":"qemu-compact-regorigin-x10-v1-20261012",
}
MAX_REPORT=128*1024
MAX_GDB=1024*1024
SCAN_BACK=0x800
SCAN_AHEAD=0x20
MASK64=(1<<64)-1

class RouteEvidenceError(ValueError):
    pass

def sign_extend(value:int,bits:int)->int:
    sign=1<<(bits-1)
    return (value^sign)-sign

def decode_direct_branch(pc:int,word:int)->dict|None:
    """Decode A64 fixed-length direct-branch immediate encodings only."""
    family=None
    displacement=None
    if word&0x7c000000==0x14000000:
        family="BL" if word&0x80000000 else "B"
        displacement=sign_extend(word&0x3ffffff,26)<<2
    elif word&0xff000010==0x54000000:
        family="B.cond"
        displacement=sign_extend((word>>5)&0x7ffff,19)<<2
    elif word&0x7e000000==0x34000000:
        family="CBNZ" if word&0x01000000 else "CBZ"
        displacement=sign_extend((word>>5)&0x7ffff,19)<<2
    elif word&0x7e000000==0x36000000:
        family="TBNZ" if word&0x01000000 else "TBZ"
        displacement=sign_extend((word>>5)&0x3fff,14)<<2
    if family is None:
        return None
    return {"source":hex(pc),"sourceWord":f"{word:08x}","branchKind":family,
            "target":hex((pc+displacement)&MASK64),
            "directTargetDecodedFromFactoryBytes":True,
            "branchExecutedInGuest":False}

def branch_neighborhood(image:bytes,fault:int,back:int=SCAN_BACK,ahead:int=SCAN_AHEAD)->dict:
    if back<0 or back>0x1000 or back%4 or ahead<0 or ahead>0x100 or ahead%4:
        raise RouteEvidenceError("Bounded source branch scan alignment/range invalid")
    start=fault-back
    end=fault+ahead
    if (start<gate.VM_BASE or end>gate.VM_BASE+len(image) or
        (start|end|fault)&3):
        raise RouteEvidenceError("Source scan outside original ARM64 Image")
    edges=[]
    nearby=[]
    for va in range(start,end,4):
        opcode=int.from_bytes(image[va-gate.VM_BASE:va-gate.VM_BASE+4],"little")
        edge=decode_direct_branch(va,opcode)
        if edge and fault-0x30<=int(edge["target"],16)<=fault+0x10:
            edges.append(edge)
        if fault-0x38<=va<=fault+0x18:
            nearby.append({"address":hex(va),"opcode":f"{opcode:08x}",
                           "directBranch":edge})
    return {
        "originalSourceScanStart":hex(start),
        "originalSourceScanEndExclusive":hex(end),
        "candidateIncomingDirectEdgesNearFault":edges,
        "faultLocalOriginalOpcodes":nearby,
        "sourceBranchDirectionsDoNotProveExecutedPredecessors":True,
        "indirectBranchesAndExceptionReturnsNotEnumerated":True,
    }

def cross_check_saved(target:str,raw:str,saved:dict,stock_image:bytes,
                      expected_compact_sha:str)->dict:
    gate.valid_source(stock_image)
    verified=owner.verify_stock_words(stock_image,target)
    rerun=owner.analyze(raw,target)
    for name,value in rerun.items():
        if saved.get(name)!=value:
            raise RouteEvidenceError("Saved register-origin report differs from raw GDB at "+name)
    if (saved.get("gdbExitCode")!=0 or
        saved.get("targetDevice")!="SM-G986U1/G986U1UESCHXL1" or
        saved.get("stockKernelSha256")!=gate.KERNEL_SHA or
        saved.get("compactDtbSha256")!=expected_compact_sha or
        saved.get("earlierVerifiedRuntimeFdtBytes")!=smc.EXPECTED_RUNTIME_BYTES):
        raise RouteEvidenceError("Saved original kernel/compact-DTB/guest-FDT provenance invalid")
    if not rerun.get("faultObservedInThisRun"):
        raise RouteEvidenceError("No same-session fault instruction capture in saved GDB")
    c=owner.CANDIDATES[target]
    source_read=rerun.get("producerSourceMemoryReadAttested",False)
    source_value=rerun.get("producerSourceMemoryValue") if source_read else None
    base_value=rerun["faultBaseValueBefore"]
    result={
        "register":target.upper(),
        "status":rerun["status"],
        "originalFactoryOpcodeAttested":verified,
        "producerObserved":rerun["producerObservedInThisRun"],
        "producerSourceMemoryReadAttested":source_read,
        "producerSourceMemoryValue":source_value,
        "faultObserved":True,
        "faultBaseValue":base_value,
        "sourceReadAndFaultBaseEqual":(
            source_read and source_value==base_value),
        "candidateProducerExecutedBeforeFault":(
            rerun["producerObservedInThisRun"] and rerun["status"]==
            "PRODUCER_THEN_FAULT_OBSERVED_NO_FULL_DEF_USE_PROOF"),
        "oneStepRegisterDefUseProven":False,
        "uhSmcCausedFaultProven":False,
        "reasonIfProducerNotObserved":(
            "Candidate producer breakpoint was not hit; do not treat its "
            "source stack restore as a verified predecessor."
            if not rerun["producerObservedInThisRun"] else None),
        "sourceReadMeaning":c["sourceValue"],
    }
    if target=="x10" and not source_read:
        result["x10SourceFieldValueEstablished"]=False
    elif target=="x10":
        result["x10SourceFieldValueEstablished"]=True
    return result

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--research-root",type=Path,default=ROOT)
    ap.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    ap.add_argument("--output",type=Path,
                    default=ROOT/"qemu-pc-compact-fdt-20261012/regorigin-route-audit-20261012.json")
    args=ap.parse_args()
    try:
        root=args.research_root.expanduser().absolute()
        out=args.output.expanduser().absolute()
        if out.exists() or out.is_symlink() or out.suffix!=".json":
            raise RouteEvidenceError("Output must be a new JSON file; preserve all source captures")
        _,dtb=smc.verify_preflight(root,args.kernel.expanduser().absolute())
        original=gate.checked_file(args.kernel.expanduser().absolute())
        data={}
        for target in ("x21","x10"):
            directory=root/SOURCE_FOLDERS[target]
            saved=json.loads(gate.checked_file(directory/"register-provenance-report.json",MAX_REPORT))
            raw=gate.checked_file(directory/"gdb.log",MAX_GDB).decode("utf-8","replace")
            data[target]=cross_check_saved(target,raw,saved,original,dtb["overrideSha256"])
        first=owner.CANDIDATES["x21"]["fault"]
        scan=branch_neighborhood(original,first)
        result={
            "status":"OWNER_COMPACT_REGISTER_ORIGINS_OFFLINE_CORRELATED",
            "factoryKernelSha256":gate.KERNEL_SHA,
            "compactDtbSha256":dtb["overrideSha256"],
            "earlierVerifiedRuntimeFdtBytes":smc.EXPECTED_RUNTIME_BYTES,
            "registerEvidence":data,
            "x21DirectBranchSourceScan":scan,
            "smcResponseOrRkpBitmapVerified":False,
            "firstAllocatorFailureRootCauseEstablished":False,
            "x10PanicSequenceProven":False,
            "originalKernelModified":False,
            "physicalDeviceTouched":False,
        }
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
        for t,r in data.items():
            print("["+t.upper()+" SAVED GDB]",r["status"])
            print("["+t.upper()+" PRODUCER HIT]",r["producerObserved"])
            print("["+t.upper()+" LIVE BASE]",r["faultBaseValue"])
            print("["+t.upper()+" SOURCE MEMORY READ]",r["producerSourceMemoryReadAttested"],
                  r["producerSourceMemoryValue"])
            print("["+t.upper()+" MEMORY==BASE]",r["sourceReadAndFaultBaseEqual"])
        print("[X21 DIRECT SOURCE EDGES NEAR FAULT]",len(scan["candidateIncomingDirectEdgesNearFault"]))
        for edge in scan["candidateIncomingDirectEdgesNearFault"][:24]:
            print("  ",edge["source"],edge["branchKind"],"->",edge["target"])
        print("[INSTRUCTION CAUSALITY PROVED] NO")
        print("[REPORT]",out)
        return 0
    except (RouteEvidenceError,gate.GateError,OSError,TypeError,ValueError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
