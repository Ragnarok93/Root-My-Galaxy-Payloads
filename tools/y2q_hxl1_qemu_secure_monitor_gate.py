#!/usr/bin/env python3
"""Validate HXL1 stock-image fault opcodes and identify the secure-monitor gate.

Fully offline: this never launches QEMU, mutates the kernel, flashes a device,
or treats missing guest register state as proof of a particular UH application.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_trace_attest as trace
from tools import y2q_hxl1_qemu_fault_sites as faults

EXPECTED = {
    0xffffff80080a5794: "d4000003",
    0xffffff80082ac90c: "f9402eb8",
    0xffffff80086de39c: "a9412149",
}
SMC_FORK_IDS = {
    0xc300c001: "Samsung RKP (fork's Qualcomm-style ABI)",
    0xc300c002: "Samsung KDP (fork's Qualcomm-style ABI)",
}

class GateError(ValueError):
    pass

def decode(word: int) -> dict:
    # AArch64 exception-generation encoding; bit[20:5] carries imm16.
    if (word & 0xffe0001f) == 0xd4000003:
        return {"instruction": "SMC", "immediate": (word >> 5) & 0xffff,
                "class": "SECURE_MONITOR_CALL",
                "x0CallId": "UNOBSERVED",
                "argumentsX1ThroughX6": "UNOBSERVED"}
    # 64-bit unsigned-offset LDR Xt, [Xn, #imm12 * 8]
    if (word & 0xffc00000) == 0xf9400000:
        return {"instruction": "LDR_X_UNSIGNED_OFFSET",
                "register": f"x{word & 31}",
                "baseRegister": f"x{(word >> 5) & 31}",
                "byteOffset": ((word >> 10) & 0xfff) * 8,
                "memoryAccess": "READ"}
    # 64-bit LDP signed scaled offset, no base writeback.
    if (word & 0xffc00000) == 0xa9400000:
        imm=(word >> 15) & 0x7f
        if imm >= 64:imm -= 128
        return {"instruction": "LDP_X_OFFSET",
                "registers": [f"x{word & 31}", f"x{(word >> 10) & 31}"],
                "baseRegister": f"x{(word >> 5) & 31}",
                "byteOffset": imm * 8,
                "memoryAccess": "READ"}
    return {"instruction": "OTHER_OR_UNSUPPORTED", "rawOpcode": f"{word:08x}"}

def classify(fault: dict, image: bytes, va_base: int) -> dict:
    elr=fault.get("elr")
    if not isinstance(elr,int):
        raise GateError("Expected integer ELR in original fault-sites JSON")
    if elr not in EXPECTED:
        raise GateError(f"Unexpected ELR: {elr:#x}; no blanket UH inference allowed")
    stock=faults.window(image,elr,va_base)
    if stock["status"]!="ORIGINAL_STOCK_IMAGE_BYTES_FOUND":
        raise GateError(f"ELR {elr:#x} not located in stock Image")
    op=stock["originalOpcode"]
    if op!=EXPECTED[elr] or op!=fault.get("originalImage",{}).get("originalOpcode"):
        raise GateError(f"ELR {elr:#x}: stock Image or report opcode mismatch")
    decoded=decode(int(op,16))
    far=fault.get("far")
    result={"elr":hex(elr),"originalImageOffset":stock["candidateImageOffset"],
            "factoryOpcode":op,"decoded":decoded,
            "originalFaultDescription":fault.get("qemuDescription"),
            "far":hex(far) if isinstance(far,int) else None,
            "guestRegistersAtTrap": "NOT_CAPTURED",
            "causalPlatformDependencyProven":False}
    if decoded["instruction"]=="SMC":
        result.update(
            gate="SMC_0_EXECUTED_WITH_UNHANDLED_OR_TRAPPED_CALL",
            forkRelevantInterception="target/arm/tcg/op_helper.c: HELPER(pre_smc)",
            forkRecognizedCallIds={hex(k):v for k,v in SMC_FORK_IDS.items()},
            forkCallIdCompatible="UNDETERMINED_UNTIL_GUEST_X0_CAPTURED",
            nextEvidence="Capture X0-X6 at ELR before SMC executes, and verify "
                         "HXL1 source command ABI before any emulation response")
    elif decoded["instruction"] in ("LDR_X_UNSIGNED_OFFSET","LDP_X_OFFSET"):
        offset=decoded["byteOffset"]
        candidate=(far-offset) if isinstance(far,int) else None
        result.update(
            gate="DATA_ABORT_READ_ADDRESS_CORRELATION",
            candidateBaseRegisterValue=hex(candidate) if candidate is not None else None,
            nullBaseIsConsistent=(candidate==0),
            nextEvidence="Capture actual guest base register and relevant "
                         "stack/call chain before attributing this null read "
                         "to the preceding SMC or changing QEMU RAM maps")
    else:
        result["gate"]="UNEXPECTED_STOCK_OPCODE"
    return result

def analyze(report: dict, image: bytes) -> dict:
    if report.get("target") != faults.TARGET:
        raise GateError("Report target is not HXL1")
    if not report.get("factoryImageTranslationCorrelated"):
        raise GateError("Original factory Image correlation absent")
    if report.get("originalKernelImageSha256") != trace.KERNEL_HASH:
        raise GateError("Report SHA does not match exact HXL1 kernel")
    va_base=int(report["virtualBase"],16)
    if va_base!=faults.VM_BASE:
        raise GateError("Report uses unexpected/unverified virtual Image base")
    entries=report.get("exceptions",[])
    if not isinstance(entries,list) or len(entries)!=3:
        raise GateError("Expected exactly three saved HXL1 exception entries")
    items=[classify(x,image,va_base) for x in entries]
    if {int(x["elr"],16) for x in items}!=set(EXPECTED):
        raise GateError("Missing or duplicated expected exception ELRs")
    return {
        "target":faults.TARGET,
        "inputSha256":trace.KERNEL_HASH,
        "originalImageUnmodified":True,
        "virtualBaseAssumption":hex(va_base),
        "faults":items,
        "validatedSmcAtOriginalImageOffset":"0x25794",
        "forkRelevantButNotReady":True,
        "smcRegisterArgumentsAvailable":False,
        "reasonForGate":"Only SMC immediate is encoded in the instruction; "
                         "Samsung UH application/command values are in guest registers.",
        "physicalDeviceUntouched":True,
        "guestSuccessfullyBooted":False,
        "kernelAccessOrKernelSuProven":False
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    base=Path.home()/"s20-artifacts/hxl1-research/qemu-first-failure-20261011"
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--fault-sites",type=Path,default=base/"original-fault-sites.json")
    p.add_argument("--output",type=Path,default=base/"secure-monitor-gate.json")
    a=p.parse_args()
    try:
        out=a.output.expanduser().absolute()
        if out.exists() or out.suffix!=".json" or out in (
                a.kernel.expanduser().absolute(), a.fault_sites.expanduser().absolute()):
            raise GateError("Choose a new JSON path; original reports are immutable")
        if not a.fault_sites.is_file() or a.fault_sites.is_symlink():
            raise GateError("Exact original fault-sites JSON missing or symlinked")
        image=trace.checked_image(a.kernel)
        report=json.loads(a.fault_sites.read_text())
        result=analyze(report,image)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
    except (ValueError,OSError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    for e in result["faults"]:
        d=e["decoded"]
        print("[STOCK]",e["elr"],e["factoryOpcode"],d["instruction"],
              "FAR",e["far"],"candidate base",e.get("candidateBaseRegisterValue","[N/A]"))
    print("[SMC X0-X6] NOT_CAPTURED")
    print("[FORK] pre_smc is relevant; UH command/argument semantics NOT VERIFIED")
    print("[REPORT]",out)
    print("[LIMIT] No original kernel boot, exploit, root or KernelSU proven")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
