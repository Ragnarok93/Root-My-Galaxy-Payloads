#!/usr/bin/env python3
"""Provenance-bound stock-HXL1 QEMU X21/X10 read-before-fault audit.

Read-only offline verifier for the *owner's* compact-DTB GDB capture.
The instruction/actual base register are from the same GDB guest run;
the matching FAR/ESR data abort is separately observed in an earlier
compact-DTB QEMU run. Treat that cross-run agreement as corroboration,
never as the same-run abort or proof that an RKP SMC caused the fault.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_fault_sites as sites
from tools import y2q_hxl1_qemu_compact_fault_regs as regs
from tools import y2q_hxl1_qemu_compact_smc_registers as smc
from tools import y2q_hxl1_compact_fault_dependencies as prior

DIRS={
    "x21":"qemu-compact-fault-x21-v1-20261012",
    "x10":"qemu-compact-fault-x10-v1-20261012",
}
MAX_JSON=128*1024

class AttributionError(ValueError):
    pass

def correlate(saved:dict,log:str,image:bytes,dep:dict,symbols:dict,target:str)->dict:
    gate.valid_source(image)
    live=regs.analyze_log(log,target)
    if live.get("status")!="LIVE_ORIGINAL_FAULT_BASE_REGISTER_CAPTURED":
        raise AttributionError("Actual GDB log does not establish a live factory fault-load base")
    if (saved.get("originalImageSha256")!=gate.KERNEL_SHA or
        saved.get("compactSourceSha256")!=smc.EXPECTED_INPUT_SHA or
        saved.get("earlierVerifiedGuestFdtSizeBytes")!=smc.EXPECTED_RUNTIME_BYTES or
        saved.get("gdbExitCode")!=0 or
        saved.get("targetDevice")!="SM-G986U1/G986U1UESCHXL1"):
        raise AttributionError("GDB report is not from the pinned original compact guest")
    for key,val in live.items():
        if saved.get(key)!=val:
            raise AttributionError("Saved live report differs from original GDB for "+key)
    pc,op,offset=regs.TARGETS[target]
    window=sites.window(image,pc,gate.VM_BASE)
    if (window.get("status")!="ORIGINAL_STOCK_IMAGE_BYTES_FOUND" or
        window.get("originalOpcode")!=op):
        raise AttributionError("Original OEM Image opcode missing from live fault address")
    if (dep.get("status")!="FACTORY_INSTRUCTION_DEPENDENCIES_OFFLINE_VERIFIED" or
        dep.get("originalFactoryImageSha256")!=gate.KERNEL_SHA or
        dep.get("sourceCompactRuntimeFdtBytes")!=smc.EXPECTED_RUNTIME_BYTES or
        dep.get("sourceCompactOverrideSha256")!=smc.EXPECTED_INPUT_SHA or
        dep.get("allThreeEventsCorrelatedToRawExceptionLog") is not True):
        raise AttributionError("Prior QEMU exception log/source evidence does not match")
    events=dep.get("events",[])
    matching=[e for e in events if e.get("elr")==hex(pc)]
    if len(matching)!=1:
        raise AttributionError("Prior original guest exception at exact target ELR missing/ambiguous")
    e=matching[0]
    if (e.get("originalOpcode")!=op or e.get("baseRegister")!=target or
        int(e.get("far","-1"),16)!=offset):
        raise AttributionError("Prior source opcode/FAR/base does not corroborate new live capture")
    addr=live["effectiveAddressesIfExecuted"]
    crosses=(hex(offset) in addr)
    sym=sites.nearest_symbol(symbols,pc)
    lr=int(live["preFaultLinkRegister"],16)
    lr_sym=sites.nearest_symbol(symbols,lr)
    return {
        "status":"ORIGINAL_COMPACT_FAULT_BASE_AT_SOURCE_INSTRUCTION_VERIFIED",
        "target":"SM-G986U1/G986U1UESCHXL1",
        "baseRegister":target.upper(),
        "liveBaseRegisterValue":live["preFaultBaseRegisterValue"],
        "nullBaseConfirmedAtPreLoadBreakpoint":live["preFaultBaseIsZero"],
        "originalInstruction":live["instructionSource"],
        "originalInstructionAddress":hex(pc),
        "liveOpcodeCorrelatedToFactory":True,
        "originalImageSha256":gate.KERNEL_SHA,
        "factoryOpcode":op,
        "factoryImageOffset":window["candidateImageOffset"],
        "originalImageLocalWindow":window,
        "originalImageDisassembly":sites.disassemble(
            window,gate.VM_BASE,shutil.which("aarch64-linux-gnu-objdump")),
        "nearestRecoveredInstructionSymbol":sym,
        "liveLinkRegister":live["preFaultLinkRegister"],
        "nearestRecoveredLinkRegisterSymbol":lr_sym,
        "liveStackPointer":live["preFaultStackPointer"],
        "liveExpectedEffectiveAddresses":addr,
        "separatePriorGuestDataAbortFar":e["far"],
        "separatePriorGuestEsr":e["esr"],
        "priorGuestFarMatchesOneCandidateAccess":crosses,
        "sameRunSmcPreCallObserved":live["smcPreCallObserved"],
        "sameRunSmcPostInstructionPcObserved":live["smcNextPcObserved"],
        "sameRunSmcNextPcX0":live.get("smcNextPcX0"),
        "sameRunSmcReturnValueSemanticsKnown":False,
        "sameRunAbortAfterBreakpointCaptured":False,
        "smcCausedNullBaseOrAbortProven":False,
        "realUhRkpServiceSupported":False,
        "linuxMemblockAllocatorExcluded":False,
        "physicalDeviceModified":False,
        "caveat":"The live pre-load base and stock opcode are directly observed together; "
                 "prior FAR/ESR comes from a different compact-FDT guest run. "
                 "Recovered symbols are reconstructed candidates. Lack of a "
                 "SMC+4 breakpoint does not demonstrate absence of an SMC return.",
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--research-root",type=Path,default=root)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--target",choices=sorted(DIRS),default="x21")
    p.add_argument("--capture-dir",type=Path,default=None)
    p.add_argument("--prior-faults",type=Path,
                   default=root/"qemu-pc-compact-fdt-20261012/compact-fault-dependencies-v2.json")
    p.add_argument("--output",type=Path,default=None)
    a=p.parse_args()
    try:
        root=a.research_root.expanduser().absolute()
        folder=a.capture_dir.expanduser().absolute() if a.capture_dir else root/DIRS[a.target]
        output=a.output.expanduser().absolute() if a.output else folder/"live-fault-attribution.json"
        if (output.suffix!=".json" or output.exists() or output.is_symlink() or
            output in {folder/"fault-register-report.json",folder/"gdb.log"}):
            raise AttributionError("Use a new JSON destination; preserve original run evidence")
        smc.verify_preflight(root,a.kernel.expanduser().absolute())
        image=gate.checked_file(a.kernel)
        data=json.loads(gate.checked_file(folder/"fault-register-report.json",MAX_JSON))
        log=gate.checked_file(folder/"gdb.log",1024*1024).decode("utf8","replace")
        dep=json.loads(gate.checked_file(a.prior_faults,MAX_JSON))
        symbols=sites.load_recovered_symbols(a.nm.expanduser().absolute())
        if symbols["status"]!="RECOVERED_NM_SYMBOLS_UNVERIFIED":
            raise AttributionError("Recovered stock symbol map unavailable")
        outcome=correlate(data,log,image,dep,symbols,a.target)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(outcome,indent=2)+"\n")
        print("[LIVE FAULT BASE]",outcome["baseRegister"],outcome["liveBaseRegisterValue"])
        print("[STOCK INSTRUCTION]",outcome["originalInstructionAddress"],outcome["factoryOpcode"])
        print("[RECOVERED FUNCTION]",outcome["nearestRecoveredInstructionSymbol"].get("name","[unresolved]"))
        print("[LINK REGISTER]",outcome["liveLinkRegister"],"nearest",outcome["nearestRecoveredLinkRegisterSymbol"].get("name","[unresolved]"))
        print("[SEPARATE QEMU FAR]",outcome["separatePriorGuestDataAbortFar"],
              "matches candidate address",outcome["priorGuestFarMatchesOneCandidateAccess"])
        print("[SMC+4 CAPTURED]",outcome["sameRunSmcPostInstructionPcObserved"])
        print("[SMC CAUSED FAULT / RKP POOL VERIFIED] NO")
        print("[REPORT]",output)
        return 0
    except (AttributionError,gate.GateError,OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
