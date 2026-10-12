#!/usr/bin/env python3
"""Validate the original compact-HXL1 live SMC #0 against exact OEM RKP ABI.

Offline source+GDB provenance: validates factory kernel, exact compact DTB and
full 35,168-byte guest FDT; rechecks saved compact SMC arguments against GDB;
pins HXL1 uh.h/rkp.h and recovered bitmap global. Does NOT emulate Samsung
UH or infer the SMC response, reserved RKP pool, memblock, root or unlock.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_compact_smc_registers as smc
from tools import y2q_hxl1_rkp_bitmap_abi_audit as abi
from tools import y2q_hxl1_memblock_trace_gate as gate

REGISTER_NAMES=tuple(f"X{x}" for x in range(7))
CAPTURE_DIR="qemu-compact-smc-registers-v1-20261012"

class BitmapEvidenceError(ValueError):
    pass

def evaluate(report:dict,log:str,uh:str,rkp:str,nm:Path,
             hashes:dict)->dict:
    reconstructed=smc.analyze_log(log)
    if (not reconstructed["smcCallArgumentsAccepted"] or
        report.get("status")!="STOCK_SMC_0_LIVE_ARGUMENTS_CAPTURED" or
        not report.get("smcCallArgumentsAccepted") or
        report.get("originalFactoryImageSha256")!=gate.KERNEL_SHA or
        report.get("sourceCompactOverrideSha256")!=smc.EXPECTED_INPUT_SHA or
        report.get("originalGuestFdtProofBytes")!=smc.EXPECTED_RUNTIME_BYTES or
        report.get("gdbExitCode")!=0 or
        report.get("registerArguments")!=reconstructed.get("registerArguments") or
        report.get("smcInstructionWord")!=hex(smc.OPCODE) or
        not report.get("factoryKernelEntryAttested")):
        raise BitmapEvidenceError("Compact SMC report does not independently match original GDB and FDT proof")
    source=abi.parse_source(uh,rkp)
    regs={x:int(reconstructed["registerArguments"][x],16) for x in REGISTER_NAMES}
    if (source["computedUhAppRkp"]!=hex(regs["X0"]) or
        source["rkpGetBufferBitmapCommand"]!=hex(regs["X1"]) or
        not source["rkpRobufferInitPassesBitmapAndMemstart"]):
        raise BitmapEvidenceError("Actual compact SMC X0/X1 source meaning differs from HXL1 rkp_robuffer_init")
    if (regs["X0"],regs["X1"],regs["X2"],regs["X3"],regs["X4"],regs["X5"])!=(
        0xc300c002,0x15,0xffffff800a4dd0b8,0x40000000,0,0):
        raise BitmapEvidenceError("Captured compact guest arguments differ from pinned owner bitmap call")
    ptr=abi.recovered_bitmap_symbol(nm,regs["X2"])
    if ptr.get("status")!="RECOVERED_SYMBOL_ADDRESS_CORRELATES":
        raise BitmapEvidenceError("X2 did not correlate with recovered OEM rkp_s_bitmap_buffer")
    return {
        "status":"COMPACT_GUEST_RKP_BITMAP_SOURCE_ABI_CORROBORATED",
        "target":"SM-G986U1/G986U1UESCHXL1",
        "factoryKernelSha256":gate.KERNEL_SHA,
        "compactInputSha256":smc.EXPECTED_INPUT_SHA,
        "originalGuestFdtBytes":smc.EXPECTED_RUNTIME_BYTES,
        "sourceSha256":hashes,
        "gdbLogSha256":hashlib.sha256(log.encode("utf8")).hexdigest(),
        "originalSmcPc":hex(smc.SMC),
        "originalSmcOpcode":hex(smc.OPCODE),
        "liveRegisterArguments":reconstructed["registerArguments"],
        "sourceAppId":source["computedUhAppRkp"],
        "sourceCommand":"RKP_GET_RKP_GET_BUFFER_BITMAP",
        "sourceCommandValue":source["rkpGetBufferBitmapCommand"],
        "x2RecoveredBitmapSlot":ptr,
        "x3SourceMeaning":"memstart_addr",
        "x6ObservedButNotSourceDefinedArgument":hex(regs["X6"]),
        "x6ExplicitSourceParameter":False,
        "sameRunSmcResponseObserved":False,
        "rkpBitmapPointerWrittenBySecureMonitor":False,
        "guestLinuxMemblockReservationVerified":False,
        "guestProtectedPoolReserved":False,
        "sourceFaithfulQemuSecureMonitorImplemented":False,
        "forkAbiCollision":"Fork's KDP_SET_NS_FLAGS at 0xc300c002/0x15 MUST NOT be reused for HXL1 RKP bitmap request",
        "hardwareBootloaderUnlocked":False,
        "kernelSuDeployed":False,
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--research-root",type=Path,default=root)
    p.add_argument("--source-root",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,default=root/CAPTURE_DIR/"bitmap-source-abi-compact.json")
    a=p.parse_args()
    try:
        out=a.output.expanduser().absolute()
        source_root=a.source_root.expanduser().absolute()
        if out.exists() or out.is_symlink() or out.suffix!=".json":
            raise BitmapEvidenceError("Output must be fresh .json (do not alter previous evidence)")
        smc.verify_preflight(a.research_root.expanduser().absolute(),
                             a.kernel.expanduser().absolute())
        folder=a.research_root.expanduser().absolute()/CAPTURE_DIR
        r=json.loads(gate.checked_file(folder/"smc-register-report.json",128*1024))
        log=gate.checked_file(folder/"gdb.log",1024*1024).decode("utf8","replace")
        uh_path=source_root/"include/linux/uh.h"
        rkp_path=source_root/"include/linux/rkp.h"
        uh,sha_uh=abi.secure_read(uh_path)
        rkp,sha_rkp=abi.secure_read(rkp_path)
        result=evaluate(r,log,uh,rkp,a.nm.expanduser().absolute(),
                        {"uh.h":sha_uh,"rkp.h":sha_rkp})
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
        print("[ORIGINAL COMPACT GUEST ABI]",result["status"])
        print("[HXL1 RKP COMMAND]",result["sourceCommand"],result["sourceCommandValue"])
        print("[X2 RECOVERED SLOT]",result["x2RecoveredBitmapSlot"]["status"])
        print("[OBSERVED X6]",result["x6ObservedButNotSourceDefinedArgument"],"(not proven as command argument)")
        print("[RKP BITMAP RESPONSE / POOL / MEMBLOCK] UNVERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
