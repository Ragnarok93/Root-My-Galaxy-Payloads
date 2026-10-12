#!/usr/bin/env python3
"""Observe original HXL1 QEMU fault-load base register after SMC #0 (no writes).

Separate bounded, ephemeral original-image guest runs for X21 or X10. Stop
at original ARM64 entry, then SMC #0 and the exact source faulting load.
Never fabricate UH responses or patch instructions. SMC+4 breakpoint can
observe a resumed X0 but is NOT evidence of successful UH service.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_compact_smc_registers as smc
from tools import y2q_hxl1_qemu_secure_monitor_gate as secure
from tools import y2q_hxl1_qemu_fault_sites as sites

TARGETS={
    "x21":(0xffffff80082ac90c,"f9402eb8",0x58),
    "x10":(0xffffff80086de39c,"a9412149",0x10),
}
HEX=r"(0x[0-9a-f]+)"
ENTRY_RE=re.compile(r"(?m)^HXL1_ENTRY_VALID PC="+HEX+" X0="+HEX+r"$")
SMC_RE=re.compile(r"(?m)^HXL1_SMC_PRE PC="+HEX+" X0="+HEX+" X1="+HEX+" X2="+HEX+" X3="+HEX+r"$")
RETURN_RE=re.compile(r"(?m)^HXL1_SMC_NEXT_PC PC="+HEX+" X0="+HEX+r"$")
FAULT_RE=re.compile(r"(?m)^HXL1_FAULT_PRE PC="+HEX+" BASE="+HEX+" SP="+HEX+" LR="+HEX+r"$")
WORD_RE=re.compile(r"(?im)^0x([0-9a-f]+):\s+0x([0-9a-f]{8})$")
FAIL_RE=re.compile(r"(?m)^HXL1_(?:ENTRY_BAD|STAGE_UNEXPECTED)")

class FaultRegisterError(ValueError):
    pass

def script(port:int,target:str)->str:
    address,opcode,offset=TARGETS[target]
    base=f"$x{target[1:]}"
    return f"""set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:{port}
hbreak *0x40080000
continue
if $pc == 0x40080000 && $x0 == 0x48000000 && $x1 == 0 && $x2 == 0 && $x3 == 0
  printf "HXL1_ENTRY_VALID PC=0x%lx X0=0x%lx\\n", $pc,$x0
  hbreak *{hex(smc.SMC)}
  hbreak *{hex(smc.SMC+4)}
  hbreak *{hex(address)}
  continue
  if $pc == {hex(smc.SMC)}
    printf "HXL1_SMC_PRE PC=0x%lx X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", $pc,$x0,$x1,$x2,$x3
    x/1wx $pc
    continue
  end
  if $pc == {hex(smc.SMC+4)}
    printf "HXL1_SMC_NEXT_PC PC=0x%lx X0=0x%lx\\n", $pc,$x0
    continue
  end
  if $pc == {hex(address)}
    printf "HXL1_FAULT_PRE PC=0x%lx BASE=0x%lx SP=0x%lx LR=0x%lx\\n", $pc,{base},$sp,$x30
    x/1wx $pc
  else
    printf "HXL1_STAGE_UNEXPECTED PC=0x%lx\\n", $pc
  end
else
  printf "HXL1_ENTRY_BAD PC=0x%lx X0=0x%lx\\n", $pc,$x0
end
detach
quit
"""

def analyze_log(log:str,target:str)->dict:
    addr,op,offset=TARGETS[target]
    answer={
        "targetRegister":target.upper(),
        "originalFaultInstructionAddress":hex(addr),
        "factoryOpcodeExpected":op,
        "factoryKernelModified":False,
        "physicalDeviceTouched":False,
        "smcServiceHandledSuccessfully":False,
        "linuxMemblockReserved":False,
        "protectedRkpPoolEstablished":False,
        "actualHardwareRootOrUnlock":False,
        "smcReturnStatusInterpretation":"NOT_ESTABLISHED",
        "actualFaultInstructionReached":False,
        "smcPreCallObserved":False,
        "smcNextPcObserved":False,
    }
    entries=ENTRY_RE.findall(log)
    if len(entries)!=1 or [int(n,16) for n in entries[0]]!=[0x40080000,0x48000000] or FAIL_RE.search(log):
        answer["status"]="ORIGINAL_ENTRY_INCONCLUSIVE"
        return answer
    smcs=SMC_RE.findall(log)
    if len(smcs)!=1:
        answer["status"]="SMC_NOT_RECORDED_IN_SAME_RUN"
        return answer
    spc,sx0,sx1,sx2,sx3=[int(n,16) for n in smcs[0]]
    words=WORD_RE.findall(log)
    if (spc!=smc.SMC or (sx0,sx1,sx2,sx3)!=
        (0xc300c002,0x15,0xffffff800a4dd0b8,0x40000000) or
        sum(int(a,16)==smc.SMC and w=="d4000003" for a,w in words)!=1):
        answer["status"]="SMC_LIVE_PRE_OPCODE_OR_ARGUMENT_MISMATCH"
        return answer
    answer["smcPreCallObserved"]=True
    answer["smcArguments"]={"X0":hex(sx0),"X1":hex(sx1),"X2":hex(sx2),"X3":hex(sx3)}
    rets=RETURN_RE.findall(log)
    if len(rets)>1:
        answer["status"]="MULTIPLE_SMC_RETURN_PC_SAMPLES"
        return answer
    if rets:
        r_pc,r_x0=[int(n,16) for n in rets[0]]
        if r_pc!=smc.SMC+4:
            answer["status"]="RETURN_BREAKPOINT_IDENTITY_MISMATCH"
            return answer
        answer["smcNextPcObserved"]=True
        answer["smcNextPcX0"]=hex(r_x0)
        answer["smcReturnStatusInterpretation"]="RAW_REGISTER_OBSERVATION_ONLY"
    faults=FAULT_RE.findall(log)
    if len(faults)!=1:
        answer["status"]="NO_FAULT_LOAD_BREAKPOINT_AFTER_SMC"
        return answer
    pc,base,sp,lr=[int(v,16) for v in faults[0]]
    if pc!=addr or sum(int(a,16)==pc and w==op for a,w in words)!=1:
        answer["status"]="FAULT_PC_OR_LIVE_OPCODE_MISMATCH"
        return answer
    offsets=[offset] if target=="x21" else [offset,offset+8]
    answer.update(
        status="LIVE_ORIGINAL_FAULT_BASE_REGISTER_CAPTURED",
        actualFaultInstructionReached=True,
        preFaultBaseRegisterValue=hex(base),
        preFaultBaseIsZero=base==0,
        effectiveAddressesIfExecuted=[hex((base+n)&((1<<64)-1)) for n in offsets],
        possibleAccessOffsetsBytes=offsets,
        instructionSource=secure.decode(int(op,16)),
        preFaultStackPointer=hex(sp),
        preFaultLinkRegister=hex(lr),
        subsequentDataAbortObservedInThisDebuggerRun=False,
        dataAbortCausallyCausedBySmcProven=False,
    )
    return answer

def capture(root:Path,kernel:Path,dtb:Path,record:dict,
            out:Path,target:str,port:int,seconds:int)->dict:
    if not 5<=seconds<=45:
        raise FaultRegisterError("Bounded GDB runtime must be 5..45 seconds")
    for name in ("qemu-system-aarch64","gdb-multiarch"):
        if not shutil.which(name):
            raise FaultRegisterError("Missing host tool "+name)
    gate.check_port(port)
    out.mkdir(parents=True,exist_ok=False)
    gdb_path=out/"fault-registers.gdb"
    gdb_path.write_text(script(port,target))
    qemu_cmd=[
        "qemu-system-aarch64","-machine","virt,gic-version=3",
        "-cpu","cortex-a57","-smp","1","-m","2048",
        "-kernel",str(kernel),"-dtb",str(dtb),
        "-append","earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr",
        "-display","none","-serial",f"file:{out/'serial.log'}",
        "-monitor","none","-no-reboot","-nic","none",
        "-d","int,guest_errors","-D",str(out/"qemu-exceptions.log"),
        "-S","-gdb",f"tcp:127.0.0.1:{port}"]
    (out/"qemu-command.json").write_text(json.dumps(qemu_cmd,indent=2)+"\n")
    (out/"input-source-audit.json").write_text(json.dumps(record,indent=2)+"\n")
    with (out/"qemu.log").open("wb") as log:
        proc=subprocess.Popen(qemu_cmd,stdout=log,stderr=subprocess.STDOUT)
        try:
            time.sleep(1.25)
            if proc.poll() is not None:
                raise FaultRegisterError("Original image QEMU terminated before debugger attached")
            try:
                r=subprocess.run(
                    ["gdb-multiarch","-q","-nx","-batch","-x",str(gdb_path)],
                    capture_output=True,text=True,timeout=seconds)
                text=r.stdout+"\n"+r.stderr
                status=r.returncode
            except subprocess.TimeoutExpired as ex:
                stdout=ex.stdout.decode("utf8","replace") if isinstance(ex.stdout,bytes) else (ex.stdout or "")
                stderr=ex.stderr.decode("utf8","replace") if isinstance(ex.stderr,bytes) else (ex.stderr or "")
                text=stdout+"\n"+stderr+"\nGDB_BOUNDED_TIMEOUT\n"
                status=124
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    (out/"gdb.log").write_text(text[-1024*1024:])
    result=analyze_log(text,target)
    result.update(
        targetDevice="SM-G986U1/G986U1UESCHXL1",
        originalImageSha256=gate.KERNEL_SHA,
        compactSourceSha256=record["overrideSha256"],
        earlierVerifiedGuestFdtSizeBytes=smc.EXPECTED_RUNTIME_BYTES,
        gdbExitCode=status,
    )
    (out/"fault-register-report.json").write_text(json.dumps(result,indent=2)+"\n")
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--research-root",type=Path,default=root)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--target",choices=sorted(TARGETS),required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--port",type=int,default=12353)
    p.add_argument("--seconds",type=int,default=35)
    p.add_argument("--preflight-only",action="store_true")
    a=p.parse_args()
    try:
        base=a.research_root.expanduser().absolute()
        kernel=a.kernel.expanduser().absolute()
        dtb,record=smc.verify_preflight(base,kernel)
        out=gate.safe_output(a.output,base)
        print("[STOCK IMAGE]",gate.KERNEL_SHA)
        print("[COMPACT FDT SOURCE]",record["overrideSha256"])
        print("[FAULT TARGET]",a.target,TARGETS[a.target][0])
        if a.preflight_only:
            print("[READY] Original source and guest evidence verified; QEMU not started")
            return 0
        result=capture(base,kernel,dtb,record,out,a.target,a.port,a.seconds)
        print("[FAULT REGISTER PROBE]",result["status"])
        if result["actualFaultInstructionReached"]:
            print("[BASE REGISTER]",result["targetRegister"],result["preFaultBaseRegisterValue"])
            print("[SMC NEXT PC OBSERVED]",result["smcNextPcObserved"])
        print("[SMC RETURN FUNCTIONALITY] NOT VERIFIED")
        print("[REPORT]",out/"fault-register-report.json")
        return 0 if result["actualFaultInstructionReached"] and result["gdbExitCode"]==0 else 3
    except (FaultRegisterError,gate.GateError,OSError,ValueError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
