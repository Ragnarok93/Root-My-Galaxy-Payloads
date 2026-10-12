#!/usr/bin/env python3
"""Same-run, read-only HXL1 register-producer to fault-load correlation.

Targets:
  x21 candidate stack restore LDP x22,x21,[sp,#64] @ ...82ac8f4
  x10 candidate pointer field LDR x10,[x24,#2840] @ ...86de394

Halt at factory kernel entry, verify original compact FDT, record exact HXL1
SMC RKP bitmap call, then stop on first candidate producer AND target load.
A skipped producer remains unobserved. Two breakpoints in same QEMU run do
not by themselves establish a complete data-flow or causality.

No original Image writes, UH response emulation, phone, root or unlock.
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
from tools import y2q_hxl1_qemu_compact_fault_regs as old

CANDIDATES={
    "x21":{
        "producer":0xffffff80082ac8f4,
        "producerOpcode":"a94457f6",
        "fault":0xffffff80082ac90c,
        "faultOpcode":"f9402eb8",
        "name":"LDP_X22_X21_SP_PLUS_64",
        "sourceValue":"stack slot SP+72, second element of paired restore",
    },
    "x10":{
        "producer":0xffffff80086de394,
        "producerOpcode":"f9458f0a",
        "fault":0xffffff80086de39c,
        "faultOpcode":"a9412149",
        "name":"LDR_X10_X24_PLUS_2840",
        "sourceValue":"memory at X24+0xB18",
    },
}
HEX=r"(0x[0-9a-f]+)"
ENTRY_RE=re.compile(r"(?m)^HXL1_ORIG_ENTRY PC="+HEX+" FDT="+HEX+r"$")
SMC_RE=re.compile(r"(?m)^HXL1_ORIG_SMC PC="+HEX+" X0="+HEX+" X1="+HEX+" X2="+HEX+" X3="+HEX+r"$")
PRODUCER_RE=re.compile(r"(?m)^HXL1_REG_PRODUCER PC="+HEX+" SOURCE_BASE="+HEX+
                       " BEFORE="+HEX+" SP="+HEX+r"$")
FAULT_RE=re.compile(r"(?m)^HXL1_REG_FAULT PC="+HEX+" BASE="+HEX+" SP="+HEX+
                    " LR="+HEX+r"$")
WORD_RE=re.compile(r"(?im)^0x([0-9a-f]+):\s+0x([0-9a-f]{8})$")
BAD_RE=re.compile(r"(?m)^HXL1_(?:ENTRY_INVALID|SMC_MISSING|STOP_UNEXPECTED)")
EXPECTED_SMC=(0xc300c002,0x15,0xffffff800a4dd0b8,0x40000000)

class ProvenanceError(ValueError):
    pass

def original_word(image:bytes,addr:int)->str:
    off=addr-gate.VM_BASE
    if off<0 or off%4 or off+4>len(image):
        raise ProvenanceError("Source instruction outside factory Image")
    return f"{int.from_bytes(image[off:off+4],'little'):08x}"

def verify_stock_words(image:bytes,target:str)->dict:
    gate.valid_source(image)
    c=CANDIDATES[target]
    p=original_word(image,c["producer"])
    f=original_word(image,c["fault"])
    if p!=c["producerOpcode"] or f!=c["faultOpcode"]:
        raise ProvenanceError("Recovered original producer/fault words differ from exact factory Image")
    return {"producerPc":hex(c["producer"]),"producerOpcode":p,
            "faultPc":hex(c["fault"]),"faultOpcode":f,
            "originalFactoryImageSha256":gate.KERNEL_SHA}

def script(port:int,target:str)->str:
    c=CANDIDATES[target]
    if target=="x21":
        base="$sp"
        prior="$x21"
        value="($sp+72)"
        # The stack slot content is sampled with an optional read-only x.
        # If the monitor cannot read it, GDB records an error and reports
        # evidence as inconclusive rather than overwriting the guest.
        after="""    printf "HXL1_PRODUCER_SOURCE_ADDRESS 0x%lx\\n", $sp+72
    x/1gx $sp+72
"""
        fault_reg="$x21"
    else:
        base="$x24"
        prior="$x10"
        value="($x24+2840)"
        after="""    printf "HXL1_PRODUCER_SOURCE_ADDRESS 0x%lx\\n", $x24+2840
    x/1gx $x24+2840
"""
        fault_reg="$x10"
    return f"""set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:{port}
hbreak *0x40080000
continue
if $pc == 0x40080000 && $x0 == 0x48000000 && $x1 == 0 && $x2 == 0 && $x3 == 0
  printf "HXL1_ORIG_ENTRY PC=0x%lx FDT=0x%lx\\n", $pc,$x0
  thbreak *0xffffff80080a5794
  continue
  if $pc == 0xffffff80080a5794
    printf "HXL1_ORIG_SMC PC=0x%lx X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", $pc,$x0,$x1,$x2,$x3
    x/1wx $pc
    thbreak *{hex(c["producer"])}
    thbreak *{hex(c["fault"])}
    continue
    if $pc == {hex(c["producer"])}
      printf "HXL1_REG_PRODUCER PC=0x%lx SOURCE_BASE=0x%lx BEFORE=0x%lx SP=0x%lx\\n", $pc,{base},{prior},$sp
      x/1wx $pc
{after}      continue
    end
    if $pc == {hex(c["fault"])}
      printf "HXL1_REG_FAULT PC=0x%lx BASE=0x%lx SP=0x%lx LR=0x%lx\\n", $pc,{fault_reg},$sp,$x30
      x/1wx $pc
    else
      printf "HXL1_STOP_UNEXPECTED PC=0x%lx\\n", $pc
    end
  else
    printf "HXL1_SMC_MISSING PC=0x%lx\\n", $pc
  end
else
  printf "HXL1_ENTRY_INVALID PC=0x%lx X0=0x%lx\\n", $pc,$x0
end
detach
quit
"""

def analyze(log:str,target:str)->dict:
    c=CANDIDATES[target]
    report={
        "targetRegister":target.upper(),
        "producerPc":hex(c["producer"]),"expectedProducerOpcode":c["producerOpcode"],
        "faultPc":hex(c["fault"]),"expectedFaultOpcode":c["faultOpcode"],
        "candidateRegisterSource":c["name"],
        "candidateAddressMeaning":c["sourceValue"],
        "producerObservedInThisRun":False,
        "faultObservedInThisRun":False,
        "completeRegisterDataFlowProven":False,
        "uhSecureMonitorResponseValidated":False,
        "allocatorCachePointerIdentified":False,
        "panicChronologyProven":False,
        "physicalDeviceTouched":False,
    }
    entry=ENTRY_RE.findall(log)
    if len(entry)!=1 or tuple(int(s,16) for s in entry[0])!=(0x40080000,0x48000000) or BAD_RE.search(log):
        report["status"]="ORIGINAL_KERNEL_ENTRY_NOT_VALIDATED"
        return report
    smc=SMC_RE.findall(log)
    if len(smc)!=1 or tuple(int(s,16) for s in smc[0])!=(
            0xffffff80080a5794,*EXPECTED_SMC):
        report["status"]="ORIGINAL_RKP_SMC_NOT_VALIDATED"
        return report
    words={(int(a,16),word) for a,word in WORD_RE.findall(log)}
    if (0xffffff80080a5794,"d4000003") not in words:
        report["status"]="RUNTIME_SMC_OPCODE_NOT_VERIFIED"
        return report
    producers=PRODUCER_RE.findall(log)
    faults=FAULT_RE.findall(log)
    if len(producers)>1 or len(faults)>1:
        report["status"]="AMBIGUOUS_DUPLICATE_GDB_STOPS"
        return report
    if producers:
        p=[int(x,16) for x in producers[0]]
        if p[0]!=c["producer"] or (c["producer"],c["producerOpcode"]) not in words:
            report["status"]="RUNTIME_PRODUCER_OPCODE_MISMATCH"
            return report
        report.update(
            producerObservedInThisRun=True,
            producerSourceRegisterValueBefore=hex(p[1]),
            producerTargetRegisterValueBefore=hex(p[2]),
            producerStackPointer=hex(p[3]),
            producerSourceEffectiveAddress=hex(p[1]+(72 if target=="x21" else 2840)),
        )
    if faults:
        f=[int(x,16) for x in faults[0]]
        if f[0]!=c["fault"] or (c["fault"],c["faultOpcode"]) not in words:
            report["status"]="RUNTIME_FAULT_OPCODE_MISMATCH"
            return report
        report.update(
            faultObservedInThisRun=True,
            faultBaseValueBefore=hex(f[1]),
            faultBaseZeroAtInstruction=f[1]==0,
            faultStackPointer=hex(f[2]),
            faultLinkRegister=hex(f[3]),
        )
    if report["producerObservedInThisRun"] and report["faultObservedInThisRun"]:
        if log.index("HXL1_REG_PRODUCER")>=log.index("HXL1_REG_FAULT"):
            report["status"]="STOP_ORDER_INCONSISTENT"
            report["faultObservedInThisRun"]=False
        else:
            report["status"]="PRODUCER_THEN_FAULT_OBSERVED_NO_FULL_DEF_USE_PROOF"
            report["completeRegisterDataFlowProven"]=False
    elif report["faultObservedInThisRun"]:
        report["status"]="FAULT_CAPTURED_PRODUCER_NOT_OBSERVED"
    elif report["producerObservedInThisRun"]:
        report["status"]="PRODUCER_CAPTURED_FAULT_NOT_OBSERVED"
    else:
        report["status"]="NO_PRODUCER_OR_FAULT_BREAKPOINT_IN_BOUNDED_RUN"
    return report

def execute(kernel:Path,dtb:Path,record:dict,target:str,out:Path,
            port:int,seconds:int)->dict:
    if not 5<=seconds<=45:
        raise ProvenanceError("GDB runtime must be 5..45 seconds")
    for program in ("qemu-system-aarch64","gdb-multiarch"):
        if not shutil.which(program):
            raise ProvenanceError("Missing host emulator/debugger: "+program)
    gate.check_port(port)
    out.mkdir(parents=True,exist_ok=False)
    gdb=out/"register-provenance.gdb"
    gdb.write_text(script(port,target))
    cmd=[
        "qemu-system-aarch64","-machine","virt,gic-version=3",
        "-cpu","cortex-a57","-smp","1","-m","2048",
        "-kernel",str(kernel),"-dtb",str(dtb),
        "-append","earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr",
        "-display","none","-serial",f"file:{out/'serial.log'}",
        "-monitor","none","-no-reboot","-nic","none",
        "-d","int,guest_errors","-D",str(out/"qemu-exceptions.log"),
        "-S","-gdb",f"tcp:127.0.0.1:{port}"]
    (out/"qemu-argv.json").write_text(json.dumps(cmd,indent=2)+"\n")
    (out/"compact-source-manifest.json").write_text(json.dumps(record,indent=2)+"\n")
    with (out/"qemu.log").open("wb") as output:
        proc=subprocess.Popen(cmd,stdout=output,stderr=subprocess.STDOUT)
        try:
            time.sleep(1.25)
            if proc.poll() is not None:
                raise ProvenanceError("QEMU terminated before GDB attached")
            try:
                r=subprocess.run(["gdb-multiarch","-q","-nx","-batch","-x",str(gdb)],
                                 capture_output=True,text=True,timeout=seconds)
                log=r.stdout+"\n"+r.stderr
                code=r.returncode
            except subprocess.TimeoutExpired as e:
                a=e.stdout.decode("utf8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
                b=e.stderr.decode("utf8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
                log=a+"\n"+b+"\nGDB_BOUNDED_TIMEOUT\n"
                code=124
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    (out/"gdb.log").write_text(log[-1024*1024:])
    report=analyze(log,target)
    report.update(
        targetDevice="SM-G986U1/G986U1UESCHXL1",
        stockKernelSha256=gate.KERNEL_SHA,
        compactDtbSha256=record["overrideSha256"],
        earlierVerifiedRuntimeFdtBytes=smc.EXPECTED_RUNTIME_BYTES,
        gdbExitCode=code,
    )
    (out/"register-provenance-report.json").write_text(json.dumps(report,indent=2)+"\n")
    return report

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    ap.add_argument("--research-root",type=Path,default=root)
    ap.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    ap.add_argument("--target",choices=sorted(CANDIDATES),required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--seconds",type=int,default=35)
    ap.add_argument("--port",type=int,default=12357)
    ap.add_argument("--preflight-only",action="store_true")
    args=ap.parse_args()
    try:
        root=args.research_root.expanduser().absolute()
        kernel=args.kernel.expanduser().absolute()
        dtb,record=smc.verify_preflight(root,kernel)
        image=gate.checked_file(kernel)
        original=verify_stock_words(image,args.target)
        out=gate.safe_output(args.output,root)
        print("[ORIGINAL IMAGE]",original["originalFactoryImageSha256"])
        print("[REGISTER PRODUCER]",original["producerPc"],original["producerOpcode"])
        print("[FAULT LOAD]",original["faultPc"],original["faultOpcode"])
        print("[COMPACT DTB]",record["overrideSha256"])
        if args.preflight_only:
            print("[READY] No emulator started")
            return 0
        result=execute(kernel,dtb,record,args.target,out,args.port,args.seconds)
        print("[PROVENANCE STATUS]",result["status"])
        print("[PRODUCER HIT]",result["producerObservedInThisRun"])
        print("[FAULT HIT]",result["faultObservedInThisRun"])
        if "producerSourceEffectiveAddress" in result:
            print("[PRODUCER EFFECTIVE ADDRESS]",result["producerSourceEffectiveAddress"])
        if "faultBaseValueBefore" in result:
            print("[FAULT BASE]",result["faultBaseValueBefore"])
        print("[FULL DATA FLOW PROVEN] NO")
        print("[REPORT]",out/"register-provenance-report.json")
        return 0 if result["faultObservedInThisRun"] and result["gdbExitCode"]==0 else 3
    except (ProvenanceError,gate.GateError,OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
