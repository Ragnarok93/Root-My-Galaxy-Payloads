#!/usr/bin/env python3
"""Read-only original HXL1 compact-QEMU SMC #0 X0-X6 breakpoint capture.

Rebuild/verify factory Image, exact source DTB and measured 35,168-byte FDT
before running the isolated QEMU guest. GDB first verifies original ARM64
entry PC/X0..X3, THEN records X0-X6 before SMC #0 instruction executes.
The stock Image is never modified, secure monitor is not emulated, no
physical device or kernel root operations occur. No UH ABI inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_compact_fdt_capture as compact
from tools import y2q_hxl1_qemu_secure_monitor_gate as secure

SMC=0xffffff80080a5794
ENTRY=0x40080000
FDT=0x48000000
OPCODE=0xd4000003
HEX=r"(0x[0-9a-f]+)"
ENTRY_RE=re.compile(r"(?m)^HXL1_COMPACT_ENTRY_OK PC="+HEX+" X0="+HEX+" X1="+HEX+" X2="+HEX+" X3="+HEX+r"$")
SMC_RE=re.compile(r"(?m)^HXL1_COMPACT_SMC_STOP PC="+HEX+" X0="+HEX+" X1="+HEX+" X2="+HEX+" X3="+HEX+" X4="+HEX+" X5="+HEX+" X6="+HEX+r"$")
OPCODE_RE=re.compile(r"(?im)^0xffffff80080a5794:\s+0x([0-9a-f]{8})$")
MISMATCH_RE=re.compile(r"(?m)^HXL1_COMPACT_(?:ENTRY|SMC)_MISMATCH")
EXPECTED_INPUT_SHA="1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd"
EXPECTED_RUNTIME_BYTES=35168

class SmcCaptureError(ValueError):
    pass

def verify_preflight(root:Path,kernel:Path)->tuple[Path,dict]:
    source,record=compact.verify_input(root,kernel)
    if record["overrideSha256"]!=EXPECTED_INPUT_SHA:
        raise SmcCaptureError("Source compact-DTB SHA differs from owner's proven source")
    cap=root/"qemu-compact-entry-fdt-20261012"
    raw=gate.checked_file(cap/"guest-compact-fdt.dtb",8*1024*1024)
    old=gate.checked_file(cap/"gdb-session.log",128*1024).decode("utf8","replace")
    report=compact.verify_capture(raw,old)
    saved=json.loads(gate.checked_file(cap/"compact-fdt-audit.json",128*1024))
    if (report["guestFdtTotalBytes"]!=EXPECTED_RUNTIME_BYTES or
        not report["guestFdtWithin2MiB"] or
        saved.get("runtimeFdtSha256")!=report["runtimeFdtSha256"] or
        saved.get("compactOverrideSha256")!=record["overrideSha256"]):
        raise SmcCaptureError("Owner's guest FDT evidence is not exact, attested 35,168-byte compact case")
    return source,record

def script(port:int)->str:
    return f"""set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:{port}
hbreak *0x40080000
continue
if $pc == 0x40080000 && $x0 == 0x48000000 && $x1 == 0 && $x2 == 0 && $x3 == 0
  printf "HXL1_COMPACT_ENTRY_OK PC=0x%lx X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", $pc,$x0,$x1,$x2,$x3
  hbreak *{hex(SMC)}
  continue
  if $pc == {hex(SMC)}
    printf "HXL1_COMPACT_SMC_STOP PC=0x%lx X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx X4=0x%lx X5=0x%lx X6=0x%lx\\n", $pc,$x0,$x1,$x2,$x3,$x4,$x5,$x6
    x/1wx $pc
  else
    printf "HXL1_COMPACT_SMC_MISMATCH PC=0x%lx\\n", $pc
  end
else
  printf "HXL1_COMPACT_ENTRY_MISMATCH PC=0x%lx X0=0x%lx\\n", $pc,$x0
end
detach
quit
"""

def analyze_log(log:str)->dict:
    entries=ENTRY_RE.findall(log)
    smcs=SMC_RE.findall(log)
    words=OPCODE_RE.findall(log)
    outcome={"factoryImageUnmodified":True,"physicalDeviceTouched":False,
             "vendorSmcServiceResultObserved":False,
             "guestSmcServiceImplementedOrSupported":False,
             "rkpSecureMemoryReserved":False,
             "linuxMemblockAllocatorVerified":False,
             "smcCallArgumentsAccepted":False}
    if len(entries)!=1:
        outcome["status"]="ORIGINAL_KERNEL_ENTRY_NOT_INDEPENDENTLY_ATTESTED"
        return outcome
    ep=[int(x,16) for x in entries[0]]
    if ep!=[ENTRY,FDT,0,0,0] or MISMATCH_RE.search(log):
        outcome["status"]="ORIGINAL_KERNEL_ENTRY_OR_STOP_MISMATCH"
        return outcome
    outcome["entryPc"]=hex(ENTRY)
    outcome["entryFdtPhysicalPointer"]=hex(FDT)
    outcome["factoryKernelEntryAttested"]=True
    if len(smcs)!=1:
        outcome["status"]="POST_ENTRY_SMC_NOT_REACHED_IN_BOUNDED_CAPTURE"
        return outcome
    args=[int(x,16) for x in smcs[0]]
    if args[0]!=SMC:
        outcome["status"]="SUSPICIOUS_SMC_PC"
        return outcome
    if len(words)!=1 or int(words[0],16)!=OPCODE:
        outcome["status"]="LIVE_SMC_OPCODE_NOT_CORRELATED_TO_STOCK_IMAGE"
        return outcome
    outcome.update(
        status="STOCK_SMC_0_LIVE_ARGUMENTS_CAPTURED",
        smcPc=hex(SMC),
        smcInstructionWord=hex(OPCODE),
        registerArguments={f"X{i}":hex(value) for i,value in enumerate(args[1:])},
        smcCallArgumentsAccepted=True,
        smcImmediateZero=True,
        smcCallIdSource="ACTUAL_COMPACT_QEMU_GDB_BEFORE_SMC",
        sameRunSmcReturnObserved=False,
        note="No matching service implementation, return value, Linux boot, or RKP protection inferred.",
    )
    return outcome

def execute(kernel:Path,dtb:Path,out:Path,port:int,timeout:int,record:dict)->dict:
    if not 5<=timeout<=45:
        raise SmcCaptureError("GDB timeout must be 5..45 seconds")
    for program in ("qemu-system-aarch64","gdb-multiarch"):
        if not shutil.which(program):
            raise SmcCaptureError("Missing local debugger/emulator: "+program)
    gate.check_port(port)
    out.mkdir(parents=True,exist_ok=False)
    cmd=["qemu-system-aarch64","-machine","virt,gic-version=3",
         "-cpu","cortex-a57","-smp","1","-m","2048",
         "-kernel",str(kernel),"-dtb",str(dtb),
         "-append","earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr",
         "-display","none","-serial",f"file:{out/'serial.log'}",
         "-monitor","none","-no-reboot","-nic","none",
         "-d","int,guest_errors","-D",str(out/"qemu-exceptions.log"),
         "-S","-gdb",f"tcp:127.0.0.1:{port}"]
    (out/"qemu-command.json").write_text(json.dumps(cmd,indent=2)+"\n")
    (out/"verified-input.json").write_text(json.dumps(record,indent=2)+"\n")
    (out/"smc-readonly.gdb").write_text(script(port))
    with (out/"qemu-stdout.log").open("wb") as output:
        proc=subprocess.Popen(cmd,stdout=output,stderr=subprocess.STDOUT)
        try:
            time.sleep(1.25)
            if proc.poll() is not None:
                raise SmcCaptureError("QEMU terminated before debugger attached")
            try:
                got=subprocess.run(
                    ["gdb-multiarch","-q","-nx","-batch","-x",str(out/"smc-readonly.gdb")],
                    capture_output=True,text=True,timeout=timeout)
                logs=got.stdout+"\n"+got.stderr
                rc=got.returncode
            except subprocess.TimeoutExpired as err:
                a=err.stdout.decode("utf8","replace") if isinstance(err.stdout,bytes) else (err.stdout or "")
                b=err.stderr.decode("utf8","replace") if isinstance(err.stderr,bytes) else (err.stderr or "")
                logs=a+"\n"+b+"\nGDB_BOUNDED_TIMEOUT\n"
                rc=124
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    (out/"gdb.log").write_text(logs[-1024*1024:])
    result=analyze_log(logs)
    result.update(
        target="SM-G986U1/G986U1UESCHXL1",
        originalFactoryImageSha256=gate.KERNEL_SHA,
        sourceCompactOverrideSha256=record["overrideSha256"],
        originalGuestFdtProofBytes=EXPECTED_RUNTIME_BYTES,
        gdbExitCode=rc,
        actualKernelUserspaceBootVerified=False,
    )
    (out/"smc-register-report.json").write_text(json.dumps(result,indent=2)+"\n")
    return result

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    parser.add_argument("--root",type=Path,default=root)
    parser.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    parser.add_argument("--output",type=Path,default=root/"qemu-compact-smc-registers-v1-20261012")
    parser.add_argument("--timeout",type=int,default=30)
    parser.add_argument("--port",type=int,default=12351)
    parser.add_argument("--preflight-only",action="store_true")
    a=parser.parse_args()
    try:
        root=a.root.expanduser().absolute()
        kernel=a.kernel.expanduser().absolute()
        dtb,record=verify_preflight(root,kernel)
        output=gate.safe_output(a.output,root)
        print("[STOCK IMAGE]",gate.KERNEL_SHA)
        print("[COMPACT INPUT]",record["overrideSha256"])
        print("[ORIGINAL GUEST FDT]",EXPECTED_RUNTIME_BYTES)
        if a.preflight_only:
            print("[READY] Verified; no guest launched")
            return 0
        r=execute(kernel,dtb,output,a.port,a.timeout,record)
        print("[SMC CAPTURE]",r["status"])
        if r["smcCallArgumentsAccepted"]:
            print("[ORIGINAL HXL1 X0-X6]",r["registerArguments"])
        print("[SECURE MONITOR SERVICE/RETURN VERIFIED] NO")
        print("[REPORT]",output/"smc-register-report.json")
        return 0 if r["smcCallArgumentsAccepted"] and r["gdbExitCode"]==0 else 3
    except (SmcCaptureError,gate.GateError,OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
