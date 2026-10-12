#!/usr/bin/env python3
"""Bounded, read-only QEMU/GDB observation of original HXL1 memblock_reserve calls.

A function-entry argument observation does not prove a successful memblock
reservation, allocator exclusion, secure RKP memory, boot, or handset root.
The factory kernel, device and previously captured FDT evidence are immutable.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_fdt_canary as canary
from tools import y2q_hxl1_qemu_fdt_canary_verify as delivery

KERNEL_SHA="ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
VM_BASE=0xffffff8008080000
SMC_PC=0xffffff80080a5794
KERNEL_ENTRY_PC=0x40080000
FDT_PA=0x48000000
FDT_SIZE=2117184
FDT_RESERVE=2117632
MAX_NM_BYTES=16*1024*1024
NM_RE=re.compile(r"^([0-9a-fA-F]{16})\s+([TtWw])\s+(\S+)$")
HIT_RE=re.compile(r"(?m)^HXL1_MEMBLOCK_RESERVE_HIT PC=(0x[0-9a-f]+) X0=(0x[0-9a-f]+) X1=(0x[0-9a-f]+)$")
WORD_RE=re.compile(r"(?m)^0x([0-9a-f]+):\s+0x([0-9a-f]{8})$")
SMC_RE=re.compile(r"(?m)^HXL1_SMC_REACHED PC=(0x[0-9a-f]+)$")
ENTRY_RE=re.compile(r"(?m)^HXL1_KERNEL_ENTRY_HIT PC=(0x[0-9a-f]+) X0=(0x[0-9a-f]+)$")
ENTRY_FAILURE_RE=re.compile(r"(?m)^HXL1_KERNEL_ENTRY_MISSED PC=(0x[0-9a-f]+)$")
GDB_WARN_RE=re.compile(r"(?im)(?:Cannot access memory|Remote connection|Connection refused|No hardware breakpoint support|Could not insert hardware|not supported|protocol error|The program is not being run|Target is not responding)")

class GateError(ValueError):
    pass

def checked_file(path:Path,max_bytes:int|None=None)->bytes:
    if not path.is_file() or path.is_symlink():
        raise GateError("Missing or symlinked evidence: "+str(path))
    if max_bytes and path.stat().st_size>max_bytes:
        raise GateError("Evidence file exceeds configured bound")
    return path.read_bytes()

def valid_source(image:bytes)->None:
    if hashlib.sha256(image).hexdigest()!=KERNEL_SHA:
        raise GateError("Original factory HXL1 Image SHA256 mismatch")

def symbol_probe(nm_text:str,image:bytes,name:str="memblock_reserve")->dict:
    valid_source(image)
    addresses=[]
    for line in nm_text.splitlines():
        m=NM_RE.match(line.strip())
        if m and m.group(3)==name:
            addresses.append((int(m.group(1),16),m.group(2)))
    if len(addresses)!=1:
        raise GateError("Expected exactly one recovered text symbol: "+name)
    va,kind=addresses[0]
    offset=va-VM_BASE
    if offset<0 or offset%4 or offset+16>len(image):
        raise GateError("Recovered symbol lies outside exact stock Image")
    code=image[offset:offset+16]
    if code==bytes(16) or code==bytes.fromhex("1f2003d5")*4:
        raise GateError("Recovered entry opcode has no distinguishing stock code")
    return {"name":name,"guestVirtualAddress":hex(va),
            "factoryImageOffset":hex(offset),"symbolType":kind,
            "originalFirstOpcode":hex(int.from_bytes(code[:4],"little")),
            "originalFirst16Sha256":hashlib.sha256(code).hexdigest(),
            "symbolTrust":"RECOVERED_NM_CANDIDATE_NOT_INDEPENDENT_RUNTIME_SYMBOL"}

def verify_existing_v3(root:Path)->dict:
    can=root/"qemu-memreserve-canary-v3-20261011"
    cap=root/"qemu-fdt-canary-delivery-v3-20261011"
    generated=checked_file(root/"qemu-virt-dtb-20261011/qemu-virt.dtb",8*1024*1024)
    baseline=checked_file(root/"qemu-runtime-fdt-20261011/runtime-fdt.dtb",8*1024*1024)
    override=checked_file(can/"canary-override.dtb",8*1024*1024)
    guest=checked_file(cap/"delivered-fdt.dtb",8*1024*1024)
    log=checked_file(cap/"gdb-session.log",128*1024).decode("utf8","replace")
    manifest=json.loads(checked_file(can/"canary-construction.json",128*1024))
    report=delivery.report_delivery(generated,override,baseline,guest,log,manifest)
    if (report.get("classification")!="DELIVERED_AND_FULLY_COVERED" or
        report.get("deliveredGuestFdtTotalSize")!=FDT_SIZE or
        report.get("deliveredSelfReservation",{}).get("start")!=hex(FDT_PA) or
        report.get("deliveredSelfReservation",{}).get("sizeBytes")!=FDT_RESERVE):
        raise GateError("Required owner-attested v3 FDT guest interval not established")
    return {"classification":report["classification"],
            "guestRuntimeFdtSha256":report["deliveredGuestFdtSha256"],
            "guestRuntimeFdtSizeBytes":FDT_SIZE,
            "guestRuntimeFdtPhysicalAddress":hex(FDT_PA),
            "guestMemreserveBytes":FDT_RESERVE,
            "linuxMemblockExcluded":False}

def build_gdb(port:int,va:int,expected_opcode:int)->str:
    """Bind to actual original Image entry before arming kernel-VA breakpoints.

    This is intentionally a TWO-PHASE probe. Failure to reach entry must
    not be presented as evidence about Linux memblock.
    """
    return f"""set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:{port}
hbreak *{hex(KERNEL_ENTRY_PC)}
continue
if $pc == {hex(KERNEL_ENTRY_PC)}
  printf "HXL1_KERNEL_ENTRY_HIT PC=0x%lx X0=0x%lx\\n", $pc, $x0
  # The original entry GDB image uses X0 as FDT physical pointer.
  hbreak *{hex(va)} if $x0 == {hex(FDT_PA)}
  hbreak *{hex(SMC_PC)}
  continue
  if $pc == {hex(va)}
    printf "HXL1_MEMBLOCK_RESERVE_HIT PC=0x%lx X0=0x%lx X1=0x%lx\\n", $pc, $x0, $x1
    x/1wx $pc
  else
    if $pc == {hex(SMC_PC)}
      printf "HXL1_SMC_REACHED PC=0x%lx\\n", $pc
    else
      printf "HXL1_UNEXPECTED_POST_ENTRY_STOP PC=0x%lx\\n", $pc
    end
  end
else
  printf "HXL1_KERNEL_ENTRY_MISSED PC=0x%lx\\n", $pc
end
detach
quit
"""

def parse_gdb(text:str,sym:dict)->dict:
    """Reject claims based solely on an incomplete, timed-out GDB session."""
    hit=HIT_RE.findall(text)
    smc=SMC_RE.findall(text)
    entries=ENTRY_RE.findall(text)
    diagnostics=GDB_WARN_RE.findall(text)
    pre={"kernelEntryObserved":False,
         "memblockReserveCallObserved":False,
         "actualAllocatorReservationVerified":False,
         "gdbWarnings":diagnostics[:8]}
    if len(entries)!=1 or len(ENTRY_FAILURE_RE.findall(text))>0:
        if len(entries)>1:
            pre["status"]="AMBIGUOUS_KERNEL_ENTRY"
        elif diagnostics:
            pre["status"]="GDB_OR_BREAKPOINT_SETUP_ERROR"
        elif "GDB_BOUNDED_TIMEOUT" in text:
            pre["status"]="TIMEOUT_BEFORE_KERNEL_ENTRY_OR_GDB_STOP"
        else:
            pre["status"]="ORIGINAL_KERNEL_ENTRY_NOT_VERIFIED"
        return pre
    pc,x0=(int(x,16) for x in entries[0])
    if pc!=KERNEL_ENTRY_PC or x0!=FDT_PA:
        pre["status"]="ENTRY_POINTER_OR_PC_MISMATCH"
        return pre
    pre["kernelEntryObserved"]=True
    pre["entryFdtPointerValidated"]=True
    if len(hit)>1 or len(smc)>1 or (hit and smc):
        pre["status"]="NON_UNIQUE_POST_ENTRY_EVENT"
        return pre
    if len(hit)==1:
        pc,x0,x1=[int(x,16) for x in hit[0]]
        if pc!=int(sym["guestVirtualAddress"],16) or x0!=FDT_PA:
            pre["status"]="BREAKPOINT_IDENTITY_MISMATCH"
            return pre
        words=WORD_RE.findall(text)
        original=int(sym["originalFirstOpcode"],16)
        if len(words)!=1 or int(words[0][0],16)!=pc or int(words[0][1],16)!=original:
            pre["status"]="GUEST_OPCODE_NOT_CORRELATED"
            return pre
        pre.update(status="STOCK_MEMBLOCK_RESERVE_ENTRY_ARGS_OBSERVED",
                   memblockReserveCallObserved=True,
                   requestedFdtStartMatches=True,
                   requestedSizeBytes=x1,
                   requestedSizeCoversFullRuntimeFdt=x1>=FDT_SIZE,
                   requestedSizeCoversV3PageAlignedReserve=x1>=FDT_RESERVE,
                   functionReturnedSuccessfully=False)
        return pre
    if len(smc)==1:
        if int(smc[0],16)!=SMC_PC:
            pre["status"]="SMC_BREAKPOINT_PC_MISMATCH"
        else:
            pre["status"]="SMC_REACHED_WITHOUT_MATCHING_MEMBLOCK_CALL"
            pre["doesNotProveCallAbsent"]=True
        return pre
    if diagnostics:
        pre["status"]="POST_ENTRY_GDB_OR_BREAKPOINT_ERROR"
    elif "GDB_BOUNDED_TIMEOUT" in text:
        pre["status"]="POST_ENTRY_EXECUTION_TIMEOUT"
    else:
        pre["status"]="POST_ENTRY_STOP_UNCLASSIFIED"
    pre["doesNotProveCallAbsent"]=True
    return pre

def audit_saved_probe(root:Path)->dict:
    """Pure offline replay of previous timeout; no new guest execution."""
    prior=checked_file(root/"gdb.log",1024*1024).decode("utf8","replace")
    qemu=checked_file(root/"qemu.log",1024*1024).decode("utf8","replace")
    exit_value=checked_file(root/"gdb-exit-code.txt",128).decode("ascii","replace").strip()
    event_lines=[line[:500] for line in prior.splitlines()
                 if any(term in line.lower() for term in (
                     "breakpoint", "remote", "target", "error", "memory",
                     "cannot", "warning", "timed", "entry", "smc"))]
    trace=root/"qemu-exceptions.log"
    exception_tail=""
    exception_size=0
    if trace.is_file() and not trace.is_symlink():
        exception_size=trace.stat().st_size
        with trace.open("rb") as fh:
            fh.seek(max(0,exception_size-4096))
            exception_tail=fh.read(4096).decode("utf8","replace")[-2000:]
    return {"status":"OFFLINE_DIAGNOSTICS_ONLY",
            "qemuExceptionLogBytes":exception_size,
            "qemuExceptionLogTail":exception_tail,
            "gdbExitCode":exit_value,
            "gdbLogLines":len(prior.splitlines()),
            "timeoutObserved":"GDB_BOUNDED_TIMEOUT" in prior or exit_value=="124",
            "gdbDiagnosticLines":event_lines[:40],
            "qemuStdoutTail":qemu[-1200:],
            "kernelEntryProof":bool(ENTRY_RE.search(prior)),
            "linuxMemblockAllocatorExclusionVerified":False,
            "deviceTouched":False}

def safe_output(out:Path,root:Path)->Path:
    target=out.expanduser().absolute()
    home_root=root.expanduser().absolute()
    if target==home_root or not target.is_relative_to(home_root):
        raise GateError("Output must be a fresh subdirectory of HXL1 research")
    if target.exists() or target.is_symlink():
        raise GateError("Output exists; never replace original evidence")
    return target

def check_port(port:int)->None:
    if not 1024<=port<=65535:
        raise GateError("Invalid loopback GDB port")
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1",port))
        except OSError as e:
            raise GateError("Local GDB port not free") from e

def execute(out:Path,root:Path,kernel:Path,can:Path,sym:dict,port:int,seconds:int,preflight:dict)->dict:
    if seconds<5 or seconds>45:
        raise GateError("Execution time must be in the bounded 5..45 second range")
    for executable in ("qemu-system-aarch64","gdb-multiarch"):
        if not shutil.which(executable):
            raise GateError("Missing host executable: "+executable)
    check_port(port)
    # Preflight is complete before creating output or launching QEMU.
    out.mkdir(parents=True,exist_ok=False)
    cmd_gdb=build_gdb(port,int(sym["guestVirtualAddress"],16),int(sym["originalFirstOpcode"],16))
    (out/"memblock-readonly.gdb").write_text(cmd_gdb)
    (out/"preflight.json").write_text(json.dumps(preflight,indent=2)+"\n")
    qemu_cmd=["qemu-system-aarch64","-machine","virt,gic-version=3",
        "-cpu","cortex-a57","-smp","1","-m","2048",
        "-kernel",str(kernel),"-dtb",str(can/"canary-override.dtb"),
        "-append","earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr",
        "-display","none","-serial",f"file:{out/'serial.log'}",
        "-monitor","none","-no-reboot","-nic","none",
        "-d","int,guest_errors","-D",str(out/"qemu-exceptions.log"),
        "-S","-gdb",f"tcp:127.0.0.1:{port}"]
    (out/"qemu-argv.json").write_text(json.dumps(qemu_cmd,indent=2)+"\n")
    with (out/"qemu.log").open("wb") as ql:
        proc=subprocess.Popen(qemu_cmd,stdout=ql,stderr=subprocess.STDOUT)
        try:
            # QEMU must bind its localhost GDB stub before GDB connects.
            time.sleep(1.5)
            if proc.poll() is not None:
                raise GateError("QEMU terminated before GDB could attach")
            try:
                r=subprocess.run(
                    ["gdb-multiarch","-q","-nx","-batch","-x",str(out/"memblock-readonly.gdb")],
                    capture_output=True,text=True,timeout=seconds)
                log=r.stdout+"\n"+r.stderr
                rc=r.returncode
            except subprocess.TimeoutExpired as e:
                stdout=(e.stdout or b"").decode("utf8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
                stderr=(e.stderr or b"").decode("utf8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
                log=stdout+"\n"+stderr+"\nGDB_BOUNDED_TIMEOUT\n"
                rc=124
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    (out/"gdb.log").write_text(log[-1024*1024:])
    (out/"gdb-exit-code.txt").write_text(str(rc)+"\n")
    result=parse_gdb(log,sym)
    trace=out/"qemu-exceptions.log"
    result["qemuExceptionLogPresent"]=trace.is_file()
    if trace.is_file():
        # Never load potentially unbounded exception-loop logs into memory.
        with trace.open("rb") as handle:
            handle.seek(max(0,trace.stat().st_size-4096))
            tail=handle.read(4096).decode("utf8","replace")
        result["qemuExceptionLogBytes"]=trace.stat().st_size
        result["qemuExceptionTail"]=tail[-3000:]
    result.update({"target":"SM-G986U1/G986U1UESCHXL1","statusCode":rc,
        "originalImageSha256":KERNEL_SHA,"sourceVerifiedV3":True,
        "factoryKernelUnmodified":True,"physicalDeviceTouched":False,
        "linuxMemblockAllocatorExclusionVerified":False,
        "secureRkpPoolAllocated":False})
    (out/"memblock-probe-report.json").write_text(json.dumps(result,indent=2)+"\n")
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--research-root",type=Path,default=root)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,default=root/"qemu-memblock-callsite-v1-20261011")
    p.add_argument("--execute",action="store_true",help="Run bounded isolated QEMU/GDB, no phone contact")
    p.add_argument("--audit-dir",type=Path,help="Read prior timed-out GDB/QEMU logs only")
    p.add_argument("--port",type=int,default=12579)
    p.add_argument("--seconds",type=int,default=30)
    a=p.parse_args()
    try:
        if a.audit_dir is not None:
            # No kernel artifacts, QEMU, output creation or device required.
            result=audit_saved_probe(a.audit_dir.expanduser().absolute())
            print(json.dumps(result,indent=2))
            return 0
        root=a.research_root.expanduser().absolute()
        kernel=a.kernel.expanduser().absolute()
        image=checked_file(kernel)
        valid_source(image)
        nm=checked_file(a.nm.expanduser().absolute(),MAX_NM_BYTES)
        sym=symbol_probe(nm.decode("utf8","replace"),image)
        v3=verify_existing_v3(root)
        can=root/"qemu-memreserve-canary-v3-20261011"
        checked_file(can/"canary-override.dtb",8*1024*1024)
        preflight={"factoryImageSha256":KERNEL_SHA,
                  "recoveredSymbol":sym,"v3":v3,
                  "noKernelOrDtbWrites":True}
        out=safe_output(a.output,root)
        print("[PINNED STOCK IMAGE]",KERNEL_SHA)
        print("[RECOVERED SYMBOL]",sym["name"],sym["guestVirtualAddress"],
              "opcode",sym["originalFirstOpcode"])
        print("[EXISTING V3]",v3["classification"])
        if not a.execute:
            print("[PLAN] Host-only original-image QEMU GDB read of memblock_reserve X0/X1")
            print("[PLAN] Add --execute to capture in",out)
            return 0
        result=execute(out,root,kernel,can,sym,a.port,a.seconds,preflight)
        print("[MEMBLOCK PROBE]",result["status"])
        print("[MEMBLOCK ALLOCATOR EXCLUSION] NOT VERIFIED")
        print("[REPORT]",out/"memblock-probe-report.json")
        return 0
    except (GateError,OSError,ValueError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
