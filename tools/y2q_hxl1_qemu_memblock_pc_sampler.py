#!/usr/bin/env python3
"""Bounded read-only QMP CPU-PC sampling for the original HXL1 QEMU guest.

This investigates the owner's v2 "post-entry timeout" independently of a
conditional GDB breakpoint. It records guest CPU registers and exception
logs via QEMU's LOCAL UNIX QMP monitor, not a phone. A QMP CPU register
snapshot cannot prove memblock function calls, allocator exclusions, or root.
"""
from __future__ import annotations

import argparse
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
from tools import y2q_hxl1_memblock_trace_gate as gate

PC_RE=re.compile(r"(?im)(?<!\w)\bPC\s*=\s*(?:0x)?([0-9a-f]{8,16})\b")
ELR_RE=re.compile(r"(?im)\bELR_EL([123])\s*=\s*(?:0x)?([0-9a-f]{8,16})\b")
FAR_RE=re.compile(r"(?im)\bFAR_EL([123])\s*=\s*(?:0x)?([0-9a-f]{8,16})\b")
ESR_RE=re.compile(r"(?im)\bESR_EL([123])\s*=\s*(?:0x)?([0-9a-f]{8,16})\b")
MAX_LOG=16*1024*1024
MAX_RAW=15000
PROTOCOL_TIMEOUT=3.0
TARGET="SM-G986U1/G986U1UESCHXL1"

class MonitorError(ValueError):
    pass

def register_snapshot(raw:str)->dict:
    def regs(regex):
        return {m.group(1):"0x"+m.group(2).lower() for m in regex.finditer(raw)}
    pcs=PC_RE.findall(raw)
    return {
        "pc":"0x"+pcs[0].lower() if len(pcs)==1 else None,
        "pcMatches":len(pcs),
        "elr":regs(ELR_RE),
        "far":regs(FAR_RE),
        "esr":regs(ESR_RE),
        "raw":raw[:MAX_RAW],
        "rawTruncated":len(raw)>MAX_RAW,
    }

def classify(report:list[dict], source:str)->dict:
    matched=[s["registers"]["pc"] for s in report
             if s.get("registers",{}).get("pc")]
    unknown=sum(not s.get("registers",{}).get("pc") for s in report)
    if not report or not matched:
        status="GUEST_PC_UNAVAILABLE"
    elif len(set(matched))==1 and len(matched)>=2:
        status="SAME_PC_IN_MULTIPLE_SNAPSHOTS"
    elif len(set(matched))>1:
        status="GUEST_PC_CHANGED_ACROSS_SNAPSHOTS"
    else:
        status="ONE_PC_SAMPLE_ONLY"
    return {
        "status":status,
        "mode":source,
        "pcSequence":matched,
        "samplesWithUnknownPc":unknown,
        "cannotInferInfiniteLoopFromIdenticalSamples":True,
        "factoryImageUnmodified":True,
        "deviceTouched":False,
        "kernelEntryReachedDuringThisSamplingRun":False,
        "linuxMemblockAllocatorExclusionVerified":False,
        "rkpProtectedPoolConfirmed":False,
    }

class QMP:
    def __init__(self,path:Path):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(PROTOCOL_TIMEOUT)
        self.sock.connect(str(path))
        self.stream=self.sock.makefile("rwb",buffering=0)
        first=self._recv()
        if "QMP" not in first:
            raise MonitorError("QMP greeting missing")
        self.request("qmp_capabilities")
        self.id=0

    def _recv(self)->dict:
        while True:
            raw=self.stream.readline()
            if not raw:
                raise MonitorError("QMP connection closed")
            obj=json.loads(raw)
            if not isinstance(obj,dict):
                raise MonitorError("Invalid QMP response")
            if "event" in obj:
                continue
            return obj

    def request(self,name:str,args:dict|None=None)->object:
        if not hasattr(self,"id"):
            self.id=0
        self.id+=1
        data={"execute":name,"id":"hxl1-"+str(self.id)}
        if args is not None:
            data["arguments"]=args
        self.stream.write((json.dumps(data)+"\n").encode())
        while True:
            reply=self._recv()
            if reply.get("id")!=data["id"]:
                raise MonitorError("QMP request/response ID mismatch")
            if "error" in reply:
                raise MonitorError("QMP "+name+": "+str(reply["error"])[:300])
            if "return" not in reply:
                raise MonitorError("Missing QMP return for "+name)
            return reply["return"]

    def close(self)->None:
        try:
            self.stream.close()
        finally:
            self.sock.close()

def wait_qmp_socket(path:Path,proc:subprocess.Popen,wait_seconds:float=4)->None:
    deadline=time.monotonic()+wait_seconds
    while time.monotonic()<deadline:
        if path.exists() and path.is_socket():
            return
        if proc.poll() is not None:
            raise MonitorError("QEMU exited before local QMP socket appeared")
        time.sleep(.1)
    raise MonitorError("Local QMP monitor socket unavailable")

def log_tail(path:Path)->dict:
    if not path.is_file() or path.is_symlink():
        return {"exists":False}
    size=path.stat().st_size
    with path.open("rb") as f:
        f.seek(max(0,size-6000))
        s=f.read(6000).decode("utf-8","replace")
    return {"exists":True,"sizeBytes":size,"tail":s[-6000:]}

def build_qemu_command(kernel:Path,canary:Path,out:Path,source:str)->list[str]:
    command=[
        "qemu-system-aarch64",
        "-machine","virt,gic-version=3",
        "-cpu","cortex-a57","-smp","1","-m","2048",
        "-kernel",str(kernel),
    ]
    if source in ("v3-canary","compact-canary"):
        command+=["-dtb",str(canary)]
    command+=[
        "-append","earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr",
        "-display","none","-serial",f"file:{out/'serial.log'}",
        "-monitor","none","-no-reboot","-nic","none",
        "-d","int,guest_errors","-D",str(out/"qemu-exceptions.log"),
        "-S","-qmp",f"unix:{out/'qmp.sock'},server=on,wait=off",
    ]
    return command

def sample_guest(qmp:QMP,out:Path,seconds:int,count:int)->list[dict]:
    result=[]
    initial=time.monotonic()
    for i in range(count):
        target=initial+(i+1)*(seconds/(count+1))
        time.sleep(max(0,target-time.monotonic()))
        if (out/"qemu-exceptions.log").exists() and (
                (out/"qemu-exceptions.log").stat().st_size>MAX_LOG):
            raise MonitorError("QEMU exception log exceeded 16MiB safety bound")
        try:
            state=qmp.request("query-status")
            registers=qmp.request("human-monitor-command",
                                  {"command-line":"info registers","cpu-index":0})
            if not isinstance(registers,str):
                raise MonitorError("QMP info registers returned non-text")
            item={"index":i+1,
                  "elapsedSeconds":round(time.monotonic()-initial,3),
                  "runStatus":state.get("status") if isinstance(state,dict) else None,
                  "registers":register_snapshot(registers)}
        except (MonitorError,TimeoutError,socket.timeout,OSError) as e:
            item={"index":i+1,
                  "elapsedSeconds":round(time.monotonic()-initial,3),
                  "error":str(e)[:350]}
        result.append(item)
    return result

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    parser.add_argument("--research-root",type=Path,default=root)
    parser.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    parser.add_argument("--mode",choices=["v3-canary","baseline","compact-canary"],default="v3-canary")
    parser.add_argument("--output",type=Path,default=root/"qemu-memblock-pc-samples-v3-20261012")
    parser.add_argument("--seconds",type=int,default=12)
    parser.add_argument("--samples",type=int,default=4)
    parser.add_argument("--preflight-only",action="store_true")
    args=parser.parse_args()
    try:
        if not 4<=args.seconds<=24 or not 2<=args.samples<=8:
            raise MonitorError("Bounded sampling requires seconds=4..24, samples=2..8")
        root=args.research_root.expanduser().absolute()
        out=gate.safe_output(args.output,root)
        kernel=args.kernel.expanduser().absolute()
        gate.valid_source(gate.checked_file(kernel))
        # The original owner's v3 evidence must be valid even in baseline mode.
        existing=gate.verify_existing_v3(root)
        can=root/"qemu-memreserve-canary-v3-20261011/canary-override.dtb"
        gate.checked_file(can,8*1024*1024)
        verified_recovery=None
        if args.mode=="compact-canary":
            # Import only here: baseline and already measured v3 do not
            # depend on a new compact DTB being available.
            from tools import y2q_hxl1_qemu_fdt_size_recovery as recovery
            compact_dir=root/"qemu-fdt-under-2m-20261012"
            compact=compact_dir/"compact-override.dtb"
            manifest=compact_dir/"compact-manifest.json"
            original=root/"qemu-virt-dtb-20261011/qemu-virt.dtb"
            verified_recovery=recovery.verify_recovery(
                gate.checked_file(original,8*1024*1024),
                gate.checked_file(compact,8*1024*1024),
                json.loads(gate.checked_file(manifest,128*1024)))
            can=compact
        cmd=build_qemu_command(kernel,can,out,args.mode)
        print("[STOCK IMAGE]",gate.KERNEL_SHA)
        print("[EXISTING V3]",existing["classification"])
        print("[MODE]",args.mode)
        if verified_recovery is not None:
            print("[COMPACT CANARY VERIFIED]",verified_recovery["overrideSha256"])
            print("[COMPACT DTB SOURCE BYTES]",verified_recovery["overrideBytes"])
            print("[ARM64 RUNTIME FDT SIZE VERIFIED] NO")
        if args.preflight_only:
            print("[PRECHECK] PASS, QEMU not started")
            return 0
        if not shutil.which("qemu-system-aarch64"):
            raise MonitorError("qemu-system-aarch64 unavailable")
        out.mkdir(parents=True,exist_ok=False)
        (out/"qemu-argv.json").write_text(json.dumps(cmd,indent=2)+"\n")
        readings=[]
        error=None
        with (out/"qemu.log").open("wb") as qlog:
            proc=subprocess.Popen(cmd,stdout=qlog,stderr=subprocess.STDOUT)
            qmp=None
            try:
                wait_qmp_socket(out/"qmp.sock",proc)
                qmp=QMP(out/"qmp.sock")
                original=qmp.request("query-status")
                if not isinstance(original,dict) or original.get("status")!="prelaunch":
                    # Depending on QEMU version the -S state may be "paused".
                    if not isinstance(original,dict) or original.get("running") is not False:
                        raise MonitorError("QEMU not initially suspended by -S")
                qmp.request("cont")
                readings=sample_guest(qmp,out,args.seconds,args.samples)
            except (MonitorError,TimeoutError,OSError,json.JSONDecodeError) as e:
                error=str(e)[:500]
            finally:
                if qmp is not None:
                    qmp.close()
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        result=classify(readings,args.mode)
        result["target"]=TARGET
        result["factorySha256"]=gate.KERNEL_SHA
        result["inputDtbSha256"]=verified_recovery["overrideSha256"] if verified_recovery else None
        result["qemuGuestFdtSizeWithinArm64LimitVerified"]=False
        result["samples"]=readings
        result["samplingError"]=error
        result["exceptionLog"]=log_tail(out/"qemu-exceptions.log")
        result["qemuStdout"]=log_tail(out/"qemu.log")
        (out/"pc-sample-report.json").write_text(json.dumps(result,indent=2)+"\n")
        print("[PC OBSERVATION]",result["status"])
        print("[PC SERIES]",result["pcSequence"])
        print("[QEMU EXCEPTIONS]",result["exceptionLog"].get("tail","")[-500:])
        print("[REPORT]",out/"pc-sample-report.json")
        return 0 if readings and not error and result["status"]!="GUEST_PC_UNAVAILABLE" else 3
    except (gate.GateError,MonitorError,OSError,ValueError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
