#!/usr/bin/env python3
"""Bounded, read-only kernel-entry guest FDT capture with compact HXL1 -dtb.

The input is reconstructed from the SHA-pinned original QEMU generated DTB.
Do not infer actual FDT size from the input: QEMU may rewrite/expand it.
No guest writes, physical device actions, privileged QEMU monitor commands,
firmware patching, root, KernelSU, or RKP protected memory allocation.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_fdt_size_recovery as recovery
from tools import y2q_hxl1_qemu_virt_dtb_inventory as fdt
from tools import y2q_hxl1_qemu_entry_fdt_audit as entry

TARGET="SM-G986U1/G986U1UESCHXL1"
FDT_PA=0x48000000
LIMIT=2*1024*1024
MAX_READ=fdt.MAX_DTB
GDB_COMPLETE="HXL1_COMPACT_FDT_DUMP_COMPLETED BYTES="
GDB_DECLARED="HXL1_COMPACT_FDT_GUEST_DECLARED_BYTES="
GDB_LENGTH=re.compile(r"(?m)^"+re.escape(GDB_COMPLETE)+r"(\d+)$")
GDB_SIZE=re.compile(r"(?m)^"+re.escape(GDB_DECLARED)+r"(\d+)$")
DEFAULT_ROOT=Path.home()/"s20-artifacts/hxl1-research"

class CompactError(ValueError):
    pass

def verify_input(root:Path,kernel:Path)->tuple[Path,dict]:
    gate.valid_source(gate.checked_file(kernel))
    orig=gate.checked_file(root/"qemu-virt-dtb-20261011/qemu-virt.dtb",MAX_READ)
    compact=root/"qemu-fdt-under-2m-20261012/compact-override.dtb"
    manifest=root/"qemu-fdt-under-2m-20261012/compact-manifest.json"
    data=gate.checked_file(compact,MAX_READ)
    record=json.loads(gate.checked_file(manifest,128*1024))
    checked=recovery.verify_recovery(orig,data,record)
    if len(data)!=checked["overrideBytes"] or len(data)>=LIMIT:
        raise CompactError("Input DTB preflight size not within strict 2MiB budget")
    return compact,checked

def gdb_script(port:int,out:Path)->str:
    return f"""set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:{port}
hbreak *0x40080000
continue
if $pc == 0x40080000 && $x0 == {hex(FDT_PA)} && $x1 == 0 && $x2 == 0 && $x3 == 0
  printf "HXL1_ENTRY_BREAKPOINT_HIT PC=0x%lx\\n", $pc
  printf "X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", $x0,$x1,$x2,$x3
  printf "FDT_HEADER_AT_X0_START\\n"
  x/16bx $x0
  printf "FDT_HEADER_AT_X0_END\\n"
  set $size = (((unsigned long long)*(unsigned char*)($x0+4)) << 24) | (((unsigned long long)*(unsigned char*)($x0+5)) << 16) | (((unsigned long long)*(unsigned char*)($x0+6)) << 8) | ((unsigned long long)*(unsigned char*)($x0+7))
  printf "{GDB_DECLARED}%llu\\n", $size
  if $size >= 40 && $size <= {MAX_READ} && ($x0 + $size) <= 0xc0000000
    dump binary memory {out}/guest-compact-fdt.dtb $x0 ($x0 + $size)
    printf "{GDB_COMPLETE}%llu\\n", $size
  else
    printf "HXL1_COMPACT_FDT_HEADER_OUT_OF_BOUNDS\\n"
  end
else
  printf "HXL1_COMPACT_FDT_ENTRY_MISMATCH PC=0x%lx X0=0x%lx\\n", $pc, $x0
end
detach
quit
"""

def verify_capture(raw:bytes,log:str)->dict:
    if len(raw)<fdt.HEADER_SIZE or len(raw)>MAX_READ:
        raise CompactError("Guest FDT binary missing or exceeds max capture bound")
    magic,total=struct.unpack_from(">II",raw)
    if magic!=fdt.MAGIC or total!=len(raw):
        raise CompactError("GDB saved FDT bytes do not match guest declared header")
    first=entry.parse_gdb(log)
    if first.get("status")!="GUEST_ENTRY_FDT_HEADER_CORRELATED":
        raise CompactError("Original factory kernel PC/X0/FDT header never verified")
    regs=first.get("registers",{})
    if regs!={"X0":hex(FDT_PA),"X1":"0x0","X2":"0x0","X3":"0x0"}:
        raise CompactError("Guest boot entry registers differ from verified original")
    if first.get("first16BytesHex")!=raw[:16].hex():
        raise CompactError("GDB printed FDT header does not match guest binary")
    sizes=GDB_SIZE.findall(log)
    complete=GDB_LENGTH.findall(log)
    if len(sizes)!=1 or len(complete)!=1 or (
            int(sizes[0])!=total or int(complete[0])!=total):
        raise CompactError("Exact GDB header-derived FDT dump marker missing/mismatched")
    summary=fdt.parse_fdt(raw)
    if summary["fdtTotalBytes"]!=total:
        raise CompactError("Parser disagrees with original guest FDT header")
    ram=summary["memoryRanges"]
    if len(ram)!=1 or (ram[0]["start"],ram[0]["endExclusive"])!=(
            "0x40000000","0xc0000000"):
        raise CompactError("Guest RAM profile differs from original QEMU virt")
    required=[{"start":hex(FDT_PA),"endExclusive":hex(FDT_PA+LIMIT),
               "sizeBytes":LIMIT}]
    if summary["memoryReservationEntries"]!=required:
        raise CompactError("Guest lost or changed the exact diagnostic self-reservation")
    if total>LIMIT:
        status="DELIVERED_COMPACT_OVERRIDE_BUT_RUNTIME_FDT_OVER_2M"
    else:
        status="DELIVERED_COMPACT_OVERRIDE_RUNTIME_FDT_WITHIN_2M"
    return {
        "target":TARGET,"status":status,
        "kernelEntryPc":"0x40080000","guestFdtPhysicalAddress":hex(FDT_PA),
        "guestFdtTotalBytes":total,"arm64EarlyFdtLimitBytes":LIMIT,
        "guestFdtWithin2MiB":total<=LIMIT,
        "runtimeFdtSha256":summary["qemuGeneratedFdtSha256"],
        "diagSelfReservation":required[0],
        "selfReservationCoversGuestFdt":total<=LIMIT,
        "guestFdtInventory":{"memoryRanges":ram,
                             "reservedMemoryRanges":summary["reservedMemoryRanges"],
                             "nodeCount":summary["nodeCount"],
                             "chosenInitrd":summary["chosenInitrd"]},
        "originalFactoryKernelModified":False,
        "guestLinuxMemblockExclusionVerified":False,
        "secureRkpPoolReserved":False,
        "physicalDeviceTouched":False,
    }

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research-root",type=Path,default=DEFAULT_ROOT)
    parser.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    parser.add_argument("--output",type=Path,default=DEFAULT_ROOT/"qemu-compact-entry-fdt-20261012")
    parser.add_argument("--audit-dir",type=Path,help="Audit existing capture only; never run guest")
    parser.add_argument("--seconds",type=int,default=30)
    parser.add_argument("--port",type=int,default=12349)
    args=parser.parse_args()
    try:
        root=args.research_root.expanduser().absolute()
        kernel=args.kernel.expanduser().absolute()
        compact,manifest=verify_input(root,kernel)
        if args.audit_dir:
            out=args.audit_dir.expanduser().absolute()
        else:
            out=gate.safe_output(args.output,root)
        if not args.audit_dir:
            if args.seconds<5 or args.seconds>45:
                raise CompactError("Bounded timeout must be 5..45 seconds")
            for command in ("gdb-multiarch","qemu-system-aarch64"):
                if not shutil.which(command):
                    raise CompactError("Missing host executable: "+command)
            gate.check_port(args.port)
            if not re.fullmatch(r"[a-zA-Z0-9_./-]+",str(out)):
                raise CompactError("GDB output path contains unsupported characters")
            out.mkdir(parents=True,exist_ok=False)
            (out/"compact-fdt-readonly.gdb").write_text(gdb_script(args.port,out))
            (out/"preflight.json").write_text(json.dumps(manifest,indent=2)+"\n")
            cmd=["qemu-system-aarch64","-machine","virt,gic-version=3",
                 "-cpu","cortex-a57","-smp","1","-m","2048",
                 "-kernel",str(kernel),"-dtb",str(compact),
                 "-append","earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr",
                 "-display","none","-serial",f"file:{out/'serial.log'}",
                 "-monitor","none","-no-reboot","-nic","none",
                 "-S","-gdb",f"tcp:127.0.0.1:{args.port}"]
            (out/"qemu-argv.json").write_text(json.dumps(cmd,indent=2)+"\n")
            with (out/"qemu.log").open("wb") as qlog:
                proc=subprocess.Popen(cmd,stdout=qlog,stderr=subprocess.STDOUT)
                try:
                    time.sleep(1.2)
                    if proc.poll() is not None:
                        raise CompactError("QEMU exited before GDB attached")
                    try:
                        r=subprocess.run(
                            ["gdb-multiarch","-q","-nx","-batch","-x",
                             str(out/"compact-fdt-readonly.gdb")],
                            capture_output=True,text=True,timeout=args.seconds)
                        stdout=r.stdout+"\n"+r.stderr
                        rc=r.returncode
                    except subprocess.TimeoutExpired as e:
                        a=e.stdout.decode("utf8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
                        b=e.stderr.decode("utf8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
                        stdout=a+"\n"+b+"\nGDB_BOUNDED_TIMEOUT\n"
                        rc=124
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
            (out/"gdb-session.log").write_text(stdout)
            (out/"gdb-exit-code.txt").write_text(str(rc)+"\n")
            if rc!=0:
                raise CompactError("GDB capture not completed; logs retained without success claim")
        raw=gate.checked_file(out/"guest-compact-fdt.dtb",MAX_READ)
        log=gate.checked_file(out/"gdb-session.log",128*1024).decode("utf8","replace")
        report=verify_capture(raw,log)
        report["factoryImageSha256"]=gate.KERNEL_SHA
        report["compactOverrideSha256"]=manifest["overrideSha256"]
        report["compactInputBytes"]=manifest["overrideBytes"]
        if not args.audit_dir:
            (out/"compact-fdt-audit.json").write_text(json.dumps(report,indent=2)+"\n")
        else:
            print("[AUDIT MODE] Source files not modified")
        print("[GUEST RUNTIME FDT BYTES]",report["guestFdtTotalBytes"])
        print("[ARM64 EARLY 2MiB]",report["guestFdtWithin2MiB"])
        print("[CANARY FDT DELIVERY]",report["status"])
        print("[RKP PROTECTED POOL VERIFIED] NO")
        print("[REPORT]",out/"compact-fdt-audit.json" if not args.audit_dir else "[stdout only]")
        return 0 if report["guestFdtWithin2MiB"] else 3
    except (CompactError,gate.GateError,recovery.RecoveryError,
            OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
