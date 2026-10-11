#!/usr/bin/env python3
"""Bounded read-only early-boot trace of original HXL1 Image in AArch64 QEMU.

This tool NEVER patches kernels, calls ADB, flashes the phone or claims boot
success merely from a timeout or a QEMU instruction trace.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

STOCK_SHA256 = "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
MAGIC = b"ARM\x64"
SOURCE = "SM-G986U1/G986U1UESCHXL1"
BASE_ARGS = ("-machine","virt,gic-version=3","-cpu","cortex-a57",
             "-smp","1","-m","2048")
BOOT_ARGS = "earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr"

class TriageError(ValueError):
    pass

def image_metadata(image: Path) -> dict:
    if not image.is_file() or image.is_symlink():
        raise TriageError("Exact original Image is missing or symlinked")
    digest=hashlib.sha256()
    with image.open("rb") as f:
        header=f.read(64)
        if len(header)!=64:raise TriageError("Image shorter than ARM64 header")
        digest.update(header)
        for data in iter(lambda:f.read(1024*1024),b""):
            digest.update(data)
    if digest.hexdigest()!=STOCK_SHA256:
        raise TriageError("Original G986U1UESCHXL1 kernel.bin SHA256 mismatch")
    if header[0x38:0x3c]!=MAGIC:
        raise TriageError("Not an ordinary ARM64 Image header; abort before QEMU")
    return {
        "sha256":digest.hexdigest(),"size":image.stat().st_size,
        "textOffset":hex(struct.unpack_from("<Q",header,0x8)[0]),
        "imageSize":hex(struct.unpack_from("<Q",header,0x10)[0]),
        "flags":hex(struct.unpack_from("<Q",header,0x18)[0]),
        "arm64ImageMagic":header[0x38:0x3c].hex(),
        "factoryBinaryUnmodified":True
    }

def qemu_args(qemu: str, image:Path, output:Path, initrd:Path|None=None)->list[str]:
    args=[qemu,*BASE_ARGS,"-kernel",str(image),"-append",BOOT_ARGS,
          "-display","none","-serial","stdio","-monitor","none",
          "-no-reboot","-d","in_asm,guest_errors,unimp,int",
          "-D",str(output/"tcg-instructions.log")]
    if initrd:args+=["-initrd",str(initrd)]
    return args

def interpret(console: str, trace: str, ended: str)->dict:
    c=console.lower()
    tb = bool(re.search(r"(?m)^\s*IN:\s*$",trace))
    pcs=re.findall(r"(?m)^\s*0x([0-9a-fA-F]{7,16}):",trace)
    boot = "booting linux on physical cpu" in c
    linux = "linux version " in c
    panic = "kernel panic" in c
    return {
        "outcome":ended,
        "qemuTranslatedInstructionBlocksSeen":tb,
        "traceSamplePcCount":len(pcs),
        "traceSampleFirstPc":("0x"+pcs[0]) if pcs else None,
        "traceSampleLastPc":("0x"+pcs[-1]) if pcs else None,
        "linuxEarlyBootBannerSeen":boot,
        "linuxVersionLogSeen":linux,
        "kernelPanicLogSeen":panic,
        "kernelEntryProven":False,
        "hxl1KernelBootedToUserspace":False,
        "sourceFaithfulGuestEstablished":False,
        "rootOrKernelSuProven":False,
        "interpretation":(
          "QEMU timed out; its exit code alone establishes no guest execution"
          if ended=="TIMEOUT" and not tb and not boot else
          "Instruction trace may include QEMU boot-loader code; verify PC "
          "against original Image before claiming factory kernel entry"
        ),
    }

def bounded_probe(image:Path, qemu:str, output:Path, seconds:int,
                  initrd:Path|None=None)->dict:
    if not 3<=seconds<=60:raise TriageError("Timeout must be 3 through 60 seconds")
    if output.exists():raise TriageError("Output directory already exists; do not overwrite evidence")
    if output.resolve()==image.resolve() or image.resolve() in output.resolve().parents:
        raise TriageError("Refuse output under input file")
    binary=shutil.which(qemu) if "/" not in qemu else str(Path(qemu).resolve())
    if not binary or not Path(binary).is_file():
        raise TriageError("QEMU executable missing: "+qemu)
    if initrd and (not initrd.is_file() or initrd.is_symlink()):
        raise TriageError("Existing read-only initrd missing/unsafe")
    metadata=image_metadata(image)
    version=subprocess.run([binary,"--version"],capture_output=True,text=True,timeout=8)
    if version.returncode:raise TriageError("QEMU --version failed")
    output.mkdir(parents=True)
    args=qemu_args(binary,image,output,initrd)
    outcome="EXITED"
    code=None
    with (output/"serial-console.log").open("wb") as log:
        try:
            proc=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=log,
                                stderr=subprocess.STDOUT,timeout=seconds,
                                check=False)
            code=proc.returncode
            if code:outcome="QEMU_NONZERO_EXIT"
        except subprocess.TimeoutExpired:
            outcome="TIMEOUT"
    serial=(output/"serial-console.log").read_bytes()[:128*1024].decode("utf8","replace")
    tracefile=output/"tcg-instructions.log"
    trace=tracefile.read_bytes()[:256*1024].decode("utf8","replace") if tracefile.exists() else ""
    verdict=interpret(serial,trace,outcome)
    result={"schemaVersion":1,"target":SOURCE,"image":metadata,
        "traceSampleBytes":len(trace.encode("utf8","replace")),
        "traceFileBytes":tracefile.stat().st_size if tracefile.exists() else 0,
        "qemuVersion":version.stdout.splitlines()[0] if version.stdout else "",
        "qemuBinary":binary,"timeoutSeconds":seconds,
        "command":args,"exitCode":code,"evidence":verdict,
        "files":{"serial":"serial-console.log","trace":"tcg-instructions.log"}}
    (output/"report.json").write_text(json.dumps(result,indent=2)+"\n")
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--qemu",default="qemu-system-aarch64")
    p.add_argument("--output",type=Path,default=Path.home()/"s20-artifacts/hxl1-research/qemu-first-failure")
    p.add_argument("--seconds",type=int,default=15)
    p.add_argument("--initrd",type=Path,help="Optional existing disposable initramfs; no extraction")
    p.add_argument("--execute",action="store_true",help="Explicitly run QEMU")
    a=p.parse_args()
    try:
        metadata=image_metadata(a.kernel)
        cmd=qemu_args(a.qemu,a.kernel,a.output,a.initrd)
        if not a.execute:
            print("[PLAN] SHA-pinned original kernel:",metadata["sha256"])
            print("[PLAN] ARM64 Image text offset:",metadata["textOffset"])
            print("[PLAN] QEMU:"," ".join(cmd))
            print("[PLAN] Re-run with --execute for a bounded, unmodified-Image trace")
            return 0
        result=bounded_probe(a.kernel,a.qemu,a.output,a.seconds,a.initrd)
        print("[QEMU]",result["evidence"]["outcome"])
        print("[TRACE BLOCKS]",result["evidence"]["qemuTranslatedInstructionBlocksSeen"])
        print("[LINUX BANNER]",result["evidence"]["linuxEarlyBootBannerSeen"])
        print("[REPORT]",a.output/"report.json")
        print("[LIMIT] No HXL1 boot/entry or physical-device root inferred from timeout")
        return 0
    except (TriageError,OSError,subprocess.TimeoutExpired) as e:
        print("[STOP]",e,file=sys.stderr);return 2

if __name__=="__main__":
    raise SystemExit(main())
