#!/usr/bin/env python3
"""Original stock HXL1 code windows for GhostLock sendmsg/iovec comparison.

Read-only original kernel.bin SHA256 and recovered nm; no frame aliases,
runtime memory addresses, root, fake objects, K40 numeric offsets or exploit.
Uses original-image-relative symbol coordinates and bounded next-symbol windows.
"""
from __future__ import annotations
import argparse
import bisect
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_ghostlock_stack_gate as gate

REPO=Path(__file__).resolve().parents[1]
NAMES=(
    "__sys_sendmsg","___sys_sendmsg","____sys_sendmsg",
    "__sys_sendto","__sys_sendmmsg",
    "rw_copy_check_uvector","copy_msghdr_from_user",
    "futex_wait_requeue_pi",
)
MAX_WINDOW=4096
DEFAULT_NM=Path.home()/"s20-artifacts/hxl1-research/vmlinux-stock.nm"
DEFAULT_IMAGE=Path.home()/"s20-artifacts/kernel.bin"
DEFAULT_DIR=Path.home()/"s20-artifacts/hxl1-research"

class WindowStop(ValueError):
    pass

def require(ok,msg):
    if not ok:raise WindowStop(msg)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def inventory(raw:bytes,nm_text:str)->tuple[dict,dict[str,bytes]]:
    require(digest(raw)==gate.STOCK_SHA,
            "Pinned original Samsung HXL1 kernel.bin SHA256 mismatch")
    require(len(raw)>64 and raw[0x38:0x3c]==b"ARM\x64",
            "Stock original ARM64 kernel Image magic missing")
    symbols=gate.parse_nm(nm_text)
    require(symbols.get("_text",(-1,))[0]==gate.IMAGE_VA,
            "Recovered text base is not the original HXL1 Image")
    all_addresses=sorted(a for a in symbols.all_text_addresses
                         if a>=gate.IMAGE_VA and
                         a<gate.IMAGE_VA+len(raw) and
                         (a-gate.IMAGE_VA)%4==0)
    rows=[]
    slices={}
    for name in NAMES:
        item=symbols.get(name)
        if item is None:
            rows.append({"symbol":name,"status":"NOT_FOUND_IN_RECOVERED_NM",
                         "compiledFunctionAbsenceProven":False,
                         "stackLayoutAuthenticated":False})
            continue
        va,kind=item
        ix=bisect.bisect_right(all_addresses,va)
        if ix>=len(all_addresses):
            rows.append({"symbol":name,"status":"NO_NEXT_TEXT_SYMBOL_BOUND",
                         "functionExtentProven":False,
                         "stackLayoutAuthenticated":False})
            continue
        end=all_addresses[ix]
        offset=va-gate.IMAGE_VA
        length=end-va
        require(length>0 and length%4==0 and
                offset%4==0 and offset>=0 and
                offset+length<=len(raw),"Original code interval invalid: "+name)
        take=min(length,MAX_WINDOW)
        code=raw[offset:offset+take]
        require(len(code)==take and take%4==0,"Original code bytes incomplete")
        slices[name]=code
        rows.append({
            "symbol":name,"status":"ORIGINAL_IMAGE_CODE_WINDOW",
            "source":"recovered kallsyms text label (not debug/local-variable proof)",
            "staticImageVA":hex(va),
            "imageRelativeOffset":hex(offset),
            "nextRecoveredTextVA":hex(end),
            "originalFullTextIntervalBytes":length,
            "sampledBytes":len(code),
            "capped":take<length,
            "sliceSha256":digest(code),
            "stackLayoutAuthenticated":False,
            "liveFunctionAddressAuthenticated":False,
        })
    return {
        "schemaVersion":1,
        "target":"SM-G986U1/G986U1UESCHXL1",
        "status":"BOUNDED_STOCK_NATIVE_CODE_WINDOWS_NOT_STACK_GEOMETRY",
        "originalKernelSha256":gate.STOCK_SHA,
        "originalKernelSha256Verified":True,
        "recoveredNmSha256":digest(nm_text.encode("utf-8")),
        "staticImageTextVA":hex(gate.IMAGE_VA),
        "requestedSymbols":len(NAMES),
        "boundedCodeWindows":len(slices),
        "functions":rows,
        "exactCompiledWaiterLocalIdentified":False,
        "sendmsgFrameAliasVerified":False,
        "crossSyscallLifetimeReclamationVerified":False,
        "actualGhostLockPrimitiveOrRootVerified":False,
        "physicalKernelHandoffVerified":False,
        "notes":"Factory Image bytes are authentic; recovered symbol names and "
                "next-symbol boundaries are not original debugging metadata. "
                "Do not infer stack object lifetimes, K40 carrier equivalence or "
                "actual runtime addresses from instruction slices."
    },slices

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kernel",type=Path,default=DEFAULT_IMAGE)
    ap.add_argument("--nm",type=Path,default=DEFAULT_NM)
    ap.add_argument("--output-dir",type=Path)
    ap.add_argument("--no-disassembly",action="store_true")
    args=ap.parse_args()
    try:
        image=args.kernel.expanduser().resolve()
        nm=args.nm.expanduser().resolve()
        output=(args.output_dir or
                DEFAULT_DIR/("ghostlock-original-sendmsg-windows-"+
                    datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
        out=output.expanduser().resolve()
        require(image.is_file() and not image.is_symlink() and
                nm.is_file() and not nm.is_symlink() and
                0<nm.stat().st_size<gate.MAX_NM_BYTES,
                "Missing/unsafe input original Image or recovered nm")
        require(not out.exists() and not out.is_symlink() and
                REPO not in out.parents and out!=REPO and
                image not in out.parents and nm not in out.parents,
                "Use a fresh output directory outside source and inputs")
        raw=image.read_bytes()
        listing=nm.read_text(encoding="utf-8")
        report,slices=inventory(raw,listing)
        out.mkdir(parents=True,exist_ok=False)
        dump=None if args.no_disassembly else shutil.which("aarch64-linux-gnu-objdump")
        for item in report["functions"]:
            name=item["symbol"]
            if name not in slices:continue
            (out/(name+".bin")).write_bytes(slices[name])
            item["nativeBytesFile"]=name+".bin"
            if dump:
                try:
                    command=subprocess.run(
                        [dump,"-b","binary","-m","aarch64","-EL","-D",
                         "--adjust-vma="+item["staticImageVA"],
                         str(out/item["nativeBytesFile"])],
                        capture_output=True,text=True,timeout=20,check=False)
                    if command.returncode==0 and len(command.stdout)<200_000:
                        path=out/(name+".disasm.txt")
                        path.write_text(command.stdout,encoding="utf-8")
                        item["disassembly"]={"status":"SAVED_NATIVE_DISASSEMBLY",
                            "filename":path.name,
                            "sha256":digest(command.stdout.encode("utf-8"))}
                    else:
                        item["disassembly"]={"status":"DISASSEMBLY_FAILED",
                            "exitCode":command.returncode}
                except (OSError,subprocess.TimeoutExpired):
                    item["disassembly"]={"status":"DISASSEMBLY_TOOL_ERROR"}
            else:
                item["disassembly"]={"status":"NOT_REQUESTED_OR_TOOL_ABSENT"}
        (out/"original-sendmsg-windows.json").write_text(
            json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("[ORIGINAL HXL1 IMAGE SHA256 VERIFIED] YES")
        print("[BOUNDED SENDMSG/IOVEC CODE WINDOWS]",len(slices),"/",len(NAMES))
        print("[OEM STACK WINDOW OVERLAP OR GHOSTLOCK ROOT] NOT VERIFIED")
        print("[REPORT]",out/"original-sendmsg-windows.json")
        return 0
    except (OSError,ValueError,UnicodeError,TypeError) as error:
        print("[STOP]",error,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
