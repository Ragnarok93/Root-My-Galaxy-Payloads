#!/usr/bin/env python3
"""Read-only stock HXL1 RT-mutex code-window evidence.

Bytes: exact SHA256-pinned original kernel.bin. Names: reconstructed
vmlinux-stock.nm, a separate and weaker symbol-recovery assumption.
Do not infer factory struct-member offsets or live kernel addresses.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_stage3_layout_inventory as stock

TEXT_VA=0xFFFFFF8008080000
MODEL="SM-G986U1"
FIRMWARE="G986U1UESCHXL1"
NAMES=(
    "rt_mutex_start_proxy_lock",
    "rt_mutex_adjust_prio_chain",
    "remove_waiter",
    "rt_mutex_init_proxy_locked",
    "rt_mutex_proxy_unlock",
    "rt_mutex_trylock",
    "rt_mutex_lock",
    "rt_mutex_unlock",
    "rt_mutex_lock_interruptible",
    "rt_mutex_next_owner",
    "futex_lock_pi",
    "futex_wait_requeue_pi",
)
REPORT=Path.home()/"s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows.json"
MAX_WINDOW=192
class WindowError(ValueError):
    pass

def require(ok:bool,msg:str)->None:
    if not ok:
        raise WindowError("Original HXL1 stock code provenance STOP: "+msg)

def parse_nm(text:str)->dict:
    found={}
    for line in text.splitlines():
        fields=line.split()
        if len(fields)!=3:
            continue
        addr,kind,name=fields
        if name not in (*NAMES,"_text") or not re.fullmatch(r"[a-fA-F0-9]{8,16}",addr):
            continue
        if kind not in ("T","t"):
            if name in NAMES:
                raise WindowError("Requested function is not a text symbol: "+name)
            continue
        value=(int(addr,16),kind)
        if name in found and found[name]!=value:
            raise WindowError("Ambiguous recovered symbol: "+name)
        found[name]=value
    return found

def windows(raw:bytes,nm:dict,max_bytes:int=MAX_WINDOW)->dict:
    require(16<=max_bytes<=256 and max_bytes%4==0,"window instruction alignment")
    require(len(raw)>=64 and raw[0x38:0x3c]==b"ARM\x64","ARM64 Image header")
    require(nm.get("_text",(-1,))[0]==TEXT_VA,
            "recovered kernel _text base unexpected")
    out={}
    for name in NAMES:
        if name not in nm:
            continue
        va,_=nm[name]
        off=va-TEXT_VA
        require(off>=0 and off%4==0 and off<len(raw),
                "recovered symbol not within original Image: "+name)
        next_address=min((v[0] for n,v in nm.items()
                          if n!="_text" and v[0]>va),
                         default=TEXT_VA+len(raw))
        count=min(max_bytes,len(raw)-off,next_address-va)
        count-=count%4
        require(count>=4,"original code window empty: "+name)
        chunk=raw[off:off+count]
        out[name]={
            "recoveredSymbolVA":hex(va),"relativeImageByteOffset":hex(off),
            "byteCount":count,
            "originalStockBytesSha256":hashlib.sha256(chunk).hexdigest(),
            "independentSymbolMappingAuthenticated":False,
            "factoryCompiledMemberOffsetsVerified":False,
            "_raw":chunk,"_va":va,
        }
    require(bool(out),"no expected RT-mutex symbol labels in recovered kallsyms")
    return out

def disassemble(data:bytes,va:int,command:str|None)->dict:
    if not command:
        return {"status":"NO_AARCH64_OBJDUMP"}
    with tempfile.TemporaryDirectory(prefix="hxl1-stock-code-") as tmp:
        filename=Path(tmp)/"code.bin"
        filename.write_bytes(data)
        try:
            result=subprocess.run([
                command,"-D","-b","binary","-m","aarch64",
                "--adjust-vma="+hex(va),str(filename)
            ],text=True,capture_output=True,timeout=20,check=False,errors="replace")
        except (OSError,subprocess.TimeoutExpired) as ex:
            return {"status":"OBJDUMP_ERROR","reason":type(ex).__name__}
    if result.returncode or len(result.stdout)>32768:
        return {"status":"OBJDUMP_FAILED","returnCode":result.returncode}
    instructions=[]
    for line in result.stdout.splitlines():
        match=re.match(r"^\s*([a-fA-F0-9]+):\s+([a-fA-F0-9]{8})\s+(.+?)\s*$",line)
        if match:
            instructions.append({"staticVA":"0x"+match.group(1),
                "word":match.group(2),
                "assembly":match.group(3)[:160],
                "fieldAccessProven":False})
    if len(instructions)!=len(data)//4:
        return {"status":"INCOMPLETE_DISASSEMBLY",
                "decoded":len(instructions),"expected":len(data)//4}
    return {"status":"ORIGINAL_IMAGE_WINDOW_DISASSEMBLED",
            "instructions":instructions}

def analyze(raw:bytes,nm_text:str,inventory:dict,command:str|None=None)->dict:
    require(hashlib.sha256(raw).hexdigest()==stock.PINNED["kernel.bin"],
            "original kernel image SHA mismatch")
    require(inventory.get("originalFileHashChecksPassed") is True and
            inventory.get("model")==MODEL and inventory.get("firmware")==FIRMWARE and
            inventory.get("offsetsVerified") is False,
            "stock source/config identity boundary")
    found=windows(raw,parse_nm(nm_text))
    for item in found.values():
        buf=item.pop("_raw")
        address=item.pop("_va")
        item["disassembly"]=disassemble(buf,address,command)
    return {
        "model":MODEL,"firmware":FIRMWARE,
        "classification":"PINNED_STOCK_CODE_AND_RECOVERED_KALLSYMS_NOT_FACTORY_ABI",
        "originalKernelSha256":stock.PINNED["kernel.bin"],
        "recoveredTextBase":hex(TEXT_VA),
        "symbolSource":"reconstructed kallsyms, not independent factory debug ELF",
        "originalCandidateCodeWindows":found,
        "missingSymbolLabels":[name for name in NAMES if name not in found],
        "stockCompiledFieldOffsetsEstablished":False,
        "recoveredBtfOrDwarfStructureLayout":False,
        "symbolBindingIndependentlyVerified":False,
        "liveKernelLoadAddressKnown":False,
        "rootExploitVerified":False,
        "kernelSuInstalled":False,
        "phoneModified":False,
    }

def markdown(result:dict)->str:
    lines=[
        "# HXL1 original kernel RT-mutex code windows","",
        "The original kernel Image is independently SHA256 pinned.",
        "Recovered kallsyms labels remain an assumption, not debug/BTF.",
        "","| Recovered function | Static Image-relative offset | Bytes | Code SHA256 |",
        "|---|---|---:|---|"
    ]
    for name,record in result["originalCandidateCodeWindows"].items():
        lines.append("| "+name+" | "+record["relativeImageByteOffset"]+
                     " | "+str(record["byteCount"])+" | "+
                     record["originalStockBytesSha256"]+" |")
    lines+=["","## Names absent from the selected recovered symbol map",""]
    lines.extend("- "+name for name in result["missingSymbolLabels"])
    if not result["missingSymbolLabels"]:
        lines.append("- None")
    lines+=["","## Bounded original instruction windows",""]
    for name,record in result["originalCandidateCodeWindows"].items():
        lines.append("### "+name)
        lines.append(record["disassembly"]["status"])
        for op in record["disassembly"].get("instructions",[]):
            lines.append("- "+op["staticVA"]+": "+op["word"]+" "+op["assembly"])
    lines+=["","## Interpretation boundary","",
            "This is original static code, not an independently verified factory",
            "structure layout. An instruction access displacement is not by",
            "itself proof of the member it accesses. Trace source and dataflow",
            "before accepting any field offset; do not borrow Clang18 values.",
            "No live memory address, privilege escalation or KernelSU proven.",""]
    return "\n".join(lines)

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    p.add_argument("--artifacts",type=Path,default=Path.home()/"s20-artifacts")
    p.add_argument("--out",type=Path,default=REPORT)
    p.add_argument("--objdump",default="aarch64-linux-gnu-objdump")
    opts=p.parse_args()
    source=opts.source.expanduser().resolve()
    artifacts=opts.artifacts.expanduser().resolve()
    target=opts.out.expanduser().absolute()
    other=target.with_suffix(".md")
    if (target.suffix!=".json" or not target.parent.is_dir() or
        any(x.exists() or x.is_symlink() for x in (target,other)) or
        source in target.parents):
        p.error("Select fresh report paths outside stock source")
    try:
        preflight=stock.make_inventory(source,artifacts)
        original_bytes=(artifacts/"kernel.bin").read_bytes()
        names=(artifacts/"hxl1-research/vmlinux-stock.nm").read_text()
        result=analyze(original_bytes,names,preflight,shutil.which(opts.objdump))
        with target.open("x") as f:
            json.dump(result,f,indent=2);f.write("\n")
        with other.open("x") as f:
            f.write(markdown(result))
    except (OSError,ValueError,stock.InventoryError,WindowError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    print("[PINNED] Exact HXL1 stock kernel, source/config SHA256")
    print("[CANDIDATE WINDOWS]",len(result["originalCandidateCodeWindows"]))
    for label,item in result["originalCandidateCodeWindows"].items():
        print("[STOCK]",label,item["byteCount"],
              item["disassembly"]["status"])
    print("[REPORT]",other)
    print("[LIMIT] Not a verified structure field offset, live address, root or KernelSU")
    return 0

if __name__=="__main__":
    sys.exit(main())
