#!/usr/bin/env python3
"""Inspect original HXL1 code preceding *both* measured zero-base fault loads.

Everything is offline: rerun exact raw GDB report/source attestations, pin the
factory Image, parse the recovered (non-authoritative) kallsyms boundaries,
disassemble bounded original function code windows, and report every textual
register mention without inventing a true register-def-use chain.

Never mistake a recovered function label, a sampled LR, or a cross-run FAR for
proof of panic chronology, an executed caller, or Samsung UH causality.
"""
from __future__ import annotations
import argparse
import gzip
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
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_fault_sites as sites
from tools import y2q_hxl1_compact_fault_live_attribution as live
from tools import y2q_hxl1_qemu_compact_fault_regs as registers
from tools import y2q_hxl1_qemu_compact_smc_registers as smc

ROOT=Path.home()/"s20-artifacts/hxl1-research"
MAX_NM_GAP=0x8000
MAX_WINDOW=0x1000
MAX_CONFIG=1024*1024
RELEVANT_CONFIG=("CONFIG_SLAB","CONFIG_SLUB","CONFIG_SLOB",
                 "CONFIG_SLUB_DEBUG","CONFIG_SLAB_FREELIST_HARDENED",
                 "CONFIG_SLAB_FREELIST_RANDOM","CONFIG_KASAN",
                 "CONFIG_SAMSUNG_DEBUG")

class WindowError(ValueError):
    pass

def stock_window(image:bytes, symbols:dict,pc:int,back:int=2048,ahead:int=64)->dict:
    if back<128 or back>MAX_WINDOW or back%4 or ahead<0 or ahead>256 or ahead%4:
        raise WindowError("Original function slice limit/alignment rejected")
    found=sites.nearest_symbol(symbols,pc)
    if found.get("status")!="NEAREST_LOWER_OR_EQUAL_RECOVERED_SYMBOL_UNVERIFIED":
        raise WindowError("Original recovered preceding symbol unavailable")
    start_sym=int(found["address"],16)
    if pc-start_sym>MAX_NM_GAP:
        raise WindowError("Recovered name too distant for focused function hypothesis")
    # A nearest lower-or-equal name is NOT a certified function extent.
    actual_start=max(start_sym,pc-back)
    actual_end=min(gate.VM_BASE+len(image),pc+4+ahead)
    if actual_start<gate.VM_BASE or actual_end<=pc or any(x%4 for x in (actual_start,actual_end)):
        raise WindowError("Factory source window outside original Image")
    data=image[actual_start-gate.VM_BASE:actual_end-gate.VM_BASE]
    return {
        "status":"ORIGINAL_IMAGE_BYTES_BOUNDED_BY_RECOVERED_SYMBOL",
        "nearestRecoveredSymbol":found,
        "sourceVirtualAddressStart":hex(actual_start),
        "sourceVirtualAddressEndExclusive":hex(actual_end),
        "bytes":len(data),
        "originalBytesSha256":hashlib.sha256(data).hexdigest(),
        "instructionCount":len(data)//4,
        "includesRecoveredFunctionEntry":actual_start==start_sym,
        "possibleCodeNotActuallyExecuted":True,
        "sourceWords":[{"address":hex(actual_start+i),
                        "opcode":f"{int.from_bytes(data[i:i+4],'little'):08x}"}
                       for i in range(0,len(data),4)],
    }

def disassemble(window:dict,image:bytes,program:str|None)->dict:
    if not program:
        return {"status":"AARCH64_OBJDUMP_MISSING","lines":[],
                "registerMentions":[],"controlFlowHints":[]}
    start=int(window["sourceVirtualAddressStart"],16)
    end=int(window["sourceVirtualAddressEndExclusive"],16)
    data=image[start-gate.VM_BASE:end-gate.VM_BASE]
    with tempfile.TemporaryDirectory(prefix="hxl1-allocator-window-") as tmp:
        fname=Path(tmp)/"stock-window.bin"
        fname.write_bytes(data)
        try:
            r=subprocess.run([program,"-D","-b","binary","-m","aarch64",
                              "--adjust-vma="+hex(start),str(fname)],
                             capture_output=True,text=True,timeout=15)
        except (OSError,subprocess.TimeoutExpired):
            return {"status":"OBJDUMP_FAILED","lines":[],
                    "registerMentions":[],"controlFlowHints":[]}
    if r.returncode:
        return {"status":"OBJDUMP_FAILED","lines":[],
                "registerMentions":[],"controlFlowHints":[]}
    rows=[s.strip() for s in r.stdout.splitlines()
          if re.match(r"^\s*[0-9a-fA-F]+:\s+[0-9a-fA-F]{8}\s+",s)]
    if len(rows)!=window["instructionCount"]:
        return {"status":"INCOMPLETE_DISASSEMBLY","lines":rows[:128],
                "registerMentions":[],"controlFlowHints":[]}
    mentions={}
    for name in ("x21","x10"):
        pattern=re.compile(r"\b(?:x|w)"+name[1:]+r"\b",re.IGNORECASE)
        mentions[name]=[line for line in rows if pattern.search(line)]
    # These are textual locations, not a computed instruction dependency graph.
    ctrl=re.compile(r"\s(?:bl|blr|b|b\.[a-z]+|cbz|cbnz|tbz|tbnz|ret)\s",re.I)
    control=[line for line in rows if ctrl.search(line)]
    return {"status":"ORIGINAL_FACTORY_IMAGE_DISASSEMBLED",
            "lines":rows,"registerMentions":mentions,
            "controlFlowHints":control[:160],
            "registerWriteOriginsEstablished":False,
            "actualExecutedControlFlowEstablished":False}

def read_config(path:Path)->dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size>MAX_CONFIG:
        raise WindowError("Original HXL1 config.gz missing/unsafe/oversized")
    with gzip.open(path,"rb") as stream:
        raw=stream.read(MAX_CONFIG+1)
    if len(raw)>MAX_CONFIG:
        raise WindowError("HXL1 kernel config decompression exceeds safe bound")
    text=raw.decode("utf8","replace")
    found={}
    for name in RELEVANT_CONFIG:
        pattern=re.compile(r"^"+re.escape(name)+r"=(.*)$",re.M)
        matches=pattern.findall(text)
        if len(matches)>1:
            raise WindowError("Ambiguous stock config key "+name)
        found[name]=matches[0] if matches else "NOT_ENABLED_OR_NOT_RECORDED"
    return {"configGzSha256":hashlib.sha256(path.read_bytes()).hexdigest(),
            "decompressedBytes":len(raw),"allocatorAndDiagnosticFlags":found,
            "configSlabVariantIdentified":sum(found[k]=="y" for k in
                                               ("CONFIG_SLAB","CONFIG_SLUB","CONFIG_SLOB"))==1}

def build(image:bytes,live_attestations:dict,symbols:dict,
          stock_config:dict,objdump:str|None)->dict:
    gate.valid_source(image)
    output={}
    for target in ("x21","x10"):
        observed=live_attestations[target]
        if (observed.get("status")!="ORIGINAL_COMPACT_FAULT_BASE_AT_SOURCE_INSTRUCTION_VERIFIED" or
            observed.get("baseRegister")!=target.upper() or
            observed.get("liveBaseRegisterValue")!="0x0" or
            observed.get("originalImageSha256")!=gate.KERNEL_SHA or
            observed.get("smcCausedNullBaseOrAbortProven") is not False):
            raise WindowError("Exact original live-fault evidence not established for "+target)
        pc,op,far=registers.TARGETS[target]
        if observed.get("originalInstructionAddress")!=hex(pc):
            raise WindowError("Original fault address mismatch")
        local=stock_window(image,symbols,pc)
        words=local["sourceWords"]
        current=[w for w in words if w["address"]==hex(pc)]
        if len(current)!=1 or current[0]["opcode"]!=op:
            raise WindowError("Original factory instruction differs from live GDB at "+target)
        decoded=disassemble(local,image,objdump)
        output[target]={
            "originalFaultInstruction":hex(pc),"factoryOpcode":op,
            "liveBaseValue":observed["liveBaseRegisterValue"],
            "priorRunFar":observed["separatePriorGuestDataAbortFar"],
            "originalCodeWindow":{k:v for k,v in local.items() if k!="sourceWords"},
            "disassembly":decoded,
            "capturedLinkRegister":observed["liveLinkRegister"],
            "nearestRecoveredLinkRegisterSymbol":sites.nearest_symbol(
                symbols,int(observed["liveLinkRegister"],16)),
        }
    x21=output["x21"]["originalCodeWindow"]["nearestRecoveredSymbol"]
    x10=output["x10"]["originalCodeWindow"]["nearestRecoveredSymbol"]
    return {
        "status":"ORIGINAL_COMPACT_ZERO_BASE_FAULT_CODE_WINDOWS_VERIFIED",
        "originalKernelSha256":gate.KERNEL_SHA,
        "recoveredSymbolMapSha256":symbols.get("sourceSha256"),
        "recoveredSymbolsNotIndependentDebugInfo":True,
        "allocatorConfig":stock_config,
        "sites":output,
        "primaryFaultHypothesis":"X21 zero in recovered kmem_cache_alloc; confirm preceding register producer/call path before diagnosing slab initialization",
        "secondaryFaultHypothesis":"X10 zero in recovered dump_stack_minidump with LR near panic; likely secondary diagnostic path, but chronological causality unproven",
        "smcCausedAllocatorFailureProven":False,
        "sameRunSmcReturnProven":False,
        "sameRunDataAbortProven":False,
        "allocatorCacheObjectIdentityKnown":False,
        "allocatorInitializationFailureProven":False,
        "panicSequenceProven":False,
        "rootOrUnlockEnabled":False,
        "physicalDeviceTouched":False,
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--research-root",type=Path,default=ROOT)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--config",type=Path,default=Path.home()/"s20-artifacts/config.gz")
    p.add_argument("--nm",type=Path,default=ROOT/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,
                   default=ROOT/"qemu-pc-compact-fdt-20261012/original-two-fault-function-windows.json")
    a=p.parse_args()
    try:
        dest=a.output.expanduser().absolute()
        if dest.exists() or dest.is_symlink() or dest.suffix!=".json":
            raise WindowError("Choose a fresh JSON output; preserve source evidence")
        root=a.research_root.expanduser().absolute()
        kernel=a.kernel.expanduser().absolute()
        smc.verify_preflight(root,kernel)
        image=gate.checked_file(kernel)
        symbols=sites.load_recovered_symbols(a.nm.expanduser().absolute())
        if symbols["status"]!="RECOVERED_NM_SYMBOLS_UNVERIFIED":
            raise WindowError("Original reconstructed text symbol map missing")
        deps=json.loads(gate.checked_file(
            root/"qemu-pc-compact-fdt-20261012/compact-fault-dependencies-v2.json",128*1024))
        gathered={}
        for target in ("x21","x10"):
            d=root/live.DIRS[target]
            record=json.loads(gate.checked_file(d/"fault-register-report.json",128*1024))
            logfile=gate.checked_file(d/"gdb.log",1024*1024).decode("utf8","replace")
            gathered[target]=live.correlate(record,logfile,image,deps,symbols,target)
        result=build(image,gathered,symbols,read_config(a.config.expanduser().absolute()),
                     shutil.which("aarch64-linux-gnu-objdump"))
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(result,indent=2)+"\n")
        print("[EXACT ORIGINAL IMAGE]",result["originalKernelSha256"])
        print("[STOCK ALLOCATOR CONFIG]",result["allocatorConfig"]["allocatorAndDiagnosticFlags"])
        for reg,item in result["sites"].items():
            window=item["originalCodeWindow"]
            n=window["nearestRecoveredSymbol"]
            print("["+reg.upper()+" STOCK SYMBOL]",n["name"],"distance",n["distance"],
                  "control-flow",item["disassembly"]["status"])
            print("["+reg.upper()+" SAVED LR]",item["capturedLinkRegister"],
                  "near",item["nearestRecoveredLinkRegisterSymbol"].get("name","[none]"))
            print("["+reg.upper()+" SOURCE REGISTER MENTIONS]")
            for line in item["disassembly"].get("registerMentions",{}).get(reg,[])[:36]:
                print(line)
        print("[PRIMARY/SECONDARY ROOT CAUSE PROVED] NO")
        print("[REPORT]",dest)
        return 0
    except (WindowError,OSError,ValueError,KeyError,TypeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
