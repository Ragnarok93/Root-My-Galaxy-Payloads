#!/usr/bin/env python3
"""Source-and-code evidence for exact HXL1 stock RT-mutex functions.

Consumes the version-2, all-symbol-bounded original-Image report.
Rechecks every window against SHA256-pinned stock kernel.bin + recovered
kallsyms, compares every disassembled word to actual Image bytes, and
extracts separately SHA256-pinned Samsung source *definitions*.

Intended for reviewing original source alongside real compiled instructions.
NEVER infer a source field from an instruction displacement: there is no
factory DWARF/BTF, full dataflow proof, runtime KASLR or root in this audit.
No on-device access, compilation, source changes or exploit generation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_stock_rtmutex_code_windows as stock_code
from tools import y2q_stage3_layout_inventory as stock

TARGETS={
    "remove_waiter":"kernel/locking/rtmutex.c",
    "rt_mutex_start_proxy_lock":"kernel/locking/rtmutex.c",
    "futex_lock_pi":"kernel/futex.c",
}
DEFAULT_V2=Path.home()/"s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows-v2.json"
DEFAULT_OUT=Path.home()/"s20-artifacts/hxl1-research/hxl1-stock-rtmutex-source-code-01.json"
SOURCE_LINES_LIMIT=90
CONTEXT_MATCHES_LIMIT=24
MAX_FILE_SIZE=4*1024*1024
MAX_REPORT_SIZE=8*1024*1024
SIGNALS=("pi_lock","pi_blocked_on","waiter->","rt_mutex_","futex_","current")

class CorrelationError(ValueError):
    pass

def ensure(ok:bool,desc:str)->None:
    if not ok:
        raise CorrelationError("HXL1 original source/code correlation STOP: "+desc)

def mask_comments_and_literals(source:str)->str:
    """Preserve byte-position equivalent text length and line count."""
    pattern=re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'
                       r"'(?:\\.|[^'\\])*'",re.S)
    return pattern.sub(
        lambda m:"".join("\n" if ch=="\n" else " " for ch in m.group()),source)

def closing_paren(code:str,opening:int)->int:
    ensure(opening<len(code) and code[opening]=="(","function declarator starts with '('")
    depth=0
    for idx in range(opening,len(code)):
        ch=code[idx]
        if ch=="(":
            depth+=1
        elif ch==")":
            depth-=1
            if depth==0:
                return idx
    raise CorrelationError("Function signature has no closing parenthesis")

def closing_brace(code:str,opening:int)->int:
    ensure(opening<len(code) and code[opening]=="{","function body starts with '{'")
    depth=0
    for idx in range(opening,len(code)):
        ch=code[idx]
        if ch=="{":
            depth+=1
        elif ch=="}":
            depth-=1
            if depth==0:
                return idx
    raise CorrelationError("Function body has no closing brace")

def find_definition(code:str,name:str)->dict:
    """Require one actual name(...) { definition, not a call or prototype."""
    masked=mask_comments_and_literals(code)
    candidates=[]
    for match in re.finditer(r"\b"+re.escape(name)+r"\s*\(",masked):
        opening=masked.find("(",match.start(),match.end())
        end=closing_paren(masked,opening)
        next_pos=end+1
        while next_pos<len(masked) and masked[next_pos].isspace():
            next_pos+=1
        if next_pos>=len(masked) or masked[next_pos]!="{":
            continue
        line_start=masked.rfind("\n",0,match.start())+1
        # This rejects preprocessor macros that resemble C function defs.
        if masked[line_start:match.start()].lstrip().startswith("#"):
            continue
        end_body=closing_brace(masked,next_pos)
        start_line=code.count("\n",0,line_start)+1
        end_line=code.count("\n",0,end_body)+1
        candidates.append({"name":name,"startLine":start_line,
                           "endLine":end_line,"bodyEnd":end_body})
    ensure(len(candidates)==1,
           "Expected one uniquely identifiable source definition for "+
           name+"; got "+str(len(candidates)))
    selected=candidates[0]
    lines=code.splitlines()
    a=selected["startLine"]
    z=selected["endLine"]
    # Limit emitted raw source, while maintaining the original line numbers.
    head=[{"line":n,"source":lines[n-1][:240]}
          for n in range(a,min(z,a+SOURCE_LINES_LIMIT-1)+1)]
    relevant=[{"line":n,"source":lines[n-1][:240]}
              for n in range(a,z+1)
              if any(word in lines[n-1] for word in SIGNALS)]
    selected.pop("bodyEnd")
    selected["sourceLinesTotal"]=z-a+1
    selected["sourceExcerpt"]=head
    selected["sourceExcerptTruncated"]=z>a+SOURCE_LINES_LIMIT-1
    selected["relevantSourceLines"]=relevant[:CONTEXT_MATCHES_LIMIT]
    selected["relevantSourceLinesTruncated"]=len(relevant)>CONTEXT_MATCHES_LIMIT
    selected["fullSourceToInstructionDataflowProven"]=False
    return selected

def verify_v2(v2:dict,original:bytes,nm_text:str)->dict:
    """Check the full v2 report and every disassembled word against stock."""
    ensure(v2.get("model")==stock_code.MODEL and
           v2.get("firmware")==stock_code.FIRMWARE and
           v2.get("originalKernelSha256")==stock.PINNED["kernel.bin"],
           "report is not for SHA256-pinned HXL1 original Image")
    ensure(v2.get("stockCompiledFieldOffsetsEstablished") is False and
           v2.get("symbolBindingIndependentlyVerified") is False and
           v2.get("liveKernelLoadAddressKnown") is False and
           v2.get("rootExploitVerified") is False,
           "report wrongly claims source/symbol/runtime privileges")
    ensure(hashlib.sha256(original).hexdigest()==stock.PINNED["kernel.bin"],
           "original kernel file checksum changed")
    recomputed=stock_code.windows(original,stock_code.parse_nm(nm_text))
    reported=v2.get("originalCandidateCodeWindows",{})
    ensure(isinstance(reported,dict) and set(recomputed)==set(reported),
           "v2 target names differ from independently recomputed stock")
    ensure(len(reported)==11,"expected original owner's 11 source-window candidates")
    windows={}
    for name,calc in recomputed.items():
        entry=reported[name]
        ensure(isinstance(entry,dict),"malformed entry for "+name)
        for attr in ("relativeImageByteOffset","byteCount",
                     "originalStockBytesSha256","nextRecoveredTextSymbolVA",
                     "boundedByFullRecoveredTextSymbolMap"):
            ensure(calc.get(attr)==entry.get(attr),
                   "full-symbol bounded bytes differ in "+name+": "+attr)
        ensure(entry.get("factoryCompiledMemberOffsetsVerified") is False
               and entry.get("independentSymbolMappingAuthenticated") is False,
               "attempt to promote factory layout/symbol mapping")
        decoded=entry.get("disassembly",{})
        ensure(decoded.get("status")=="ORIGINAL_IMAGE_WINDOW_DISASSEMBLED",
               "incomplete original code disassembly for "+name)
        insns=decoded.get("instructions")
        ensure(isinstance(insns,list) and len(insns)==calc["byteCount"]//4,
               "partial decoded instruction list for "+name)
        va=int(calc["recoveredSymbolVA"],16)
        raw=calc["_raw"]
        verified=[]
        for idx,ins in enumerate(insns):
            ensure(isinstance(ins,dict) and
                   ins.get("fieldAccessProven") is False,
                   "field attribution not proven: "+name)
            expected=int.from_bytes(raw[idx*4:(idx+1)*4],"little")
            ensure(re.fullmatch(r"[0-9a-fA-F]{8}",str(ins.get("word",""))) is not None and
                   int(ins["word"],16)==expected,
                   "disassembly word does not match stock Image: "+name)
            ensure(int(ins["staticVA"],16)==va+idx*4,
                   "disassembly static VA does not match stock Image: "+name)
            verified.append({
                "staticVA":ins["staticVA"],
                "word":ins["word"],
                "assembly":str(ins.get("assembly",""))[:160],
                "sourceMemberIdentified":False
            })
        windows[name]={
            "stockCodeSha256":calc["originalStockBytesSha256"],
            "codeBytes":calc["byteCount"],
            "nextRecoveredTextSymbolVA":calc["nextRecoveredTextSymbolVA"],
            "allDecodedWordsAgreeWithStock":True,
            "windowMayBeTruncatedBy192ByteLimit":
                not calc["windowStoppedAtNextTextSymbol"],
            "factorySourceMemberOffsetsIdentified":False,
            "instructions":verified,
        }
    return windows

def analyze(stock_source:Path,artifacts:Path,v2_file:Path)->dict:
    inventory=stock.make_inventory(stock_source,artifacts)
    for rel in set(TARGETS.values()):
        expected=stock.SOURCE_PINNED.get(rel)
        ensure(bool(expected),"source file lacks HXL1 original SHA256 pin: "+rel)
        path=stock_source/rel
        ensure(path.is_file() and not path.is_symlink() and
               path.stat().st_size<=MAX_FILE_SIZE,"original source missing/oversized: "+rel)
        ensure(stock.digest(path)==expected,"Samsung original source hash changed: "+rel)
    ensure(v2_file.is_file() and not v2_file.is_symlink() and
           v2_file.stat().st_size<=MAX_REPORT_SIZE,"v2 report missing/oversized")
    v2=json.loads(v2_file.read_text())
    original=(artifacts/"kernel.bin").read_bytes()
    nm=(artifacts/"hxl1-research/vmlinux-stock.nm").read_text()
    evidence=verify_v2(v2,original,nm)
    result={}
    for name,rel in TARGETS.items():
        ensure(name in evidence,"selected function missing original code: "+name)
        source_def=find_definition((stock_source/rel).read_text(errors="replace"),name)
        result[name]={
            "originalCFile":rel,
            "originalCFileSha256":stock.SOURCE_PINNED[rel],
            "originalSourceDefinition":source_def,
            "originalCode":evidence[name],
            "symbolToSourceBindingProvenByDebugInfo":False,
            "instructionToSourceMemberMappingProven":False,
        }
    return {
        "classification":"HXL1_ORIGINAL_C_AND_ORIGINAL_IMAGE_INSTRUCTION_REVIEW_NOT_FACTORY_ABI",
        "device":stock_code.MODEL,"firmware":stock_code.FIRMWARE,
        "originalImageSha256":stock.PINNED["kernel.bin"],
        "originalConfigSha256":stock.PINNED["config.gz"],
        "v2ReportSha256":stock.digest(v2_file),
        "full11WindowByteAndDisassemblyWordChecksPassed":True,
        "focus":result,
        "allOriginalSourceHashesVerified":inventory["originalFileHashChecksPassed"],
        "sourceToDisassemblyMappingIndependentlyProven":False,
        "originalFactoryStructOffsetsRecovered":False,
        "experimentalClang18OffsetsUsed":False,
        "liveKernelAddressKnown":False,
        "runtimeVulnerabilityValidated":False,
        "rootOrKernelSuInstalled":False,
        "phoneContacted":False,
    }

def markdown(r:dict)->str:
    lines=[
        "# HXL1 stock C definitions and stock AArch64 instruction review",
        "",
        "All 11 original v2 windows reverified word-by-word from the exact stock Image.",
        "All cited Samsung C source files independently match their pinned hashes.",
        "The pairing of labels and C definitions is **name-based**, not a proven",
        "factory debug location or a verified source-to-machine-code mapping.",
        "",
    ]
    for name,entry in r["focus"].items():
        source=entry["originalSourceDefinition"]
        code=entry["originalCode"]
        lines.extend([
            "## "+name,
            "",
            "Stock file: "+entry["originalCFile"]+
                " (SHA256 "+entry["originalCFileSha256"]+")",
            "Original definition lines: "+str(source["startLine"])+"–"+
                str(source["endLine"]),
            "Original disassembly bytes: "+str(code["codeBytes"])+
                " (192-byte cap may truncate: "+
                str(code["windowMayBeTruncatedBy192ByteLimit"])+")",
            "All words independently matched: "+str(code["allDecodedWordsAgreeWithStock"]),
            "",
            "### Original C excerpt",
            "",
        ])
        for item in source["sourceExcerpt"]:
            lines.append(str(item["line"])+": "+item["source"])
        if source["sourceExcerptTruncated"]:
            lines.append("... Remaining original source definition not displayed.")
        lines.extend(["","### Other original source lines mentioning RT-mutex state",""])
        for item in source["relevantSourceLines"]:
            lines.append(str(item["line"])+": "+item["source"])
        if source["relevantSourceLinesTruncated"]:
            lines.append("... Additional signal lines withheld by bound.")
        lines.extend(["","### Original stock AArch64 instructions",""])
        for item in code["instructions"]:
            lines.append(item["staticVA"]+": "+item["word"]+"  "+item["assembly"])
        lines.extend([
            "","**Interpretation:** Instructions are authentic original bytes at",
            "recovered static virtual locations. No instruction above has been",
            "independently tied to a particular C struct member.","",
        ])
    lines.extend([
        "## Unresolved factory ABI gates","",
        "No factory Clang10 DWARF/BTF member-layout proof, no complete",
        "source-to-machine-code dataflow analysis, no live address/KASLR",
        "proof, no reproduced on-device vulnerability and no KernelSU.",
        "No firmware, build object or device was modified.",""
    ])
    return "\n".join(lines)

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    p.add_argument("--artifacts",type=Path,default=Path.home()/"s20-artifacts")
    p.add_argument("--v2",type=Path,default=DEFAULT_V2)
    p.add_argument("--out",type=Path,default=DEFAULT_OUT)
    a=p.parse_args()
    source=a.source.expanduser().resolve()
    artifacts=a.artifacts.expanduser().resolve()
    origin=a.v2.expanduser().absolute()
    out=a.out.expanduser().absolute()
    if out.suffix!=".json" or not out.parent.is_dir() or any(
       file.exists() or file.is_symlink() for file in (out,out.with_suffix(".md"))
    ) or source in out.parents:
        p.error("Choose fresh, separate, non-symlinked evidence reports outside stock source")
    try:
        data=analyze(source,artifacts,origin)
        with out.open("x") as target:
            json.dump(data,target,indent=2)
            target.write("\n")
        with out.with_suffix(".md").open("x") as target:
            target.write(markdown(data))
    except (OSError,ValueError,stock.InventoryError,CorrelationError) as err:
        print("[STOP]",err,file=sys.stderr)
        return 2
    print("[VERIFIED] 11/11 full-symbol bounded stock windows; every ARM64 word matches exact Image")
    print("[VERIFIED] Both pinned Samsung RT-mutex/futex C source files")
    for name,item in data["focus"].items():
        c=item["originalSourceDefinition"]
        a=item["originalCode"]
        print("[CORRELATION CANDIDATE]",name,"stock source lines",
              str(c["startLine"])+"-"+str(c["endLine"]),
              "AArch64 instructions",len(a["instructions"]),
              "192-cap truncation",a["windowMayBeTruncatedBy192ByteLimit"])
    print("[REPORT]",out.with_suffix(".md"))
    print("[LIMIT] Name pairing only; NO factory member offset, runtime address, root or KernelSU")
    return 0

if __name__=="__main__":
    sys.exit(main())
