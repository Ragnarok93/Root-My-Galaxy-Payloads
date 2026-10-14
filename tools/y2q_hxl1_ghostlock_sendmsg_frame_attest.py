#!/usr/bin/env python3
"""HXL1 read-only original-Image sendmsg/futex code-window attestation.

Requires original full kernel.bin, exact recovered kallsyms, a prior bounded
code-window manifest, and the raw .bin/.disasm.txt siblings. Cross-checks
every reported instruction against the ORIGINAL kernel Image and records
conservative static ARM64 frame observations. Never claims a local variable,
cross-syscall overlap, exploitable waiter, KASLR or root.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_ghostlock_stack_gate as gate
from tools import y2q_hxl1_ghostlock_original_sendmsg_windows as prior
from tools import y2q_hxl1_frame_footprint_audit as frames

REPO=Path(__file__).resolve().parents[1]
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
INSTRUCTION=re.compile(r"^\s*([0-9a-f]{16}):\s*([0-9a-f]{8})\s+([a-z][a-z0-9_.]*)(?:\s+(.*?))?\s*$",re.I)
SP_ADDRESS=re.compile(r"^(?:x(?:[12]?\d|30)|w(?:[12]?\d|30)),\s*sp(?:,\s*#(0x[0-9a-f]+|\d+))?$",re.I)
MAX_DISASM=200000
MAX_REPORT=200000
EXPECTED_COUNT=len(prior.NAMES)

class VerifyError(ValueError):
    pass

def require(ok,why):
    if not ok:
        raise VerifyError("Original HXL1 window verification: "+why)

def digest(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def read_regular(p:Path,limit:int)->bytes:
    require(p.is_file() and not p.is_symlink(),"missing/unsafe "+str(p))
    require(0 < p.stat().st_size <= limit,"empty/oversize "+str(p))
    return p.read_bytes()

def parse_disasm(raw:bytes,expected_code:bytes,base:int)->list[tuple[int,str,str]]:
    try:
        lines=raw.decode("utf-8","strict").splitlines()
    except UnicodeDecodeError as exc:
        raise VerifyError("disassembly is not UTF-8") from exc
    rows=[]
    for line in lines:
        mat=INSTRUCTION.match(line)
        if mat is None:
            continue
        address=int(mat.group(1),16)
        word=int(mat.group(2),16)
        opcode=mat.group(3).lower()
        operands=(mat.group(4) or "").split("//",1)[0].strip()
        index=len(rows)
        require(index<len(expected_code)//4,"more instruction rows than raw bytes")
        require(address==base+index*4,"disassembly instruction gap/reorder")
        require(word==int.from_bytes(expected_code[index*4:index*4+4],"little"),
                "disassembly word differs from original Image")
        rows.append((address,opcode,operands))
    require(len(rows)==len(expected_code)//4,
            "missing disassembly instruction slots")
    return rows

def structural_features(rows:list[tuple[int,str,str]])->dict:
    observed=frames.frame(rows)
    sp_address=[]
    for address,opcode,operands in rows:
        if opcode in ("add","sub","mov") and SP_ADDRESS.fullmatch(operands):
            sp_address.append({"staticImageVA":hex(address),
                               "instruction":opcode+" "+operands})
    return {
       "instructionSlotsChecked":len(rows),
       "literalSpAdjustments":observed,
       "spRelativeAddressConstructs":sp_address[:40],
       "spRelativeAddressConstructsTruncated":len(sp_address)>40,
       "compilerLocalVariablesRecovered":False,
       "pathSensitiveFrameEquivalenceProven":False,
       "stackOverlapWithFutexWaiterProven":False,
    }

def audit(report:dict,image:bytes,nm:bytes,directory:Path)->dict:
    require(isinstance(report,dict) and
            report.get("schemaVersion")==1 and
            report.get("target")=="SM-G986U1/G986U1UESCHXL1" and
            report.get("status")=="BOUNDED_STOCK_NATIVE_CODE_WINDOWS_NOT_STACK_GEOMETRY" and
            report.get("originalKernelSha256Verified") is True and
            report.get("originalKernelSha256")==gate.STOCK_SHA and
            report.get("staticImageTextVA")==hex(gate.IMAGE_VA) and
            report.get("requestedSymbols")==EXPECTED_COUNT,
            "manifest identity or original-Image contract")
    require(digest(image)==gate.STOCK_SHA and
            len(image)>0x3c and image[0x38:0x3c]==b"ARM\x64",
            "independent original kernel SHA/header")
    require(digest(nm)==report.get("recoveredNmSha256"),
            "recovered nm SHA mismatch")
    try:
        symbols=gate.parse_nm(nm.decode("utf-8","strict"))
    except UnicodeDecodeError as exc:
        raise VerifyError("recovered nm is not UTF-8") from exc
    require(symbols.get("_text",(-1,))[0]==gate.IMAGE_VA,
            "recovered static text origin")
    addresses=sorted(x for x in symbols.all_text_addresses
                     if gate.IMAGE_VA <= x < gate.IMAGE_VA+len(image) and
                     (x-gate.IMAGE_VA)%4==0)
    items=report.get("functions")
    require(isinstance(items,list) and len(items)==EXPECTED_COUNT,
            "exact requested symbol list count")
    require([x.get("symbol") if isinstance(x,dict) else None for x in items]
            ==list(prior.NAMES),"reordered/unexpected symbol labels")
    reviewed=[]
    found=0
    for item in items:
        name=item["symbol"]
        name_present=name in symbols
        require(name not in getattr(symbols,"duplicate_unrelated_names",{}),
                "ambiguous recovered symbol: "+name)
        if item.get("status")=="NOT_FOUND_IN_RECOVERED_NM":
            require(not name_present and item.get("compiledFunctionAbsenceProven") is False,
                    "unverified absence claim: "+name)
            reviewed.append({"symbol":name,"status":"NOT_FOUND_IN_RECOVERED_NM",
                             "compiledFunctionAbsent":False})
            continue
        require(item.get("status")=="ORIGINAL_IMAGE_CODE_WINDOW" and name_present,
                "window missing/cannot be tied to recovered symbol: "+name)
        address=symbols[name][0]
        pos=bisect.bisect_right(addresses,address)
        require(pos<len(addresses),"no recovered next text symbol: "+name)
        next_address=addresses[pos]
        offset=address-gate.IMAGE_VA
        count=min(next_address-address,prior.MAX_WINDOW)
        require(item.get("staticImageVA")==hex(address) and
                item.get("imageRelativeOffset")==hex(offset) and
                item.get("nextRecoveredTextVA")==hex(next_address) and
                item.get("originalFullTextIntervalBytes")==next_address-address and
                item.get("sampledBytes")==count and
                item.get("capped")==(count<next_address-address) and
                count>0 and count%4==0 and
                offset>=0 and offset+count<=len(image),
                "code interval provenance mismatch: "+name)
        code=image[offset:offset+count]
        require(digest(code)==item.get("sliceSha256"),
                "raw code slice SHA mismatch: "+name)
        require(item.get("nativeBytesFile")==name+".bin",
                "unexpected code filename: "+name)
        disk=read_regular(directory/(name+".bin"),prior.MAX_WINDOW)
        require(code==disk,"cached raw function bytes differ from original: "+name)
        asm=item.get("disassembly")
        require(isinstance(asm,dict) and
                asm.get("status")=="SAVED_NATIVE_DISASSEMBLY" and
                asm.get("filename")==name+".disasm.txt",
                "original disassembly not saved: "+name)
        disasm=read_regular(directory/(name+".disasm.txt"),MAX_DISASM)
        require(digest(disasm)==asm.get("sha256"),
                "saved disassembly SHA mismatch: "+name)
        decoded=parse_disasm(disasm,code,address)
        features=structural_features(decoded)
        reviewed.append({"symbol":name,
                         "status":"CODE_BYTES_AND_DISASSEMBLY_INDEPENDENTLY_VERIFIED",
                         "staticImageVA":hex(address),
                         "relativeImageOffset":hex(offset),
                         "originalCodeSha256":digest(code),
                         "savedDisassemblySha256":digest(disasm),
                         "features":features})
        found+=1
    require(found==report.get("boundedCodeWindows"),
            "count of independently checked original windows differs from manifest")
    return {
      "schemaVersion":1,
      "target":"SM-G986U1/G986U1UESCHXL1",
      "scope":"ORIGINAL_IMAGE_FRAME_INSTRUCTION_OBSERVATIONS_ONLY",
      "originalKernelSha256":gate.STOCK_SHA,
      "originalImageIndependentlyRehashedByThisTool":True,
      "recoveredNmSha256":digest(nm),
      "upstreamWindowManifestSha256":None,
      "codeWindowsVerified":found,
      "requestedSymbols":EXPECTED_COUNT,
      "functions":reviewed,
      "exactOriginalCompilerStackObjectsKnown":False,
      "danglingWaiterToSendmsgAliasVerified":False,
      "runtimeKernelStackReuseVerified":False,
      "ghostLockPrimitiveVerified":False,
      "temporaryRootVerified":False,
      "kernelSuLoaded":False,
      "deviceModified":False,
      "status":"ORIGINAL_CODE_ATTESTED_STACK_RELATIONSHIP_UNPROVEN",
    }

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--kernel",type=Path,default=prior.DEFAULT_IMAGE)
    parser.add_argument("--nm",type=Path,default=prior.DEFAULT_NM)
    parser.add_argument("--output",type=Path,required=True)
    opts=parser.parse_args()
    try:
        report_path=opts.report.expanduser().absolute()
        output=opts.output.expanduser().absolute()
        kernel=opts.kernel.expanduser().absolute()
        nm=opts.nm.expanduser().absolute()
        source=SOURCE.resolve()
        root=REPO.resolve()
        require(not output.exists() and not output.is_symlink() and
                root not in output.parents and source not in output.parents and
                output not in (root,source,kernel,nm,report_path),
                "output must be new and outside source / existing evidence")
        original_report=read_regular(report_path,MAX_REPORT)
        manifest=json.loads(original_report)
        result=audit(manifest,read_regular(kernel,60*1024*1024),
                     read_regular(nm,gate.MAX_NM_BYTES),report_path.parent)
        result["upstreamWindowManifestSha256"]=digest(original_report)
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x",encoding="utf-8") as fp:
            json.dump(result,fp,indent=2)
            fp.write("\n")
        print("[ORIGINAL CODE WINDOWS ATTESTED]",result["codeWindowsVerified"],
              "/",result["requestedSymbols"])
        print("[WAITER/SENDMSG STACK ALIAS, ROOT, KERNELSU] NOT VERIFIED")
        print("[REPORT]",output)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
