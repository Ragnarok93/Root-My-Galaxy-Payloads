#!/usr/bin/env python3
"""Verify 4 real HXL1 EnvDxe protocol methods and decode direct AArch64 calls.

Original firmware PE and REA/Ghidra evidence only; zero execution on S20+.
A raw window is NOT necessarily one complete function. Function boundaries,
PE relocations, callback return ABI and live DRAM still need separate proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_ram_registration_callback import audit as parent_audit
from tools.y2q_hxl1_envdxe_entry_strings import (
    PE_SHA256, REPORT_DIR, ExtractionError, evidence_json, COORD,
)
from tools.y2q_hxl1_envdxe_rea_xrefs import source_info
from tools.y2q_abl_linuxloader_extract import identify_pe

WINDOW=128
EXPECTED_SLOTS=(
    ("method-08",1,"0x1ee8"),
    ("method-10",2,"0x1f0c"),
    ("get-ram-partitions",3,"0x1f74"),
    ("method-20",4,"0x1f28"),
)
EXPECTED_NONPOINTER=("0x10001","0x10001")
ADDITIONAL_CODE_LEADS=(("callback-bl-callee", "0x52cc"),)
CALLBACK_FIRST64_SHA="7d4e16e4b3402ff3959080b7ca298f46c5b9b963b6ddd59203a613948d0d12ef"
GET_RAM_CALL_TARGET="0x52cc"
MAX_REPORT_BYTES=1024*1024
REFS=(
    ("callback-static-xrefs","0x1f74"),
    ("callback-callee-xrefs","0x52cc"),
)

def signed(value,bits):
    value&=(1<<bits)-1
    return value-(1<<bits) if value&(1<<(bits-1)) else value

def arm64_edges(raw:bytes,base:int)->list[dict]:
    """Minimal architecture-defined direct-control-flow decoder, no inference of live execution."""
    if len(raw)%4:
        raise ExtractionError("Unaligned ARM64 instruction window")
    edges=[]
    for delta in range(0,len(raw),4):
        w=struct.unpack_from("<I",raw,delta)[0]
        at=base+delta
        op=None
        disp=0
        if w&0xfc000000 == 0x94000000:
            op="BL"
            disp=signed(w&0x03ffffff,26)*4
        elif w&0xfc000000 == 0x14000000:
            op="B"
            disp=signed(w&0x03ffffff,26)*4
        elif w&0xff000010 == 0x54000000:
            op="B.cond"
            disp=signed((w>>5)&0x7ffff,19)*4
        elif w&0x7e000000 == 0x34000000:
            op="CBZ" if not(w&(1<<24)) else "CBNZ"
            disp=signed((w>>5)&0x7ffff,19)*4
        elif w&0x7e000000 == 0x36000000:
            op="TBZ" if not(w&(1<<24)) else "TBNZ"
            disp=signed((w>>5)&0x3fff,14)*4
        elif w&0xfffffc1f == 0xd65f0000:
            op="RET"
        elif w&0xfffffc1f == 0xd63f0000:
            op="BLR"
        elif w&0xfffffc1f == 0xd61f0000:
            op="BR"
        if op:
            edges.append({
                "instructionAddress":hex(at),"rawWord":f"0x{w:08x}",
                "mnemonicClass":op,
                "directBranchTarget":hex(at+disp) if op in ("BL","B","B.cond","CBZ","CBNZ","TBZ","TBNZ") else None,
                "runtimeExecutionObserved":False,
            })
    return edges


def authenticated_parent(folder:Path)->dict:
    p=parent_audit(folder)
    if p.get("exactOriginalEnvDxeSha256")!=PE_SHA256:
        raise ExtractionError("Parent original EnvDxe SHA mismatch")
    if (p.get("runtimeRegistrationSuccessful") is not False or
        p.get("runtimeRamPartitionTableMeasured") is not False or
        p.get("kernelPhysicalLoadMeasured") is not False):
        raise ExtractionError("Parent improperly promotes static provider to runtime")
    info=p.get("protocolInterfaceStructure")
    if not isinstance(info,dict):
        raise ExtractionError("Original 48-byte interface result missing")
    expect=["0x10001","0x1ee8","0x1f0c","0x1f74","0x1f28","0x10001"]
    if info.get("qwordsHex")!=expect or info.get("getRamPartitionsSlotStaticAddress")!="0xd1e8":
        raise ExtractionError("HXL1 interface qword layout changed from original REA readback")
    if info.get("getRamPartitionsSlotRawQword")!="0x1f74":
        raise ExtractionError("Original Ghidra GetRamPartitions pointer not 0x1f74")
    imported=p.get("originalCallbackGhidraReadback")
    if (not isinstance(imported,dict) or
        imported.get("importedBytesEqualOriginal") is not True or
        imported.get("bytesSha256")!=CALLBACK_FIRST64_SHA):
        raise ExtractionError("Original callback first 64 bytes not independently corroborated")
    return p


def original_window(folder:Path,addr:str,size:int=WINDOW)->dict:
    if (not isinstance(addr,str) or COORD.fullmatch(addr) is None or
        not isinstance(size,int) or size<=0 or size>4096 or size%4 or
        int(addr,16)%4):
        raise ExtractionError("Invalid ARM64 static window coordinate/size")
    source=source_info(folder)
    raw=Path(source["efiFile"]).read_bytes()
    pe=identify_pe(raw)
    if not isinstance(pe,dict) or pe.get("sha256")!=PE_SHA256:
        raise ExtractionError("Original EnvDxe PE identity changed")
    imagebase=int(pe["preferredImageBase"],16)
    rva=int(addr,16)-imagebase
    if rva<0:
        raise ExtractionError("PE callback static coordinate below preferred image base")
    nt=struct.unpack_from("<I",raw,0x3c)[0]
    count=struct.unpack_from("<H",raw,nt+6)[0]
    opt=struct.unpack_from("<H",raw,nt+20)[0]
    table=nt+24+opt
    candidates=[]
    for i in range(count):
        sec=table+i*40
        if sec+40>len(raw):
            raise ExtractionError("Original PE section table truncated")
        vsize,sec_rva,rawsize,rawpos=struct.unpack_from("<IIII",raw,sec+8)
        flags=struct.unpack_from("<I",raw,sec+36)[0]
        offset=rva-sec_rva
        if 0<=offset and offset+size<=rawsize:
            seek=rawpos+offset
            if seek+size>len(raw):
                raise ExtractionError("Original PE raw section exceeds PE file")
            candidates.append((sec,seek,flags))
    if len(candidates)!=1:
        raise ExtractionError("Original ARM64 static window does not uniquely map into PE")
    sec,offset,flags=candidates[0]
    if not flags&0x20000000:
        raise ExtractionError("Original callback window not within PE executable section")
    data=raw[offset:offset+size]
    return {
        "staticAddress":addr,"size":size,"sectionName":
            raw[sec:sec+8].split(b"\0",1)[0].decode("ascii","replace"),
        "peFileOffset":hex(offset),"bytesHex":data.hex(),
        "sha256":hashlib.sha256(data).hexdigest(),
        "originalEnvDxePeSha256":PE_SHA256,
        "edges":arm64_edges(data,int(addr,16)),
        "windowIsCompleteFunction":False,
        "liveKernelOrDramAddress":False,
    }


def imported_window(folder:Path,label:str,addr:str,original:dict)->dict:
    ev=evidence_json(folder,"rea-envdxe-method-window-"+label+".json")
    if (ev.get("operation")!="read_bytes" or
        ev.get("parameters",{}).get("address")!=addr or
        ev.get("parameters",{}).get("length")!=WINDOW):
        raise ExtractionError("Original Ghidra method window query mismatch: "+label)
    value=ev.get("normalized_result")
    if (not isinstance(value,dict) or value.get("address")!=addr or
        value.get("requested_bytes")!=WINDOW or
        value.get("returned_bytes")!=WINDOW or
        value.get("complete") is not True or
        not isinstance(value.get("bytes_hex"),str) or
        re.fullmatch(r"[0-9a-fA-F]{256}",value["bytes_hex"]) is None):
        raise ExtractionError("Original Ghidra method code window incomplete: "+label)
    if value["bytes_hex"].lower()!=original["bytesHex"]:
        raise ExtractionError("Original firmware/Ghidra imported method bytes differ: "+label)
    return {
        "evidenceId":ev["evidence_id"],"address":addr,
        "originalBytesMatchImported":True,"size":WINDOW,
    }


def references(folder:Path,label:str,addr:str)->dict:
    ev=evidence_json(folder,"rea-envdxe-method-xrefs-"+label+".json")
    if (ev.get("operation")!="xrefs" or
        ev.get("parameters",{}).get("address")!=addr):
        raise ExtractionError("Wrong direct callback reference query")
    obj=ev.get("normalized_result")
    if not isinstance(obj,list) or len(obj)>5000 or not all(
        isinstance(v,str) and COORD.fullmatch(v) for v in obj
    ):
        raise ExtractionError("Invalid direct callback reference list")
    return {"target":addr,"count":len(obj),
            "sources":list(dict.fromkeys(obj)),"evidenceId":ev["evidence_id"],
            "runtimeCallerObserved":False}


def slot_bounded_edges(entries:list[dict])->list[dict]:
    """Do not attribute a neighbor's branch to an overlapping 128-byte window.

    The first three provisional upper bounds are the next function pointer in
    ascending executable-address order. The final pointer's provisional end
    is one instruction after its final observed RET in its current 128-byte
    window. These are observation bounds, NOT Ghidra-established function
    extents and not proof of control-flow reachability.
    """
    ordered=sorted(entries,key=lambda e:int(e["originalCode"]["staticAddress"],16))
    for index,item in enumerate(ordered):
        raw=item["originalCode"]
        start=int(raw["staticAddress"],16)
        if index+1<len(ordered):
            stop=int(ordered[index+1]["originalCode"]["staticAddress"],16)
            source="next-protocol-method-entry"
        else:
            rets=[int(edge["instructionAddress"],16) for edge in raw["edges"]
                  if edge["mnemonicClass"]=="RET" and
                  int(edge["instructionAddress"],16)>=start]
            if not rets:
                raise ExtractionError("Final EFI RAM callback has no observed return boundary")
            stop=max(rets)+4
            source="last-observed-ret-in-128-byte-window"
        if stop<=start or stop>start+raw["size"] or stop%4:
            raise ExtractionError("Invalid provisional method window attribution limit")
        own=[e for e in raw["edges"]
             if start<=int(e["instructionAddress"],16)<stop]
        overlap=[e for e in raw["edges"] if int(e["instructionAddress"],16)>=stop]
        item["boundedInterpretation"]={
            "entry":hex(start),"exclusiveUpperBound":hex(stop),
            "boundarySource":source,
            "inRegionControlFlow":own,
            "overlappingNeighborInstructionsNotAttributed":overlap,
            "boundaryIsVerifiedGhidraFunctionEnd":False,
            "dynamicCallGraphProven":False,
        }
    return entries


def report(folder:Path,allow_missing:bool=True)->dict:
    parent=authenticated_parent(folder)
    entries=[]
    for label,index,at in EXPECTED_SLOTS:
        src=original_window(folder,at)
        imported=None
        name="rea-envdxe-method-window-"+label+".json"
        path=folder/name
        if path.exists() or path.is_symlink():
            imported=imported_window(folder,label,at,src)
        elif not allow_missing:
            raise ExtractionError("Missing original Ghidra method window read: "+label)
        entries.append({"role":label,"protocolQwordIndex":index,
                        "protocolOffset":hex(index*8),
                        "originalCode":src,"ghidraCode":imported,
                        "allEdgesAreStatic":True})
    slot_bounded_edges(entries)
    callback=next(e for e in entries if e["role"]=="get-ram-partitions")
    targets=[edge["directBranchTarget"]
             for edge in callback["boundedInterpretation"]["inRegionControlFlow"]
             if edge["mnemonicClass"]=="BL"]
    if GET_RAM_CALL_TARGET not in targets:
        raise ExtractionError("Original GetRamPartitions AArch64 BL 0x52cc not established")
    direct_callees=[]
    for label,at in ADDITIONAL_CODE_LEADS:
        proof=original_window(folder,at)
        name="rea-envdxe-method-window-"+label+".json"
        imported=(imported_window(folder,label,at,proof)
                  if (folder/name).exists() or (folder/name).is_symlink()
                  else None)
        direct_callees.append({"label":label,"fromVerifiedBlAt":"0x1fa4",
                              "code":proof,"ghidraCode":imported,
                              "functionExtentInferred":False})
    refs=[]
    for label,at in REFS:
        path=folder/("rea-envdxe-method-xrefs-"+label+".json")
        if path.exists() or path.is_symlink():
            refs.append(references(folder,label,at))
    return {
        "classification":"ORIGINAL_HXL1_RAMPARTITION_FOUR_METHOD_AARCH64_STATIC_TRACE",
        "sha256PinnedEnvDxe":PE_SHA256,
        "originalInterfaceEvidenceId":
            parent["protocolInterfaceStructure"]["shaPinnedOriginalGhidraEvidenceId"],
        "methods":entries,"directCalleeCode":direct_callees,
        "verifiedGetRamPartitionsDirectCallee":GET_RAM_CALL_TARGET,
        "additionalTargetedXrefs":refs,
        "livePhysicalMemoryObserved":False,
        "callbackRuntimeInvocationObserved":False,
        "privilegeEscalationDemonstrated":False,
        "kernelSuInstalled":False,
    }


def markdown(report:dict)->str:
    rows=["# Original HXL1 EnvDxe: four EFI RAM interface methods (ARM64)",
          "","Exact original PE SHA256: "+report["sha256PinnedEnvDxe"],"",
          "Static GetRamPartitions direct BL target: "+
          report["verifiedGetRamPartitionsDirectCallee"],"",
          "These are 128-byte windows, NOT verified complete function extents.",
          "No runtime address, call or SMEM data is observed.",""]
    for item in report["methods"]:
        src=item["originalCode"]
        rows+=["## "+item["role"]+" at "+src["staticAddress"],"",
               "Protocol interface offset: "+item["protocolOffset"],
               "Original PE offset: "+src["peFileOffset"],
               "Original executable section: "+src["sectionName"],
               "128 original bytes SHA256: "+src["sha256"],
               "Original bytes: "+src["bytesHex"],
               "Imported Ghidra byte agreement: "+
               str(item["ghidraCode"] is not None),""]
        if item["ghidraCode"] is not None:
            rows+=["REA evidence: "+item["ghidraCode"]["evidenceId"],""]
        bounded=item["boundedInterpretation"]
        rows+=["Provisional method interval: ["+bounded["entry"]+","+
               bounded["exclusiveUpperBound"]+")",
               "Bound established by: "+bounded["boundarySource"],
               "This is NOT a validated Ghidra function extent.","",
               "| Instruction | Class | Static target |",
               "|---|---|---|"]
        for edge in bounded["inRegionControlFlow"]:
            rows+=["| "+edge["instructionAddress"]+" | "+edge["mnemonicClass"]+
                   " | "+str(edge["directBranchTarget"])+" |"]
        rows+=["","Overlapping window instructions NOT attributed to this method: "+
               str(len(bounded["overlappingNeighborInstructionsNotAttributed"])),""]
    rows+=["## Follow direct ARM64 BL 0x1fa4 -> 0x52cc",""]
    for callee in report["directCalleeCode"]:
        code=callee["code"]
        rows+=["### "+callee["label"],"",
               "Static PE address: "+code["staticAddress"],
               "Original PE file offset: "+code["peFileOffset"],
               "Executable section: "+code["sectionName"],
               "128-byte SHA256: "+code["sha256"],
               "Original bytes: "+code["bytesHex"],
               "Ghidra import matches: "+str(callee["ghidraCode"] is not None)]
        if callee["ghidraCode"] is not None:
            rows+=["Ghidra REA evidence: "+callee["ghidraCode"]["evidenceId"]]
        rows+=[""]
        for edge in code["edges"]:
            rows+=["- "+edge["instructionAddress"]+": "+edge["mnemonicClass"]+
                   " => "+str(edge["directBranchTarget"])]
        rows+=[""]
    rows+=["## Targeted static xrefs",""]
    for x in report["additionalTargetedXrefs"]:
        rows+=["- "+x["target"]+": "+str(x["count"])+
               " direct references, evidence "+x["evidenceId"]]
    rows+=["","## Remaining proof obligations","",
           "Ghidra does not define a procedure at 0x1f74, even though the",
           "original executable ARM64 instructions and branch targets exist.",
           "The direct callee 0x52cc is a code lead, not proof of the",
           "callback's full return structure or runtime invocation.",
           "Physical kernel load, KASLR, GhostLock and KernelSU remain unknown.",""]
    return "\n".join(rows)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out",type=Path,default=REPORT_DIR)
    ap.add_argument("--verify",choices=[a for a,_,_ in EXPECTED_SLOTS]+
                    [a for a,_ in ADDITIONAL_CODE_LEADS]+[a for a,_ in REFS])
    args=ap.parse_args()
    try:
        if args.verify:
            if args.verify in (a for a,_,_ in EXPECTED_SLOTS):
                label,_,at=next(x for x in EXPECTED_SLOTS if x[0]==args.verify)
                src=original_window(args.out,at)
                imported=imported_window(args.out,label,at,src)
                print("[METHOD VERIFIED]",label,at,imported["evidenceId"])
            elif args.verify in (a for a,_ in ADDITIONAL_CODE_LEADS):
                label,at=next(x for x in ADDITIONAL_CODE_LEADS if x[0]==args.verify)
                src=original_window(args.out,at)
                imported=imported_window(args.out,label,at,src)
                print("[DIRECT CALLEE VERIFIED]",label,at,imported["evidenceId"])
            else:
                label,at=next(x for x in REFS if x[0]==args.verify)
                ref=references(args.out,label,at)
                print("[REFS VERIFIED]",label,ref["count"])
            return 0
        value=report(args.out)
        (args.out/"rea-envdxe-four-method-arm64.json").write_text(
            json.dumps(value,indent=2)+"\n")
        (args.out/"rea-envdxe-four-method-arm64.md").write_text(markdown(value))
    except (ExtractionError,OSError,ValueError,KeyError,StopIteration) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for item in value["methods"]:
        code=item["originalCode"]
        print("[ORIGINAL AARCH64]",item["role"],code["staticAddress"],
              "edges",len(code["edges"]),
              "Ghidra match",item["ghidraCode"] is not None)
        for edge in item["boundedInterpretation"]["inRegionControlFlow"]:
            if edge["mnemonicClass"]=="BL":
                print("  [BL OWN PROVISIONAL INTERVAL]",edge["instructionAddress"],edge["directBranchTarget"])
    for item in value["directCalleeCode"]:
        print("[BL TARGET ORIGINAL EXECUTABLE]",item["label"],
              item["code"]["staticAddress"],
              "Ghidra match",item["ghidraCode"] is not None)
    print("[REPORT]",args.out/"rea-envdxe-four-method-arm64.md")
    print("[LIMIT] Static interface and direct instructions; no runtime physical kernel or root")
    return 0


if __name__=="__main__":
    sys.exit(main())
