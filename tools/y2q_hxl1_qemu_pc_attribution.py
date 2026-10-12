#!/usr/bin/env python3
"""Attribute a repeatedly sampled HXL1 QMP guest PC to pinned factory Image.

Read-only: correlate saved QMP register snapshots to exact OEM Image opcode
bytes, a reconstructed symbol map and candidate read-only ASCII strings.
Never claim kernel progress, a live guest instruction, an infinite loop,
bootloader status, memblock state, RKP reservation, or handset root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_memblock_pc_sampler as sampler
from tools import y2q_hxl1_qemu_fault_sites as sites

TARGET="SM-G986U1/G986U1UESCHXL1"
PC_FROM_OWNER_QMP=0xffffff800a60514c
IMAGE_BASE=gate.VM_BASE
MAX_JSON=320*1024
MAX_NM=16*1024*1024
REG_RE=re.compile(r"(?<!\S)X([0-2][0-9]|30)=([0-9a-fA-F]{16})(?![0-9a-fA-F])")
HEX_PC_RE=re.compile(r"^0x[0-9a-f]{8,16}$")
REG_NAMES=("X00","X01","X02","X03","X13","X14","X16","X20","X21","X29","X30")

class PcAttributionError(ValueError):
    pass


def verify_sample_report(document:dict,expected_pc:int|None=None)->dict:
    if document.get("target")!=TARGET or document.get("factorySha256")!=gate.KERNEL_SHA:
        raise PcAttributionError("Saved QMP report not pinned to original factory HXL1 Image")
    if document.get("mode") not in ("baseline","v3-canary"):
        raise PcAttributionError("Unexpected QEMU machine profile")
    if document.get("samplingError"):
        raise PcAttributionError("QMP sampling reported an error")
    samples=document.get("samples")
    if not isinstance(samples,list) or not 2<=len(samples)<=8:
        raise PcAttributionError("Need two to eight independent QMP CPU samples")
    pcs=[]
    register_sets=[]
    for row in samples:
        if row.get("runStatus")!="running":
            raise PcAttributionError("CPU sample not marked running")
        original=row.get("registers")
        if not isinstance(original,dict) or original.get("rawTruncated"):
            raise PcAttributionError("Raw register snapshot missing or truncated")
        text=original.get("raw")
        if not isinstance(text,str) or len(text)>sampler.MAX_RAW:
            raise PcAttributionError("Missing or oversized raw QMP register text")
        repro=sampler.register_snapshot(text)
        if repro["pcMatches"]!=1 or repro["pc"]!=original.get("pc"):
            raise PcAttributionError("QMP PC inconsistent with retained raw text")
        if not HEX_PC_RE.fullmatch(repro["pc"]):
            raise PcAttributionError("Invalid guest PC string")
        found={}
        for match in REG_RE.finditer(text):
            key="X"+match.group(1)
            if key in found:
                raise PcAttributionError("Duplicate guest register "+key)
            found[key]=int(match.group(2),16)
        if "X16" not in found or "X30" not in found:
            raise PcAttributionError("Missing indirect branch/link register evidence")
        pcs.append(int(repro["pc"],16))
        register_sets.append(found)
    saved_pcs=document.get("pcSequence")
    if saved_pcs!=[hex(pc) for pc in pcs]:
        raise PcAttributionError("Original PC sequence differs from raw evidence")
    if document.get("status")!=sampler.classify(samples,document["mode"])["status"]:
        raise PcAttributionError("Saved PC classification inconsistent with raw evidence")
    if expected_pc is not None and pcs!=[expected_pc]*len(pcs):
        raise PcAttributionError("PC sequence changed from expected owner observation")
    return {
        "count":len(pcs),
        "samplePcSequence":[hex(x) for x in pcs],
        "uniquePcCount":len(set(pcs)),
        "allRegistersByteIdentical":all(
            register_sets[0]==x for x in register_sets[1:]),
        "registers":register_sets[0],
        "qmpStatus":document["status"],
        "mode":document["mode"],
    }


def candidate_ascii(image:bytes,va:int,limit:int=128)->dict:
    offset=va-IMAGE_BASE
    record={"address":hex(va),"candidateImageOffset":hex(offset),
            "status":"NOT_ESTABLISHED","source":"FACTORY_IMAGE_BYTES_NOT_LIVE_GUEST_MEMORY"}
    if offset<0 or offset>=len(image):
        record["status"]="NOT_BACKED_BY_ORIGINAL_IMAGE_FILE"
        return record
    raw=image[offset:min(len(image),offset+limit+1)]
    end=raw.find(b"\0")
    if end<0:
        record["status"]="NOT_NULL_TERMINATED_WITHIN_BOUND"
        return record
    value=raw[:end]
    if not value or any(c<0x20 or c>0x7e for c in value):
        record["status"]="NOT_PLAUSIBLE_PRINTABLE_ASCII"
        return record
    record.update(status="CANDIDATE_NULL_TERMINATED_IMAGE_ASCII",
                  value=value.decode("ascii"),length=len(value))
    return record


def decode_gp_fragments(registers:dict)->dict:
    return {
        name:{
            "littleEndianBytesHex":int(registers[name]).to_bytes(8,"little").hex(),
            "printableFragment":"".join(
                chr(b) if 0x20<=b<=0x7e else "."
                for b in int(registers[name]).to_bytes(8,"little")),
            "warning":"Register bytes are not proof of a complete message",
        }
        for name in ("X13","X14") if name in registers
    }


def aarch64_unconditional_branch(opcode:int,pc:int)->dict:
    """Decode only A64 B/BL imm26; avoid interpreting arbitrary instruction."""
    ident=opcode&0xfc000000
    if ident not in (0x14000000,0x94000000):
        return {"status":"NOT_A64_DIRECT_B_OR_BL"}
    imm=opcode&0x03ffffff
    if imm&(1<<25):
        imm-=1<<26
    target=pc+imm*4
    return {"status":"A64_B_OR_BL_IMM26",
            "kind":"B" if ident==0x14000000 else "BL",
            "target":hex(target),
            "directBranchToSelf":target==pc}


def build_report(
    data:dict,image:bytes,symbols:dict,
    disassembler:str|None,
    expected_pc:int|None=PC_FROM_OWNER_QMP,
)->dict:
    gate.valid_source(image)
    verified=verify_sample_report(data,expected_pc)
    if verified["uniquePcCount"]!=1:
        raise PcAttributionError("Multiple PCs: require focused report per original address")
    pc=int(verified["samplePcSequence"][0],16)
    original=sites.window(image,pc,IMAGE_BASE)
    if original.get("status")!="ORIGINAL_STOCK_IMAGE_BYTES_FOUND":
        raise PcAttributionError("Sampled PC outside original SHA-pinned Image")
    opcode=int(original["originalOpcode"],16)
    registers=verified["registers"]
    candidate_pointers={}
    for name in ("X01","X05","X06","X16","X20","X21","X23","X30"):
        if name in registers:
            candidate_pointers[name]=candidate_ascii(image,registers[name])
    pointers_from_pc={
        name:{
            "value":hex(registers[name]),
            "distanceFromPcBytes":registers[name]-pc,
            "nearestRecoveredTextSymbol":sites.nearest_symbol(symbols,registers[name]),
        }
        for name in ("X16","X30") if name in registers
    }
    return {
        "target":TARGET,
        "factoryImageSha256":gate.KERNEL_SHA,
        "sourceQmpSampleStatus":verified["qmpStatus"],
        "sourceQmpMode":verified["mode"],
        "sampleCount":verified["count"],
        "allSampledPcsIdentical":verified["uniquePcCount"]==1,
        "allRetainedGpRegistersIdentical":verified["allRegistersByteIdentical"],
        "sampledPc":hex(pc),
        "reconstructedVmBase":hex(IMAGE_BASE),
        "vmBaseStatus":"RECOVERED_IMAGE_BASE_NOT_INDEPENDENTLY_RUNTIME_ATTESTED",
        "originalImage":original,
        "nearestRecoveredTextSymbol":sites.nearest_symbol(symbols,pc),
        "symbolMapStatus":symbols["status"],
        "symbolMapSha256":symbols.get("sourceSha256"),
        "disassembly":sites.disassemble(original,IMAGE_BASE,disassembler),
        "opcodeDirectBranch":aarch64_unconditional_branch(opcode,pc),
        "nearbyBranchOrLinkRegisters":pointers_from_pc,
        "candidateOriginalImageStringsFromGpPointers":candidate_pointers,
        "asciiRegisterFragments":decode_gp_fragments(registers),
        "entryFdtPointerInX20":(
            hex(registers["X20"])==hex(gate.FDT_PA)
            if "X20" in registers else None),
        "liveGuestInstructionBytesMatched":False,
        "kernelEntryObservedByThisSampler":False,
        "actualGuestHangOrInfiniteLoopProven":False,
        "memblockAllocatorReservationProven":False,
        "rkpProtectedMemoryReserved":False,
        "note":"Host-only original-file correlation. Repeated PC snapshots do not "
               "prove a permanent loop; nearest recovered symbol need not be "
               "the enclosing executed function. Inspect the disassembly and "
               "independently compare guest opcode bytes before diagnosis.",
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    original=root/"qemu-memblock-pc-samples-v3-20261012"
    p.add_argument("--report",type=Path,default=original/"pc-sample-report.json")
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,default=original/"original-pc-attribution.json")
    p.add_argument("--allow-other-pc",action="store_true",
                   help="For fresh evidence from baseline run, not original owner v3 PC")
    a=p.parse_args()
    try:
        dest=a.output.expanduser().absolute()
        inputs=(a.report,a.kernel,a.nm)
        if dest.suffix!=".json" or dest.exists() or dest.is_symlink() or (
              dest in [x.expanduser().absolute() for x in inputs]):
            raise PcAttributionError("Use a fresh JSON output; original evidence must remain")
        if a.report.stat().st_size>MAX_JSON:
            raise PcAttributionError("Original QMP JSON oversized")
        sample=json.loads(gate.checked_file(a.report,MAX_JSON))
        image=gate.checked_file(a.kernel)
        symbols=sites.load_recovered_symbols(a.nm)
        if symbols["status"]!="RECOVERED_NM_SYMBOLS_UNVERIFIED":
            raise PcAttributionError("Missing or unsafe original recovered symbol map")
        disassembler=shutil.which("aarch64-linux-gnu-objdump")
        result=build_report(sample,image,symbols,disassembler,
                            expected_pc=None if a.allow_other_pc else PC_FROM_OWNER_QMP)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(result,indent=2)+"\n")
        print("[ORIGINAL IMAGE]",result["factoryImageSha256"])
        print("[REPEATED PC]",result["sampledPc"])
        print("[IMAGE OFFSET]",result["originalImage"]["candidateImageOffset"])
        print("[FACTORY OPCODE]",result["originalImage"]["originalOpcode"])
        near=result["nearestRecoveredTextSymbol"]
        print("[RECOVERED SYMBOL]",near.get("name","[none]"),
              "distance",near.get("distance","[unknown]"))
        print("[DISASSEMBLY]",result["disassembly"]["status"])
        for name,entry in result["candidateOriginalImageStringsFromGpPointers"].items():
            if entry["status"]=="CANDIDATE_NULL_TERMINATED_IMAGE_ASCII":
                print(f"[{name} IMAGE STRING]",repr(entry["value"]))
        for name,part in result["asciiRegisterFragments"].items():
            print(f"[{name} FRAGMENT]",repr(part["printableFragment"]))
        print("[LOOP PROVEN] NO")
        print("[MEMBLOCK / RKP PROVEN] NO")
        print("[REPORT]",dest)
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
