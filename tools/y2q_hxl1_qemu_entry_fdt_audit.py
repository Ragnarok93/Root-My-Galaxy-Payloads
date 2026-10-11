#!/usr/bin/env python3
"""Offline, read-only HXL1 kernel-entry FDT register/header verification.

Requires original SHA-pinned boot-memory report, QEMU generated FDT blob,
and a bounded GDB capture of the *guest* PC/X0. The first 16 FDT bytes alone
are NOT a complete runtime DTB and do not establish memblock reservations.
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
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_boot_memory_audit as prior

ENTRY_PC=0x40080000
FDT_MAGIC=0xd00dfeed
MAX_GUEST_FDT=8*1024*1024
PINNED_IMAGE_SHA=prior.image_probe.STOCK_SHA256
PINNED_DTB_SHA=prior.EXPECTED_DTB_SHA
RAM_BEGIN=0x40000000
RAM_END=0xc0000000
REG_RE=re.compile(
    r"(?m)^\s*X0=(0x[0-9a-fA-F]+)\s+X1=(0x[0-9a-fA-F]+)\s+"
    r"X2=(0x[0-9a-fA-F]+)\s+X3=(0x[0-9a-fA-F]+)\s*$")
HIT_RE=re.compile(r"(?m)^HXL1_ENTRY_BREAKPOINT_HIT PC=(0x[0-9a-fA-F]+)\s*$")
BYTES_RE=re.compile(r"(?m)^\s*0x([0-9a-fA-F]{6,16}):[ \t]+(.*?)\s*$")
VALUE_RE=re.compile(r"\b0x([0-9a-fA-F]{1,2})\b")


class EntryEvidenceError(ValueError):
    pass


def interval_overlap(lo:int, hi:int, b:int, end:int)->dict|None:
    a=max(lo,b)
    z=min(hi,end)
    return {"start":hex(a),"endExclusive":hex(z),"bytes":z-a} if a<z else None


def parse_gdb(text:str)->dict:
    hits=list(HIT_RE.finditer(text))
    if len(hits)!=1:
        return {"status":"BREAKPOINT_NOT_UNIQUELY_OBSERVED",
                "bootEntryObserved":False,"guestFdtPointerValidated":False}
    pc=int(hits[0].group(1),16)
    if pc!=ENTRY_PC:
        return {"status":"BREAKPOINT_NOT_AT_PINNED_IMAGE_ENTRY",
                "pc":hex(pc),"bootEntryObserved":False,
                "guestFdtPointerValidated":False}
    after=text[hits[0].end():]
    regs=REG_RE.search(after)
    if regs is None:
        return {"status":"ENTRY_HIT_BUT_REGISTER_LINE_MISSING",
                "pc":hex(pc),"bootEntryObserved":True,
                "guestFdtPointerValidated":False}
    x0,x1,x2,x3=(int(regs.group(i),16) for i in range(1,5))
    result={"status":"ENTRY_HIT_FDT_HEADER_UNVERIFIED",
            "pc":hex(pc),
            "registers":{"X0":hex(x0),"X1":hex(x1),"X2":hex(x2),"X3":hex(x3)},
            "bootEntryObserved":True,"guestFdtPointerValidated":False}
    start_marker="FDT_HEADER_AT_X0_START"
    end_marker="FDT_HEADER_AT_X0_END"
    if start_marker not in after or end_marker not in after:
        result["status"]="ENTRY_HIT_BUT_FDT_HEADER_DUMP_MISSING"
        return result
    section=after.split(start_marker,1)[1].split(end_marker,1)[0]
    chunks=[]
    for line in section.splitlines():
        match=BYTES_RE.match(line)
        if match is None:
            continue
        address=int(match.group(1),16)
        raw=match.group(2)
        values=VALUE_RE.findall(raw)
        if not values:
            continue
        if len(values)>16:
            result["status"]="FDT_BYTES_TOO_MANY"
            return result
        chunks.append((address,bytes(int(x,16) for x in values)))
    if not chunks:
        result["status"]="FDT_GUEST_MEMORY_UNREADABLE"
        return result
    position=x0
    first=bytearray()
    for addr,data in chunks:
        if addr!=position:
            result["status"]="FDT_READ_NOT_CONTIGUOUS_FROM_X0"
            return result
        first.extend(data)
        position+=len(data)
    if len(first)!=16:
        result["status"]="FDT_HEADER_INCOMPLETE_OR_EXCESS"
        return result
    result["first16BytesHex"]=first.hex()
    magic,total,struct_off,string_off=struct.unpack(">IIII",first)
    result["fdtHeader"]={
        "magic":hex(magic),"totalSizeBytes":total,
        "structureOffset":hex(struct_off),"stringsOffset":hex(string_off)
    }
    if magic!=FDT_MAGIC:
        result["status"]="GUEST_X0_NOT_AN_FDT_MAGIC"
    elif x0%8 or not (40<=total<=MAX_GUEST_FDT) or (
          not 40<=struct_off<total or not 40<=string_off<total):
        result["status"]="FDT_HEADER_INVALID_OR_UNALIGNED"
    elif x0<RAM_BEGIN or x0+total>RAM_END:
        result["status"]="FDT_NOT_FULLY_CONTAINED_IN_PROFILE_RAM"
    else:
        result["status"]="GUEST_ENTRY_FDT_HEADER_CORRELATED"
        result["guestFdtPointerValidated"]=True
        result["runtimeFdtPhysicalInterval"]={
            "start":hex(x0),"endExclusive":hex(x0+total),
            "sizeBytes":total}
        result["bootProtocolRegistersZero"]=(x1==x2==x3==0)
    return result


def correlate(gdb:dict,boot_audit:dict,dtb_raw:bytes)->dict:
    if boot_audit.get("inputKernelSha256")!=PINNED_IMAGE_SHA:
        raise EntryEvidenceError("Boot-memory report is not the exact HXL1 factory Image")
    if boot_audit.get("inputFdtSha256")!=PINNED_DTB_SHA:
        raise EntryEvidenceError("Boot-memory report is not the pinned QEMU-generated DTB")
    parsed_fdt=prior.dtb_probe.parse_fdt(dtb_raw)
    if parsed_fdt["qemuGeneratedFdtSha256"]!=PINNED_DTB_SHA:
        raise EntryEvidenceError("Original generated DTB bytes changed")
    if boot_audit.get("ramBytesAdvertised")!=2147483648:
        raise EntryEvidenceError("Unexpected QEMU RAM profile")
    if len(boot_audit.get("ram",[]))!=1 or (
        boot_audit["ram"][0].get("start")!=hex(RAM_BEGIN) or
        boot_audit["ram"][0].get("endExclusive")!=hex(RAM_END)):
        raise EntryEvidenceError("Guest RAM range does not match observed QEMU profile")
    result={
        "target":"SM-G986U1/G986U1UESCHXL1",
        "sourceFactoryImageSha256":PINNED_IMAGE_SHA,
        "sourceGeneratedQemuDtbSha256":PINNED_DTB_SHA,
        "entry":gdb,
        "candidateImageSpan":boot_audit["candidateOriginalImageSpan"],
        "guestRuntimeFdtHeaderOnly":True,
        "fullRuntimeFdtShaOrReservationUnverified":True,
        "protectedRkpPoolReservationNotProven":True,
        "qemuRkpGuestMemoryAdapterReady":False,
        "physicalHandsetUntouched":True,
    }
    fdt=gdb.get("runtimeFdtPhysicalInterval")
    image=boot_audit["candidateOriginalImageSpan"]
    if fdt:
        result["candidateImageOverlapWithRuntimeFdt"]=interval_overlap(
            int(fdt["start"],16),int(fdt["endExclusive"],16),
            int(image["start"],16),int(image["endExclusive"],16))
        result["runtimeFdtPhysicalInterval"]=fdt
    else:
        result["candidateImageOverlapWithRuntimeFdt"]=None
    return result


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--gdb",type=Path,
                   default=root/"qemu-entry-fdt-20261011/gdb-session.log")
    p.add_argument("--boot-memory",type=Path,
                   default=root/"qemu-virt-dtb-20261011/boot-memory-conflict-audit.json")
    p.add_argument("--dtb",type=Path,
                   default=root/"qemu-virt-dtb-20261011/qemu-virt.dtb")
    p.add_argument("--output",type=Path,
                   default=root/"qemu-entry-fdt-20261011/entry-fdt-audit.json")
    a=p.parse_args()
    try:
        dest=a.output.expanduser().absolute()
        sources=(a.gdb,a.boot_memory,a.dtb)
        if (dest.suffix!=".json" or dest.exists() or
            dest in [x.expanduser().absolute() for x in sources]):
            raise EntryEvidenceError("Use a fresh JSON output; original evidence immutable")
        for src in sources:
            if not src.is_file() or src.is_symlink():
                raise EntryEvidenceError("Missing or symlinked input: "+str(src))
        if a.gdb.stat().st_size>128*1024:
            raise EntryEvidenceError("Unexpected oversized GDB text log")
        raw=a.dtb.read_bytes()
        report=json.loads(a.boot_memory.read_text())
        parsed=parse_gdb(a.gdb.read_text(errors="replace"))
        result=correlate(parsed,report,raw)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(result,indent=2)+"\n")
        print("[ENTRY]",parsed["status"])
        if "registers" in parsed:
            print("[X0-X3]",parsed["registers"])
        if "runtimeFdtPhysicalInterval" in result:
            print("[RUNTIME FDT CANDIDATE]",result["runtimeFdtPhysicalInterval"])
            print("[IMAGE INTERSECTION]",result["candidateImageOverlapWithRuntimeFdt"])
        print("[PROTECTED MEMORY RESERVED] NO")
        print("[REPORT]",dest)
        return 0 if parsed.get("guestFdtPointerValidated") else 3
    except (OSError,ValueError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
