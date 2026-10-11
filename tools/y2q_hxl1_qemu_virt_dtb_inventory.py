#!/usr/bin/env python3
"""Read-only QEMU virt DTB inventory for the original HXL1 guest profile.

Reports literal FDT RAM, memreserve entries, reserved-memory and /chosen.
FDT gaps are *not* free RAM: kernel, FDT, initrd, memblock and future
carveouts require independent validation. NO memory is reserved here.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

MAGIC=0xd00dfeed
BEGIN_NODE=1
END_NODE=2
PROP=3
NOP=4
END=9
HEADER_SIZE=40
MAX_DTB=8*1024*1024
ORIGINAL_SHA="ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"

class FdtError(ValueError):
    pass

def checked_range(start:int, size:int)->dict:
    if size<1 or start<0 or start+size>2**64:
        raise FdtError("Invalid/overflowed guest-physical region")
    return {"start":hex(start),"endExclusive":hex(start+size),"sizeBytes":size}

def cells(value:bytes)->list[int]:
    if len(value)%4:
        raise FdtError("FDT cell data is not 32-bit aligned")
    return [int.from_bytes(value[i:i+4],"big") for i in range(0,len(value),4)]

def reg_pairs(blob:bytes,ac:int,sc:int)->list[dict]:
    if ac not in (1,2) or sc not in (1,2):
        raise FdtError("Unsupported FDT address/size-cell count (must be 1 or 2)")
    words=cells(blob)
    stride=ac+sc
    if len(words)%stride:
        raise FdtError("FDT reg length does not match parent cells")
    result=[]
    for p in range(0,len(words),stride):
        addr=0
        size=0
        for w in words[p:p+ac]:addr=(addr<<32)|w
        for w in words[p+ac:p+stride]:size=(size<<32)|w
        if size:result.append(checked_range(addr,size))
    return result

def parse_fdt(data:bytes)->dict:
    if len(data)<HEADER_SIZE or len(data)>MAX_DTB:
        raise FdtError("Truncated or oversized DTB")
    (magic,total,off_struct,off_strings,off_reserved,version,last_compat,
     boot_cpu,size_strings,size_struct)=struct.unpack_from(">10I",data)
    if magic!=MAGIC or version<16 or last_compat>version:
        raise FdtError("Unexpected FDT magic/version")
    if total<HEADER_SIZE or total>len(data):
        raise FdtError("Invalid declared DTB size")
    for name,off,length in (
        ("structure",off_struct,size_struct),
        ("strings",off_strings,size_strings)):
        if off<HEADER_SIZE or off+length>total:
            raise FdtError(f"Out-of-range FDT {name} block")
    if off_reserved<HEADER_SIZE or off_reserved+16>total:
        raise FdtError("Invalid reservation block")
    if (off_struct&3) or (off_reserved&7):
        raise FdtError("Unaligned FDT sections")
    string_block=data[off_strings:off_strings+size_strings]
    pos=off_reserved
    memreserve=[]
    for _ in range(2048):
        if pos+16>total:raise FdtError("Unterminated FDT memreserve map")
        start,size=struct.unpack_from(">QQ",data,pos)
        pos+=16
        if start==0 and size==0:break
        memreserve.append(checked_range(start,size))
    else:
        raise FdtError("Too many FDT memreserve entries")

    def read_name(offset:int)->str:
        if offset<0 or offset>=len(string_block):raise FdtError("Invalid FDT property name offset")
        end=string_block.find(b"\0",offset)
        if end<0:raise FdtError("Unterminated FDT string")
        return string_block[offset:end].decode("utf-8","replace")
    nodes={}
    stack=[]
    cur=off_struct
    stop=off_struct+size_struct
    ended=False
    for _ in range(250000):
        if cur+4>stop:raise FdtError("Truncated FDT structure")
        token=struct.unpack_from(">I",data,cur)[0]
        cur+=4
        if token==BEGIN_NODE:
            end=data.find(b"\0",cur,stop)
            if end<0:raise FdtError("Unterminated node name")
            name=data[cur:end].decode("utf-8","replace")
            cur=(end+4)&~3
            path=("/"+name) if not stack else stack[-1].rstrip("/")+"/"+name
            if not name and not stack:path="/"
            if path in nodes:raise FdtError("Duplicate FDT node")
            nodes[path]={}
            stack.append(path)
        elif token==END_NODE:
            if not stack:raise FdtError("Unexpected END_NODE")
            stack.pop()
        elif token==PROP:
            if not stack or cur+8>stop:raise FdtError("Invalid FDT property")
            length,name_offset=struct.unpack_from(">II",data,cur)
            cur+=8
            if cur+length>stop:raise FdtError("Property exceeds DTB structure")
            key=read_name(name_offset)
            if key in nodes[stack[-1]]:raise FdtError("Repeated FDT property")
            nodes[stack[-1]][key]=data[cur:cur+length]
            cur=(cur+length+3)&~3
        elif token==NOP:continue
        elif token==END:
            if stack:raise FdtError("FDT ended with open nodes")
            ended=True
            break
        else:raise FdtError(f"Unsupported FDT token {token}")
    if not ended or "/" not in nodes:raise FdtError("Missing FDT_END/root")

    def n_cells(path:str,key:str,default:int)->int:
        raw=nodes[path].get(key)
        if raw is None:return default
        if len(raw)!=4:raise FdtError("Invalid address/size cells property")
        return struct.unpack(">I",raw)[0]
    def strprop(b:bytes)->str:
        return b.split(b"\0",1)[0].decode("utf-8","replace")

    root_ac=n_cells("/","#address-cells",2)
    root_sc=n_cells("/","#size-cells",1)
    memory=[]
    for path,props in nodes.items():
        if path.count("/")!=1:continue
        if path.startswith("/memory@") or path=="/memory" or (
            strprop(props.get("device_type",b""))=="memory"):
            for r in reg_pairs(props.get("reg",b""),root_ac,root_sc):
                memory.append({"node":path,**r})
    reserved=[]
    dynamic=[]
    found_reserved="/reserved-memory" in nodes
    if found_reserved:
        res_ac=n_cells("/reserved-memory","#address-cells",root_ac)
        res_sc=n_cells("/reserved-memory","#size-cells",root_sc)
        for path,props in nodes.items():
            if not path.startswith("/reserved-memory/") or path.count("/")!=2:
                continue
            if "reg" in props:
                for r in reg_pairs(props["reg"],res_ac,res_sc):
                    reserved.append({"node":path,**r})
            elif "size" in props:
                dynamic.append({"node":path,"requestedSizeBytes":
                                int.from_bytes(props["size"],"big")})
    chosen=nodes.get("/chosen",{})
    initrd={}
    for prop in ("linux,initrd-start","linux,initrd-end"):
        if prop in chosen and len(chosen[prop]) in (4,8):
            initrd[prop]=hex(int.from_bytes(chosen[prop],"big"))
    return {
        "qemuGeneratedFdtSha256":hashlib.sha256(data[:total]).hexdigest(),
        "fdtTotalBytes":total,
        "cpuBootIdFromHeader":boot_cpu,
        "rootAddressCells":root_ac,"rootSizeCells":root_sc,
        "memoryRanges":memory,
        "memoryReservationEntries":memreserve,
        "reservedMemoryNodePresent":found_reserved,
        "reservedMemoryRanges":reserved,
        "dynamicReservedMemoryRequests":dynamic,
        "chosenInitrd":initrd,
        "nodeCount":len(nodes),
        "suitableProtectedPoolProven":False,
        "guestLinuxMemblockReservationProven":False,
        "kernelFdtInitrdOverlapExcluded":False,
        "warning":"The DTB does NOT identify empty or safely usable RAM. "
                  "All unlisted guest RAM may be occupied by kernel, allocator, "
                  "initrd, FDT, runtime device allocations, or other regions.",
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    default=Path.home()/"s20-artifacts/hxl1-research/qemu-virt-dtb-20261011"
    p.add_argument("--dtb",type=Path,default=default/"qemu-virt.dtb")
    p.add_argument("--output",type=Path,default=default/"qemu-virt-inventory.json")
    a=p.parse_args()
    try:
        out=a.output.expanduser().absolute()
        if out.exists() or out.suffix!=".json" or out==a.dtb.expanduser().absolute():
            raise FdtError("Choose a fresh JSON output, preserving all evidence")
        if not a.dtb.is_file() or a.dtb.is_symlink():
            raise FdtError("DTB evidence missing or symlinked")
        report=parse_fdt(a.dtb.read_bytes())
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(report,indent=2)+"\n")
        print("[DTB SHA256]",report["qemuGeneratedFdtSha256"])
        for r in report["memoryRanges"]:
            print("[MEMORY]",r["node"],r["start"],r["endExclusive"])
        for r in report["memoryReservationEntries"]:
            print("[MEMRESERVE]",r["start"],r["endExclusive"])
        for r in report["reservedMemoryRanges"]:
            print("[RESERVED]",r["node"],r["start"],r["endExclusive"])
        for r in report["dynamicReservedMemoryRequests"]:
            print("[DYNAMIC RESERVATION]",r["node"],r["requestedSizeBytes"])
        print("[RAM RESERVATION VERIFIED] NO")
        print("[REPORT]",out)
        return 0 if report["memoryRanges"] else 3
    except (OSError,ValueError,struct.error) as e:
        print("[STOP]",e,file=sys.stderr);return 2

if __name__=="__main__":
    raise SystemExit(main())
