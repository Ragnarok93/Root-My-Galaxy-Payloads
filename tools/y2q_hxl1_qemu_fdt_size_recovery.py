#!/usr/bin/env python3
"""Prepare SHA-pinned compact DTB input to test the ARM64 2MiB FDT boot limit.

No guest memory writes, image patches, RKP pool or phone operations.
QEMU may expand this input, so guest size must be independently captured.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_virt_dtb_inventory as fdt
from tools import y2q_hxl1_qemu_fdt_canary as canary

ARM64_LIMIT=2*1024*1024
OWNER_V3_GUEST_BYTES=2117184
ALIGNMENT=8

class RecoveryError(ValueError):
    pass

def compact_source(source:bytes,strict_pin:bool=True)->tuple[bytes,dict]:
    parsed=fdt.parse_fdt(source)
    if strict_pin and parsed["qemuGeneratedFdtSha256"]!=canary.SOURCE_SHA:
        raise RecoveryError("Exact original generated QEMU FDT hash mismatch")
    if len(source)!=parsed["fdtTotalBytes"]:
        raise RecoveryError("Source declared size and actual bytes differ")
    if (parsed["memoryReservationEntries"] or parsed["reservedMemoryRanges"] or
        len(parsed["memoryRanges"])!=1 or
        parsed["memoryRanges"][0]["start"]!="0x40000000" or
        parsed["memoryRanges"][0]["endExclusive"]!="0xc0000000"):
        raise RecoveryError("Generated source is not the known unreserved 2GiB QEMU DTB")
    magic,total,ost,ostr,ors,ver,compat,boot,nstr,nst=struct.unpack_from(">10I",source)
    if (ost%4 or ors%8 or min(ost,ostr,ors)<fdt.HEADER_SIZE or
        max(ost+nst,ostr+nstr,ors+16)>len(source)):
        raise RecoveryError("Bad FDT offsets")
    pos=ors
    while pos+16<=len(source):
        addr,size=struct.unpack_from(">QQ",source,pos)
        pos+=16
        if (addr,size)==(0,0):break
    else:
        raise RecoveryError("Unterminated reservation list")
    minimum=max(fdt.HEADER_SIZE,pos,ost+nst,ostr+nstr)
    end=(minimum+ALIGNMENT-1)&~(ALIGNMENT-1)
    if end>len(source) or any(source[end:]):
        raise RecoveryError("Cannot safely discard nonzero trailing FDT data")
    result=bytearray(source[:end])
    struct.pack_into(">I",result,4,end)
    shortened=bytes(result)
    check=fdt.parse_fdt(shortened)
    stable=("memoryRanges","memoryReservationEntries","reservedMemoryRanges",
            "dynamicReservedMemoryRequests","reservedMemoryNodePresent",
            "chosenInitrd","nodeCount","rootAddressCells","rootSizeCells")
    if any(parsed[key]!=check[key] for key in stable):
        raise RecoveryError("FDT structure changed during padding trim")
    if (shortened[ost:ost+nst]!=source[ost:ost+nst] or
        shortened[ostr:ostr+nstr]!=source[ostr:ostr+nstr]):
        raise RecoveryError("FDT source structure or property strings mutated")
    return shortened, {
        "sourceSha256":parsed["qemuGeneratedFdtSha256"],
        "originalBytes":len(source),"compactBytes":end,
        "removedVerifiedZeroPaddingBytes":len(source)-end,
        "compactSha256":hashlib.sha256(shortened).hexdigest(),
        "originalStructureBytesPreserved":True,
        "originalStringsBytesPreserved":True}

def build_recovery(source:bytes,strict_pin:bool=True)->tuple[bytes,dict]:
    smaller,pre=compact_source(source,strict_pin)
    if len(smaller)>=len(source):
        raise RecoveryError("No removable trailing padding; no meaningful compact test")
    # 2MiB is a diagnostic FDT self-reservation cap, NOT secure RKP memory.
    compact,record=canary.make_canary(
        smaller,check_pinned=False,self_reserve_bytes=ARM64_LIMIT)
    if len(compact)>=ARM64_LIMIT:
        raise RecoveryError("Compact input still violates ARM64 early-FDT size budget")
    return compact,{**pre,
        "purpose":"UNDER_2M_ARM64_EARLY_FDT_SIZE_DIAGNOSTIC",
        "overrideSha256":record["overrideFdtSha256"],
        "overrideBytes":len(compact),
        "maxArm64FdtBytes":ARM64_LIMIT,
        "ownerMeasuredV3GuestBytes":OWNER_V3_GUEST_BYTES,
        "ownerV3BytesOverLimit":OWNER_V3_GUEST_BYTES-ARM64_LIMIT,
        "diagnosticFdtSelfReserve":record["addedMemreserve"],
        "qemuGuestRuntimeFdtSizeVerified":False,
        "guestLinuxMemblockAllocatorExclusionVerified":False,
        "secureRkpPoolReserved":False,
        "factoryKernelModified":False,
        "physicalDeviceTouched":False}

def verify_recovery(source:bytes,dtb:bytes,manifest:dict,strict_pin:bool=True)->dict:
    recreated,expected=build_recovery(source,strict_pin)
    if dtb!=recreated or manifest!=expected:
        raise RecoveryError("Manifest or compact FDT differs from exact source reconstruction")
    return expected

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--source",type=Path,default=root/"qemu-virt-dtb-20261011/qemu-virt.dtb")
    p.add_argument("--output-dir",type=Path,default=root/"qemu-fdt-under-2m-20261012")
    p.add_argument("--verify-dir",type=Path)
    a=p.parse_args()
    try:
        if not a.source.is_file() or a.source.is_symlink():
            raise RecoveryError("Missing or symlinked original generated DTB")
        orig=a.source.read_bytes()
        if a.verify_dir:
            out=a.verify_dir.expanduser().absolute()
            dtb=out/"compact-override.dtb"
            manifest=out/"compact-manifest.json"
            if any(not x.is_file() or x.is_symlink() for x in (dtb,manifest)):
                raise RecoveryError("Missing or symlinked recovery evidence")
            r=verify_recovery(orig,dtb.read_bytes(),json.loads(manifest.read_text()))
            print("[COMPACT RECONSTRUCTION PASS]",r["overrideSha256"])
            return 0
        out=a.output_dir.expanduser().absolute()
        if out.exists() or out.is_symlink():
            raise RecoveryError("Output directory exists; original evidence immutable")
        if out==a.source.expanduser().absolute().parent:
            raise RecoveryError("Never place diagnostics inside pinned source directory")
        compact,r=build_recovery(orig)
        out.mkdir(parents=True,exist_ok=False)
        (out/"compact-override.dtb").write_bytes(compact)
        (out/"compact-manifest.json").write_text(json.dumps(r,indent=2)+"\n")
        print("[SOURCE DTB BYTES]",r["originalBytes"])
        print("[SOURCE ZERO PADDING TRIMMED]",r["removedVerifiedZeroPaddingBytes"])
        print("[COMPACT OVERRIDE BYTES]",r["overrideBytes"])
        print("[ARM64 EARLY FDT LIMIT]",r["maxArm64FdtBytes"])
        print("[SOURCE SHA]",r["overrideSha256"])
        print("[DIAGNOSTIC FDT SELF-RESERVE]",r["diagnosticFdtSelfReserve"])
        print("[RUNTIME GUEST FDT UNDER 2MiB] NOT YET VERIFIED")
        print("[OUTPUT]",out/"compact-override.dtb")
        return 0
    except (RecoveryError,OSError,ValueError,TypeError,KeyError,struct.error) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
