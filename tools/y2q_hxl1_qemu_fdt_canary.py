#!/usr/bin/env python3
"""Offline diagnostic ARM QEMU FDT self-reservation canary.

Adds ONE FDT memreserve entry covering the *already occupied*, directly
observed entry FDT span at 0x48000000, rounded to its final page, to a SHA-pinned *copy* of
QEMU's original generated DTB. This is NOT a usable RKP pool and is NOT
a suggested free RAM address. No factory Image, guest or handset is changed.
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
from tools import y2q_hxl1_qemu_boot_memory_audit as boot

SOURCE_SHA=boot.EXPECTED_DTB_SHA
FDT_PA=0x48000000
FDT_SIZE=1048576  # previously observed baseline guest FDT length
FDT_PAGE=4096  # confirmed stock HXL1 PAGE_SIZE; reserve final occupied FDT page
EXPECTED_RAM_START=0x40000000
EXPECTED_RAM_END=0xc0000000


class CanaryError(ValueError):
    pass


def make_canary(original:bytes, check_pinned:bool=True,
                self_reserve_bytes:int|None=None)->tuple[bytes,dict]:
    baseline=fdt.parse_fdt(original)
    if check_pinned and baseline["qemuGeneratedFdtSha256"]!=SOURCE_SHA:
        raise CanaryError("Original generated QEMU virt FDT SHA mismatch")
    if baseline["memoryReservationEntries"] or baseline["reservedMemoryRanges"]:
        raise CanaryError("Source already reserves memory; refuse changed baseline")
    if len(baseline["memoryRanges"])!=1 or (
        baseline["memoryRanges"][0]["start"]!=hex(EXPECTED_RAM_START) or
        baseline["memoryRanges"][0]["endExclusive"]!=hex(EXPECTED_RAM_END)):
        raise CanaryError("Source RAM is not the original HXL1 2 GiB QEMU profile")
    if baseline["fdtTotalBytes"]!=len(original):
        raise CanaryError("Source FDT contains trailing or untracked bytes")
    header=list(struct.unpack_from(">10I",original))
    (magic,total,off_struct,off_strings,off_reserve,version,last,
     boot_cpu,size_strings,size_struct)=header
    if off_reserve+16>off_struct:
        raise CanaryError("No space for old reservation terminator")
    if struct.unpack_from(">QQ",original,off_reserve)!=(0,0):
        raise CanaryError("Source reserve map is not empty")
    if total+16>fdt.MAX_DTB:
        raise CanaryError("Modified DTB would be too large")
    override_total=total+16
    fdt_reserved_bytes=(override_total+FDT_PAGE-1)&~(FDT_PAGE-1)
    if self_reserve_bytes is not None:
        if (not isinstance(self_reserve_bytes,int) or
            self_reserve_bytes<FDT_PAGE or
            self_reserve_bytes%FDT_PAGE!=0 or
            self_reserve_bytes>fdt.MAX_DTB):
            raise CanaryError("Requested self-reserve must be page-aligned and <=8MiB")
        if self_reserve_bytes<fdt_reserved_bytes:
            raise CanaryError("Requested self-reserve cannot truncate the override FDT")
        fdt_reserved_bytes=self_reserve_bytes
    if FDT_PA+fdt_reserved_bytes>EXPECTED_RAM_END:
        raise CanaryError("Self-reservation extends beyond guest RAM")
    inserted=struct.pack(">QQ",FDT_PA,fdt_reserved_bytes)
    result=bytearray(original[:off_reserve]+inserted+original[off_reserve:])
    # Preserve every prior FDT structure/name/property byte and all old
    # memreserve table contents; only shift their offsets by 16 bytes.
    struct.pack_into(">I",result,4,total+16)
    struct.pack_into(">I",result,8,off_struct+16)
    struct.pack_into(">I",result,12,off_strings+16)
    patched=bytes(result)
    parsed=fdt.parse_fdt(patched)
    expected=[{"start":hex(FDT_PA),"endExclusive":hex(FDT_PA+fdt_reserved_bytes),
               "sizeBytes":fdt_reserved_bytes}]
    if parsed["memoryReservationEntries"]!=expected:
        raise CanaryError("Canary entry not independently parsed")
    same_fields=("memoryRanges","reservedMemoryRanges",
                 "dynamicReservedMemoryRequests","chosenInitrd",
                 "rootAddressCells","rootSizeCells","nodeCount")
    diffs=[key for key in same_fields if baseline[key]!=parsed[key]]
    if diffs:
        raise CanaryError("Unintended FDT semantic changes: "+", ".join(diffs))
    if patched[off_struct+16:off_struct+16+size_struct]!=(
         original[off_struct:off_struct+size_struct]):
        raise CanaryError("Original QEMU FDT structure bytes changed")
    if patched[off_strings+16:off_strings+16+size_strings]!=(
         original[off_strings:off_strings+size_strings]):
        raise CanaryError("Original QEMU FDT property strings changed")
    return patched,{
        "sourceGeneratedFdtSha256":baseline["qemuGeneratedFdtSha256"],
        "overrideFdtSha256":parsed["qemuGeneratedFdtSha256"],
        "addedMemreserve":expected[0],
        "sourceFdtTotalSizeBytes":total,
        "overrideFdtTotalSizeBytes":override_total,
        "fdtReservationPageAlignment":FDT_PAGE,
        "selfReservationCoversOverrideFdt":True,
        "selfReservationExplicitGuestMeasuredBytes":self_reserve_bytes,\n        "selfReservationReachesObservedRuntimeFdt":None,
        "purpose":"FDT_SELF_RESERVATION_DELIVERY_CANARY_NOT_RKP_POOL",
        "onlyOriginalMemreserveMapChanged":True,
        "originalStructureAndStringsByteIdentical":True,
        "sourceKernelNotModified":True,
        "qemuCanaryDeliveredToGuest":False,
        "linuxMemblockReservedMemoryConfirmed":False,
        "rkpProtectedPoolReserved":False,
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    source=Path.home()/"s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/qemu-virt.dtb"
    output=Path.home()/"s20-artifacts/hxl1-research/qemu-memreserve-canary-20261011"
    p.add_argument("--source",type=Path,default=source)
    p.add_argument("--output-dir",type=Path,default=output)\n    p.add_argument("--self-reserve-bytes",type=int,
                   help="Optional independently measured, 4KiB-aligned guest FDT extent; not an RKP pool")
    a=p.parse_args()
    try:
        if not a.source.is_file() or a.source.is_symlink():
            raise CanaryError("Missing or symlinked source generated DTB")
        out=a.output_dir.expanduser().absolute()
        if out.exists() or out.is_symlink():
            raise CanaryError("Canary output directory already exists; preserve evidence")
        if out==a.source.expanduser().absolute().parent:
            raise CanaryError("Never write into original generated FDT directory")
        patched,record=make_canary(a.source.read_bytes(),
                                   self_reserve_bytes=a.self_reserve_bytes)
        out.mkdir(parents=True,exist_ok=False)
        (out/"canary-override.dtb").write_bytes(patched)
        (out/"canary-construction.json").write_text(json.dumps(record,indent=2)+"\n")
        print("[ORIGINAL]",record["sourceGeneratedFdtSha256"])
        print("[CANARY FDT]",record["overrideFdtSha256"])
        print("[ONLY ADDED MEMRESERVE]",record["addedMemreserve"])
        print("[GUEST DELIVERY VERIFIED] NO")
        print("[GUEST FINAL FDT EXTENT VERIFIED] NO — requires new GDB capture")
        print("[RKP PROTECTED POOL RESERVED] NO")
        print("[OUTPUT]",out/"canary-override.dtb")
        return 0
    except (OSError,ValueError,struct.error,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
