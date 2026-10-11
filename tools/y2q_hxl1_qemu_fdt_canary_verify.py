#!/usr/bin/env python3
"""Offline proof that a diagnostic FDT self-memreserve reached ARM QEMU guest.

This checks an actual binary DTB captured from a paused original kernel
entry after -dtb <canary>. It DOES NOT verify a new free/secure physical
pool, Linux memblock, UH behaviour, Samsung hardware, or KernelSU.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_entry_fdt_audit as entry
from tools import y2q_hxl1_qemu_fdt_canary as canary
from tools import y2q_hxl1_qemu_virt_dtb_inventory as fdt

BASELINE_RUNTIME_SHA="e842cd6cc6b7fc391420bd571dd0f9af3aec7f223101367ddcf14853bd3a7814"
MARKER="HXL1_CANARY_DUMP_COMPLETED BYTES=1048576"
TARGET="SM-G986U1/G986U1UESCHXL1"


class DeliveryError(ValueError):
    pass


def report_delivery(source:bytes, override:bytes, baseline_runtime:bytes,
                    delivered:bytes, gdb:str, manifest:dict,
                    strict_sha:bool=True)->dict:
    if len(delivered)!=canary.FDT_SIZE:
        raise DeliveryError("Incomplete guest FDT binary dump")
    gen=fdt.parse_fdt(source)
    patched=fdt.parse_fdt(override)
    baseline=fdt.parse_fdt(baseline_runtime)
    guest=fdt.parse_fdt(delivered)
    if strict_sha and gen["qemuGeneratedFdtSha256"]!=canary.SOURCE_SHA:
        raise DeliveryError("Generated FDT does not match original owner's SHA")
    if strict_sha and baseline["qemuGeneratedFdtSha256"]!=BASELINE_RUNTIME_SHA:
        raise DeliveryError("Original runtime FDT does not match owner's SHA")
    expected_override,expected=canary.make_canary(source,check_pinned=strict_sha)
    if override!=expected_override:
        raise DeliveryError("The custom -dtb file contains changes beyond the one canary")
    if manifest.get("overrideFdtSha256")!=patched["qemuGeneratedFdtSha256"] or (
       manifest.get("purpose")!="FDT_SELF_RESERVATION_DELIVERY_CANARY_NOT_RKP_POOL"):
        raise DeliveryError("Original canary construction manifest does not match DTB")
    if gdb.count(MARKER)!=1:
        raise DeliveryError("GDB did not attest one complete guest FDT dump")
    stop=entry.parse_gdb(gdb)
    if stop.get("status")!="GUEST_ENTRY_FDT_HEADER_CORRELATED" or (
        stop.get("registers")!={"X0":hex(canary.FDT_PA),
                                "X1":"0x0","X2":"0x0","X3":"0x0"}):
        raise DeliveryError("Original HXL1 guest entry or X0 boot protocol not verified")
    if stop.get("first16BytesHex")!=delivered[:16].hex():
        raise DeliveryError("GDB entry FDT header and full binary dump disagree")
    guest_total=guest["fdtTotalBytes"]
    if guest_total>len(delivered):
        raise DeliveryError("Delivered FDT total size exceeds complete saved buffer")
    expected_reserved=[expected["addedMemreserve"]]
    if guest["memoryReservationEntries"]!=expected_reserved:
        raise DeliveryError("Canary self-reservation not present exactly in guest FDT")
    if len(guest["memoryRanges"])!=1 or (
        guest["memoryRanges"][0]["start"]!=hex(canary.EXPECTED_RAM_START) or
        guest["memoryRanges"][0]["endExclusive"]!=hex(canary.EXPECTED_RAM_END)):
        raise DeliveryError("Delivered guest RAM differs from verified QEMU virt profile")
    fields=("memoryRanges","reservedMemoryRanges",
            "dynamicReservedMemoryRequests","reservedMemoryNodePresent")
    for key in fields:
        if baseline.get(key)!=guest.get(key):
            raise DeliveryError("Guest FDT drift outside memreserve: "+key)
    # The self-reserve address only qualifies if it still covers the guest's
    # measured X0+totalsize. It cannot reserve a new free RKP pool.
    fdt_start=canary.FDT_PA
    fdt_end=fdt_start+guest_total
    if not (fdt_start>=canary.FDT_PA and
            fdt_end<=canary.FDT_PA+canary.FDT_SIZE):
        raise DeliveryError("Canary does not cover delivered device-tree bytes")

    return {
        "target":TARGET,
        "sourceGeneratedSha256":gen["qemuGeneratedFdtSha256"],
        "originalRuntimeSha256":baseline["qemuGeneratedFdtSha256"],
        "overrideCanarySha256":patched["qemuGeneratedFdtSha256"],
        "deliveredGuestFdtSha256":guest["qemuGeneratedFdtSha256"],
        "deliveredGuestFdtPhysicalAddress":hex(canary.FDT_PA),
        "deliveredGuestFdtTotalSize":guest_total,
        "deliveredSelfReservation":guest["memoryReservationEntries"][0],
        "sameBaseGuestMemoryAsOwnerBaseline":True,
        "selfReservationSeenAtOriginalImageEntry":True,
        "runtimeChosenDifferences":{
            "baseline":baseline["chosenInitrd"],
            "canary":guest["chosenInitrd"],
        },
        "diagnosticCanaryDelivered":True,
        "hxl1RkpProtectedPoolReserved":False,
        "linuxMemblockReservationObserved":False,
        "guestMmuPageTableMappingVerified":False,
        "originalFactoryImageModified":False,
        "note":"This is only a *self-reservation* of previously occupied "
               "FDT pages, not a safe RAM carveout, functioning UH emulation, "
               "guest Linux memblock proof, physical bootloader unlock or root.",
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--generated",type=Path,
                   default=root/"qemu-virt-dtb-20261011/qemu-virt.dtb")
    p.add_argument("--baseline-runtime",type=Path,
                   default=root/"qemu-runtime-fdt-20261011/runtime-fdt.dtb")
    p.add_argument("--canary-dir",type=Path,
                   default=root/"qemu-memreserve-canary-20261011")
    p.add_argument("--delivery-dir",type=Path,
                   default=root/"qemu-fdt-canary-delivery-20261011")
    p.add_argument("--output",type=Path)
    a=p.parse_args()
    src=a.generated
    baseline=a.baseline_runtime
    can=a.canary_dir
    delivered=a.delivery_dir
    out=a.output or (delivered/"canary-delivery-audit.json")
    try:
        sources=(src,baseline,can/"canary-override.dtb",
                 can/"canary-construction.json",delivered/"delivered-fdt.dtb",
                 delivered/"gdb-session.log")
        out=out.expanduser().absolute()
        if out.suffix!=".json" or out.exists() or out in [
            s.expanduser().absolute() for s in sources]:
            raise DeliveryError("Use a fresh .json output; preserve all originals")
        for file in sources:
            if not file.is_file() or file.is_symlink():
                raise DeliveryError("Missing or symlinked input: "+str(file))
        if (delivered/"gdb-session.log").stat().st_size>128*1024:
            raise DeliveryError("Oversized GDB session text")
        result=report_delivery(
            src.read_bytes(),(can/"canary-override.dtb").read_bytes(),
            baseline.read_bytes(),(delivered/"delivered-fdt.dtb").read_bytes(),
            (delivered/"gdb-session.log").read_text(errors="replace"),
            json.loads((can/"canary-construction.json").read_text()))
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
        print("[GUEST CANARY]",result["deliveredSelfReservation"])
        print("[DELIVERED AT X0]",result["deliveredGuestFdtPhysicalAddress"])
        print("[MEMRESERVE REACHED KERNEL ENTRY] YES")
        print("[SECURE RKP MEMORY RESERVED] NO")
        print("[LINUX MEMBLOCK VERIFIED] NO")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
