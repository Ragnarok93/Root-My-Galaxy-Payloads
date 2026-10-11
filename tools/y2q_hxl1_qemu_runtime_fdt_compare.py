#!/usr/bin/env python3
"""Read-only original HXL1 full runtime-FDT vs generated-QEMU FDT comparison.

Requires a second SHA-pinned, halted-at-entry QEMU GDB session containing
the FULL FDT bytes. Does not infer RKP usable RAM from DTB gaps or silently
equate generated QEMU DTB bytes with the runtime bootloader FDT.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_entry_fdt_audit as entry
from tools import y2q_hxl1_qemu_boot_memory_audit as boot
from tools import y2q_hxl1_qemu_virt_dtb_inventory as fdt

EXPECTED_GUEST_PA=0x48000000
EXPECTED_BYTES=1048576
COMPLETE_MARKER="HXL1_RUNTIME_FDT_DUMP_COMPLETED BYTES=1048576"
RAM_START=0x40000000
RAM_END=0xc0000000
TARGET="SM-G986U1/G986U1UESCHXL1"


class RuntimeFdtError(ValueError):
    pass


def check_prior(prior:dict, generated:dict, gen_raw:bytes)->dict:
    if prior.get("target")!=TARGET or prior.get("sourceFactoryImageSha256")!=entry.PINNED_IMAGE_SHA:
        raise RuntimeFdtError("Entry evidence is not from original pinned HXL1 factory Image")
    if prior.get("sourceGeneratedQemuDtbSha256")!=entry.PINNED_DTB_SHA:
        raise RuntimeFdtError("Entry evidence is not from the original QEMU generated DTB")
    if generated.get("qemuGeneratedFdtSha256")!=entry.PINNED_DTB_SHA:
        raise RuntimeFdtError("Generated FDT content does not match pinned SHA")
    if fdt.parse_fdt(gen_raw)["qemuGeneratedFdtSha256"]!=entry.PINNED_DTB_SHA:
        raise RuntimeFdtError("Generated FDT bytes are not pinned")
    earlier=prior.get("entry",{})
    if earlier.get("status")!="GUEST_ENTRY_FDT_HEADER_CORRELATED" or not earlier.get("guestFdtPointerValidated"):
        raise RuntimeFdtError("Original GDB entry X0/FDT header was never verified")
    if earlier.get("registers",{}).get("X0")!=hex(EXPECTED_GUEST_PA):
        raise RuntimeFdtError("Previous guest X0 differs from observed address")
    if earlier.get("registers",{}).get("X1")!="0x0" or (
        earlier.get("registers",{}).get("X2")!="0x0" or earlier.get("registers",{}).get("X3")!="0x0"):
        raise RuntimeFdtError("Original boot protocol X1-X3 were not zero")
    if earlier.get("fdtHeader",{}).get("totalSizeBytes")!=EXPECTED_BYTES:
        raise RuntimeFdtError("Original GDB FDT header size differs from exactly captured 1MiB")
    if prior.get("runtimeFdtPhysicalInterval")!={
        "start":hex(EXPECTED_GUEST_PA),
        "endExclusive":hex(EXPECTED_GUEST_PA+EXPECTED_BYTES),
        "sizeBytes":EXPECTED_BYTES
    }:
        raise RuntimeFdtError("Original FDT physical span was not verified")
    return earlier


def compare_runtime(prior:dict, generated_bytes:bytes, runtime_bytes:bytes,
                    gdb_text:str)->dict:
    if len(runtime_bytes)!=EXPECTED_BYTES:
        raise RuntimeFdtError("Runtime FDT capture is not the exact 1MiB original guest header size")
    generated=fdt.parse_fdt(generated_bytes)
    earlier=check_prior(prior,generated,generated_bytes)
    if gdb_text.count(COMPLETE_MARKER)!=1:
        raise RuntimeFdtError("GDB did not uniquely confirm completion of the full read")
    current=entry.parse_gdb(gdb_text)
    if current.get("status")!="GUEST_ENTRY_FDT_HEADER_CORRELATED":
        raise RuntimeFdtError("New GDB guest PC/X0/FDT header not validated")
    if current.get("registers")!=earlier.get("registers"):
        raise RuntimeFdtError("Current guest entry registers differ from prior verified boot")
    if current.get("first16BytesHex")!=earlier.get("first16BytesHex"):
        raise RuntimeFdtError("Runtime FDT header differs from previously observed 16 bytes")
    if current.get("first16BytesHex")!=runtime_bytes[:16].hex():
        raise RuntimeFdtError("GDB printed FDT header does not match saved runtime FDT file")
    runtime=fdt.parse_fdt(runtime_bytes)
    if runtime["fdtTotalBytes"]!=EXPECTED_BYTES:
        raise RuntimeFdtError("Saved guest FDT declared size differs from original X0 header")
    if runtime["memoryRanges"]!=generated["memoryRanges"]:
        raise RuntimeFdtError("Guest runtime RAM layout differs from the generated virt profile")
    if len(runtime["memoryRanges"])!=1 or runtime["memoryRanges"][0]["start"]!=hex(RAM_START) or (
            runtime["memoryRanges"][0]["endExclusive"]!=hex(RAM_END)):
        raise RuntimeFdtError("Guest runtime FDT is not the original 2GiB RAM profile")

    source=prior.get("candidateImageSpan",{})
    if not (source.get("start") and source.get("endExclusive")):
        raise RuntimeFdtError("Missing prior kernel Image footprint hypothesis")
    fdt_start=EXPECTED_GUEST_PA
    fdt_end=fdt_start+EXPECTED_BYTES
    overlap=entry.interval_overlap(fdt_start,fdt_end,
                                   int(source["start"],16),
                                   int(source["endExclusive"],16))
    summary_keys=(
        "memoryRanges","memoryReservationEntries","reservedMemoryNodePresent",
        "reservedMemoryRanges","dynamicReservedMemoryRequests",
        "chosenInitrd","nodeCount",
    )
    differences={
        k:{"generated":generated[k],"runtime":runtime[k]}
        for k in summary_keys if generated.get(k)!=runtime.get(k)
    }
    return {
        "target":TARGET,
        "originalKernelSha256":entry.PINNED_IMAGE_SHA,
        "originalGeneratedFdtSha256":entry.PINNED_DTB_SHA,
        "runtimeFdtSha256":runtime["qemuGeneratedFdtSha256"],
        "runtimeFdtByteIdenticalToGenerated":(
            runtime["qemuGeneratedFdtSha256"]==generated["qemuGeneratedFdtSha256"]),
        "runtimeFdtPhysicalSpan":{"start":hex(fdt_start),
                                  "endExclusive":hex(fdt_end),
                                  "sizeBytes":EXPECTED_BYTES},
        "runtimeHeaderMatchesBothEntryGdbRuns":True,
        "guestRamProfileMatches":True,
        "runtimeMemoryReservationEntries":runtime["memoryReservationEntries"],
        "runtimeReservedMemoryNodes":runtime["reservedMemoryRanges"],
        "runtimeDynamicReservedMemoryRequests":runtime["dynamicReservedMemoryRequests"],
        "runtimeChosenInitrd":runtime["chosenInitrd"],
        "generatedChosenInitrd":generated["chosenInitrd"],
        "semanticInventoryDifferences":differences,
        "candidateImageOverlapWithRuntimeFdt":overlap,
        "sourceGeneratedFdtNodeCount":generated["nodeCount"],
        "sourceRuntimeFdtNodeCount":runtime["nodeCount"],
        "fullRuntimeFdtCapturedAndParsed":True,
        "actualKernelMemblockStateCaptured":False,
        "guestRuntimePageTablesCaptured":False,
        "actualReservedProtectedPoolConfirmed":False,
        "qemuRkpMemoryAdapterReady":False,
        "note":"Complete FDT bytes read at entry do not imply Linux memblock "
               "or any HXL1 UH RKP protected memory pool was actually reserved. "
               "No guest writes, firmware modifications, root, or KernelSU.",
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    home=Path.home()/"s20-artifacts/hxl1-research"
    captured=home/"qemu-runtime-fdt-20261011"
    generated=home/"qemu-virt-dtb-20261011"
    p.add_argument("--entry-report",type=Path,
                   default=home/"qemu-entry-fdt-20261011/entry-fdt-audit.json")
    p.add_argument("--gdb-log",type=Path,default=captured/"gdb-session.log")
    p.add_argument("--runtime-dtb",type=Path,default=captured/"runtime-fdt.dtb")
    p.add_argument("--generated-dtb",type=Path,default=generated/"qemu-virt.dtb")
    p.add_argument("--output",type=Path,
                   default=captured/"runtime-fdt-comparison.json")
    a=p.parse_args()
    try:
        files=(a.entry_report,a.gdb_log,a.runtime_dtb,a.generated_dtb)
        dest=a.output.expanduser().absolute()
        if dest.suffix!=".json" or dest.exists() or (
            dest in (f.expanduser().absolute() for f in files)):
            raise RuntimeFdtError("Choose a fresh output; do not overwrite original data")
        for file in files:
            if not file.is_file() or file.is_symlink():
                raise RuntimeFdtError("Original input missing or symlinked: "+str(file))
        if a.gdb_log.stat().st_size>128*1024:
            raise RuntimeFdtError("Unexpectedly large GDB text log")
        if a.runtime_dtb.stat().st_size!=EXPECTED_BYTES:
            raise RuntimeFdtError("Incomplete or unexpectedly sized guest memory capture")
        source=json.loads(a.entry_report.read_text())
        report=compare_runtime(source,a.generated_dtb.read_bytes(),
                               a.runtime_dtb.read_bytes(),
                               a.gdb_log.read_text(errors="replace"))
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(report,indent=2)+"\n")
        print("[GUEST FDT]",report["runtimeFdtPhysicalSpan"])
        print("[GUEST FDT SHA256]",report["runtimeFdtSha256"])
        print("[BYTE IDENTICAL TO dumpdtb]",report["runtimeFdtByteIdenticalToGenerated"])
        print("[SEMANTIC DIFFERENCES]",",".join(report["semanticInventoryDifferences"]) or "[none]")
        print("[RUNTIME MEMRESERVE]",len(report["runtimeMemoryReservationEntries"]))
        print("[RUNTIME /reserved-memory]",len(report["runtimeReservedMemoryNodes"]))
        print("[KERNEL IMAGE OVERLAP]",report["candidateImageOverlapWithRuntimeFdt"])
        print("[RKP POOL RESERVED] NO")
        print("[REPORT]",dest)
        return 0
    except (OSError,ValueError,TypeError,KeyError,OverflowError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
