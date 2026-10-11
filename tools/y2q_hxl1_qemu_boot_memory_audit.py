#!/usr/bin/env python3
"""Offline HXL1 QEMU virt boot-memory conflict audit.

Combines the SHA-pinned *original* ARM64 Image and captured, unmodified
QEMU-generated FDT to report occupied/possibly occupied spans; never guesses
a suitable RKP pool from apparently unreserved RAM. Never boots, flashes,
modifies an FDT or writes guest memory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_earlyboot_triage as image_probe
from tools import y2q_hxl1_qemu_virt_dtb_inventory as dtb_probe

EXPECTED_DTB_SHA = "85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87"
OBSERVED_IMAGE_PC = 0x40080000
PAGE = 4096
TARGET = "SM-G986U1/G986U1UESCHXL1"


class AuditError(ValueError):
    pass


def parse_interval(entry: dict, reason: str, provenance: str) -> dict:
    try:
        start = int(entry["start"], 16)
        end = int(entry["endExclusive"], 16)
    except (KeyError, TypeError, ValueError) as e:
        raise AuditError("Invalid region in " + reason) from e
    if start < 0 or end > 1 << 64 or start >= end:
        raise AuditError("Invalid non-empty physical interval: " + reason)
    return {"start": hex(start), "endExclusive": hex(end),
            "sizeBytes": end-start, "description": reason,
            "provenance": provenance}


def intersections(interval: dict, ram: list[dict]) -> list[dict]:
    lo = int(interval["start"], 16)
    hi = int(interval["endExclusive"], 16)
    found = []
    for r in ram:
        a = max(lo, int(r["start"], 16))
        b = min(hi, int(r["endExclusive"], 16))
        if a < b:
            found.append({"start": hex(a), "endExclusive": hex(b),
                          "bytes": b-a})
    return found


def image_span(metadata: dict) -> dict:
    """Trace-correlated low PC is an address hypothesis, not a loaded PA proof."""
    raw = metadata["size"]
    hdr = int(metadata["imageSize"], 16)
    if raw <= 0 or hdr < 0:
        raise AuditError("Invalid ARM64 Image size")
    footprint = max(raw, hdr)
    if OBSERVED_IMAGE_PC+footprint > 1 << 64:
        raise AuditError("Image placement overflows guest physical address space")
    return {
        "start": hex(OBSERVED_IMAGE_PC),
        "endExclusive": hex(OBSERVED_IMAGE_PC+footprint),
        "maxOfFileAndHeaderImageSize": footprint,
        "kernelFileBytes": raw, "kernelHeaderImageSizeBytes": hdr,
        "textOffsetBytes": int(metadata["textOffset"],16),
        "status": "POSSIBLE_QEMU_IMAGE_PLACEMENT_NOT_PHYSICALLY_ATTESTED",
        "warning": "Lower guest PC original-image correlation does not alone "
                   "prove QEMU's complete loader / BSS / init-time footprint."
    }


def validate_fdt(fdt_bytes: bytes, inventory: dict) -> dict:
    if not isinstance(inventory, dict):
        raise AuditError("Missing inventory")
    parsed = dtb_probe.parse_fdt(fdt_bytes)
    digest = parsed["qemuGeneratedFdtSha256"]
    if inventory.get("qemuGeneratedFdtSha256") != digest:
        raise AuditError("Prior FDT inventory hash does not match original DTB")
    for key in ("memoryRanges","memoryReservationEntries","reservedMemoryRanges",
                "dynamicReservedMemoryRequests","chosenInitrd"):
        if inventory.get(key) != parsed.get(key):
            raise AuditError("Inventory disagrees with original DTB in "+key)
    # Verifies the actual user's captured generated FDT and detects profile drift.
    return parsed


def audit(image_meta: dict, fdt: dict) -> dict:
    if image_meta.get("sha256") != image_probe.STOCK_SHA256:
        raise AuditError("Not the SHA-pinned HXL1 Image")
    if not fdt.get("memoryRanges"):
        raise AuditError("No FDT RAM ranges")
    ram = [parse_interval(r,"QEMU-generated /memory",
                          "DTB memory.reg, not reservation")
           for r in fdt["memoryRanges"]]
    for idx,a in enumerate(ram):
        if any(intersections(a,[b]) for b in ram[:idx]):
            raise AuditError("Overlapping FDT memory ranges")
    reservations = [
        parse_interval(r,"FDT memreserve","DTB reserve-map entry")
        for r in fdt["memoryReservationEntries"]
    ]
    reservations += [
        parse_interval(r, r.get("node", "reserved-memory"),
                       "DTB /reserved-memory child reg")
        for r in fdt["reservedMemoryRanges"]
    ]
    image = image_span(image_meta)
    image_inside = intersections(
        {"start":image["start"],"endExclusive":image["endExclusive"]},ram)
    image_inside_bytes = sum(r["bytes"] for r in image_inside)
    if image_inside_bytes != image["maxOfFileAndHeaderImageSize"]:
        raise AuditError("Candidate image file/header span not fully within RAM")
    chosen = fdt["chosenInitrd"]
    initrd = None
    if chosen:
        if "linux,initrd-start" not in chosen or "linux,initrd-end" not in chosen:
            raise AuditError("Only one /chosen initrd bound is present")
        start=int(chosen["linux,initrd-start"],16)
        end=int(chosen["linux,initrd-end"],16)
        if start>=end:
            raise AuditError("Invalid /chosen initrd span")
        initrd = {"start":hex(start),"endExclusive":hex(end),
                  "bytes":end-start,"source":"/chosen (not independently verified)"}
    warnings = [
        "No DTB reservation means no HXL1 protected pool is reserved.",
        "Original Image low-PC correlation does not establish the complete physical "
        "footprint, BSS, loader, page tables or memblock state.",
        "The FDT is a generated *disk blob*, not the runtime DTB physical address.",
        "No FDT address, kernel stack, initrd, kernel BSS or live memblock placement "
        "can be inferred by choosing a gap in RAM.",
        "No SMC memory write or QEMU source-hypervisor component has been installed.",
    ]
    return {
        "target":TARGET,"inputKernelSha256":image_meta["sha256"],
        "inputFdtSha256":fdt["qemuGeneratedFdtSha256"],
        "ram":ram,
        "ramBytesAdvertised":sum(int(r["sizeBytes"]) for r in ram),
        "fdtMemreserveAndReservedMemory":reservations,
        "fdtDynamicReservationRequests":fdt["dynamicReservedMemoryRequests"],
        "fdtReservationCount":len(reservations),
        "candidateOriginalImageSpan":image,
        "candidateOriginalImageInsideRam":image_inside,
        "dtbChosenInitrd":initrd,
        "unknownGuestPhysicalPlacements":[
            "runtime FDT guest physical address", "early page tables",
            "original Image expanded/BSS/heap use", "Linux memblock state",
            "QEMU loader temporary regions and boot stack",
            "Samsung UH secure firmware / protected pool",
        ],
        "hxl1ProtectedPoolAlreadyReserved":False,
        "canChooseCarveoutFromFdtAlone":False,
        "sourceFaithfulGuestMemoryAdapterReady":False,
        "noKernelOrDeviceModification":True,
        "warnings":warnings,
        "nextEvidenceGate":"Independently measure runtime FDT address/size, exact "
            "loaded Image footprint and early memblock reservations, then introduce "
            "a real pre-Linux memory reservation that the guest confirms. Do not "
            "select a protected pool from apparent unused RAM."
    }


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    base=Path.home()/"s20-artifacts/hxl1-research/qemu-virt-dtb-20261011"
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--dtb",type=Path,default=base/"qemu-virt.dtb")
    p.add_argument("--inventory",type=Path,default=base/"qemu-virt-inventory.json")
    p.add_argument("--output",type=Path,default=base/"boot-memory-conflict-audit.json")
    a=p.parse_args()
    try:
        out=a.output.expanduser().absolute()
        files=(a.kernel,a.dtb,a.inventory)
        if (out.exists() or out.suffix!=".json" or
            out in (x.expanduser().absolute() for x in files)):
            raise AuditError("Output must be fresh JSON, never overwrite original evidence")
        for file in files:
            if not file.is_file() or file.is_symlink():
                raise AuditError("Evidence input missing or symlinked: "+str(file))
        meta=image_probe.image_metadata(a.kernel)
        raw=a.dtb.read_bytes()
        inventory=json.loads(a.inventory.read_text())
        parsed=validate_fdt(raw,inventory)
        report=audit(meta,parsed)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(report,indent=2)+"\n")
        print("[STOCK]",report["inputKernelSha256"])
        print("[DTB]",report["inputFdtSha256"])
        print("[RAM BYTES]",report["ramBytesAdvertised"])
        for r in report["ram"]:
            print("[RAM]",r["start"],r["endExclusive"])
        image=report["candidateOriginalImageSpan"]
        print("[ORIGINAL IMAGE PROBABLE SPAN]",image["start"],
              image["endExclusive"],"status:",image["status"])
        print("[FDT RESERVATIONS]",report["fdtReservationCount"])
        print("[PROTECTED POOL VERIFIED] NO")
        print("[OUTPUT]",out)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
