#!/usr/bin/env python3
"""Offline stock HXL1 embedded DTB-format inventory (no device access).

Only identifies bounded FDT v17 header candidates and common container magic.
Does not infer hardware RAM layout, chosen DTB, physical Linux load address,
bootloader relocation, KASLR, exploit offsets, or kernel-root compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from tools.y2q_stock_boot_v2_audit import PINS, AuditError, boot_header, pinned

FDT_MAGIC = b"\xd0\x0d\xfe\xed"
DT_TABLE_MAGIC = b"\xd7\xb7\xab\x1e"
MAX_CANDIDATES = 4096


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def check_fdt_header(blob: bytes, at: int) -> dict | None:
    if at < 0 or at + 40 > len(blob) or blob[at:at + 4] != FDT_MAGIC:
        return None
    (magic, total, off_struct, off_strings, off_reserved, version,
     last_compatible, cpuid, strings_size, struct_size) = struct.unpack_from(">10I", blob, at)
    if not (version >= 17 and last_compatible <= 17 and
            0 < struct_size and 0 < strings_size and
            40 <= off_reserved < off_struct < total and
            40 <= off_strings < total and
            off_struct % 4 == 0 and off_strings % 4 == 0 and
            total <= len(blob) - at and
            struct_size <= total - off_struct and
            strings_size <= total - off_strings):
        return None
    if blob[at + off_struct:at + off_struct + 4] != b"\x00\x00\x00\x01":
        return None
    if blob[at + off_struct + struct_size - 4:at + off_struct + struct_size] != (
        b"\x00\x00\x00\x09"
    ):
        return None
    if blob[at + off_strings] != 0:
        return None
    # The mem-reservation map must terminate with two zero 64-bit values.
    reservation = blob[at + off_reserved:at + off_struct]
    if len(reservation) < 16 or not any(
        reservation[i:i + 16] == b"\x00" * 16
        for i in range(0, len(reservation) - 15, 16)
    ):
        return None
    return {
        "offsetWithinDtbRegion": at, "totalSize": total,
        "dtbSha256": digest(blob[at:at + total]),
        "version": version, "lastCompatibleVersion": last_compatible,
        "structBlockBytes": struct_size, "stringsBlockBytes": strings_size,
        "headerAndBoundaryChecksPassed": True,
        "fullFdtSemanticTreeVerified": False,
    }


def inventory_dtb_region(blob: bytes) -> dict:
    prefix = blob[:16].hex()
    if blob.startswith(b"QCDT"):
        kind = "QCDT_MAGIC"
    elif blob.startswith(DT_TABLE_MAGIC):
        kind = "ANDROID_DT_TABLE_MAGIC"
    elif blob.startswith(FDT_MAGIC):
        kind = "FDT_MAGIC_AT_START"
    else:
        kind = "UNKNOWN_PREFIX"
    trees = []
    cursor = 0
    occurrences = 0
    while True:
        pos = blob.find(FDT_MAGIC, cursor)
        if pos == -1:
            break
        occurrences += 1
        if occurrences > MAX_CANDIDATES:
            raise AuditError("FDT header candidate count exceeds analysis limit")
        checked = check_fdt_header(blob, pos)
        if checked is not None:
            trees.append(checked)
            # Avoid accepting nested false matches inside the confirmed FDT.
            cursor = pos + checked["totalSize"]
        else:
            cursor = pos + 4
    return {
        "dtbRegionSize": len(blob),
        "prefixFirst16BytesHex": prefix,
        "containerPrefixClass": kind,
        "fdtMagicOccurrencesExamined": occurrences,
        "validatedFdtV17HeaderCount": len(trees),
        "fdtV17Candidates": trees,
        "limit": "Header/bounds check only. No specific device-tree selection or "
                 "actual Android kernel RAM location established.",
    }


def analyze(artifacts: Path) -> dict:
    original = pinned(artifacts / "boot.img", PINS["boot.img"])
    if len(original) != 67108864:
        raise AuditError("unexpected original boot.img size")
    header = boot_header(original)
    region = header["regions"]["dtb"]
    dtb = original[region["offset"]:region["offset"] + region["size"]]
    if digest(dtb) != PINS["dtb.img"]:
        raise AuditError("embedded DTB does not match known original HXL1 pin")
    results = inventory_dtb_region(dtb)
    return {
        "target": "SM-G986U1 G986U1UESCHXL1",
        "source": "SHA256-pinned original boot.img embedded DTB region",
        "bootHeaderVersion": 2, "embeddedDtbOffset": region["offset"],
        "embeddedDtbDeclaredBytes": region["size"],
        "embeddedDtbSha256": digest(dtb),
        "bootHeaderDeclaredDtbAddr": header["declaredAddressFields"]["dtb_addr"],
        "dtbInventory": results,
        "kernelPhysicalHandoffVerified": False,
        "selectedRuntimeDeviceTreeVerified": False,
        "phoneModified": False,
    }


def markdown(report: dict) -> str:
    d = report["dtbInventory"]
    lines = [
        "# HXL1 original boot.img embedded DTB inventory",
        "",
        "**Original boot and embedded DTB SHA256 verified. No runtime address established.**",
        "",
        f"- Embedded offset: 0x{report['embeddedDtbOffset']:x}",
        f"- Embedded bytes: {report['embeddedDtbDeclaredBytes']}",
        f"- Embedded SHA256: {report['embeddedDtbSha256']}",
        f"- Boot-header declared dtb_addr: 0x{report['bootHeaderDeclaredDtbAddr']:x} (not runtime proof)",
        f"- First 16 bytes: {d['prefixFirst16BytesHex']}",
        f"- Container signature: {d['containerPrefixClass']}",
        f"- Validated FDT v17-or-newer headers: {d['validatedFdtV17HeaderCount']}",
        "", "| DTB offset | Total bytes | FDT version | SHA256 |",
        "|---:|---:|---:|---|",
    ]
    for c in d["fdtV17Candidates"]:
        lines.append(
            f"| 0x{c['offsetWithinDtbRegion']:x} | {c['totalSize']} | "
            f"{c['version']} | {c['dtbSha256']} |"
        )
    if not d["fdtV17Candidates"]:
        lines.append("| No validated FDT v17 headers | | | |")
    lines += ["", "Valid FDT header boundaries do not identify which DTB the "
              "original bootloader selected. If no valid headers were found, "
              "classify the wrapper/signature before claiming the DTB is absent.",
              "Stage 4 original Linux physical handoff: OPEN.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=Path.home() / "s20-artifacts")
    parser.add_argument("--output", type=Path, default=Path.home() /
                        "s20-artifacts/hxl1-research/stock-dtb-inventory.json")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    root = args.artifacts.expanduser().resolve()
    if output.suffix != ".json" or output == root / "boot.img":
        parser.error("JSON report must not overwrite original boot.img")
    try:
        report = analyze(root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        output.with_suffix(".md").write_text(markdown(report))
    except (AuditError, OSError, struct.error) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    r = report["dtbInventory"]
    print("[PASS] original boot.img and embedded DTB original SHA256 pins")
    print("[DTB] prefix", r["prefixFirst16BytesHex"],
          "class", r["containerPrefixClass"])
    print("[FDT] valid v17+ header candidates", r["validatedFdtV17HeaderCount"])
    print("[report]", output)
    print("[report]", output.with_suffix(".md"))
    print("[LIMIT] No actual bootloader-selected DTB or Linux physical load identified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
