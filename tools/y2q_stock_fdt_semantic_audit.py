#!/usr/bin/env python3
"""Read-only semantic FDT stream inventory of checksum-pinned original HXL1 DTBs.

Parse FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP and FDT_END with
strict bounds; summarize root model/compatible strings and node counts.
This is OFFLINE firmware identification, NOT determination of boot-time
DTB choice, Linux physical memory map, kernel load or root/payload offsets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_stock_boot_v2_audit import PINS, AuditError, boot_header, pinned
from tools.y2q_stock_dtb_inventory import (EXPECTED_BOOT_FILE_SIZE,
                                             check_fdt_header, digest,
                                             inventory_dtb_region)

FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9
MAX_NODES = 200000
MAX_PROPERTIES = 500000
MAX_DEPTH = 1000
MAX_PROPERTY_STRINGS = 32
MAX_PROPERTY_STRING_BYTES = 4096


def aligned4(x: int) -> int:
    return (x + 3) & ~3


def string_list(value: bytes) -> list[str]:
    # String-valued root properties only; never interpret binary cells as UTF-8.
    if not value or len(value) > MAX_PROPERTY_STRING_BYTES or value[-1] != 0:
        return []
    parts = value[:-1].split(b"\0")
    if len(parts) > MAX_PROPERTY_STRINGS:
        return []
    if any(not p or any(c < 0x20 or c >= 0x7f for c in p)
           for p in parts):
        return []
    return [p.decode("ascii") for p in parts]


def property_name(strings: bytes, at: int) -> str:
    if at >= len(strings):
        raise AuditError("FDT property name offset out of bounds")
    end = strings.find(b"\0", at)
    if end == -1:
        raise AuditError("FDT property name unterminated")
    data = strings[at:end]
    if not data or any(c < 0x20 or c >= 0x7f for c in data):
        raise AuditError("FDT property name not printable ASCII")
    return data.decode("ascii")


def validate_fdt_tree(blob: bytes) -> dict:
    hdr = check_fdt_header(blob, 0)
    if hdr is None or hdr["totalSize"] != len(blob):
        raise AuditError("FDT candidate failed header/full-length check")
    (_magic, _total, off_struct, off_strings, _off_reserved, _ver,
     _last, _cpuid, size_strings, size_struct) = struct.unpack_from(">10I", blob)
    block = blob[off_struct:off_struct + size_struct]
    strings = blob[off_strings:off_strings + size_strings]
    nodes, props, depth, cursor = 0, 0, 0, 0
    root_props: dict[str, list[str]] = {}
    child_names: list[str] = []
    root_identifiers = ("compatible", "model")
    while cursor + 4 <= len(block):
        token = struct.unpack_from(">I", block, cursor)[0]
        cursor += 4
        if token == FDT_BEGIN_NODE:
            end = block.find(b"\0", cursor)
            if end == -1 or end >= len(block):
                raise AuditError("FDT unterminated node name")
            node_raw = block[cursor:end]
            if len(node_raw) > 255 or any(b < 0x20 or b >= 0x7f for b in node_raw):
                raise AuditError("FDT nonprintable/oversized node name")
            name = node_raw.decode("ascii")
            cursor = aligned4(end + 1)
            if cursor > len(block):
                raise AuditError("FDT node padding truncated")
            if depth == 0:
                if nodes or name:
                    raise AuditError("FDT requires exactly one empty-named root node")
            elif depth == 1 and len(child_names) < 40:
                child_names.append(name)
            depth += 1
            nodes += 1
            if depth > MAX_DEPTH or nodes > MAX_NODES:
                raise AuditError("FDT depth/node count limit")
        elif token == FDT_END_NODE:
            if depth == 0:
                raise AuditError("FDT_END_NODE without matching FDT_BEGIN_NODE")
            depth -= 1
        elif token == FDT_PROP:
            if depth < 1 or cursor + 8 > len(block):
                raise AuditError("FDT property outside node or truncated")
            size, nameoff = struct.unpack_from(">II", block, cursor)
            cursor += 8
            if size > len(block) - cursor:
                raise AuditError("FDT property exceeds structure block")
            propname = property_name(strings, nameoff)
            value = block[cursor:cursor + size]
            cursor = aligned4(cursor + size)
            if cursor > len(block):
                raise AuditError("FDT property padding truncated")
            props += 1
            if props > MAX_PROPERTIES:
                raise AuditError("FDT property count limit")
            if depth == 1 and propname in root_identifiers:
                root_props[propname] = string_list(value)
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            if depth != 0 or nodes == 0 or cursor != len(block):
                raise AuditError("FDT_END before fully closed tree or trailing structure data")
            return {
                "fullStructureTokenValidation": "PASS",
                "nodeCount": nodes,
                "propertyCount": props,
                "topLevelChildNamesSample": child_names,
                "rootModel": root_props.get("model", []),
                "rootCompatible": root_props.get("compatible", []),
                "rootModelPropertyPresent": "model" in root_props,
                "rootCompatiblePropertyPresent": "compatible" in root_props,
                "rootPropertyStringDecodeLimitations":
                    "Only bounded printable ASCII NUL-delimited root model/compatible decoded",
                "selectedRuntimeDtbProved": False,
            }
        else:
            raise AuditError(f"invalid FDT structure token 0x{token:x}")
    raise AuditError("FDT structure block lacks final FDT_END")


def audit(root: Path) -> dict:
    original = pinned(root / "boot.img", PINS["boot.img"])
    if len(original) != EXPECTED_BOOT_FILE_SIZE:
        raise AuditError("original boot.img length changed")
    header = boot_header(original)
    region = header["regions"]["dtb"]
    blob = original[region["offset"]:region["offset"] + region["size"]]
    if digest(blob) != PINS["dtb.img"]:
        raise AuditError("embedded DTB SHA256 mismatch from original HXL1 evidence")
    listing = inventory_dtb_region(blob)
    records = []
    for i, candidate in enumerate(listing["fdtV17Candidates"], 1):
        start = candidate["offsetWithinDtbRegion"]
        end = start + candidate["totalSize"]
        tree = blob[start:end]
        item = {
            "index": i,
            "offsetWithinDtbRegion": start,
            "lengthBytes": len(tree),
            "sha256": candidate["dtbSha256"],
        }
        try:
            item.update(validate_fdt_tree(tree))
        except AuditError as exc:
            item.update({
                "fullStructureTokenValidation": "FAILED",
                "parseError": str(exc),
                "selectedRuntimeDtbProved": False,
            })
        records.append(item)
    contiguous = (bool(records) and records[0]["offsetWithinDtbRegion"] == 0
                  and all(records[i]["offsetWithinDtbRegion"]
                          == records[i - 1]["offsetWithinDtbRegion"]
                          + records[i - 1]["lengthBytes"]
                          for i in range(1, len(records)))
                  and records[-1]["offsetWithinDtbRegion"] +
                  records[-1]["lengthBytes"] == len(blob))
    return {
        "target": "SM-G986U1 / G986U1UESCHXL1",
        "originalFirmwareBootAndDtbSha256Verified": True,
        "embeddedDtbRegionSize": len(blob),
        "fdtHeaderCandidates": len(records),
        "contiguousCompleteRegionCoverage": contiguous,
        "candidates": records,
        "allFdtStructuresPass": bool(records) and all(
            r["fullStructureTokenValidation"] == "PASS" for r in records),
        "exactRuntimeSelectedDtbVerified": False,
        "physicalKernelLoadAddressVerified": False,
        "phoneModified": False,
        "warning": "Root model/compatible strings and FDT token structure belong "
                   "to static original firmware candidates only. Neither bootloader "
                   "selection nor effective memory placement is established.",
    }


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 stock DTB — structural validation and root identity",
        "",
        "**Original firmware hashes verified. No runtime selection or kernel base known.**",
        "",
        f"- Header candidates: {report['fdtHeaderCandidates']}",
        f"- Full contiguous DTB region: {report['contiguousCompleteRegionCoverage']}",
        f"- All structural token streams pass: {report['allFdtStructuresPass']}",
        "",
    ]
    for item in report["candidates"]:
        lines += [
            f"## Candidate {item['index']} (0x{item['offsetWithinDtbRegion']:x})",
            "",
            f"- File bytes: {item['lengthBytes']}",
            f"- SHA256: {item['sha256']}",
            f"- Semantic token check: {item['fullStructureTokenValidation']}",
        ]
        if "parseError" in item:
            lines.append(f"- Error: {item['parseError']}")
        else:
            lines += [
                f"- Nodes: {item['nodeCount']}; properties: {item['propertyCount']}",
                "- Root model: " + (", ".join(item["rootModel"]) or "(missing/unreadable)"),
                "- Root compatible: " +
                    (", ".join(item["rootCompatible"]) or "(missing/unreadable)"),
                "- Top-level nodes (sample): " +
                    (", ".join(item["topLevelChildNamesSample"]) or "(none)"),
            ]
        lines.append("")
    lines += [
        "This checks FDT tokens and bounded root identification properties only. "
        "An FDT without a readable root compatible value may still be meaningful; "
        "the small fourth candidate is not automatically a runtime-selectable DTB.",
        "",
        "Original physical kernel load/handoff remains **OPEN**.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", type=Path, default=Path.home() / "s20-artifacts")
    p.add_argument("--output", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/stock-fdt-semantic-audit.json")
    args = p.parse_args()
    root, dest = args.artifacts.expanduser().resolve(), args.output.expanduser().resolve()
    if dest.suffix != ".json" or any(dest == root / n for n in PINS):
        p.error("report destination must be JSON outside original firmware artifacts")
    try:
        report = audit(root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(report, indent=2) + "\n")
        dest.with_suffix(".md").write_text(markdown(report))
    except (OSError, AuditError, struct.error) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[PASS] original boot/DTB original SHA256")
    print("[FDT]", report["fdtHeaderCandidates"],
          "header candidates; full coverage", report["contiguousCompleteRegionCoverage"])
    for item in report["candidates"]:
        print("[FDT]", item["index"], "size", item["lengthBytes"],
              "tokens", item["fullStructureTokenValidation"],
              "root-compatible", ",".join(item.get("rootCompatible", [])))
    print("[report]", dest)
    print("[report]", dest.with_suffix(".md"))
    print("[LIMIT] No runtime selected DTB, physical kernel address or root operation")
    if not report["allFdtStructuresPass"] or not report["contiguousCompleteRegionCoverage"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
