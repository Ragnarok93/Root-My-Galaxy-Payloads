#!/usr/bin/env python3
"""Read-only, checksum-pinned ELF header/segment inventory of original HXL1 BL images.

This tool does not locate the Android kernel physical handoff. The output only
describes bootloader ELF file headers and PT_LOAD segment address ranges.
Original file digests were reported by the owner after independently verifying
the exact original Samsung HXL1 BL tar.md5 archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

INPUTS = {
    "abl.elf": {
        "sha256": "6d717ef96e7355d72db1ac167ef1b74ff6ef33d22a8bfc08affc62f9cabcdeef",
        "class": 1, "machine": 40, "entry": 0x9FA00000, "programHeaders": 3,
    },
    "xbl.elf": {
        "sha256": "78d1bff9ef5c2aa626652390c112f0bf81869bb1f9a05fcd8a8e3dfff8f8b357",
        "class": 2, "machine": 183, "entry": 0x148157A8, "programHeaders": 15,
    },
    "xbl_config.elf": {
        "sha256": "757fc6ef87134283d37fa4ee57f5180e3849107e216f48f379323ce473f40d7f",
        "class": 2, "machine": 40, "entry": 0x148D0000, "programHeaders": 6,
    },
}


class AuditError(ValueError):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_elf(data: bytes) -> dict:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise AuditError("not a complete ELF header")
    elf_class, endian, ident_version = data[4:7]
    if elf_class not in (1, 2) or endian != 1 or ident_version != 1:
        raise AuditError("expected little-endian ELF32 or ELF64")
    fmt = "<"
    header_size = 52 if elf_class == 1 else 64
    if len(data) < header_size:
        raise AuditError("truncated ELF header")
    elf_type, machine, version = struct.unpack_from(fmt + "HHI", data, 16)
    if version != 1:
        raise AuditError("unsupported ELF version")
    if elf_class == 1:
        entry, table_offset = struct.unpack_from(fmt + "II", data, 24)
        e_ehsize, ph_size, ph_count = struct.unpack_from(fmt + "HHH", data, 40)
        min_entry_size = 32
    else:
        entry, table_offset = struct.unpack_from(fmt + "QQ", data, 24)
        e_ehsize, ph_size, ph_count = struct.unpack_from(fmt + "HHH", data, 52)
        min_entry_size = 56
    if e_ehsize < header_size or ph_size < min_entry_size or ph_count == 0:
        raise AuditError("invalid ELF/program header size")
    if table_offset < header_size or table_offset > len(data):
        raise AuditError("invalid program header offset")
    if ph_count > (len(data) - table_offset) // ph_size:
        raise AuditError("program header table extends beyond file")
    segments = []
    for index in range(ph_count):
        at = table_offset + index * ph_size
        if elf_class == 1:
            kind, offset, virt, phys, fsize, msize, flags, align = struct.unpack_from(
                fmt + "IIIIIIII", data, at)
        else:
            kind, flags, offset, virt, phys, fsize, msize, align = struct.unpack_from(
                fmt + "IIQQQQQQ", data, at)
        if kind == 1:
            if msize < fsize or offset > len(data) or fsize > len(data) - offset:
                raise AuditError(f"PT_LOAD[{index}] has invalid file or memory size")
            if msize and virt + msize > 1 << (32 if elf_class == 1 else 64):
                raise AuditError(f"PT_LOAD[{index}] virtual address wraps")
            if msize and phys + msize > 1 << (32 if elf_class == 1 else 64):
                raise AuditError(f"PT_LOAD[{index}] physical address wraps")
        segments.append({
            "index": index,
            "type": "LOAD" if kind == 1 else ("NULL" if kind == 0 else str(kind)),
            "fileOffset": offset, "virtualStart": virt, "physicalStart": phys,
            "fileSize": fsize, "memorySize": msize,
            "flags": flags, "alignment": align,
        })
    executable_loads = [
        x for x in segments if x["type"] == "LOAD"
        and x["memorySize"] and (x["flags"] & 1)
        and x["virtualStart"] <= entry < x["virtualStart"] + x["memorySize"]
    ]
    return {
        "elfClass": "ELF32" if elf_class == 1 else "ELF64",
        "machine": machine,
        "elfType": elf_type,
        "entryPoint": entry,
        "programHeaderCount": ph_count,
        "entryInExecutableLoadSegment": bool(executable_loads),
        "entryExecutableLoadIndices": [x["index"] for x in executable_loads],
        "segments": segments,
    }


def overlap_ranges(a: dict, b: dict) -> list[dict]:
    findings = []
    for one in a["segments"]:
        for two in b["segments"]:
            if one["type"] != "LOAD" or two["type"] != "LOAD":
                continue
            if not one["memorySize"] or not two["memorySize"]:
                continue
            start = max(one["physicalStart"], two["physicalStart"])
            end = min(one["physicalStart"] + one["memorySize"],
                      two["physicalStart"] + two["memorySize"])
            if start < end:
                findings.append({
                    "firstIndex": one["index"],
                    "secondIndex": two["index"],
                    "physicalStart": start,
                    "physicalEndExclusive": end,
                    "overlapBytes": end - start,
                    "note": "Across separate bootloader images. Address reuse at different boot phases is possible; this is not kernel handoff evidence.",
                })
    return findings


def audit(root: Path) -> dict:
    results = {}
    for name, expected in INPUTS.items():
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise AuditError(f"missing or symlinked HXL1 image: {path}")
        actual = digest(path)
        if actual != expected["sha256"]:
            raise AuditError(f"SHA256 mismatch, STOP: {name}: {actual}")
        parsed = parse_elf(path.read_bytes())
        for key, val in (("machine", expected["machine"]),
                         ("entryPoint", expected["entry"]),
                         ("programHeaderCount", expected["programHeaders"])):
            if parsed[key] != val:
                raise AuditError(f"{name}: expected {key}={val}, got {parsed[key]}")
        expected_class = "ELF32" if expected["class"] == 1 else "ELF64"
        if parsed["elfClass"] != expected_class:
            raise AuditError(f"{name}: ELF class changed")
        parsed["sha256"] = actual
        parsed["fileSizeBytes"] = path.stat().st_size
        results[name] = parsed
    return {
        "schemaVersion": 1,
        "target": "Samsung SM-G986U1 / G986U1UESCHXL1",
        "input": str(root),
        "source": "Hash-verified decompression of original matching Samsung BL tar.md5",
        "images": results,
        "ablXblCrossImagePhysicalLoadOverlaps": overlap_ranges(
            results["abl.elf"], results["xbl.elf"]),
        "xblConfigHasUnusualElfClassMachineCombination":
            results["xbl_config.elf"]["elfClass"] == "ELF64"
            and results["xbl_config.elf"]["machine"] == 40,
        "runtimeLinuxKernelPhysicalBaseVerified": False,
        "bootloaderExecutionOrderProved": False,
        "linuxHandoffRegistersVerified": False,
        "androidBootloaderUnlockAttempted": False,
        "phoneModified": False,
        "caveat": "ELF p_paddr/p_vaddr and entry points are BOOTLOADER IMAGE metadata. "
                  "They do not identify the kernel's physical load base or KASLR slide.",
    }


def report_markdown(r: dict) -> str:
    lines = [
        "# SM-G986U1 HXL1 — original BL ELF header inventory",
        "", "**Read-only firmware evidence; kernel boot handoff not established.**",
        "", "| Image | Class | Machine | Entry | Headers | Entry in executable PT_LOAD |",
        "|---|---|---:|---|---:|---|",
    ]
    for name, img in r["images"].items():
        lines.append(
            f"| {name} | {img['elfClass']} | {img['machine']} | "
            f"0x{img['entryPoint']:x} | {img['programHeaderCount']} | "
            f"{img['entryInExecutableLoadSegment']} |")
    lines += ["", "## Original extracted image SHA256", ""]
    for name, img in r["images"].items():
        lines.append(f"- {name}: {img['sha256']}")
    lines += [
        "", "## Cross-image ELF physical LOAD ranges", "",
        "These segments belong to separate bootloader images and may reflect "
        "boot-stage memory reuse. No result identifies an Android kernel base.",
    ]
    overlaps = r["ablXblCrossImagePhysicalLoadOverlaps"]
    if not overlaps:
        lines.append("- No intersecting nonempty PT_LOAD physical ranges detected")
    for region in overlaps:
        lines.append(
            f"- ABL PT_LOAD[{region['firstIndex']}] and XBL PT_LOAD"
            f"[{region['secondIndex']}]: [0x{region['physicalStart']:x}, "
            f"0x{region['physicalEndExclusive']:x}), "
            f"{region['overlapBytes']} bytes")
    lines += [
        "", "## Remaining evidence", "",
        "- Stage 4 physical Android kernel load/handoff: **OPEN**.",
        "- Original ARM64 Image text_offset=0x80000 is not sufficient to infer RAM base.",
        "- XBL_CONFIG is ELF64 with e_machine ARM (not AArch64); classify cautiously.",
        "- This audit performs no flashing, root, payload execution, or device actions.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path,
                        default=Path.home() / "s20-artifacts/hxl1-research/bl-stock")
    parser.add_argument("--output", type=Path,
                        default=Path.home()
                        / "s20-artifacts/hxl1-research/bl-stock-elf-audit.json")
    args = parser.parse_args()
    root, output = args.input_dir.expanduser().resolve(), args.output.expanduser().resolve()
    if output.suffix != ".json" or output == root or root in output.parents:
        parser.error("output must be JSON outside original BL image directory")
    try:
        r = audit(root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(r, indent=2) + "\n")
        output.with_suffix(".md").write_text(report_markdown(r))
    except (AuditError, OSError, struct.error) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2
    print("[PASS] three original HXL1 BL image hashes and ELF headers")
    for name, img in r["images"].items():
        print(f"[ELF] {name} {img['elfClass']} machine={img['machine']} "
              f"entry=0x{img['entryPoint']:x} "
              f"entry_in_exec_load={img['entryInExecutableLoadSegment']}")
    print("[overlaps] ABL/XBL separate-image PT_LOAD:",
          len(r["ablXblCrossImagePhysicalLoadOverlaps"]))
    print("[report]", output)
    print("[report]", output.with_suffix(".md"))
    print("[LIMIT] These are bootloader segments, not Linux physical handoff")
    return 0


if __name__ == "__main__":
    sys.exit(main())
