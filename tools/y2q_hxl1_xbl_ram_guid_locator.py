#!/usr/bin/env python3
"""Locate only the verified EFI_RAMPARTITION GUID within stock HXL1 XBL ELFs.

Original Samsung HXL1 xbl.elf and xbl_config.elf are SHA256-pinned.
This is a targeted literal-GUID examination of existing host-side firmware,
NOT a general FDT/image scan, a DXE extraction or a runtime DRAM measurement.
A zero-hit result does not exclude a GUID held in compressed firmware volumes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_stock_bl_elf_audit import INPUTS, parse_elf

GUID = "5172ffb5-4253-7d51-c641-a701f973103c"
GUID_LE = bytes.fromhex("b5ff72515342517dc641a701f973103c")
GUID_BE = bytes.fromhex("5172ffb542537d51c641a701f973103c")
MAX_MATCHES = 256
DEFAULT_SOURCE = Path.home() / "s20-artifacts/hxl1-research/bl-stock"
DEFAULT_REPORT = Path.home() / "s20-artifacts/hxl1-research/xbl-rampartition"


class LocateError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def matches(data: bytes, needle: bytes, *, max_hits: int = MAX_MATCHES) -> list[int]:
    if not needle:
        raise LocateError("Empty binary needle")
    found = []
    offset = 0
    while True:
        i = data.find(needle, offset)
        if i < 0:
            return found
        found.append(i)
        if len(found) > max_hits:
            raise LocateError("Excessive RAM-protocol GUID occurrences")
        offset = i + len(needle)


def locate(data: bytes, expected: dict) -> dict:
    if sha256(data) != expected["sha256"]:
        raise LocateError("Original stock XBL SHA256 mismatch")
    layout = parse_elf(data)
    for key, actual in (
        ("class", 1 if layout["elfClass"] == "ELF32" else 2),
        ("machine", layout["machine"]),
        ("entry", layout["entryPoint"]),
        ("programHeaders", layout["programHeaderCount"]),
    ):
        if actual != expected[key]:
            raise LocateError("Original stock XBL ELF " + key + " mismatch")
    results = []
    for representation, guid_bytes in (
        ("UEFI_GUID_LITTLE_ENDIAN", GUID_LE),
        ("GUID_CANONICAL_BYTES", GUID_BE),
    ):
        for file_offset in matches(data, guid_bytes):
            load_maps = []
            for seg in layout["segments"]:
                if seg["type"] != "LOAD":
                    continue
                if seg["fileOffset"] <= file_offset and (
                    file_offset + len(guid_bytes)
                    <= seg["fileOffset"] + seg["fileSize"]
                ):
                    relative = file_offset - seg["fileOffset"]
                    load_maps.append({
                        "segmentIndex": seg["index"],
                        "elfSegmentVirtualAddress": hex(seg["virtualStart"] + relative),
                        "segmentFileOffset": hex(seg["fileOffset"]),
                    })
            results.append({
                "representation": representation,
                "fileOffset": hex(file_offset),
                "withinFileBackedLoadSegment": bool(load_maps),
                "loadSegmentLocations": load_maps,
            })
    return {
        "stockImageSha256": sha256(data),
        "elfClass": layout["elfClass"],
        "elfMachine": layout["machine"],
        "programHeaderCount": layout["programHeaderCount"],
        "guid": GUID,
        "matchCount": len(results),
        "matches": results,
        "uncompressedProviderIdentified": False,
        "protocolImplementationIdentified": False,
        "actualRamPartitionEntriesMeasured": False,
        "runtimePhysicalKernelEntryVerified": False,
        "deviceModified": False,
    }


def analyze_folder(source: Path) -> dict:
    result = {}
    for filename in ("xbl.elf", "xbl_config.elf"):
        p = source / filename
        if p.is_symlink() or not p.is_file():
            raise LocateError("Missing original regular ELF input: " + str(p))
        result[filename] = locate(p.read_bytes(), INPUTS[filename])
    return {
        "classification": "PINNED_ORIGINAL_XBL_EXACT_RAMPARTITION_GUID_LOCATOR",
        "protocolGuid": GUID,
        "sourceDirectory": str(source),
        "images": result,
        "providerIdentified": False,
        "runtimeRamEntriesMeasured": False,
        "physicalKernelLoadVerified": False,
        "deviceModified": False,
        "nextDecision": (
            "If exact little-endian GUID lies inside a file-backed LOAD, "
            "inspect its actual XBL code/data references; a data hit alone "
            "does not prove registration. If no literal match, investigate "
            "targeted compressed DXE/EnvDxe modules; absence in raw ELF "
            "does not prove absence of protocol."
        ),
    }


def markdown(report: dict) -> str:
    lines = [
        "# Stock HXL1 XBL: exact EFI_RAMPARTITION GUID evidence", "",
        "This is an exact, checksum-gated protocol GUID lookup in the",
        "already recovered Samsung XBL ELF files, not a broad firmware scan.", "",
        "Expected protocol: " + report["protocolGuid"], "",
    ]
    for name, item in report["images"].items():
        lines += ["## " + name, "",
                  "Original SHA256: " + item["stockImageSha256"],
                  "ELF: " + item["elfClass"] + " machine " + str(item["elfMachine"]),
                  "Exact GUID representations matched: " + str(item["matchCount"]), ""]
        for hit in item["matches"]:
            lines += ["- " + hit["representation"] + " at file offset " +
                      hit["fileOffset"] + "; inside ELF PT_LOAD: " +
                      str(hit["withinFileBackedLoadSegment"])]
            for loc in hit["loadSegmentLocations"]:
                lines += ["  - ELF virtual coordinate " +
                          loc["elfSegmentVirtualAddress"] + ", segment " +
                          str(loc["segmentIndex"])]
        lines += [""]
    lines += [
        "## Interpretation boundary", "",
        "UEFI little-endian GUID bytes are the primary candidate. Canonical",
        "byte order matches are recorded separately and must not automatically",
        "be interpreted as deployed EFI_GUID objects.", "",
        "Even an actual GUID reference only identifies a potential provider or",
        "consumer. It is not evidence of an XBL protocol registration or DRAM",
        "values. No matches would leave open compressed DXE firmware volumes.",
        "XBL ELF segment coordinates MUST NOT be used as Linux kernel addresses.",
        "", "Next: " + report["nextDecision"], "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    try:
        report = analyze_folder(args.source)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "original-xbl-rampartition-guid.json").write_text(
            json.dumps(report, indent=2) + "\n")
        (args.out / "original-xbl-rampartition-guid.md").write_text(markdown(report))
    except (LocateError, OSError, ValueError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for name, item in report["images"].items():
        print("[EXACT GUID]", name, item["matchCount"], "matches")
        for hit in item["matches"][:12]:
            print(" ", hit["representation"], hit["fileOffset"],
                  "ELF PT_LOAD:", hit["withinFileBackedLoadSegment"])
    print("[REPORT]", args.out / "original-xbl-rampartition-guid.md")
    print("[LIMIT] XBL provider and boot-time physical RAM values still UNVERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
