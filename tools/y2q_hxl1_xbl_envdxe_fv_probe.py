#!/usr/bin/env python3
"""Targeted original-HXL1 XBL firmware-volume inspection for EFI_RAMPARTITION.

Reuses the validated ABL FV/FFS/LZMA decoder; additionally admits bounded,
CRC-checked gzip streams, as used in some Qualcomm XBL generations. Only
hash-pinned original XBL ELFs are consumed. No device contact or image writes.
Zero results are not proof the protocol provider is absent; unsupported EFI
Tiano/LZ4 or other vendor compression remains a possible evidence gap.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zlib

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_abl_linuxloader_extract import Walker, ExtractError
from tools.y2q_stock_bl_elf_audit import INPUTS, parse_elf
from tools.y2q_hxl1_xbl_ram_guid_locator import GUID_LE

INPUT_NAMES = ("xbl.elf", "xbl_config.elf")
MAX_INPUT = 32 * 1024 * 1024
MAX_GZIP_CANDIDATES = 150
MAX_GZIP_EXPAND = 48 * 1024 * 1024
MAX_TARGET_PE = 256
MAX_NOTES = 24
GZIP_MAGIC = b"\x1f\x8b\x08"
TARGET_WORDS = (b"EnvDxe", b"RamPartition", b"GetRamPartitions", b"EFI_RAMPARTITION")
TARGET_WIDE_WORDS = tuple(x.decode().encode("utf-16le") for x in TARGET_WORDS)
DEFAULT_DIR = Path.home() / "s20-artifacts/hxl1-research/bl-stock"
DEFAULT_OUT = Path.home() / "s20-artifacts/hxl1-research/xbl-rampartition"


class ProviderProbeError(ValueError):
    pass


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def firmware_gzip(data: bytes, offset: int) -> bytes | None:
    """Fully validate a gzip member, with memory and work bounded.

    XBL commonly stores inner UEFI FVs inside a GUID-defined gzip section.
    The original compressed bytes are never executed or saved as a binary.
    """
    if data[offset:offset+3] != GZIP_MAGIC:
        return None
    decoder = zlib.decompressobj(wbits=31)
    output = bytearray()
    cursor = offset
    try:
        while cursor < len(data):
            chunk = data[cursor:min(cursor + 65536, len(data))]
            cursor += len(chunk)
            remaining = MAX_GZIP_EXPAND - len(output)
            if remaining <= 0:
                return None
            output.extend(decoder.decompress(chunk, remaining + 1))
            if len(output) > MAX_GZIP_EXPAND:
                return None
            if decoder.eof:
                break
        if not decoder.eof:
            return None
        # Must be a full, internally validated gzip including end CRC.
        if decoder.flush():
            return None
        return bytes(output)
    except (zlib.error, ValueError, MemoryError):
        return None


def discover_gzip(data: bytes) -> tuple[list[tuple[int, bytes]], int]:
    good = []
    found = 0
    cursor = 0
    while True:
        offset = data.find(GZIP_MAGIC, cursor)
        if offset < 0:
            return good, found
        cursor = offset + len(GZIP_MAGIC)
        found += 1
        if found > MAX_GZIP_CANDIDATES:
            raise ProviderProbeError("Too many gzip candidates; stop unbounded probing")
        unpacked = firmware_gzip(data, offset)
        if unpacked is not None and b"_FVH" in unpacked:
            good.append((offset, unpacked))


def provider_pe_match(payload: bytes, *, ui: str, guid: str, trace: list[str],
                      representation: str) -> dict | None:
    terms = [
        word.decode("ascii") for word in TARGET_WORDS
        if word.lower() in payload.lower()
    ]
    terms += [
        word.decode("utf-16le") + " (UTF-16)"
        for word in TARGET_WIDE_WORDS if word in payload
    ]
    offsets = []
    cursor = 0
    while True:
        pos = payload.find(GUID_LE, cursor)
        if pos < 0:
            break
        offsets.append(hex(pos))
        if len(offsets) > 64:
            raise ProviderProbeError("Too many protocol GUID literals inside PE")
        cursor = pos + 16
    if not (terms or offsets or "envdxe" in ui.lower()):
        return None
    return {
        "uiName": ui, "ffsGuid": guid, "source": representation,
        "trace": trace[-9:],
        "peBytes": len(payload), "peSha256": sha256(payload),
        "guidOffsetsWithinPe": offsets,
        "relatedTerms": list(dict.fromkeys(terms)),
        "classification": (
            "CANDIDATE_BINARY_CONTAINS_PROTOCOL_GUID" if offsets else
            "CANDIDATE_BINARY_NAME_OR_DIAGNOSTICS_ONLY"
        ),
        "registrationProven": False,
    }


def observe(blob: bytes, description: str) -> dict:
    walker = Walker()
    try:
        walker.search_fv(blob, [description], 0)
    except (ExtractError, RecursionError, ValueError) as exc:
        return {
            "status": "FV_DECODER_ERROR", "error": str(exc)[:500],
            "volumeCount": len(walker.fv_headers),
            "targetCandidates": [], "eligiblePeCount": len(walker.identified),
            "notes": walker.notes[:MAX_NOTES],
            "uiNames": [],
        }
    matches = []
    if len(walker.identified) > MAX_TARGET_PE:
        return {
            "status": "EXCESSIVE_PE_COUNT", "error": "Unexpected large executable collection",
            "volumeCount": len(walker.fv_headers), "targetCandidates": [],
            "eligiblePeCount": len(walker.identified), "notes": walker.notes[:MAX_NOTES],
            "uiNames": [],
        }
    for candidate in walker.identified:
        result = provider_pe_match(
            candidate["image"], ui=candidate["ui"],
            guid=candidate["fileGuid"], trace=candidate["trace"],
            representation=description)
        if result:
            matches.append(result)
    # UI sections may name a driver even when it has no PE recognized by
    # our subset of the UEFI parser; preserve that as a distinct weak lead.
    ui_names = sorted({
        item["ui"] for item in walker.sections
        if item["ui"] and item["sectionType"] == "0x15"
    })
    named = [x for x in ui_names
             if any(s.lower() in x.lower() for s in ("envdxe", "rampartition"))]
    return {
        "status": "FV_PARSED" if walker.fv_headers else "NO_VALID_FIRMWARE_VOLUME",
        "volumeCount": len(walker.fv_headers),
        "firmwareVolumes": walker.fv_headers[:12],
        "eligiblePeCount": len(walker.identified),
        "targetCandidates": matches,
        "namedDriverCandidatesWithoutVerifiedPe": named[:30],
        "uiNames": ui_names[:40],
        "notes": walker.notes[:MAX_NOTES],
    }


def analyze_image(data: bytes, name: str, expected: dict) -> dict:
    if len(data) > MAX_INPUT:
        raise ProviderProbeError("Original XBL input exceeds analysis cap")
    if sha256(data) != expected["sha256"]:
        raise ProviderProbeError("Original SHA256 pin mismatch: " + name)
    layout = parse_elf(data)
    if (layout["elfClass"] != ("ELF32" if expected["class"] == 1 else "ELF64")
        or layout["machine"] != expected["machine"]
        or layout["entryPoint"] != expected["entry"]
        or layout["programHeaderCount"] != expected["programHeaders"]):
        raise ProviderProbeError("Original XBL ELF structural identity mismatch: " + name)
    direct = observe(data, name + ":original-ELF")
    gzip, raw_headers = discover_gzip(data)
    decoded = []
    for offset, decompressed in gzip:
        item = observe(decompressed, name + ":gzip@0x%x" % offset)
        decoded.append({
            "fileOffsetOfOriginalGzipHeader": hex(offset),
            "decodedLength": len(decompressed),
            "decodedSha256": sha256(decompressed),
            **item,
        })
    return {
        "original": name,
        "sha256": sha256(data),
        "bytes": len(data),
        "elfClass": layout["elfClass"],
        "directFv": direct,
        "gzipHeaderCandidates": raw_headers,
        "gzipStreamsContainingFvSignature": len(gzip),
        "decodedFvObservations": decoded,
        "providerLocated": False,
        "liveRamPartitionValuesObserved": False,
        "kernelPhysicalEntryVerified": False,
    }


def scan_folder(source: Path) -> dict:
    images = {}
    for name in INPUT_NAMES:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ProviderProbeError("Missing original regular ELF input " + str(path))
        images[name] = analyze_image(path.read_bytes(), name, INPUTS[name])
    return {
        "classification": "TARGETED_ORIGINAL_XBL_ENV_DXE_GUIDED_FV_INVESTIGATION",
        "images": images,
        "protocolGuid": "5172ffb5-4253-7d51-c641-a701f973103c",
        "targetProviderIdentified": False,
        "unsupportedCompressionRemainsPossible": True,
        "numericRuntimeRamBaseKnown": False,
        "deviceModified": False,
    }


def markdown(report: dict) -> str:
    lines = ["# Original HXL1 XBL — targeted EnvDxe firmware volume investigation", "",
             "This is an original-hash-pinned, host-only FV/FFS/LZMA/gzip inspection.",
             "Only decompressed original-ELF firmware volumes are considered.", ""]
    for name, info in report["images"].items():
        lines += ["## " + name, "", "Original SHA256: " + info["sha256"],
                  "Original bytes: " + str(info["bytes"]),
                  "Direct validated FV count: " + str(info["directFv"]["volumeCount"]),
                  "Direct parser status: " + info["directFv"]["status"],
                  "gzip header candidates: " + str(info["gzipHeaderCandidates"]),
                  "gzip streams with FV magic: " + str(info["gzipStreamsContainingFvSignature"]), ""]
        all_views = [("Original XBL bytes", info["directFv"])]
        all_views += [(x["fileOffsetOfOriginalGzipHeader"], x)
                      for x in info["decodedFvObservations"]]
        for title, item in all_views:
            lines += ["### " + title, "", "Status: " + item["status"],
                      "Parsed firmware volumes: " + str(item["volumeCount"]),
                      "Recognized AArch64 PE32+ images: " + str(item["eligiblePeCount"]),
                      "Target candidate count: " + str(len(item["targetCandidates"])), ""]
            for candidate in item["targetCandidates"]:
                lines += ["- UI=" + candidate["uiName"] +
                          ", GUID=" + candidate["ffsGuid"] +
                          ", SHA256=" + candidate["peSha256"],
                          "  Evidence=" + candidate["classification"],
                          "  GUID offsets: " + str(candidate["guidOffsetsWithinPe"]),
                          "  Relevant text: " + str(candidate["relatedTerms"]), ""]
            if item.get("namedDriverCandidatesWithoutVerifiedPe"):
                lines += ["Named FFS/UI candidates without verified PE: " +
                          str(item["namedDriverCandidatesWithoutVerifiedPe"]), ""]
            if item.get("notes"):
                lines += ["Bounded decoder notes: " + str(item["notes"][:12]), ""]
    lines += ["## Inference limit", "",
              "A candidate PE GUID literal or diagnostic string is not proof of",
              "a protocol installer. No valid FV or compressed candidate does",
              "not rule out packed DXE, non-gzip compression, or split XBL_CORE.",
              "No observed value is a live DRAM base or Linux kernel entry.", ""]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, default=DEFAULT_DIR)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    a = p.parse_args()
    try:
        result = scan_folder(a.source)
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out/"original-xbl-envdxe-fv.json").write_text(json.dumps(result,indent=2)+"\n")
        (a.out/"original-xbl-envdxe-fv.md").write_text(markdown(result))
    except (OSError, ValueError, ExtractError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for name, entry in result["images"].items():
        print("[XBL]",name,"directFV",entry["directFv"]["volumeCount"],
              "gzipFV",entry["gzipStreamsContainingFvSignature"])
        for view in [entry["directFv"], *entry["decodedFvObservations"]]:
            print("[TARGETS]",len(view["targetCandidates"]),"status",view["status"])
            for candidate in view["targetCandidates"][:15]:
                print(" ", candidate["uiName"],candidate["ffsGuid"],
                      candidate["classification"],candidate["peSha256"])
    print("[REPORT]", a.out/"original-xbl-envdxe-fv.md")
    print("[LIMIT] No XBL provider registration or runtime physical base established")
    return 0


if __name__ == "__main__":
    sys.exit(main())
