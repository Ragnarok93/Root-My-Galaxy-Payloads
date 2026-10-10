#!/usr/bin/env python3
"""Prove static HXL1 ARM64 handoff call and classify OEM fallback data.

Uses already authenticated REA/Ghidra JSON only. No phone access; reported
Ghidra virtual addresses are never promoted to live Linux physical addresses.
"""
from __future__ import annotations
import argparse
import json
import re
import struct
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_linuxloader_rea_stage4_placement import (
    trace as authenticate_placement, original_dossier,
)
from tools.y2q_linuxloader_rea_stage4_xrefs import LOADER_SHA256, AuditError

READS = (
    ("oem-offset-words", "0xb2210", 16),
    ("kaslr-static-word", "0x32a4c8", 4),
)
ARM64 = re.compile(
    r"\(\*local_190\)\s*\(\s*local_178\s*,\s*local_1c0\s*,\s*"
    r"\(longlong\)\s*local_190\s*-\s*local_1c0\s*,\s*0\s*\)\s*;")
LEGACY = re.compile(r"\(\*local_190\)\s*\(\s*0\s*,\s*0\s*,\s*local_178\s*\)\s*;")
SWITCH = re.compile(r"lVar13\s*=\s*\(\*pcVar24\)\s*\(\s*local_108\s*\)\s*;")
MAX_BYTES_FILE = 65536


def read_bytes(folder: Path, label: str, address: str, length: int) -> dict:
    path = folder / ("rea-stage4-" + label + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES_FILE:
        raise AuditError("Missing/oversize REA read-bytes Evidence: " + label)
    item = json.loads(path.read_text())
    if not isinstance(item, dict) or "error" in item:
        raise AuditError("REA read-bytes Evidence is not a successful record")
    subj = item.get("subject", {})
    if (item.get("operation") != "read_bytes" or
        item.get("provider", {}).get("id") != "ghidra" or
        subj.get("digest", {}).get("sha256") != LOADER_SHA256 or
        subj.get("architecture") != "arm64"):
        raise AuditError("REA static bytes are not from the original HXL1 AArch64 EFI")
    p = item.get("parameters", {})
    if p.get("address") != address or p.get("length") != length:
        raise AuditError("REA requested address/byte count changed")
    result = item.get("normalized_result")
    if not isinstance(result, dict):
        raise AuditError("Missing REA byte result object")
    if (result.get("address") != address or result.get("requested_bytes") != length or
        result.get("returned_bytes") != length or result.get("complete") is not True):
        raise AuditError("REA memory read was not complete or not at requested address")
    hx = result.get("bytes_hex")
    if (not isinstance(hx, str) or len(hx) != length * 2 or
        re.fullmatch(r"[0-9a-fA-F]+", hx) is None):
        raise AuditError("REA memory read is malformed, truncated, or not hex")
    evidence_id = item.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise AuditError("REA byte evidence ID missing")
    return {"label": label, "address": address, "byteCount": length,
            "bytes": bytes.fromhex(hx), "evidenceId": evidence_id}


def evaluate(folder: Path) -> dict:
    authenticated = authenticate_placement(folder)
    if authenticated.get("loaderSha256") != LOADER_SHA256:
        raise AuditError("Placement analysis not tied to exact HXL1 executable")
    loader = original_dossier(folder, "kernel-load-print")
    code = loader.get("pseudocode")
    if not isinstance(code, str):
        raise AuditError("Missing original full BootLinux pseudocode")
    arm64 = ARM64.search(code)
    legacy = LEGACY.search(code)
    switch = SWITCH.search(code)
    if not all((arm64, legacy, switch)):
        raise AuditError("Expected original three handoff forms not all evidenced")
    exit_services = code.find("lVar13 = FUN_0001e868();")
    post_exit = code.find("FUN_0001e9b8();", exit_services + 1)
    if not (0 <= exit_services < post_exit < arm64.start()):
        raise AuditError("Cannot prove EFI shutdown precedes direct ARM64 handoff")
    if "if (lVar13 < 0)" not in code[exit_services:post_exit]:
        raise AuditError("ExitBootServices failure guard not evident")
    raw_oem = read_bytes(folder, *READS[0])
    raw_kaslr = read_bytes(folder, *READS[1])
    words = struct.unpack("<4I", raw_oem["bytes"])
    sentinel, = struct.unpack("<I", raw_kaslr["bytes"])
    if words != (0x80000, 0x05600000, 0x03c00000, 0x8000):
        raise AuditError("Original HXL1 fallback constants differ from observed firmware")
    if sentinel != 0x40:
        raise AuditError("Original HXL1 KASLR static sentinel not observed")
    lines = code.splitlines()
    def context(start: int) -> str:
        line = code.count("\n", 0, start)
        return "\n".join(lines[max(0, line-3): min(len(lines), line+4)])
    return {
        "classification": "VERIFIED_ORIGINAL_STATIC_ARM64_KERNEL_HANDOFF_CODE",
        "loaderSha256": LOADER_SHA256,
        "bootLinux": "0x20a60",
        "uefiShutdownCall": "FUN_0001e868",
        "staticHandoff": {
            "arm64DirectKernelEntry": "local_190",
            "arm64ArgumentExpressions": [
                "local_178", "local_1c0", "(longlong)local_190 - local_1c0", "0"],
            "arm64PseudocodeExcerpt": context(arm64.start()),
            "legacyCallExcerpt": context(legacy.start()),
            "modeSwitchCallExcerpt": context(switch.start()),
            "shutdownExcerpt": context(exit_services),
        },
        "fallbackConstants": {
            "arm64Offset": words[0],
            "arm64RegionBytes": words[1],
            "alternateRegionBytes": words[2],
            "alternateOffset": words[3],
            "evidenceId": raw_oem["evidenceId"],
        },
        "kaslrState": {
            "imageInitializer": sentinel,
            "initializerMeaning": "0x40 sentinel, runtime random state not observed",
            "evidenceId": raw_kaslr["evidenceId"],
        },
        "conditionalKernelBase": [
            "UEFI KernelBaseAddr + imageFormatBias, then + (KASLRState << 15)",
            "(BaseMemory | OEMImageFormatOffset), then + (KASLRState << 15)",
        ],
        "kernelRuntimePhysicalBaseMeasured": False,
        "kernelEntryExecutedObserved": False,
        "actualDtbSelected": False,
        "deviceModified": False,
    }


def render(data: dict) -> str:
    lines = ["# HXL1 original LinuxLoader: final static ARM64 handoff",
             "", "Original EFI SHA256: " + data["loaderSha256"], "",
             "**Static ARM64 transfer proven; numerical runtime physical kernel load is NOT proven.**",
             "", "## Exact fallback words, original little-endian REA evidence", ""]
    for k, v in data["fallbackConstants"].items():
        lines.append("- " + k + ": " + (hex(v) if isinstance(v, int) else str(v)))
    lines += ["", "KASLR initializer: "+hex(data["kaslrState"]["imageInitializer"]),
              " (sentinel, not a measured boot-time offset)", "",
              "## Original Ghidra handoff excerpts", ""]
    for key, value in data["staticHandoff"].items():
        if key.endswith("Excerpt"):
            lines += ["### "+key,"","~~~c",value,"~~~",""]
    lines += ["## Conditional placement equations", ""]
    for formula in data["conditionalKernelBase"]:
        lines.append("- " + formula)
    lines += ["", "## Remaining evidence gaps", "",
              "Need actual runtime BaseMemory or UEFI KernelBaseAddr branch value, "
              "runtime KASLR choice, selected DTB and matching real device context. "
              "PE static bytes and decompiler source alone do not resolve these.", ""]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/abl-linuxloader")
    args = p.parse_args()
    try:
        result = evaluate(args.out)
        (args.out / "rea-stage4-handoff-static.json").write_text(json.dumps(result, indent=2)+"\n")
        (args.out / "rea-stage4-handoff-static.md").write_text(render(result))
    except (AuditError, OSError, ValueError, KeyError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[VERIFIED] Original ARM64 kernel-entry call through local_190")
    print("[VERIFIED] Original UEFI boot-service shutdown precedes call")
    print("[OEM OFFSETS]", {k: hex(v) for k,v in result["fallbackConstants"].items()
                            if isinstance(v,int)})
    print("[KASLR] static sentinel", hex(result["kaslrState"]["imageInitializer"]))
    print("[REPORT]", args.out / "rea-stage4-handoff-static.md")
    print("[LIMIT] Numerical runtime physical kernel destination still unknown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
