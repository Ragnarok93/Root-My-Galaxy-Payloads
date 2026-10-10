#!/usr/bin/env python3
"""Read original HXL1 Ghidra RAM-partition chain; never infer runtime PA.

Requires four SHA256-pinned original REA source dossiers. No device calls.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_linuxloader_rea_stage4_sources import audit as source_audit
from tools.y2q_linuxloader_rea_stage4_xrefs import LOADER_SHA256, AuditError

CALL = "FUN_0001eca0(&local_30,&local_34)"
WRITE = "*param_1 = uVar5"
LOG = "Memory Base Address: 0x%x"
MAX_READER_CHARS = 250000


def analyze(directory: Path) -> dict:
    sources = source_audit(directory)
    if sources.get("loaderSha256") != LOADER_SHA256:
        raise AuditError("Wrong exact original HXL1 EFI digest")
    entries = sources.get("functions", [])
    if len(entries) != 4 or any(x.get("status") != "VERIFIED_STATIC_FUNCTION"
                                for x in entries):
        raise AuditError("Four genuine HXL1 function dossiers are required")
    by_label = {entry["label"]: entry for entry in entries}
    parent = by_label["base-memory-provider"]
    reader = by_label["ram-partition-reader"]
    if parent["functionEntry"] != "0x1f018" or reader["functionEntry"] != "0x1eca0":
        raise AuditError("Reader or caller function entry mismatch")
    caller_code = parent.get("pseudocode")
    reader_code = reader.get("pseudocode")
    if not isinstance(caller_code, str) or not isinstance(reader_code, str):
        raise AuditError("Source function pseudocode unavailable")
    if not all(needle in caller_code for needle in (CALL, WRITE, LOG)):
        raise AuditError("Cannot authenticate original RAM reader call and base output")
    if not reader_code.strip() or len(reader_code) > MAX_READER_CHARS:
        raise AuditError("RAM partition reader decompilation absent or oversized")
    references = [
        line.strip() for line in reader_code.splitlines()
        if "FUN_" in line or "DAT_" in line or "Protocol" in line or "Partitions" in line
    ]
    return {
        "classification": "VERIFIED_ORIGINAL_HXL1_RAM_PARTITION_STATIC_CALL_CHAIN",
        "loaderSha256": LOADER_SHA256,
        "baseProviderEntry": parent["functionEntry"],
        "partitionReaderEntry": reader["functionEntry"],
        "baseProviderEvidenceId": parent["evidenceId"],
        "readerEvidenceId": reader["evidenceId"],
        "callerExpressions": [CALL, WRITE, LOG],
        "callerFunctionPseudocode": caller_code,
        "readerFunctionPseudocode": reader_code,
        "readerReferenceLines": references[:400],
        "readerPcodeAvailable": reader["highFunctionAvailable"],
        "ramPartitionDescriptorsObservedAtRuntime": False,
        "physicalRamBaseMeasured": False,
        "kernelPhysicalEntryVerified": False,
        "deviceModified": False,
    }


def render(result: dict) -> str:
    output = [
        "# HXL1 LinuxLoader: provenance of BootLinux BaseMemory", "",
        "Original EFI SHA256: " + result["loaderSha256"], "",
        "STATIC Ghidra source evidence — no runtime partition table or kernel PA.",
        "", "## Verified decompiled call chain", "",
        "Caller FUN_0001f018 (0x1f018); REA evidence " +
        result["baseProviderEvidenceId"],
        "Reader FUN_0001eca0 (0x1eca0); REA evidence " +
        result["readerEvidenceId"], "",
        "The caller obtains a pointer and count from the RAM reader and",
        "assigns a derived address to its output. The reader's descriptor",
        "format and return behavior still need examination.", "",
        "## Original base-provider pseudocode", "", "~~~c",
        result["callerFunctionPseudocode"], "~~~", "",
        "## Original RAM partition reader pseudocode", "", "~~~c",
        result["readerFunctionPseudocode"], "~~~", "",
        "## Reader calls and data references", "", "~~~text",
        *result["readerReferenceLines"], "~~~", "",
        "## Unresolved", "",
        "No RAM partition table contents, actual selected physical base,",
        "KernelBaseAddr UEFI variable or per-boot KASLR entropy measured.", "",
    ]
    return "\n".join(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path.home() /
                        "s20-artifacts/hxl1-research/abl-linuxloader")
    options = parser.parse_args()
    try:
        report = analyze(options.out)
        (options.out / "rea-stage4-ram-partition-chain.json").write_text(
            json.dumps(report, indent=2) + "\n")
        (options.out / "rea-stage4-ram-partition-chain.md").write_text(render(report))
    except (AuditError, ValueError, OSError, KeyError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[VERIFIED] Original HXL1 FUN_0001f018 -> FUN_0001eca0 static call")
    print("[READER EVIDENCE]", report["readerEvidenceId"])
    print("[READER LINES]", len(report["readerFunctionPseudocode"].splitlines()))
    print("[REPORT]", options.out / "rea-stage4-ram-partition-chain.md")
    print("[LIMIT] Runtime RAM base and kernel physical entry UNVERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
