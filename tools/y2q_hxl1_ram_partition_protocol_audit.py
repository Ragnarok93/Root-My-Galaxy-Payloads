#!/usr/bin/env python3
"""Authenticate HXL1 EFI RAM-partition GUID and 16-byte descriptor ABI.

Uses SHA256-verified original Ghidra Evidence, not running phone memory.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
import uuid

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_linuxloader_rea_ram_partition_chain import analyze as verify_call_chain
from tools.y2q_linuxloader_rea_stage4_xrefs import LOADER_SHA256, AuditError

GUID_ADDR = "0xef880"
GUID_HEX = "b5ff72515342517dc641a701f973103c"
GUID_TEXT = "5172ffb5-4253-7d51-c641-a701f973103c"
READ_FILE = "rea-stage4-ram-partition-protocol-guid.json"
HEX = re.compile(r"^[0-9a-fA-F]{32}$")


def guid_observation(folder: Path) -> dict:
    path = folder / READ_FILE
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise AuditError("Missing/oversized original Ghidra RAM protocol GUID Evidence")
    doc = json.loads(path.read_text())
    if (not isinstance(doc, dict) or "error" in doc or
        doc.get("operation") != "read_bytes" or
        doc.get("provider", {}).get("id") != "ghidra" or
        doc.get("subject", {}).get("digest", {}).get("sha256") != LOADER_SHA256 or
        doc.get("subject", {}).get("architecture") != "arm64" or
        doc.get("parameters", {}).get("address") != GUID_ADDR or
        doc.get("parameters", {}).get("length") != 16):
        raise AuditError("GUID read not from authenticated original HXL1 EFI")
    data = doc.get("normalized_result")
    if (not isinstance(data, dict) or
        data.get("address") != GUID_ADDR or data.get("requested_bytes") != 16 or
        data.get("returned_bytes") != 16 or data.get("complete") is not True):
        raise AuditError("Original EFI GUID read incomplete or not at intended address")
    hex_bytes = data.get("bytes_hex")
    if not isinstance(hex_bytes, str) or HEX.fullmatch(hex_bytes) is None:
        raise AuditError("Expected exactly 16 original GUID bytes")
    evidence_id = doc.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise AuditError("Missing REA GUID Evidence ID")
    return {
        "hex": hex_bytes.lower(),
        "guid": str(uuid.UUID(bytes_le=bytes.fromhex(hex_bytes))),
        "evidenceId": evidence_id,
    }


def audit(folder: Path) -> dict:
    chain = verify_call_chain(folder)
    if (chain.get("loaderSha256") != LOADER_SHA256 or
        chain.get("partitionReaderEntry") != "0x1eca0" or
        chain.get("baseProviderEntry") != "0x1f018"):
        raise AuditError("Original HXL1 RAM reader/caller not verified")
    reader = chain.get("readerFunctionPseudocode", "")
    caller = chain.get("callerFunctionPseudocode", "")
    reader_patterns = (
        "DAT_000ef880", "DAT_00351a38 + 0x140",
        "local_50 + 0x18", "DAT_00346ae0 << 4",
    )
    caller_patterns = ("FUN_0001eca0(&local_30,&local_34)", "puVar8 + 2")
    if not all(x in reader for x in reader_patterns):
        raise AuditError("Original EFI reader protocol dispatch/layout cannot be confirmed")
    if not all(x in caller for x in caller_patterns):
        raise AuditError("Original EFI caller lacks verified 16-byte stride")
    guid = guid_observation(folder)
    if guid["hex"] != GUID_HEX or guid["guid"] != GUID_TEXT:
        raise AuditError("Original EFI GUID differs from published Qualcomm protocol")
    return {
        "classification": "VERIFIED_ORIGINAL_STATIC_EFI_RAMPARTITION_ABI",
        "loaderSha256": LOADER_SHA256,
        "readerEntry": "0x1eca0",
        "baseProviderEntry": "0x1f018",
        "readerEvidenceId": chain["readerEvidenceId"],
        "guidEvidenceId": guid["evidenceId"],
        "protocolGuid": guid["guid"],
        "guidAddress": GUID_ADDR,
        "guidBytesLittleEndian": guid["hex"],
        "recordSize": 16,
        "fieldOffsets": {"Base": 0, "AvailableLength": 8},
        "protocolMethodOffset": 0x18,
        "sourceReference": "https://www.cnblogs.com/schips/p/qualcomm_about_uefi.html",
        "runtimeRamPartitionsObserved": False,
        "physicalBaseMeasured": False,
        "kernelPhysicalEntryVerified": False,
        "deviceModified": False,
    }


def markdown(report: dict) -> str:
    return "\n".join([
        "# Original HXL1 LinuxLoader EFI_RAMPARTITION contract", "",
        "Original PE SHA256: " + report["loaderSha256"], "",
        "GUID at static Ghidra address " + report["guidAddress"] +
        ": " + report["protocolGuid"],
        "Original REA GUID Evidence ID: " + report["guidEvidenceId"], "",
        "The Qualcomm EFI_RAMPARTITION protocol GetRamPartitions method",
        "lives at protocol + 0x18. The original HXL1 function allocates",
        "partitionCount * 16 bytes and the caller uses a 16-byte stride.", "",
        "Per published Qualcomm protocol header, entries have:", "",
        "- UINT64 Base at offset 0",
        "- UINT64 AvailableLength at offset 8", "",
        "This authenticates the ABI, not the runtime partition array.", "",
        "The numerical partition bases and sizes, actual selected",
        "BaseMemory, runtime KASLR state, and kernel physical entry",
        "remain UNVERIFIED.", "",
        "External protocol reference: " + report["sourceReference"], "",
    ])


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/abl-linuxloader")
    args = p.parse_args()
    try:
        result = audit(args.out)
        (args.out / "rea-stage4-ram-partition-protocol.json").write_text(
            json.dumps(result, indent=2) + "\n")
        (args.out / "rea-stage4-ram-partition-protocol.md").write_text(
            markdown(result))
    except (AuditError, ValueError, KeyError, OSError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[VERIFIED] Original HXL1 EFI_RAMPARTITION GUID and record ABI")
    print("[GUID]", result["protocolGuid"])
    print("[EVIDENCE]", result["guidEvidenceId"])
    print("[REPORT]", args.out / "rea-stage4-ram-partition-protocol.md")
    print("[LIMIT] No actual RAM partition value or kernel physical address measured")
    return 0


if __name__ == "__main__":
    sys.exit(main())
