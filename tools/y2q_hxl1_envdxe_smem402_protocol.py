#!/usr/bin/env python3
"""Trace verified original HXL1 EnvDxe RAM-table caller and SMEM 402 reader.

This audit analyzes only original SHA256-bound REA/Ghidra function dossiers,
and one 16-byte GUID read at a candidate UEFI registration call. It never
executes firmware, contacts the handset, or infers boot-time physical DRAM.
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
from tools.y2q_hxl1_envdxe_ram_table_input_trace import audit as input_audit
from tools.y2q_hxl1_envdxe_entry_strings import (
    COORD, PE_SHA256, REPORT_DIR, ExtractionError, contains, evidence_json,
)
from tools.y2q_hxl1_extract_envdxe import GUID_LE

GUID_AT = "0xd2e8"
GUID_FILE = "rea-envdxe-ram-provider-install-guid.json"
FUNCTIONS = (
    ("ram-table-initializer-caller", "0x2064"),
    ("smem-partition-format-reader", "0x5288"),
    ("smem-item-accessor", "0x7d08"),
)
MAX_CODE = 350000
CALL_RE = re.compile(r"\b(?:thunk_)?FUN_[0-9a-fA-F]{6,16}\b")
MAX_CALLS = 200

def authenticated_parent(folder: Path) -> dict:
    parent = input_audit(folder)
    if parent.get("originalEnvDxeSha256") != PE_SHA256:
        raise ExtractionError("Original EnvDxe parent SHA256 mismatch")
    by_label = {f["label"]: f for f in parent.get("supplierAndSetupCandidates", [])}
    smem = by_label.get("table-input-provider")
    install = by_label.get("init-protocol-candidate")
    if not isinstance(smem, dict) or smem.get("functionEntry") != "0x53b0":
        raise ExtractionError("Original table-input provider is unverified")
    text = smem.get("pseudocode", "")
    if (not isinstance(text, str) or
        "FUN_00007d08(" not in text or
        "0x192" not in text or
        "FUN_00005288(" not in text):
        raise ExtractionError("Actual original 0x192 SMEM item access not evidenced")
    if not isinstance(install, dict) or install.get("functionEntry") != "0x23b0":
        raise ExtractionError("Original initializer protocol candidate unverified")
    code = install.get("pseudocode", "")
    if (not isinstance(code, str) or
        "DAT_0000d328 + 0x80" not in code or
        "&DAT_0000d2e8" not in code or
        "&DAT_0000d178" not in code):
        raise ExtractionError("Original service table/GUID/interface args not evidenced")
    xrefs = parent.get("ramTableCallerXrefs", {})
    if (xrefs.get("requestedAddress") != "0x5560" or
        xrefs.get("count") != 1 or
        xrefs.get("callsiteAddresses") != ["0x2064"]):
        raise ExtractionError("0x2064 is not authenticated as sole Ghidra populator reference")
    if parent.get("efiRamProtocolRegistrationProven") is not False:
        raise ExtractionError("Prior evidence incorrectly claims EFI protocol installation")
    return parent


def observed_protocol_guid(folder: Path) -> dict:
    ev = evidence_json(folder, GUID_FILE)
    if (ev.get("operation") != "read_bytes" or
        ev.get("parameters", {}).get("address") != GUID_AT or
        ev.get("parameters", {}).get("length") != 16):
        raise ExtractionError("Original EnvDxe other-protocol GUID read has wrong target")
    data = ev.get("normalized_result")
    if not isinstance(data, dict):
        raise ExtractionError("No Ghidra bytes returned for other-protocol GUID")
    raw = data.get("bytes_hex")
    if (data.get("address") != GUID_AT or
        data.get("requested_bytes") != 16 or
        data.get("returned_bytes") != 16 or
        data.get("complete") is not True or
        not isinstance(raw, str) or
        re.fullmatch(r"[0-9a-fA-F]{32}", raw) is None):
        raise ExtractionError("Original EnvDxe other-protocol GUID read incomplete")
    buffer = bytes.fromhex(raw)
    matched = buffer == GUID_LE
    return {
        "sourceExpression": "&DAT_0000d2e8",
        "staticAddress": GUID_AT,
        "originalBytesHex": buffer.hex(),
        "efiGuidLittleEndianDecoded": str(uuid.UUID(bytes_le=buffer)),
        "matchesKnownRamPartitionGuid": matched,
        "knownRamPartitionGuidAddress": "0xd118",
        "readbackEvidenceId": ev["evidence_id"],
        "bootServicesOffset": "0x80",
        "possibleUEFIInstallProtocolInterface": True,
        "actualRamProtocolRegistrationProven": False,
        "runtimeProtocolInstalledObserved": False,
    }


def audited_function(folder: Path, label: str, address: str) -> dict:
    ev = evidence_json(folder, "rea-envdxe-ram-source-verify-" + label + ".json")
    if (ev.get("operation") != "analyze_function" or
        ev.get("parameters", {}).get("procedure") != address):
        raise ExtractionError("Incorrect Ghidra original function query: "+label)
    result = ev.get("normalized_result")
    if not isinstance(result, dict):
        raise ExtractionError("No original Ghidra source result")
    proc = result.get("procedure")
    if not isinstance(proc, dict):
        raise ExtractionError("Missing Ghidra function identity")
    entry, body = proc.get("address"), proc.get("body")
    if (not isinstance(entry, str) or not COORD.fullmatch(entry) or
        not isinstance(body, dict) or body.get("available") is not True or
        body.get("provenance") != "ghidra-function-body-address-set" or
        not isinstance(body.get("ranges"), list) or
        not contains(address, body["ranges"]) or
        not contains(entry, body["ranges"])):
        raise ExtractionError("Requested original source instruction outside Ghidra function")
    code = result.get("pseudocode")
    if not isinstance(code, str) or not code.strip() or len(code) > MAX_CODE:
        raise ExtractionError("Ghidra original function code missing or oversized")
    flow = result.get("native_value_flow")
    if not isinstance(flow, dict) or not isinstance(flow.get("available"), bool):
        raise ExtractionError("Original Ghidra p-code availability not known")
    symbols = list(dict.fromkeys(CALL_RE.findall(code)))
    if len(symbols) > MAX_CALLS:
        raise ExtractionError("Excessive original Ghidra function symbols")
    return {
        "label": label,
        "queriedAddress": address,
        "functionEntry": entry,
        "functionName": proc.get("name"),
        "functionBodyRanges": body["ranges"],
        "originalEvidenceId": ev["evidence_id"],
        "highFunctionAvailable": flow["available"],
        "originalPseudocode": code,
        "referencedCallSymbols": symbols,
        "runOnActualDeviceObserved": False,
    }


def audit(folder: Path) -> dict:
    previous = authenticated_parent(folder)
    guid = observed_protocol_guid(folder)
    originals = [audited_function(folder, label, at) for label, at in FUNCTIONS]
    return {
        "classification": "ORIGINAL_HXL1_ENV_DXE_RAM_SMEM402_AND_PROTOCOL_IDENTITY_AUDIT",
        "originalEnvDxeSha256": PE_SHA256,
        "originalParentEvidence": {
            x["label"]: x["evidenceId"] for x in previous["supplierAndSetupCandidates"]
        },
        "ramTablePopulatorCallerReferenceEvidence":
            previous["ramTableCallerXrefs"]["evidenceId"],
        "smemItemIdentifier": {"hex": "0x192", "decimal": 402,
                               "meaningInPublishedQualcommHeader":
                               "SMEM_USABLE_RAM_PARTITION_TABLE"},
        "originalCandidateInstallationGuid": guid,
        "originalSourceFunctions": originals,
        "ramProtocolImplementationRegistrationConfirmed": False,
        "runtimeSmemTableContentsObserved": False,
        "physicalBaseMemoryMeasured": False,
        "kernelPhysicalLoadVerified": False,
        "deviceModified": False,
    }


def render(report: dict) -> str:
    g = report["originalCandidateInstallationGuid"]
    lines = [
        "# Original HXL1 EnvDxe: SMEM item 402 and EFI registration identity", "",
        "Original EnvDxe PE SHA256: " + report["originalEnvDxeSha256"], "",
        "## Known SMEM item in firmware", "",
        "FUN_000053b0 requests item 0x192 (402 decimal). Qualcomm's",
        "public rampart.h declares SMEM_USABLE_RAM_PARTITION_TABLE = 402.",
        "The code path is static; live table contents remain unmeasured.",
        "Reference: https://www.mail-archive.com/u-boot@lists.denx.de/msg564611.html",
        "", "## Candidate registration at original 0x23b0", "",
        "Indirect method offset: +0x80 (corresponds to UEFI InstallProtocolInterface",
        "if the source table is EFI_BOOT_SERVICES).",
        "GUID source: " + g["sourceExpression"] + " at " + g["staticAddress"],
        "Original bytes: " + g["originalBytesHex"],
        "Decoded EFI GUID: " + g["efiGuidLittleEndianDecoded"],
        "Matches EFI_RAMPARTITION GUID: " + str(g["matchesKnownRamPartitionGuid"]),
        "REA readback Evidence: " + g["readbackEvidenceId"], "",
    ]
    if not g["matchesKnownRamPartitionGuid"]:
        lines += ["This call DOES NOT directly pass the verified EFI_RAMPARTITION",
                  "GUID from 0xd118. Do not mislabel it as the RAM protocol installer.", ""]
    else:
        lines += ["A matching GUID is necessary but insufficient to prove the",
                  "called EFI service or published function-table callback.", ""]
    lines += [
        "## Original code following verified 0x2064 caller and SMEM provider", "",
    ]
    for f in report["originalSourceFunctions"]:
        lines += [
            "### " + f["label"] + " (" + f["queriedAddress"] + ")", "",
            "Containing Ghidra function: " + f["functionEntry"],
            "Original REA evidence: " + f["originalEvidenceId"],
            "Native p-code available: " + str(f["highFunctionAvailable"]),
            "Observed function symbols: " + ", ".join(f["referencedCallSymbols"]),
            "", "~~~c", f["originalPseudocode"], "~~~", "",
        ]
    lines += [
        "## Unresolved", "",
        "Whether and where original firmware installs EFI_RAMPARTITION",
        "and exposes a GetRamPartitions callback remains unproven.",
        "No boot-time SMEM data, selected BaseMemory, KASLR or physical",
        "kernel entry was measured. This is not a root/KernelSU payload.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=REPORT_DIR)
    p.add_argument("--verify-single",choices=["protocol-guid"]+[x[0] for x in FUNCTIONS])
    args=p.parse_args()
    try:
        if args.verify_single:
            authenticated_parent(args.out)
            if args.verify_single == "protocol-guid":
                v=observed_protocol_guid(args.out)
                print("[VERIFIED GUID]",v["efiGuidLittleEndianDecoded"],
                      "ram-protocol-match",v["matchesKnownRamPartitionGuid"])
            else:
                label,at=next(x for x in FUNCTIONS if x[0]==args.verify_single)
                v=audited_function(args.out,label,at)
                print("[VERIFIED ORIGINAL FUNCTION]",label,v["functionEntry"],
                      v["originalEvidenceId"])
            return 0
        report=audit(args.out)
        (args.out/"rea-envdxe-smem402-protocol.json").write_text(
            json.dumps(report,indent=2)+"\n")
        (args.out/"rea-envdxe-smem402-protocol.md").write_text(render(report))
    except (ExtractionError,ValueError,OSError,KeyError,StopIteration) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    guid=report["originalCandidateInstallationGuid"]
    print("[GUID]",guid["efiGuidLittleEndianDecoded"],
          "matches RAM protocol",guid["matchesKnownRamPartitionGuid"])
    for fn in report["originalSourceFunctions"]:
        print("[FUNCTION VERIFIED]",fn["label"],fn["functionEntry"],
              "lines",len(fn["originalPseudocode"].splitlines()))
    print("[REPORT]",args.out/"rea-envdxe-smem402-protocol.md")
    print("[LIMIT] Exact static XBL only: no runtime RAM BaseMemory or root")
    return 0


if __name__=="__main__":
    sys.exit(main())
