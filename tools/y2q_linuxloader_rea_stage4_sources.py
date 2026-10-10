#!/usr/bin/env python3
"""Inspect only verified original HXL1 supporting functions for BootLinux.

Queries already-known original callers: base-memory provider, KASLR entropy
initializer and firmware boot-services shutdown. No runtime physical values
are inferred from decompiler pseudocode.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_linuxloader_rea_stage4_xrefs import LOADER_SHA256, AuditError, digest

SOURCES = (
    ("base-memory-provider", "0x1f018", "FUN_0001f018"),
    ("kaslr-initializer", "0x20838", "FUN_00020838"),
    ("exit-boot-services", "0x1e868", "FUN_0001e868"),
    # Direct call observed at 0x1f018: consumes Qualcomm RAM partition protocol.
    ("ram-partition-reader", "0x1eca0", "FUN_0001eca0"),
)
ADDRESS = re.compile(r"^0x[0-9a-f]+$")
MAX_FILE_BYTES = 50000000
MAX_PSEUDOCODE = 250000


def validate(folder: Path, label: str, query: str) -> dict:
    filename = folder / ("rea-stage4-source-" + label + ".json")
    if filename.is_symlink() or not filename.is_file() or filename.stat().st_size > MAX_FILE_BYTES:
        raise AuditError("Missing/untrusted original REA function dossier " + label)
    ev = json.loads(filename.read_text())
    if (not isinstance(ev, dict) or "error" in ev or
        ev.get("operation") != "analyze_function" or
        ev.get("provider", {}).get("id") != "ghidra" or
        ev.get("subject", {}).get("digest", {}).get("sha256") != LOADER_SHA256 or
        ev.get("subject", {}).get("architecture") != "arm64" or
        ev.get("parameters", {}).get("procedure") != query):
        raise AuditError("REA function query or original HXL1 provenance mismatch")
    fn = ev.get("normalized_result")
    if not isinstance(fn, dict) or not isinstance(fn.get("procedure"), dict):
        raise AuditError("No original Ghidra procedure identity")
    identity = fn["procedure"]
    entry = identity.get("address")
    body = identity.get("body")
    if (not isinstance(entry, str) or not ADDRESS.fullmatch(entry) or
        not isinstance(body, dict) or body.get("available") is not True or
        body.get("provenance") != "ghidra-function-body-address-set" or
        not isinstance(body.get("ranges"), list)):
        raise AuditError("Function body not properly authenticated")
    def contained(addr: str) -> bool:
        target = int(addr, 16)
        return any(
            isinstance(r, dict) and
            isinstance(r.get("start"), str) and ADDRESS.fullmatch(r["start"]) and
            isinstance(r.get("end"), str) and ADDRESS.fullmatch(r["end"]) and
            int(r["start"], 16) <= target <= int(r["end"], 16)
            for r in body["ranges"]
        )
    if not contained(query) or not contained(entry):
        raise AuditError("Requested supporting function address not contained in body")
    pseudocode = fn.get("pseudocode")
    if not isinstance(pseudocode, str) or len(pseudocode) > MAX_PSEUDOCODE:
        raise AuditError("Missing/oversized supporting-function pseudocode")
    flow = fn.get("native_value_flow")
    if not isinstance(flow, dict) or not isinstance(flow.get("available"), bool):
        raise AuditError("Native p-code evidence availability not identified")
    evidence_id = ev.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise AuditError("Missing original REA Evidence ID")
    return {
        "label": label, "requestedAddress": query, "functionEntry": entry,
        "functionName": identity.get("name"), "functionBody": body["ranges"],
        "highFunctionAvailable": flow["available"], "highFunctionTruncated": flow.get("truncated"),
        "evidenceId": evidence_id, "pseudocode": pseudocode,
        "sourceFile": str(filename),
    }


def audit(folder: Path) -> dict:
    loader = folder / "LinuxLoader-HXL1.efi"
    if loader.is_symlink() or not loader.is_file() or digest(loader) != LOADER_SHA256:
        raise AuditError("Original HXL1 LinuxLoader source digest mismatch")
    records = []
    for label, address, name in SOURCES:
        try:
            record = validate(folder, label, address)
            record["status"] = "VERIFIED_STATIC_FUNCTION"
        except (AuditError, ValueError, OSError) as exc:
            record = {"label": label, "requestedAddress": address,
                      "status": "FUNCTION_NOT_VERIFIED", "reason": str(exc)}
        records.append(record)
    return {
        "classification": "ORIGINAL_HXL1_STATIC_INPUT_SOURCE_CODE_ONLY",
        "loaderSha256": LOADER_SHA256, "functions": records,
        "kernelPhysicalBaseMeasured": False, "bootTimeKaslrMeasured": False,
        "actualUefiShutdownExecutionObserved": False, "deviceModified": False,
    }


def markdown(data: dict) -> str:
    output = ["# HXL1 original BootLinux supporting functions",
              "", "Original EFI SHA256: " + data["loaderSha256"], "",
              "**Static Ghidra decompilation; no actual runtime physical memory base is measured.**", ""]
    for fn in data["functions"]:
        output += ["## " + fn["label"], "", "Status: " + fn["status"], ""]
        if fn["status"] != "VERIFIED_STATIC_FUNCTION":
            output += ["Gap: " + fn["reason"], ""]
            continue
        output += ["Ghidra function: " + str(fn["functionName"]) + " at " +
                   fn["functionEntry"], "",
                   "Full body: " + json.dumps(fn["functionBody"]), "",
                   "Original REA Evidence ID: " + fn["evidenceId"], "",
                   "HighFunction p-code available: " + str(fn["highFunctionAvailable"]), "",
                   "~~~c", fn["pseudocode"], "~~~", ""]
    output += ["## What this does NOT prove", "",
               "A static firmware initialization, UEFI API call, or decompiled "
               "routine does not establish which boot branch ran or what physical "
               "address/entropy value the original S20+ used at boot.", ""]
    return "\n".join(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path.home() /
                        "s20-artifacts/hxl1-research/abl-linuxloader")
    parser.add_argument("--verify-single", choices=[x[0] for x in SOURCES])
    args = parser.parse_args()
    try:
        if args.verify_single:
            entry = next(x for x in SOURCES if x[0] == args.verify_single)
            fn = validate(args.out, entry[0], entry[1])
            print("[SOURCE VERIFIED]", fn["label"], fn["functionEntry"], fn["evidenceId"])
            return 0
        report = audit(args.out)
        (args.out/"rea-stage4-source-functions.json").write_text(json.dumps(report,indent=2)+"\n")
        (args.out/"rea-stage4-source-functions.md").write_text(markdown(report))
    except (AuditError, OSError, ValueError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for fn in report["functions"]:
        print("["+fn["status"]+"]", fn["label"],
              fn.get("functionEntry", fn["requestedAddress"]))
    print("[REPORT]", args.out/"rea-stage4-source-functions.md")
    print("[LIMIT] No numerical boot-time BaseMemory or KASLR result yet")
    return 0 if all(x["status"] == "VERIFIED_STATIC_FUNCTION"
                    for x in report["functions"]) else 2


if __name__ == "__main__":
    sys.exit(main())
