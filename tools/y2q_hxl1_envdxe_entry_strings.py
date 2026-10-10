#!/usr/bin/env python3
"""Investigate verified stock HXL1 XBL EnvDxe's entrypoint and target strings.

Preconditions: exact pinned EnvDxe, verified Ghidra readback of RAM protocol
GUID, and prior legitimate zero-reference result. Consumes saved REA/Ghidra
Evidence only; all coordinates are PE analysis addresses, not Linux physical
addresses. No device operation or firmware modification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_rea_xrefs import (
    PE_SHA256, REPORT_DIR, ExtractionError, source_info, xref_info,
)
from tools.y2q_abl_linuxloader_extract import identify_pe

QUERIES = (
    ("ram-partition", "RamPartition"),
    ("get-ram-partitions", "GetRamPartitions"),
    ("env-driver", "EnvDxe"),
)
MAX_JSON = 50 * 1024 * 1024
MAX_STRINGS = 400
MAX_CODE = 450000
COORD = re.compile(r"^0x[0-9a-fA-F]+$")


def entry_address(folder: Path) -> str:
    """Calculate entry from verified PE metadata, not an arbitrary label."""
    info = source_info(folder)
    manifest = json.loads((folder / "original-envdxe-hxl1.json").read_text())
    actual_pe = identify_pe(Path(info["efiFile"]).read_bytes())
    imported_pe = manifest.get("peInfo")
    if not isinstance(imported_pe, dict) or actual_pe != imported_pe:
        raise ExtractionError("Exact EnvDxe PE header differs from extraction manifest")
    base = imported_pe.get("preferredImageBase")
    rva = imported_pe.get("entryPointRva")
    if not isinstance(base, str) or not COORD.fullmatch(base):
        raise ExtractionError("Original EnvDxe PE preferred image base absent")
    if not isinstance(rva, str) or not COORD.fullmatch(rva):
        raise ExtractionError("Original EnvDxe PE entry RVA absent")
    entry = int(base, 16) + int(rva, 16)
    if entry < 0 or entry >= 2**64:
        raise ExtractionError("Original EnvDxe PE entry coordinate overflows")
    if entry == int(info["preferredAddress"], 16):
        raise ExtractionError("Entrypoint unexpectedly equals protocol GUID data")
    return hex(entry)


def evidence_json(folder: Path, filename: str) -> dict:
    f = folder / filename
    if f.is_symlink() or not f.is_file() or f.stat().st_size > MAX_JSON:
        raise ExtractionError("Required saved original REA evidence missing: " + filename)
    ev = json.loads(f.read_text())
    if not isinstance(ev, dict) or "error" in ev:
        raise ExtractionError("REA returned a failed evidence record: " + filename)
    if (ev.get("provider", {}).get("id") != "ghidra" or
        ev.get("subject", {}).get("digest", {}).get("sha256") != PE_SHA256 or
        ev.get("subject", {}).get("architecture") != "arm64" or
        not isinstance(ev.get("evidence_id"), str) or not ev["evidence_id"]):
        raise ExtractionError("REA Ghidra evidence not bound to original EnvDxe: " + filename)
    return ev


def search_audit(folder: Path, label: str, pattern: str) -> dict:
    ev = evidence_json(folder, "rea-envdxe-search-" + label + ".json")
    params = ev.get("parameters", {})
    if (ev.get("operation") != "search_strings" or
        not isinstance(params, dict) or
        params.get("pattern") != pattern or
        params.get("mode") not in (None, "literal") or
        params.get("case_sensitive") not in (None, False)):
        raise ExtractionError("REA search query operation/coordinates do not match " + label)
    hits = ev.get("normalized_result")
    if not isinstance(hits, list) or len(hits) > MAX_STRINGS:
        raise ExtractionError("Original Ghidra search hits unbounded or absent")
    results = []
    for hit in hits:
        if (not isinstance(hit, dict) or
            not isinstance(hit.get("address"), str) or
            not COORD.fullmatch(hit["address"]) or
            not isinstance(hit.get("value"), str)):
            raise ExtractionError("Invalid Ghidra string coordinate/value for " + label)
        if pattern.lower() not in hit["value"].lower():
            raise ExtractionError("Original Ghidra string did not match requested literal")
        results.append({"address": hit["address"], "value": hit["value"][:1000]})
    return {"label": label, "pattern": pattern, "evidenceId": ev["evidence_id"],
            "hitCount": len(hits), "hits": results}


def contains(source: str, ranges: list) -> bool:
    address = int(source,16)
    for region in ranges:
        if (not isinstance(region,dict) or
            not isinstance(region.get("start"),str) or
            not isinstance(region.get("end"),str) or
            not COORD.fullmatch(region["start"]) or
            not COORD.fullmatch(region["end"])):
            raise ExtractionError("Invalid Ghidra EnvDxe function range")
        if int(region["start"],16) <= address <= int(region["end"],16):
            return True
    return False


def entry_audit(folder: Path) -> dict:
    entry = entry_address(folder)
    ev = evidence_json(folder, "rea-envdxe-entry-function.json")
    if (ev.get("operation") != "analyze_function" or
        ev.get("parameters", {}).get("procedure") != entry):
        raise ExtractionError("Original Ghidra function query not actual PE entry")
    dossier = ev.get("normalized_result")
    if not isinstance(dossier, dict) or not isinstance(dossier.get("procedure"), dict):
        raise ExtractionError("Ghidra EnvDxe entry dossier identity absent")
    fn = dossier["procedure"]
    address = fn.get("address")
    body = fn.get("body")
    if (not isinstance(address, str) or not COORD.fullmatch(address) or
        not isinstance(body, dict) or body.get("available") is not True or
        body.get("provenance") != "ghidra-function-body-address-set" or
        not isinstance(body.get("ranges"), list) or
        not contains(entry,body["ranges"]) or not contains(address,body["ranges"])):
        raise ExtractionError("PE entry not contained in genuine Ghidra function body")
    code = dossier.get("pseudocode")
    if not isinstance(code, str) or len(code) > MAX_CODE:
        raise ExtractionError("Ghidra function pseudocode unavailable/oversized")
    native = dossier.get("native_value_flow")
    if not isinstance(native, dict) or not isinstance(native.get("available"), bool):
        raise ExtractionError("Ghidra p-code availability not classified")
    return {
        "requestedEntryAddress": entry,
        "containingFunctionEntry":address,
        "name":fn.get("name"),
        "body":body["ranges"],
        "evidenceId":ev["evidence_id"],
        "pcodeAvailable":native["available"],
        "pseudocode":code,
        "callerCount":len(dossier.get("callers", []))
            if isinstance(dossier.get("callers"),list) else None,
        "calleeCount":len(dossier.get("callees", []))
            if isinstance(dossier.get("callees"),list) else None,
    }


def analyze(folder: Path) -> dict:
    baseline = xref_info(folder)
    if baseline.get("referenceCount") != 0 or not baseline.get("importedGuidBytesVerified"):
        raise ExtractionError("This branch specifically investigates the verified zero-xref case")
    entry = entry_audit(folder)
    searches = [search_audit(folder, label, literal) for label,literal in QUERIES]
    return {
        "classification":"EXACT_HXL1_ENV_DXE_ENTRY_AND_DIAGNOSTIC_STRING_INVESTIGATION",
        "originalEnvDxeSha256":PE_SHA256,
        "guidReadEvidenceId":baseline["guidByteReadbackEvidenceId"],
        "guidXrefsEvidenceId":baseline["evidenceId"],
        "guidXrefsCount":0,
        "entryFunction":entry,
        "stringSearches":searches,
        "protocolRegistrationFunctionProved":False,
        "getRamPartitionsImplementationProved":False,
        "actualFirmwareRamPartitionsRead":False,
        "numericPhysicalKernelBaseVerified":False,
        "deviceModified":False,
    }


def render(report:dict)->str:
    entry=report["entryFunction"]
    lines=[
        "# Original HXL1 EnvDxe: entrypoint and RAM-partition diagnostics",
        "", "Original EnvDxe SHA256: "+report["originalEnvDxeSha256"],
        "GUID readback REA ID: "+report["guidReadEvidenceId"],
        "Original zero-GUID-xrefs REA ID: "+report["guidXrefsEvidenceId"], "",
        "The GUID address is verified yet Ghidra records no direct reference.",
        "The entrypoint and string evidence below are independent static leads.",
        "",
        "## Exact PE entrypoint and owning Ghidra function", "",
        "PE entry: "+entry["requestedEntryAddress"],
        "Owning function: "+entry["containingFunctionEntry"]+" "+str(entry["name"]),
        "Ghidra Evidence: "+entry["evidenceId"],
        "HighFunction p-code available: "+str(entry["pcodeAvailable"]),
        "Callers: "+str(entry["callerCount"])+", callees: "+str(entry["calleeCount"]),
        "", "~~~c",entry["pseudocode"],"~~~","",
        "## Targeted Ghidra string searches","",
    ]
    for observation in report["stringSearches"]:
        lines += ["### "+observation["pattern"],"",
                  "REA Evidence: "+observation["evidenceId"],
                  "Total Ghidra hits: "+str(observation["hitCount"]), ""]
        for hit in observation["hits"]:
            lines += ["- "+hit["address"]+" — "+hit["value"].replace("\n"," ").replace("\r"," ")[:350]]
        lines += [""]
    lines += ["## Proof obligations", "",
              "Next follow only observed string xrefs or the original",
              "entrypoint's actual callees; inspect the EFI boot-services",
              "InstallMultipleProtocolInterfaces call and the function-pointer",
              "table for EFI_GetRamPartitions. The reference Qualcomm source",
              "is a hypothesis, not a substitute for actual Samsung code.",
              "No runtime DRAM values or Linux physical kernel entry proved.", ""]
    return "\n".join(lines)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=REPORT_DIR)
    p.add_argument("--verify-single",choices=["entry"]+[k for k,_ in QUERIES])
    a=p.parse_args()
    try:
        if a.verify_single:
            if a.verify_single == "entry":
                entry=entry_audit(a.out)
                print("[VERIFIED ENVDXE ENTRY]",entry["containingFunctionEntry"])
            else:
                label,pat=next((k,v) for k,v in QUERIES if k==a.verify_single)
                observation=search_audit(a.out,label,pat)
                print("[VERIFIED SEARCH]",label,observation["hitCount"])
            return 0
        result=analyze(a.out)
        (a.out/"rea-envdxe-entry-strings-audit.json").write_text(
            json.dumps(result,indent=2)+"\n")
        (a.out/"rea-envdxe-entry-strings-audit.md").write_text(render(result))
    except (ExtractionError, OSError, ValueError, KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    entry=result["entryFunction"]
    print("[VERIFIED] Exact HXL1 EnvDxe entry",entry["requestedEntryAddress"],
          "owning",entry["containingFunctionEntry"])
    print("[ENTRY EVIDENCE]",entry["evidenceId"])
    for item in result["stringSearches"]:
        print("[VERIFIED Ghidra strings]",item["pattern"],"hits",item["hitCount"])
        for hit in item["hits"][:12]:
            print(" ",hit["address"],repr(hit["value"][:150]))
    print("[REPORT]",a.out/"rea-envdxe-entry-strings-audit.md")
    print("[LIMIT] No proven XBL installer, runtime RAM data or kernel PA")
    return 0


if __name__=="__main__":
    sys.exit(main())
