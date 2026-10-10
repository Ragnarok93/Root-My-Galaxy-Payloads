#!/usr/bin/env python3
"""Authenticate targeted REA/Ghidra xrefs of the original HXL1 EnvDxe RAM GUID.

The module MUST be extracted from original sha-pinned XBL by the narrow
extractor before submitting addresses. A PE RVA or Ghidra analysis address is
not device DRAM or a Linux kernel physical address.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_extract_envdxe import (
    OUT_NAME, PE_SHA256, FILE_GUID, GUID_LE,
    GUID_PE_FILE_OFFSET, XBL_SHA256,
    ExtractionError, REPORT_DIR,
)

ADDRESS=re.compile(r"^0x[0-9a-fA-F]+$")
XREF_NAME="rea-envdxe-ram-guid-xrefs.json"
READBACK_NAME="rea-envdxe-ram-guid-import-read.json"
MAX_JSON=16*1024*1024
MAX_REFS=5000


def source_info(folder: Path) -> dict:
    target=folder/OUT_NAME
    manifest=folder/"original-envdxe-hxl1.json"
    if (target.is_symlink() or not target.is_file() or
        manifest.is_symlink() or not manifest.is_file()):
        raise ExtractionError("No verified original EnvDxe or extraction manifest")
    data=target.read_bytes()
    if (hashlib.sha256(data).hexdigest()!=PE_SHA256 or
        data[GUID_PE_FILE_OFFSET:GUID_PE_FILE_OFFSET+16]!=GUID_LE):
        raise ExtractionError("Original EnvDxe bytes, SHA256 or GUID do not match")
    obj=json.loads(manifest.read_text())
    if (not isinstance(obj,dict) or
        obj.get("xblSha256")!=XBL_SHA256 or
        obj.get("originalEnvDxePeSha256")!=PE_SHA256 or
        obj.get("ffsGuid")!=FILE_GUID or
        obj.get("ui")!="EnvDxe" or
        obj.get("guidPeFileOffset")!=hex(GUID_PE_FILE_OFFSET)):
        raise ExtractionError("Original EnvDxe extraction manifest provenance mismatch")
    pos=obj.get("guidPosition")
    if not isinstance(pos,dict):
        raise ExtractionError("GUID PE file offset does not map to a section RVA")
    va=pos.get("preferredImageVirtualAddress")
    if not isinstance(va,str) or not ADDRESS.fullmatch(va):
        raise ExtractionError("Invalid original EnvDxe preferred VA in manifest")
    if not isinstance(pos.get("guidRva"),str) or not ADDRESS.fullmatch(pos["guidRva"]):
        raise ExtractionError("Missing original EnvDxe PE GUID RVA")
    return {
        "efiFile":str(target), "preferredAddress":va,
        "guidRva":pos["guidRva"],
        "guidPeFileOffset":hex(GUID_PE_FILE_OFFSET),
        "originalEnvDxeSha256":PE_SHA256,
        "originalXblSha256":XBL_SHA256,
    }


def readback_info(folder: Path) -> dict:
    """Prevent silently treating a mismatched Ghidra image base as no xrefs."""
    source=source_info(folder)
    f=folder/READBACK_NAME
    if f.is_symlink() or not f.is_file() or f.stat().st_size>MAX_JSON:
        raise ExtractionError("Ghidra exact imported-GUID read Evidence absent")
    ev=json.loads(f.read_text())
    if (not isinstance(ev,dict) or "error" in ev or
        ev.get("operation")!="read_bytes" or
        ev.get("provider",{}).get("id")!="ghidra" or
        ev.get("subject",{}).get("digest",{}).get("sha256")!=PE_SHA256 or
        ev.get("subject",{}).get("architecture")!="arm64" or
        ev.get("parameters",{}).get("address")!=source["preferredAddress"] or
        ev.get("parameters",{}).get("length")!=16):
        raise ExtractionError("Ghidra imported GUID read provenance mismatch")
    read=ev.get("normalized_result")
    if (not isinstance(read,dict) or
        read.get("address")!=source["preferredAddress"] or
        read.get("requested_bytes")!=16 or
        read.get("returned_bytes")!=16 or
        read.get("complete") is not True or
        read.get("bytes_hex","").lower()!=GUID_LE.hex()):
        raise ExtractionError(
            "Ghidra import address does not contain original RAM GUID; "
            "image base must be investigated, do not trust xrefs")
    evidence=ev.get("evidence_id")
    if not isinstance(evidence,str) or not evidence:
        raise ExtractionError("Missing original GUID readback Evidence ID")
    return {"evidenceId":evidence,
            "importedGuidAddress":source["preferredAddress"],
            "importedBytesVerified":True}


def xref_info(folder: Path) -> dict:
    source=source_info(folder)
    corroborated=readback_info(folder)
    f=folder/XREF_NAME
    if f.is_symlink() or not f.is_file() or f.stat().st_size>MAX_JSON:
        raise ExtractionError("Original EnvDxe Ghidra xrefs Evidence absent")
    ev=json.loads(f.read_text())
    if (not isinstance(ev,dict) or "error" in ev or
        ev.get("operation")!="xrefs" or
        ev.get("provider",{}).get("id")!="ghidra" or
        ev.get("subject",{}).get("digest",{}).get("sha256")!=PE_SHA256 or
        ev.get("subject",{}).get("architecture")!="arm64" or
        ev.get("parameters",{}).get("address")!=source["preferredAddress"]):
        raise ExtractionError("Ghidra xrefs not for exact HXL1 EnvDxe and mapped GUID VA")
    refs=ev.get("normalized_result")
    if not isinstance(refs,list) or len(refs)>MAX_REFS:
        raise ExtractionError("Invalid/unbounded REA Ghidra xrefs")
    for addr in refs:
        if not isinstance(addr,str) or not ADDRESS.fullmatch(addr):
            raise ExtractionError("Bad Ghidra source reference address: "+repr(addr))
    evidence=ev.get("evidence_id")
    if not isinstance(evidence,str) or not evidence:
        raise ExtractionError("Missing REA original EnvDxe evidence ID")
    return {
        "classification":"VERIFIED_STATIC_ORIGINAL_ENV_DXE_RAMPARTITION_GUID_XREFS",
        **source,
        "evidenceId":evidence,
        "guidByteReadbackEvidenceId":corroborated["evidenceId"],
        "importedGuidBytesVerified":True,
        "referenceCount":len(refs),
        "distinctSourceReferences":list(dict.fromkeys(refs)),
        "protocolInstallCallIdentified":False,
        "getRamPartitionsImplementationIdentified":False,
        "runtimeRamEntriesMeasured":False,
        "actualKernelPhysicalAddressVerified":False,
        "deviceModified":False,
    }


def report_text(result:dict)->str:
    lines=[
        "# HXL1 XBL EnvDxe: Ghidra references to exact EFI_RAMPARTITION GUID", "",
        "Original XBL SHA256: "+result["originalXblSha256"],
        "Original EnvDxe SHA256: "+result["originalEnvDxeSha256"], "",
        "Static EnvDxe GUID original file offset: "+result["guidPeFileOffset"],
        "Static PE RVA: "+result["guidRva"],
        "Original preferred static PE VA: "+result["preferredAddress"], "",
        "Ghidra REA evidence ID: "+result["evidenceId"],
        "Imported GUID bytes verified via REA read: "+
        result["guidByteReadbackEvidenceId"],
        "Source reference count: "+str(result["referenceCount"]), "",
        "## Reference instructions", "",
    ]
    if result["referenceCount"]==0:
        lines+=["No Ghidra xref found for this VA. This is not proof the",
                "driver lacks an installer; PIC/relocated pointers or a",
                "different importer image base may require corroboration.",""]
    for address in result["distinctSourceReferences"]:
        lines.append("- "+address)
    lines+=["","## Next proof gate","",
            "Obtain each observed reference instruction's actual containing",
            "Ghidra function and inspect calls to InstallMultipleProtocolInterfaces.",
            "A GUID reference or string is only a registration candidate.",
            "The XBL image base and GUID RVA are not a physical Linux load.", ""]
    return "\n".join(lines)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=REPORT_DIR)
    p.add_argument("--verify-only",action="store_true")
    a=p.parse_args()
    try:
        result=xref_info(a.out)
        if not a.verify_only:
            (a.out/"rea-envdxe-ram-guid-xrefs-audit.json").write_text(
                json.dumps(result,indent=2)+"\n")
            (a.out/"rea-envdxe-ram-guid-xrefs-audit.md").write_text(report_text(result))
    except (OSError, ValueError, KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    print("[VERIFIED] Original EnvDxe GUID xrefs; count",result["referenceCount"])
    for addr in result["distinctSourceReferences"][:30]:
        print(" ",addr)
    print("[LIMIT] No actual EFI protocol registration or live RAM base established")
    return 0


if __name__=="__main__":
    sys.exit(main())
