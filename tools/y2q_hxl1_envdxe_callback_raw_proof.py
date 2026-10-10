#!/usr/bin/env python3
"""Independent original PE executable proof for EnvDxe callback 0x1f74.

Ghidra can read original imported bytes even when it cannot decompile a
function at this address. Preserve the original function-analysis failure;
never interpret it as absence of a callback or a live boot memory location.
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path

from tools.y2q_hxl1_envdxe_entry_strings import (
    COORD, PE_SHA256, ExtractionError, evidence_json,
)
from tools.y2q_hxl1_envdxe_rea_xrefs import source_info
from tools.y2q_abl_linuxloader_extract import identify_pe

CALLBACK_BYTES_LENGTH=64
CALLBACK_BYTES_EVIDENCE="rea-envdxe-ram-protocol-callback-code-read.json"
CALLBACK_PARTIAL="rea-envdxe-ram-protocol-callback-function.partial.json"
CALLBACK_STDERR="rea-envdxe-ram-protocol-callback-function-stderr.txt"
MAX_FAILURE_LOG=1024*1024


def original_code(folder:Path,address:str)->dict:
    """Map one preferred PE code VA to exactly one executable backed section."""
    if not isinstance(address,str) or COORD.fullmatch(address) is None:
        raise ExtractionError("Invalid stock callback static analysis address")
    source=source_info(folder)
    original=Path(source["efiFile"]).read_bytes()
    pe=identify_pe(original)
    if not isinstance(pe,dict) or pe.get("sha256")!=PE_SHA256:
        raise ExtractionError("Original EnvDxe callback source PE identity mismatch")
    preferred=int(pe["preferredImageBase"],16)
    rva=int(address,16)-preferred
    if rva<0 or int(address,16)%4:
        raise ExtractionError("Original callback RVA negative or AArch64-misaligned")
    nt=struct.unpack_from("<I",original,0x3c)[0]
    count=struct.unpack_from("<H",original,nt+6)[0]
    size=struct.unpack_from("<H",original,nt+20)[0]
    first=nt+24+size
    matches=[]
    for i in range(count):
        pos=first+40*i
        if pos+40>len(original):
            raise ExtractionError("Truncated original HXL1 EnvDxe PE section")
        item=original[pos:pos+40]
        vsize,va,rawsize,rawpos=struct.unpack_from("<IIII",item,8)
        flags=struct.unpack_from("<I",item,36)[0]
        relative=rva-va
        if 0<=relative and relative+CALLBACK_BYTES_LENGTH<=rawsize:
            offset=rawpos+relative
            if offset+CALLBACK_BYTES_LENGTH>len(original):
                raise ExtractionError("Original stock PE callback data truncated")
            matches.append((offset,item[:8].split(b"\0",1)[0].decode("ascii","replace"),
                            va,flags))
    if len(matches)!=1:
        raise ExtractionError("Original EnvDxe callback not uniquely backed by PE section")
    offset,name,section_rva,flags=matches[0]
    if not (flags & 0x20000000):
        raise ExtractionError("Original EnvDxe callback pointer not in executable PE section")
    content=original[offset:offset+CALLBACK_BYTES_LENGTH]
    if len(content)!=CALLBACK_BYTES_LENGTH:
        raise ExtractionError("Original stock callback code bytes truncated")
    return {
        "coordinate":address,
        "fileOffset":hex(offset),
        "sectionName":name,
        "sectionRva":hex(section_rva),
        "bytesSha256":hashlib.sha256(content).hexdigest(),
        "bytesHex":content.hex(),
        "length":CALLBACK_BYTES_LENGTH,
        "originalEnvDxeSha256":PE_SHA256,
        "execSectionVerified":True,
        "physicalMemoryInferred":False,
    }


def imported_code_match(folder:Path,address:str)->dict:
    """REA/Ghidra read-bytes must equal the independent pinned original PE."""
    original=original_code(folder,address)
    ev=evidence_json(folder,CALLBACK_BYTES_EVIDENCE)
    if (ev.get("operation")!="read_bytes" or
        ev.get("parameters",{}).get("address")!=address or
        ev.get("parameters",{}).get("length")!=CALLBACK_BYTES_LENGTH):
        raise ExtractionError("Ghidra callback code byte-read target mismatch")
    data=ev.get("normalized_result")
    if (not isinstance(data,dict) or
        data.get("address")!=address or
        data.get("requested_bytes")!=CALLBACK_BYTES_LENGTH or
        data.get("returned_bytes")!=CALLBACK_BYTES_LENGTH or
        data.get("complete") is not True or
        not isinstance(data.get("bytes_hex"),str) or
        re.fullmatch(r"[0-9a-fA-F]{128}",data["bytes_hex"]) is None):
        raise ExtractionError("Ghidra callback read incomplete or corrupted")
    if data["bytes_hex"].lower()!=original["bytesHex"]:
        raise ExtractionError("Ghidra callback code differs from pinned original EnvDxe PE")
    return {**original,
            "originalGhidraEvidenceId":ev["evidence_id"],
            "importedBytesEqualOriginal":True}


def failure_record(folder:Path)->dict:
    """Report preserved failed Ghidra analysis without fabricating its reason."""
    found=[]
    for name in (CALLBACK_PARTIAL,CALLBACK_STDERR):
        file=folder/name
        if file.is_symlink():
            raise ExtractionError("Symlinked Ghidra failure evidence refused")
        if file.exists():
            if not file.is_file() or file.stat().st_size>MAX_FAILURE_LOG:
                raise ExtractionError("Invalid or oversized callback failure artifact")
            data=file.read_bytes()
            found.append({
                "filename":name,"length":len(data),
                "sha256":hashlib.sha256(data).hexdigest(),
                "excerpt":data.decode("utf-8","replace")[:1000],
            })
    return {
        "status":("PREVIOUS_GHIDRA_CALLBACK_ANALYSIS_FAILED_OR_PARTIAL"
                  if any(a["filename"]==CALLBACK_PARTIAL for a in found)
                  else "GHIDRA_CALLBACK_FUNCTION_NOT_ANALYZED"),
        "files":found,
        "callbackAbsent":False,
    }
