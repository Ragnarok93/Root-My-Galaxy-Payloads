#!/usr/bin/env python3
"""Extract ONLY the verified original HXL1 XBL EnvDxe AArch64 PE.

Reuses exact original xbl.elf pin, existing CRC-checked bounded gzip,
and original validated EFI FV/FFS Walker. Refuses any mismatched EnvDxe
PE hash, FFS file GUID, literal EFI_RAMPARTITION GUID, or compressed offset.
Writes a single original extracted PE to host artifacts for REA/Ghidra.
No device access, no boot/EFI execution, and no arbitrary PE patching.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_xbl_envdxe_fv_probe import (
    firmware_gzip, GUID_LE, Walker, ProviderProbeError,
)
from tools.y2q_abl_linuxloader_extract import identify_pe
from tools.y2q_stock_bl_elf_audit import INPUTS, parse_elf

XBL_SHA256 = "78d1bff9ef5c2aa626652390c112f0bf81869bb1f9a05fcd8a8e3dfff8f8b357"
GZIP_OFFSET = 0xC6488
FILE_GUID = "90a49afd-422f-08ae-9611-e788d3804845"
PE_SHA256 = "9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670"
GUID_PE_FILE_OFFSET = 0xD118
ORIGINAL_DIR = Path.home() / "s20-artifacts/hxl1-research/bl-stock"
REPORT_DIR = Path.home() / "s20-artifacts/hxl1-research/xbl-rampartition"
OUT_NAME = "EnvDxe-HXL1.efi"


class ExtractionError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guid_file_offset_to_rva(pe: bytes, file_offset: int) -> dict:
    """Map original PE file byte offset only within a declared section.

    PE loader may rebase preferred image base; RVA is not a physical address.
    """
    meta = identify_pe(pe)
    if meta is None:
        raise ExtractionError("Original EnvDxe has invalid AArch64 PE32+ header")
    nt = struct.unpack_from("<I", pe, 0x3c)[0]
    count = struct.unpack_from("<H", pe, nt + 6)[0]
    optional_len = struct.unpack_from("<H", pe, nt + 20)[0]
    section_table = nt + 24 + optional_len
    hit = []
    for i in range(count):
        start = section_table + i * 40
        section = pe[start:start+40]
        if len(section) != 40:
            raise ExtractionError("Truncated section header in original PE")
        name = section[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
        vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", section, 8)
        if raw_offset <= file_offset and file_offset + len(GUID_LE) <= raw_offset + raw_size:
            if raw_offset + raw_size > len(pe):
                raise ExtractionError("Original PE section extends beyond file")
            rva = vaddr + file_offset - raw_offset
            if rva + len(GUID_LE) > vaddr + max(vsize,raw_size):
                raise ExtractionError("GUID location outside declared PE section")
            hit.append({"sectionIndex":i, "sectionName":name,
                        "sectionRawFileOffset":hex(raw_offset),
                        "sectionRva":hex(vaddr), "guidRva":hex(rva),
                        "preferredImageVirtualAddress":hex(int(
                            meta["preferredImageBase"],16)+rva)})
    if len(hit) > 1:
        raise ExtractionError("Overlapping original section records claim GUID location")
    return {
        "guidPeFileOffset": hex(file_offset),
        "guidPosition": hit[0] if hit else None,
        "guidFileOffsetMappedToSection": bool(hit),
        "preferredPeImageBase": meta["preferredImageBase"],
        "warning": ("Original PE preferred VA is static only; Ghidra import "
                    "address should be checked against actual REA binary_overview."),
    }


def exact_candidate(source: bytes) -> dict:
    if digest(source) != XBL_SHA256 or source.__len__() != 4194304:
        raise ExtractionError("Original XBL source SHA256/size does not match HXL1 stock")
    original = INPUTS["xbl.elf"]
    if original["sha256"] != XBL_SHA256:
        raise ExtractionError("Pinned original XBL manifest changed")
    layout = parse_elf(source)
    if (layout["elfClass"] != "ELF64" or
        layout["machine"] != original["machine"] or
        layout["entryPoint"] != original["entry"] or
        layout["programHeaderCount"] != original["programHeaders"]):
        raise ExtractionError("Original XBL ELF structural identity mismatch")
    fv = firmware_gzip(source,GZIP_OFFSET)
    if fv is None or b"_FVH" not in fv:
        raise ExtractionError("Pinned XBL gzip stream does not decode to firmware volume")
    walker = Walker()
    walker.search_fv(fv,["xbl.elf:gzip@0xc6488"],0)
    matched = [obj for obj in walker.identified
               if obj["ui"]=="EnvDxe" and obj["fileGuid"]==FILE_GUID]
    if len(matched)!=1:
        raise ExtractionError("Expected one original EnvDxe with known FFS GUID")
    candidate=matched[0]
    raw=candidate["image"]
    if digest(raw)!=PE_SHA256:
        raise ExtractionError("Original EnvDxe PE SHA256 mismatch")
    if raw[GUID_PE_FILE_OFFSET:GUID_PE_FILE_OFFSET+16] != GUID_LE:
        raise ExtractionError("Original protocol GUID missing at exact EnvDxe file offset")
    layout=guid_file_offset_to_rva(raw,GUID_PE_FILE_OFFSET)
    return {
        "bytes":raw,
        "manifest":{
            "classification":"ORIGINAL_HXL1_XBL_ENV_DXE_SHA256_VERIFIED",
            "xblSha256":XBL_SHA256,
            "gzipOriginalFileOffset":hex(GZIP_OFFSET),
            "decompressedFvSha256":digest(fv),
            "originalEnvDxePeSha256":PE_SHA256,
            "peBytes":len(raw),
            "ffsGuid":candidate["fileGuid"],
            "ui":candidate["ui"],
            "trace":candidate["trace"],
            "peInfo":candidate["info"],
            "guidRepresentation":"UEFI_LITTLE_ENDIAN",
            **layout,
            "protocolRegistrationProven":False,
            "runtimePartitionDataObserved":False,
            "kernelPhysicalEntryVerified":False,
            "deviceModified":False,
        }
    }


def run(source_dir:Path, out_dir:Path)->dict:
    source=source_dir/"xbl.elf"
    if source.is_symlink() or not source.is_file():
        raise ExtractionError("Original XBL regular source file missing")
    record=exact_candidate(source.read_bytes())
    out_dir.mkdir(parents=True,exist_ok=True)
    target=out_dir/OUT_NAME
    if target.exists() or target.is_symlink():
        if not target.is_file() or target.is_symlink() or digest(target.read_bytes())!=PE_SHA256:
            raise ExtractionError("Existing EnvDxe PE differs: refusing overwrite")
        action="VERIFIED_EXISTING"
    else:
        with target.open("xb") as fp:
            fp.write(record["bytes"])
        target.chmod(0o600)
        action="CREATED_ORIGINAL_PE"
    manifest=record["manifest"]
    manifest["outputPath"]=str(target)
    manifest["outputStatus"]=action
    (out_dir/"original-envdxe-hxl1.json").write_text(json.dumps(manifest,indent=2)+"\n")
    report=[
        "# Stock HXL1 XBL EnvDxe — exact provenance", "",
        "Original XBL sha256: "+XBL_SHA256,
        "Embedded gzip offset: "+hex(GZIP_OFFSET),
        "Original FFS GUID: "+FILE_GUID,
        "Verified EnvDxe SHA256: "+PE_SHA256,
        "Extracted static EFI PE: "+str(target),
        "Original RAM GUID PE file offset: "+hex(GUID_PE_FILE_OFFSET),
        "Mapped RVA: "+str((manifest["guidPosition"] or {}).get("guidRva","UNMAPPED")),
        "PE preferred VA: "+str((manifest["guidPosition"] or {}).get(
            "preferredImageVirtualAddress","UNMAPPED")), "",
        "Neither the GUID offset nor the PE preferred VA is a Linux kernel",
        "physical address or proof the RAM protocol has been installed.", "",
    ]
    (out_dir/"original-envdxe-hxl1.md").write_text("\n".join(report))
    return manifest


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ORIGINAL_DIR)
    parser.add_argument("--out",type=Path,default=REPORT_DIR)
    args=parser.parse_args()
    try:
        result=run(args.source,args.out)
    except (OSError,ValueError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[VERIFIED]",result["ui"],result["originalEnvDxePeSha256"])
    print("[OUTPUT]",result["outputPath"],result["outputStatus"])
    print("[GUID FILE OFFSET]",result["guidPeFileOffset"])
    print("[GUID RVA]",(result["guidPosition"] or {}).get("guidRva","UNMAPPED"))
    print("[REPORT]",args.out/"original-envdxe-hxl1.md")
    print("[LIMIT] Protocol registration and runtime RAM partitions not established")
    return 0


if __name__=="__main__":
    sys.exit(main())
