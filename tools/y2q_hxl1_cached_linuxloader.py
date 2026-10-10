#!/usr/bin/env python3
"""Recover genuine HXL1 LinuxLoader PE section from ALREADY unpacked ABL data.

Correlates 2 independent decoders' exact bytes: the native pinned-ABL section
SHA256/length and the independent uefi-firmware-parser's section1.pe. Never
executes the PE, touches the phone or guesses its PE/COFF machine type.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_abl_linuxloader_extract import (
    ORIGINAL_ABL_SHA256, ORIGINAL_ABL_BYTES, LOADER_GUID,
    digest, identify_pe, ExtractError,
)

class CorrelationError(ValueError):
    pass


def check_regular(p: Path) -> None:
    if not p.is_file() or p.is_symlink():
        raise CorrelationError(f"Not a regular, non-symlinked input: {p}")


def characterize_pe(data: bytes) -> dict:
    """Record raw DOS/COFF evidence; *only* mark verified if strict check passes."""
    strict=identify_pe(data)
    result={
        "dosMZ": data.startswith(b"MZ"),
        "strictAarch64Pe32PlusVerified": strict is not None,
        "strictPeInfo": strict,
    }
    if len(data) < 64 or not data.startswith(b"MZ"):
        return result
    coff=int.from_bytes(data[0x3c:0x40], "little")
    result["dosPeHeaderOffset"]=f"0x{coff:x}"
    if not (0x40 <= coff <= len(data)-24):
        result["reason"]="DOS e_lfanew out of PE header range"
        return result
    magic=data[coff:coff+4]
    result["peSignatureHex"]=magic.hex()
    if magic!=b"PE\x00\x00":
        result["reason"]="PE\\x00\\x00 signature not found at DOS e_lfanew"
        return result
    result.update({
        "coffMachine": f"0x{int.from_bytes(data[coff+4:coff+6],'little'):x}",
        "coffSectionCount": int.from_bytes(data[coff+6:coff+8],"little"),
        "coffOptionalHeaderSize": int.from_bytes(data[coff+20:coff+22],"little"),
        "optionalHeaderMagic": f"0x{int.from_bytes(data[coff+24:coff+26],'little'):x}",
    })
    if strict is None:
        result["reason"]="COFF observed but strict AArch64 PE32+ acceptance incomplete"
    return result


def recover(abl: Path, diagnostics: Path, extracted: Path, output: Path,
            *, abl_sha: str=ORIGINAL_ABL_SHA256, abl_size: int=ORIGINAL_ABL_BYTES) -> dict:
    for path in (abl, diagnostics):
        check_regular(path)
    original=abl.read_bytes()
    if len(original)!=abl_size or digest(original)!=abl_sha:
        raise CorrelationError("STOP: original HXL1 ABL size/hash mismatch")
    diag=json.loads(diagnostics.read_text())
    if (diag.get("sourceSha256")!=abl_sha or
        diag.get("sourceBytes")!=abl_size or
        diag.get("status")!="NO_VERIFIED_LINUXLOADER"):
        raise CorrelationError("Native section inventory not tied to original ABL")
    guid=str(LOADER_GUID).lower()
    records=[x for x in diag.get("sections",[])
             if x.get("fileGuid") == guid
             and x.get("ui")=="LinuxLoader"
             and x.get("sectionType")=="0x10"]
    files=[x for x in diag.get("ffsFiles",[])
           if x.get("fileGuid")==guid and x.get("fileType")=="0x09"]
    if len(records)!=1 or len(files)!=1:
        raise CorrelationError("Missing/ambiguous original-native LinuxLoader section and FFS")
    record=records[0]
    if not extracted.is_dir() or extracted.is_symlink():
        raise CorrelationError("Missing independent UEFI unpacked directory")
    origin=extracted.resolve()
    candidates=[p for p in extracted.rglob("section1.pe")
                if p.parent.name.lower()==f"file-{guid}" and
                p.resolve().is_relative_to(origin)]
    if len(candidates)!=1:
        raise CorrelationError(f"Expected one independent LinuxLoader section1.pe, found {len(candidates)}")
    src=candidates[0]
    check_regular(src)
    ui=src.parent/"section0.ui"
    check_regular(ui)
    raw_ui=ui.read_bytes()
    if (len(raw_ui)%2 or
        raw_ui.decode("utf-16-le",errors="strict").split("\x00")[0]!="LinuxLoader"):
        raise CorrelationError("Independent LinuxLoader UI name mismatch")
    data=src.read_bytes()
    if (len(data)!=record["sectionBodyBytes"] or
        digest(data)!=record["sha256"] or
        data[:64].hex()!=record["first64Hex"]):
        raise CorrelationError("STOP: independent decoder PE bytes differ from original native decoder")
    if not data.startswith(b"MZ"):
        raise CorrelationError("LinuxLoader section lacks DOS/PE MZ signature")
    info=characterize_pe(data)
    if output.resolve()==src.resolve() or output.resolve()==abl.resolve():
        raise CorrelationError("Cannot overwrite source inputs")
    if output.exists() and (output.is_symlink() or digest(output.read_bytes())!=digest(data)):
        raise CorrelationError("Pre-existing LinuxLoader output mismatches; refusing overwrite")
    output.parent.mkdir(parents=True,exist_ok=True)
    if not output.exists():
        output.write_bytes(data)
    return {
        "status":"STOCK_HXL1_LINUXLOADER_SECTION_CORRELATED",
        "classification": ("PE_HEADER_AARCH64_VERIFIED" if info["strictAarch64Pe32PlusVerified"]
                           else "FFS_UI_SECTION_PROVENANCE_VERIFIED_PE_ARCH_UNCLASSIFIED"),
        "sourceAblSha256":abl_sha,
        "nativeDecoderSectionSha256":record["sha256"],
        "independentDecoderSectionSha256":digest(data),
        "sourceSectionBytes":len(data),
        "sourceSectionPath":str(src),
        "verifiedFfsGuid":guid,
        "verifiedUiName":"LinuxLoader",
        "peHeader":info,
        "output":str(output),
        "physicalKernelLoadVerified":False,
        "androidLinuxHandoffVerified":False,
        "phoneModified":False,
        "limit":"PE section byte equality and FFS/UI identity do not prove runtime kernel placement",
    }


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    home=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--abl",type=Path,default=home/"bl-stock/abl.elf")
    p.add_argument("--diagnostics",type=Path,default=home/"abl-linuxloader/linuxloader-extraction-diagnostics.json")
    p.add_argument("--independent-unpacked",type=Path,default=home/"abl-linuxloader/independent-unpacked")
    p.add_argument("--out",type=Path,default=home/"abl-linuxloader/LinuxLoader-HXL1.unclassified.pe")
    args=p.parse_args()
    try:
        result=recover(args.abl,args.diagnostics,args.independent_unpacked,args.out,
                       abl_sha=ORIGINAL_ABL_SHA256, abl_size=ORIGINAL_ABL_BYTES)
        if result["peHeader"]["strictAarch64Pe32PlusVerified"]:
            # Keep the old unclassified copy for audit continuity. Publish a
            # correctly named EFI only after independent original-byte
            # correlation AND PE32+/AArch64 structural validation.
            verified=args.out.parent/"LinuxLoader-HXL1.efi"
            raw=args.out.read_bytes()
            if verified.exists():
                check_regular(verified)
                if digest(verified.read_bytes())!=digest(raw):
                    raise CorrelationError(
                        "Existing verified LinuxLoader EFI mismatches cached original bytes")
            else:
                verified.write_bytes(raw)
            result["verifiedPeOutput"]=str(verified)
            result["verificationStatus"]="HXL1_ORIGINAL_FFS_UI_PE32PLUS_AARCH64_VERIFIED"
        else:
            result["verificationStatus"]="PE_ARCHITECTURE_UNVERIFIED"
        report=args.out.parent/"linuxloader-cached-correlation.json"
        report.write_text(json.dumps(result,indent=2)+"\n")
    except (OSError,CorrelationError,ValueError,UnicodeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[PASS] Two independent decoders' exact LinuxLoader section SHA256 and byte count")
    print("[PASS] Original SHA256-pinned HXL1 ABL, FFS GUID and UTF-16 UI")
    print("[SOURCE]",result["sourceSectionPath"])
    print("[LOADER]",result["output"])
    if "verifiedPeOutput" in result:
        print("[VERIFIED EFI]",result["verifiedPeOutput"])
    print("[PE]",json.dumps(result["peHeader"],sort_keys=True))
    print("[REPORT]",report)
    print("[LIMIT] No physical kernel load, runtime handoff, exploit or root")
    return 0


if __name__=="__main__":
    sys.exit(main())
