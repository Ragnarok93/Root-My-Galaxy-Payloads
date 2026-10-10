#!/usr/bin/env bash
# Independent, bounded, offline recovery of original HXL1 LinuxLoader.
# The original ABL is read-only; no ADB, execution of firmware code, or flashing.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
ABL="$HOME/s20-artifacts/hxl1-research/bl-stock/abl.elf"
mkdir -p "$OUT"

echo "=== Native extractor regression suite ==="
python3 -m unittest -q tools/test_y2q_abl_linuxloader_extract.py

echo "=== Try the hash-pinned native HXL1 extractor ==="
if python3 tools/y2q_abl_linuxloader_extract.py; then
  echo "[PASS] Native firmware-volume decoding recovered LinuxLoader"
  file "$OUT/LinuxLoader-HXL1.efi"
  sha256sum "$OUT/LinuxLoader-HXL1.efi"
  exit 0
fi

echo "=== Native inner-FV diagnostics ==="
if [ -f "$OUT/linuxloader-extraction-diagnostics.json" ]; then
  python3 - "$OUT/linuxloader-extraction-diagnostics.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print("FFS files:",len(d.get("ffsFiles",[])))
for item in d.get("ffsFiles",[]):
    print("FFS",item["fileGuid"],item["fileType"],item["fileSize"],item["trace"][-1])
print("Sections:",len(d.get("sections",[])))
for item in d.get("sections",[]):
    print("SEC",item["sectionType"],item["sectionBodyBytes"],
          item.get("ui",""),item["fileGuid"],item["first64Hex"][:40])
print("Rejected executable sections:",len(d.get("nonPeExecutableSections",[])))
for item in d.get("nonPeExecutableSections",[]):
    print("REJECTED",item["signature"],item["payloadBytes"],
          item["fileGuid"],item["first64Hex"][:64])
PY
fi

echo "=== Independent UEFI parser (isolated Python virtual environment) ==="
VENV="$OUT/uefi-parser-venv"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --disable-pip-version-check "uefi-firmware==1.16"

# The original pinned input is not modified by the external decoder.
python3 - "$ABL" <<'PY'
from pathlib import Path
import hashlib,sys
from tools.y2q_abl_linuxloader_extract import ORIGINAL_ABL_SHA256, ORIGINAL_ABL_BYTES
p=Path(sys.argv[1])
assert p.is_file() and not p.is_symlink(), "Original ABL absent or symlinked"
assert p.stat().st_size == ORIGINAL_ABL_BYTES, "Original ABL byte count changed"
assert hashlib.sha256(p.read_bytes()).hexdigest() == ORIGINAL_ABL_SHA256, "Original ABL SHA256 changed"
print("[PASS] Independent decoder input matches exact stock HXL1 ABL")
PY

EXT="$OUT/independent-unpacked"
mkdir -p "$EXT"
"$VENV/bin/uefi-firmware-parser" -b -e -o "$EXT" "$ABL" \
  | tee "$OUT/independent-uefi-tree.txt"

echo "=== Identify LinuxLoader by exact FFS GUID and validated ARM64 PE header ==="
python3 - "$EXT" "$OUT" <<'PY'
import json
from pathlib import Path
import sys
from tools.y2q_abl_linuxloader_extract import (
    LOADER_GUID, identify_pe, digest
)

base=Path(sys.argv[1]).resolve()
out=Path(sys.argv[2]).resolve()
guid=str(LOADER_GUID).lower()
checked=[]
matches=[]
for path in base.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    if not path.resolve().is_relative_to(base):
        continue
    # Only the extracted PE32 firmware sections are candidates, never
    # arbitrary MZ signatures embedded in unrelated firmware data.
    if path.suffix.lower() not in {".pe32",".efi",".pe"}:
        continue
    if path.stat().st_size > 48 * 1024 * 1024:
        continue
    raw=path.read_bytes()
    pe=identify_pe(raw)
    relative=path.relative_to(base).as_posix()
    matched_guid=guid in relative.lower()
    ui_file=path.parent/"section0.ui"
    ui_name=(ui_file.read_bytes().decode("utf-16-le","replace").split("\x00")[0]
             if ui_file.is_file() and not ui_file.is_symlink() else "")
    matched_ui=ui_name=="LinuxLoader"
    # Surface actual DOS+COFF fields even when our strict AArch64 checker
    # rejects a section that a mature UEFI decoder classified as PE32.
    diag={"path":relative,"bytes":len(raw),"sha256":digest(raw),
          "verifiedAarch64Pe":pe is not None,
          "matchingFfsGuidInPath":matched_guid,"verifiedUiName":ui_name,
          "first64Hex":raw[:64].hex()}
    if raw.startswith(b"MZ") and len(raw) >= 0x40:
        dos_pe_offset=int.from_bytes(raw[0x3c:0x40],"little")
        diag["dosPeOffset"]=hex(dos_pe_offset)
        if 0x40 <= dos_pe_offset <= len(raw)-24:
            diag["peSignatureHex"]=raw[dos_pe_offset:dos_pe_offset+4].hex()
            if raw[dos_pe_offset:dos_pe_offset+4] == b"PE\x00\x00":
                diag["coffMachine"]=hex(int.from_bytes(raw[dos_pe_offset+4:dos_pe_offset+6],"little"))
                diag["coffSections"]=int.from_bytes(raw[dos_pe_offset+6:dos_pe_offset+8],"little")
                diag["optionalHeaderMagic"]=hex(int.from_bytes(raw[dos_pe_offset+24:dos_pe_offset+26],"little"))
                diag["coffOptionalHeaderSize"]=int.from_bytes(raw[dos_pe_offset+20:dos_pe_offset+22],"little")
    checked.append(diag)
    if pe is not None and matched_guid and matched_ui:
        matches.append((path,raw,pe))
    elif matched_guid:
        print("[CHECK] Exact LinuxLoader FFS recovered; PE rejection detail:",diag)
report={"status":"UNVERIFIED","source":"independent uefi-firmware 1.16 decoder",
        "candidatePeSections":checked[:256],
        "matchingLoaderCandidates":len(matches),
        "matchingUefiLoaderFiles":[x for x in checked if x["matchingFfsGuidInPath"]],
        "linuxKernelPhysicalLoadVerified":False,
        "phoneModified":False}
if len(matches)==1:
    src,raw,pe=matches[0]
    dest=out/"LinuxLoader-HXL1.efi"
    if dest.exists() and dest.read_bytes()!=raw:
        raise SystemExit("[STOP] Existing LinuxLoader output differs; refuse overwrite")
    dest.write_bytes(raw)
    report.update({"status":"VERIFIED_LINUXLOADER_PE_FROM_MATCHING_FFS_GUID",
                   "loaderFile":str(dest),"loader":pe})
    print("[PASS] Extracted verified ARM64 PE for FFS",guid)
    print("[LOADER]",dest)
    print("[SHA256]",pe["sha256"])
else:
    print("[STOP] Unique, independently decoded matching LinuxLoader AArch64 PE not yet proven")
    print("[CHECK] Strict AArch64 PE candidates:",len(matches))
    # No fabricated PE success: keep the authentic GUID- and UI-bound bytes
    # under an explicitly *unclassified* name for independent format analysis.
    original_candidates = [x for x in checked if
                           x["matchingFfsGuidInPath"] and x["verifiedUiName"]=="LinuxLoader"]
    if len(original_candidates) == 1:
        selected = base/original_candidates[0]["path"]
        raw = selected.read_bytes()
        dest = out/"LinuxLoader-HXL1.unclassified.pe"
        if dest.exists() and dest.read_bytes() != raw:
            raise SystemExit("[STOP] Existing unclassified loader differs; refuse overwrite")
        dest.write_bytes(raw)
        report.update({
            "status":"LINUXLOADER_SECTION_RECOVERED_PE_ARCHITECTURE_UNVERIFIED",
            "candidateFile":str(dest),"candidateSha256":digest(raw)
        })
        print("[RECOVERED] Exact LinuxLoader FFS and UI bytes:",dest)
        print("[NOTE] PE/COFF or architecture validation remains unresolved")
    else:
        print("[CHECK] Could not isolate one matching FFS/UI raw PE section")
report_path=out/"independent-uefi-recovery.json"
report_path.write_text(json.dumps(report,indent=2)+"\n")
print("[REPORT]",report_path)
if len(matches)!=1:
    raise SystemExit(2)
PY

file "$OUT/LinuxLoader-HXL1.efi"
sha256sum "$OUT/LinuxLoader-HXL1.efi"
echo "[LIMIT] This is an extracted executable, NOT proof of physical Linux load or root"
