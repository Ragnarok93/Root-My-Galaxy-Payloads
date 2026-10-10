#!/usr/bin/env bash
# REA (Ragnarok93/rea) static analysis of original HXL1 LinuxLoader only.
# NO device operation or execution of the firmware PE.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
REA_SOURCE="$HOME/src/rea"
mkdir -p "$OUT"

python3 - "$OUT" <<'PY'
from pathlib import Path
import hashlib,json,sys
from tools.y2q_abl_linuxloader_extract import ORIGINAL_ABL_SHA256, ORIGINAL_ABL_BYTES

out=Path(sys.argv[1])
abl=Path.home()/"s20-artifacts/hxl1-research/bl-stock/abl.elf"
if not abl.is_file() or abl.is_symlink() or abl.stat().st_size != ORIGINAL_ABL_BYTES:
    raise SystemExit("[STOP] Missing exact stock ABL input")
if hashlib.sha256(abl.read_bytes()).hexdigest() != ORIGINAL_ABL_SHA256:
    raise SystemExit("[STOP] Stock ABL digest changed")

target=out/"LinuxLoader-HXL1.efi"
if target.is_file():
    if (out/"linuxloader-extraction.json").is_file():
        info=json.loads((out/"linuxloader-extraction.json").read_text())
        sha=info["loaderInfo"]["sha256"]
    else:
        info=json.loads((out/"independent-uefi-recovery.json").read_text())
        sha=info["loader"]["sha256"]
    cls="PE_HEADER_VALIDATED"
else:
    target=out/"LinuxLoader-HXL1.unclassified.pe"
    if not target.is_file():
        raise SystemExit("[STOP] No recovered LinuxLoader section")
    info=json.loads((out/"independent-uefi-recovery.json").read_text())
    if info.get("status")!="LINUXLOADER_SECTION_RECOVERED_PE_ARCHITECTURE_UNVERIFIED":
        raise SystemExit("[STOP] Missing section provenance")
    matches=[x for x in info["matchingUefiLoaderFiles"]
             if x["matchingFfsGuidInPath"] and x["verifiedUiName"]=="LinuxLoader"]
    if len(matches)!=1:
        raise SystemExit("[STOP] Matching LinuxLoader FFS/UI section not unique")
    sha=info["candidateSha256"]
    cls="EXACT_SECTION_PE_ARCHITECTURE_UNVERIFIED"
if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest()!=sha:
    raise SystemExit("[STOP] Loader digest mismatch or symlink")
(out/"rea-loader-target.txt").write_text(str(target)+"\n")
print("[PASS] Original ABL and extracted LinuxLoader section digests")
print("[TARGET]",target,"[SHA256]",sha,"[CLASSIFICATION]",cls)
PY

TARGET="$(cat "$OUT/rea-loader-target.txt")"
file "$TARGET" | tee "$OUT/linuxloader-file-classification.txt"
sha256sum "$TARGET" | tee "$OUT/linuxloader-sha256.txt"
if command -v llvm-readobj >/dev/null 2>&1; then
  llvm-readobj --file-headers --sections "$TARGET" \
    > "$OUT/linuxloader-llvm-headers.txt" 2> "$OUT/linuxloader-llvm-headers-errors.txt" || true
fi
if command -v llvm-objdump >/dev/null 2>&1; then
  llvm-objdump --disassemble "$TARGET" \
    > "$OUT/linuxloader-llvm-assembly.txt" 2> "$OUT/linuxloader-llvm-assembly-errors.txt" || true
fi

if [ ! -f "$REA_SOURCE/scripts/rea.mjs" ]; then
  echo "[REA NOT PRESENT] The user's fork should be checked out at $REA_SOURCE"
  echo "  git clone https://github.com/Ragnarok93/rea.git \"$REA_SOURCE\""
  echo "  cd \"$REA_SOURCE\" && npm ci && npm run build"
  echo "[RESULT] Exact loader, file/LLVM reports retained; REA pending"
  exit 0
fi
if ! command -v node >/dev/null 2>&1; then
  echo "[REA BLOCKED] Node.js missing; fork requires 22.19+, 24.11+, or 26+"
  exit 0
fi
if ! node -e 'const v=process.versions.node.split(".").map(Number);process.exit((v[0]===22&&v[1]>=19)||(v[0]===24&&v[1]>=11)||v[0]>=26?0:1)'; then
  echo "[REA BLOCKED] Unsupported Node version for this fork"
  node --version
  exit 0
fi
if ! node "$REA_SOURCE/scripts/rea.mjs" providers --json > "$OUT/rea-providers.json" \
    2> "$OUT/rea-providers-errors.txt"; then
  echo "[REA BLOCKED] Fork CLI not built or dependencies missing"
  echo "  cd \"$REA_SOURCE\" && npm ci && npm run build"
  exit 0
fi
if ! node "$REA_SOURCE/scripts/rea.mjs" analyze "$TARGET" --provider ghidra --json \
    > "$OUT/rea-ghidra-overview.json" 2> "$OUT/rea-ghidra-errors.txt"; then
  echo "[REA BLOCKED] Ghidra unavailable or did not admit this PE"
  echo "[DIAGNOSTICS] $OUT/rea-ghidra-errors.txt"
  exit 0
fi
for keyword in bootimg kernel dtb; do
  node "$REA_SOURCE/scripts/rea.mjs" search "$TARGET" "$keyword" --provider ghidra --json \
    > "$OUT/rea-ghidra-search-$keyword.json" \
    2> "$OUT/rea-ghidra-search-$keyword-errors.txt" || true
done
echo "[PASS] Original HXL1 loader and REA/Ghidra evidence saved under $OUT"
echo "[LIMIT] Static PE evidence does not establish actual Linux physical handoff"
