#!/usr/bin/env bash
# Original stock HXL1 XBL EnvDxe: 4 EFI RAM methods + directly observed BL 0x52cc.
# ~317 distinct offline tests; 5 independent 128-byte provenance reads;
# 2 direct xrefs, full static ARM64 branch report. NO ADB/phone writes.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== 317 original EnvDxe RAM interface/ARM64 static-analysis regressions ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_ram_registration_interface.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_callback.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py \
  tools/test_y2q_hxl1_envdxe_callback_raw_proof.py \
  tools/test_y2q_hxl1_envdxe_callback_mutations.py \
  tools/test_y2q_hxl1_envdxe_method_arm64_trace.py

[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing pinned HXL1 EnvDxe or REA tool" >&2
  exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original HXL1 EnvDxe executable SHA256 mismatch" >&2
  exit 2
}

echo "=== Authenticate original 4-method interface and observed 0x1fa4 BL ==="
python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_method_arm64_trace import (
    authenticated_parent, original_window, GET_RAM_CALL_TARGET
)
folder=Path(sys.argv[1])
p=authenticated_parent(folder)
print("[VERIFIED ORIGINAL RAM INTERFACE]",
      ",".join(p["protocolInterfaceStructure"]["qwordsHex"]))
cb=original_window(folder,"0x1f74")
bl=[e for e in cb["edges"] if e["mnemonicClass"]=="BL"]
if GET_RAM_CALL_TARGET not in [e["directBranchTarget"] for e in bl]:
    raise SystemExit("[STOP] Authentic ARM64 callback no longer calls expected 0x52cc")
print("[VERIFIED ARM64 CALL]", "0x1fa4 ->",GET_RAM_CALL_TARGET)
for addr in ("0x1ee8","0x1f0c","0x1f74","0x1f28","0x52cc"):
    original=original_window(folder,addr)
    print("[VERIFIED ORIGINAL EXECUTABLE]",addr,original["sectionName"],
          original["peFileOffset"],original["sha256"])
PY

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
ENV="$HOME/s20-artifacts/hxl1-research/abl-linuxloader/rea-ghidra-env.sh"
if [[ -s "$ENV" ]]; then
  # shellcheck source=/dev/null
  . "$ENV"
fi
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0:1)' || {
  echo "[STOP] Native Linux Node.js 24 required for host-side REA" >&2
  exit 2
}

echo "=== Five static 128-byte Ghidra code windows, preserved and hash-matched ==="
while IFS='|' read -r label address; do
  file="$OUT/rea-envdxe-method-window-$label.json"
  if python3 tools/y2q_hxl1_envdxe_method_arm64_trace.py \
       --out "$OUT" --verify "$label" >/dev/null 2>&1; then
    echo "[REUSE] Original Ghidra method code verified $label $address"
    continue
  fi
  [[ ! -e "$file" && ! -L "$file" ]] || {
    echo "[STOP] Conflicting Ghidra method window must be inspected: $file" >&2
    exit 2
  }
  partial="$OUT/rea-envdxe-method-window-$label.partial.json"
  if [[ -e "$partial" || -L "$partial" ]]; then
    echo "[LIMIT] Preserving previous failed Ghidra byte read: $partial"
    continue
  fi
  echo "[GHIDRA READ] $label at $address (128 exact executable bytes)"
  if node "$REA" read-bytes "$EFI" "$address" --length 128 \
     --provider ghidra --json > "$partial" \
     2> "$OUT/rea-envdxe-method-window-$label-stderr.txt"; then
    mv "$partial" "$file"
    python3 tools/y2q_hxl1_envdxe_method_arm64_trace.py \
        --out "$OUT" --verify "$label"
  else
    echo "[LIMIT] Failed optional imported code read $label; original PE proof retained"
  fi
done <<'CODE'
method-08|0x1ee8
method-10|0x1f0c
get-ram-partitions|0x1f74
method-20|0x1f28
callback-bl-callee|0x52cc
CODE

echo "=== Two targeted Ghidra reference checks (callback and 0x52cc) ==="
while IFS='|' read -r label address; do
  file="$OUT/rea-envdxe-method-xrefs-$label.json"
  if python3 tools/y2q_hxl1_envdxe_method_arm64_trace.py \
      --out "$OUT" --verify "$label" >/dev/null 2>&1; then
    echo "[REUSE] Original Ghidra references $label"
    continue
  fi
  [[ ! -e "$file" && ! -L "$file" ]] || {
    echo "[STOP] Conflicting reference evidence: $file" >&2
    exit 2
  }
  partial="$OUT/rea-envdxe-method-xrefs-$label.partial.json"
  if [[ -e "$partial" || -L "$partial" ]]; then
    echo "[LIMIT] Previous reference request partial preserved: $partial"
    continue
  fi
  echo "[GHIDRA XREFS] $label $address"
  if node "$REA" xrefs "$EFI" "$address" --provider ghidra --json \
       > "$partial" 2> "$OUT/rea-envdxe-method-xrefs-$label-stderr.txt"; then
    mv "$partial" "$file"
    python3 tools/y2q_hxl1_envdxe_method_arm64_trace.py \
        --out "$OUT" --verify "$label"
  else
    echo "[LIMIT] Optional Ghidra references unavailable; original ARM64 bytes remain valid"
  fi
done <<'XREFS'
callback-static-xrefs|0x1f74
callback-callee-xrefs|0x52cc
XREFS

echo "=== Unified four-method + direct-callee ARM64 provenance report ==="
python3 tools/y2q_hxl1_envdxe_method_arm64_trace.py --out "$OUT"
cat "$OUT/rea-envdxe-four-method-arm64.md"
echo "[LIMIT] Host-only static code; no actual runtime kernel physical base or root proven"
