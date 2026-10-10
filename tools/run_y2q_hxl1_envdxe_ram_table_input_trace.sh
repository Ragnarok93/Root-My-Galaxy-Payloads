#!/usr/bin/env bash
# Exact original HXL1 EnvDxe: table source, two init service candidates, one
# observed populator-function xref. Host-side Ghidra only; no ADB/device writes.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
SHA=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== Synthetic exact-EnvDxe original-evidence regression tests ==="
python3 -m unittest -q tools/test_y2q_hxl1_envdxe_ram_table_input_trace.py

echo "=== Verify previous original source and conditional fallback ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Original SHA-pinned EnvDxe or REA missing" >&2
  exit 2
}
echo "$SHA  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original EnvDxe SHA256 mismatch" >&2
  exit 2
}
python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_ram_table_input_trace import authenticated_parent
doc=authenticated_parent(Path(sys.argv[1]))
print("[VERIFIED] Original PE, init dispatch, two RAM-table code branches")
for fn in doc["functionDossiers"]:
    print("[PARENT EVIDENCE]",fn["label"],fn["evidenceId"])
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
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0 : 1)' || {
  echo "[STOP] Native Linux Node.js 24 required" >&2
  exit 2
}

echo "=== Three evidence-derived original Ghidra functions ==="
while IFS='|' read -r label addr; do
  file="$OUT/rea-envdxe-input-trace-$label.json"
  if python3 tools/y2q_hxl1_envdxe_ram_table_input_trace.py \
      --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Verified $label"
    continue
  fi
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing invalid Ghidra evidence $file; no overwrite" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-input-trace-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial Ghidra evidence $tmp" >&2
    exit 2
  }
  echo "[GHIDRA FUNCTION] $label $addr"
  if ! node "$REA" function "$EFI" "$addr" --provider ghidra --json \
       > "$tmp" 2> "$OUT/rea-envdxe-input-trace-$label-stderr.txt"; then
    echo "[STOP] REA/Ghidra failed: $label; inspect stderr and partial JSON" >&2
    exit 2
  fi
  mv "$tmp" "$file"
  python3 tools/y2q_hxl1_envdxe_ram_table_input_trace.py \
      --out "$OUT" --verify-single "$label"
done <<'FUNCTIONS'
table-input-provider|0x53b0
init-protocol-candidate|0x23b0
init-services-candidate|0x20ac
FUNCTIONS

echo "=== One exact original RAM table-populator xref query ==="
label=ram-table-populator
file="$OUT/rea-envdxe-input-trace-$label.json"
if python3 tools/y2q_hxl1_envdxe_ram_table_input_trace.py \
    --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
  echo "[REUSE] Verified populator xrefs"
else
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing invalid xref evidence $file; no overwrite" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-input-trace-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial xref evidence $tmp" >&2
    exit 2
  }
  echo "[GHIDRA XREFS] Original table-populator function 0x5560"
  if ! node "$REA" xrefs "$EFI" 0x5560 --provider ghidra --json \
      > "$tmp" 2> "$OUT/rea-envdxe-input-trace-$label-stderr.txt"; then
    echo "[STOP] REA/Ghidra xrefs failed; inspect stderr/partial JSON" >&2
    exit 2
  fi
  mv "$tmp" "$file"
  python3 tools/y2q_hxl1_envdxe_ram_table_input_trace.py \
      --out "$OUT" --verify-single "$label"
fi

python3 tools/y2q_hxl1_envdxe_ram_table_input_trace.py --out "$OUT"
cat "$OUT/rea-envdxe-ram-table-input-trace.md"
echo "[LIMIT] Static provider evidence is not a dynamic physical RAM measurement or root"
