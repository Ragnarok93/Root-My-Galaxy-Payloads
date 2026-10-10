#!/usr/bin/env bash
# Exact original EnvDxe from Samsung HXL1: SMEM402 and UEFI candidate GUID.
# Reuses previous authenticated source evidence. NO ADB or phone writes.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
SHA=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== Synthetic original HXL1 SMEM402 and UEFI candidate source tests ==="
python3 -m unittest -q tools/test_y2q_hxl1_envdxe_smem402_protocol.py

echo "=== Exact original PE and prior source observations ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing original SHA-pinned EnvDxe or REA" >&2; exit 2;
}
echo "$SHA  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original EnvDxe SHA256 mismatch" >&2; exit 2;
}
python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_smem402_protocol import authenticated_parent
p=authenticated_parent(Path(sys.argv[1]))
print("[VERIFIED] Original RAM-table request 0x192 (= 402)")
print("[VERIFIED] Protocol candidate uses GUID at 0xd2e8 and service method +0x80")
print("[VERIFIED] Unique Ghidra caller reference at 0x2064")
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
  echo "[STOP] Native Linux Node 24 required" >&2; exit 2;
}

echo "=== One exact candidate installation GUID read ==="
file="$OUT/rea-envdxe-ram-provider-install-guid.json"
if python3 tools/y2q_hxl1_envdxe_smem402_protocol.py \
   --out "$OUT" --verify-single protocol-guid >/dev/null 2>&1; then
  echo "[REUSE] Verified 16-byte original candidate registration GUID"
else
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing invalid original GUID read evidence: $file" >&2; exit 2;
  }
  tmp="$OUT/rea-envdxe-ram-provider-install-guid.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial Ghidra GUID read: $tmp" >&2; exit 2;
  }
  echo "[GHIDRA READ] Exact 16 GUID bytes at 0xd2e8"
  if ! node "$REA" read-bytes "$EFI" 0xd2e8 --length 16 \
      --provider ghidra --json > "$tmp" \
      2> "$OUT/rea-envdxe-ram-provider-install-guid-stderr.txt"; then
    echo "[STOP] Ghidra candidate GUID read failed; inspect partial and stderr" >&2
    exit 2
  fi
  mv "$tmp" "$file"
  python3 tools/y2q_hxl1_envdxe_smem402_protocol.py \
      --out "$OUT" --verify-single protocol-guid
fi

echo "=== Exact original 0x2064 caller, 0x5288 format, 0x7d08 SMEM getter ==="
while IFS='|' read -r label address; do
  file="$OUT/rea-envdxe-ram-source-verify-$label.json"
  if python3 tools/y2q_hxl1_envdxe_smem402_protocol.py \
      --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Verified original Ghidra function $label"
    continue
  fi
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing invalid function evidence: $file" >&2; exit 2;
  }
  tmp="$OUT/rea-envdxe-ram-source-verify-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial function evidence: $tmp" >&2; exit 2;
  }
  echo "[GHIDRA FUNCTION] $label at $address"
  if ! node "$REA" function "$EFI" "$address" --provider ghidra --json \
      > "$tmp" 2> "$OUT/rea-envdxe-ram-source-verify-$label-stderr.txt"; then
    echo "[STOP] Original Ghidra function analysis failed: $label" >&2
    exit 2
  fi
  mv "$tmp" "$file"
  python3 tools/y2q_hxl1_envdxe_smem402_protocol.py \
      --out "$OUT" --verify-single "$label"
done <<'FUNCTIONS'
ram-table-initializer-caller|0x2064
smem-partition-format-reader|0x5288
smem-item-accessor|0x7d08
FUNCTIONS

python3 tools/y2q_hxl1_envdxe_smem402_protocol.py --out "$OUT"
cat "$OUT/rea-envdxe-smem402-protocol.md"
echo "[LIMIT] Static firmware evidence; no runtime RAM table, root or KernelSU"
