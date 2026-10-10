#!/usr/bin/env bash
# Follow verified HXL1 original EnvDxe initialization and three diagnostic strings.
# Host-only: original firmware, REA/Ghidra; NO adb/device execution/flash/write.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
SHA=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== Original HXL1 RAM source xrefs synthetic regression checks ==="
python3 -m unittest -q tools/test_y2q_hxl1_envdxe_ram_source_xrefs.py

[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing original exact EnvDxe or local REA fork" >&2
  exit 2
}
echo "$SHA  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original EnvDxe SHA256 mismatch" >&2
  exit 2
}
echo "=== Re-authenticate earlier zero-xref and entrypoint/string evidence ==="
python3 - "$OUT" <<'PY'
import sys
from pathlib import Path
from tools.y2q_hxl1_envdxe_ram_source_xrefs import validated_baseline
b=validated_baseline(Path(sys.argv[1]))
print("[VERIFIED] Original entry", b["entryFunction"]["requestedEntryAddress"],
      "with 2 observed startup callees")
for s in b["stringSearches"]:
    print("[AUTHENTICATED]",s["pattern"], "hits",s["hitCount"])
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
  echo "[STOP] Node 24 required for original REA/Ghidra commands" >&2
  exit 2
}

echo "=== Targeted static Ghidra string xrefs: 3 previously observed addresses ==="
while IFS='|' read -r label address; do
  file="$OUT/rea-envdxe-xrefs-$label.json"
  if python3 tools/y2q_hxl1_envdxe_ram_source_xrefs.py \
       --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Original $label xrefs verified"
    continue
  fi
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing invalid xrefs evidence; retaining $file" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-xrefs-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial xrefs file: $tmp" >&2
    exit 2
  }
  echo "[GHIDRA XREFS] $label at $address"
  node "$REA" xrefs "$EFI" "$address" --provider ghidra --json \
       > "$tmp" 2> "$OUT/rea-envdxe-xrefs-$label-stderr.txt" || {
    echo "[STOP] Ghidra xrefs command failed: $label; inspect partial and stderr" >&2
    exit 2
  }
  mv "$tmp" "$file"
  python3 tools/y2q_hxl1_envdxe_ram_source_xrefs.py \
     --out "$OUT" --verify-single "$label"
done <<'STRINGS'
ram-table-lib|0xa87e
ram-entry-limit|0xa895
env-driver-source|0x90bf
STRINGS

echo "=== Two exact original direct EnvDxe startup callees ==="
while IFS='|' read -r label address; do
  file="$OUT/rea-envdxe-function-$label.json"
  if python3 tools/y2q_hxl1_envdxe_ram_source_xrefs.py \
      --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Original $label function verified"
    continue
  fi
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing invalid function evidence; retaining $file" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-function-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial function file: $tmp" >&2
    exit 2
  }
  echo "[GHIDRA FUNCTION] $label at $address"
  node "$REA" function "$EFI" "$address" --provider ghidra --json \
     > "$tmp" 2> "$OUT/rea-envdxe-function-$label-stderr.txt" || {
    echo "[STOP] Ghidra function command failed: $label; inspect partial and stderr" >&2
    exit 2
  }
  mv "$tmp" "$file"
  python3 tools/y2q_hxl1_envdxe_ram_source_xrefs.py \
      --out "$OUT" --verify-single "$label"
done <<'FUNCTIONS'
startup-helper|0x10f4
env-initializer|0x1150
FUNCTIONS

python3 tools/y2q_hxl1_envdxe_ram_source_xrefs.py --out "$OUT"
cat "$OUT/rea-envdxe-ram-source-xrefs.md"
echo "[LIMIT] Static EnvDxe xrefs and code do not verify live RAM base or KernelSU"
