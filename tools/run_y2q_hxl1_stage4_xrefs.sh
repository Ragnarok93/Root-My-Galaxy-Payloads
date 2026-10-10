#!/usr/bin/env bash
# Targeted static xrefs for the authenticated original HXL1 LinuxLoader.
# Runs only three real Ghidra queries. Reuses matching saved Evidence on rerun.
# No binary modification, flashing, bootloader execution or root attempt.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
EXPECTED="5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
if [[ -s "$OUT/rea-ghidra-env.sh" ]]; then
  # shellcheck source=/dev/null
  . "$OUT/rea-ghidra-env.sh"
fi

[[ -f "$EFI" && ! -L "$EFI" ]] || {
  echo "[STOP] Authenticated original HXL1 LinuxLoader not present" >&2; exit 2;
}
echo "$EXPECTED  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original HXL1 LinuxLoader SHA256 mismatch" >&2; exit 2;
}
[[ -f "$REA" ]] || {
  echo "[STOP] Existing local REA fork is missing" >&2; exit 2;
}
node -e 'process.exit(process.platform==="linux"&&Number(process.versions.node.split(".")[0])===24?0:1)' || {
  echo "[STOP] Linux Node 24 required for REA" >&2; exit 2;
}

echo "=== Re-check saved original Ghidra search seeds ==="
python3 -m unittest -q tools/test_y2q_linuxloader_rea_stage4_seeds.py
python3 tools/y2q_linuxloader_rea_stage4_seeds.py --out "$OUT"
python3 - "$OUT" <<'PY'
import sys
from pathlib import Path
from tools.y2q_linuxloader_rea_stage4_xrefs import REFS, validate_seed
folder=Path(sys.argv[1])
for item in REFS:
    evidence=validate_seed(folder,item)
    print("[SEED VERIFIED]",item[0],item[2],evidence)
PY

echo "=== Exactly three target-specific REA/Ghidra xref queries ==="
# DO NOT infer a containing function from the data string address.
while read -r label address; do
  file="$OUT/rea-stage4-xrefs-$label.json"
  if python3 tools/y2q_linuxloader_rea_stage4_xrefs.py --out "$OUT" \
       --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Existing authenticated xrefs: $label"
    continue
  fi
  echo "[Ghidra xrefs] $label -> $address"
  node "$REA" xrefs "$EFI" "$address" --provider ghidra --json \
    > "$file" 2> "$OUT/rea-stage4-xrefs-$label-stderr.txt" || true
  if ! python3 tools/y2q_linuxloader_rea_stage4_xrefs.py --out "$OUT" \
       --verify-single "$label"; then
    echo "[BLOCKED] Ghidra did not produce valid xref Evidence for $label" >&2
    echo "[DIAGNOSTICS] $file" >&2
    exit 2
  fi
done <<'ADDRESSES'
kernel-load-print 0xbc48c
kernel-dt-boundary 0xbce52
best-dtb-match 0xbd674
ADDRESSES

python3 tools/y2q_linuxloader_rea_stage4_xrefs.py --out "$OUT"
cat "$OUT/rea-stage4-xrefs-audit.md"
echo "[LIMIT] Xrefs are not Linux physical runtime kernel addresses"
