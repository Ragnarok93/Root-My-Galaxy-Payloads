#!/usr/bin/env bash
# Decompile only the three function bodies containing authenticated loader xrefs.
# Reuses saved REA evidence. No firmware modification, flashing or execution.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
EXPECTED=5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
if [[ -s "$OUT/rea-ghidra-env.sh" ]]; then
  . "$OUT/rea-ghidra-env.sh"
fi

[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Verified HXL1 EFI or existing REA fork missing" >&2; exit 2;
}
echo "$EXPECTED  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original EFI SHA256 changed" >&2; exit 2;
}
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24?0:1)' || {
  echo "[STOP] Native Linux Node 24 required" >&2; exit 2;
}
python3 -m unittest -q tools/test_y2q_linuxloader_rea_stage4_functions.py

# The original xref source instruction coordinates, not the string addresses.
while read -r label source; do
  out="$OUT/rea-stage4-function-$label.json"
  if python3 tools/y2q_linuxloader_rea_stage4_functions.py \
       --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Authenticated function dossier: $label"
    continue
  fi
  echo "[GHIDRA FUNCTION] $label source instruction $source"
  node "$REA" function "$EFI" "$source" --provider ghidra --json \
    > "$out" 2> "$OUT/rea-stage4-function-$label-stderr.txt" || true
  if ! python3 tools/y2q_linuxloader_rea_stage4_functions.py \
          --out "$OUT" --verify-single "$label"; then
    echo "[BLOCKED] Function dossier invalid: $label" >&2
    echo "[RAW] $out" >&2
    exit 2
  fi
done <<'REFERENCES'
kernel-load-print 0x2178c
kernel-dt-boundary 0x216e8
best-dtb-match 0x24e18
REFERENCES

python3 tools/y2q_linuxloader_rea_stage4_functions.py --out "$OUT"
cat "$OUT/rea-stage4-functions-audit.md"
echo "[LIMIT] Static Ghidra functions are not Linux kernel runtime handoff"
