#!/usr/bin/env bash
# HXL1: authenticate original handoff and decompile exact RAM partition reader.
# Reuses already-authenticated base-memory, PRNG and ExitBootServices dossiers.
# Original firmware integrity is SHA256-pinned; no phone operations.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003

echo "=== Regression tests: original HXL1 handoff and supporting sources ==="
python3 -m unittest -q \
  tools/test_y2q_linuxloader_rea_stage4_handoff.py \
  tools/test_y2q_linuxloader_rea_stage4_sources.py \
  tools/test_y2q_linuxloader_rea_ram_partition_chain.py

echo "=== Authenticate real HXL1 handoff and firmware fallback values ==="
python3 tools/y2q_linuxloader_rea_stage4_handoff.py --out "$OUT"
# Full original handoff proof remains saved; no duplicate printing.

[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing genuine HXL1 LinuxLoader or REA fork" >&2; exit 2;
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original HXL1 LinuxLoader SHA256 mismatch" >&2; exit 2;
}
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
node -e 'process.exit(process.platform==="linux"&&Number(process.versions.node.split(".")[0])===24?0:1)' || {
  echo "[STOP] Native Linux Node.js 24 required" >&2; exit 2;
}

echo "=== Four targeted REA/Ghidra static supporting function observations ==="
while read -r label address; do
  target="$OUT/rea-stage4-source-$label.json"
  if python3 tools/y2q_linuxloader_rea_stage4_sources.py \
      --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Verified HXL1 source function $label at $address"
    continue
  fi
  echo "[GHIDRA FUNCTION] $label at $address"
  node "$REA" function "$EFI" "$address" --provider ghidra --json \
    > "$target" 2> "$OUT/rea-stage4-source-$label-stderr.txt" || true
  if ! python3 tools/y2q_linuxloader_rea_stage4_sources.py \
      --out "$OUT" --verify-single "$label"; then
    echo "[STOP] Ghidra function output did not verify: $label" >&2
    echo "[EVIDENCE] $target" >&2
    exit 2
  fi
done <<'FUNCTIONS'
base-memory-provider 0x1f018
kaslr-initializer 0x20838
exit-boot-services 0x1e868
ram-partition-reader 0x1eca0
FUNCTIONS

python3 tools/y2q_linuxloader_rea_stage4_sources.py --out "$OUT"
python3 tools/y2q_linuxloader_rea_ram_partition_chain.py --out "$OUT"
sed -n '/^## ram-partition-reader/,/^## What this does NOT prove/p' "$OUT/rea-stage4-source-functions.md"
echo "[LIMIT] Static function code; boot-time physical kernel load still unmeasured"
