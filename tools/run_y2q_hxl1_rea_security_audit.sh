#!/usr/bin/env bash
# Stock HXL1 bootloader security-path analysis using existing REA/Ghidra only.
# Read-only host-side; no phone, flash, arbitrary binary or firmware execution.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/bootloader-unlock"
if [[ ! -f "$OUT/hxl1-bootloader-hotspots.json" ]]; then
  echo "[STOP] Run python3 tools/y2q_hxl1_bootloader_hotspots.py first" >&2
  exit 2
fi

echo "=== Synthetic host-only regression ==="
python3 -m unittest -q tools.test_y2q_hxl1_rea_security_audit

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

REA="$HOME/src/rea/scripts/rea.mjs"
[[ -f "$REA" && ! -L "$REA" ]] || {
  echo "[STOP] Existing REA fork not found at $REA" >&2; exit 2;
}
command -v node >/dev/null || { echo "[STOP] Node missing" >&2; exit 2; }
node -e 'const v=process.versions.node.split(".").map(Number);process.exit((v[0]===22&&v[1]>=19)||(v[0]===24&&v[1]>=11)||v[0]>=26?0:1)' || {
  echo "[STOP] REA requires Node 22.19+, 24.11+, or 26+" >&2
  node --version
  exit 2
}

echo "=== REA/Ghidra discovery, no import or firmware execution ==="
node "$REA" providers --json >/dev/null || {
  echo "[STOP] REA fork provider discovery failed" >&2; exit 2;
}

echo "=== Execute bounded offline Ghidra search → xrefs → function review ==="
python3 tools/y2q_hxl1_rea_security_audit.py \
  --execute --rea "$REA" "$@"

echo "=== Saved analysis report ==="
cat "$OUT/rea-security-audit/security-paths.md"
echo "[LIMIT] Candidate audit only, no software/hardware unlock verified"
