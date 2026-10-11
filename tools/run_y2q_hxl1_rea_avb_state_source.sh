#!/usr/bin/env bash
# SHA-verified read-only HXL1 AVB unlock-state source 0x33770 Ghidra dossier.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
ENV="$HOME/s20-artifacts/hxl1-research/abl-linuxloader/rea-ghidra-env.sh"
if [[ -s "$ENV" ]]; then
  . "$ENV"
fi
REA="$HOME/src/rea/scripts/rea.mjs"
if [[ ! -f "$REA" || -L "$REA" ]]; then
  echo "[STOP] REA Node script missing or unsafe at $REA" >&2
  exit 2
fi
python3 -m unittest -q tools.test_y2q_hxl1_rea_avb_state_source
python3 tools/y2q_hxl1_rea_avb_state_source.py --execute --rea "$REA" "$@"
cat "$HOME/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/avb-unlock-state-source.md"
