#!/usr/bin/env bash
# HXL1 original OEM/FRP provider and native boot entry dispatch forensics.
# Read-only Ghidra; no phone access, unlock, flash or firmware modification.
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
  echo "[STOP] Original REA script unavailable or symlinked: $REA" >&2
  exit 2
fi
python3 -m unittest -q tools.test_y2q_hxl1_rea_avb_oem_providers_entry
python3 tools/y2q_hxl1_rea_avb_oem_providers_entry.py --execute --rea "$REA" "$@"
cat "$HOME/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/avb-oem-providers-entry.md"
