#!/usr/bin/env bash
# Original HXL1 LinuxLoader W0 returned byte and source-attested xref inspection.
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
  echo "[STOP] Original REA script missing/unsafe at $REA" >&2
  exit 2
fi
python3 -m unittest -q tools.test_y2q_hxl1_rea_avb_byte_writers
python3 tools/y2q_hxl1_rea_avb_byte_writers.py --execute --rea "$REA" "$@"
cat "$HOME/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/avb-byte-writer-sites.md"
