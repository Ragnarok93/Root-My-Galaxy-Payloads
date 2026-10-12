#!/usr/bin/env bash
# One-command, host-only REA/Ghidra original-kernel Stage 3 ABI field investigation.
# Never touches a phone, installed firmware, original kernel, or production target.h.
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
  echo "[STOP] Existing REA/Ghidra CLI missing or unsafe: $REA" >&2
  exit 2
fi
command -v node >/dev/null || { echo "[STOP] Node.js is missing" >&2; exit 2; }
node "$REA" providers --json >/dev/null || {
  echo "[STOP] REA provider discovery failed" >&2; exit 2;
}
REPORT="$HOME/s20-artifacts/hxl1-research/stage3-offset-verification-20261012T152423477542Z.json"
python3 tools/y2q_hxl1_stage3_rea_live_review.py \
  --verified-stage3-report "$REPORT" --rea "$REA" --execute "$@"
