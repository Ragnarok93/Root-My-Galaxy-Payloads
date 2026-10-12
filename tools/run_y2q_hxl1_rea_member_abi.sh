#!/usr/bin/env bash
# Single source-pinned, read-only original HXL1 REA/Ghidra HighFunction pass.
# No firmware writes, device access, KernelSU loading or release operations.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
REA_ENV="$HOME/s20-artifacts/hxl1-research/abl-linuxloader/rea-ghidra-env.sh"
if [[ -s "$REA_ENV" ]]; then
  . "$REA_ENV"
fi
REA="$HOME/src/rea/scripts/rea.mjs"
if [[ ! -f "$REA" || -L "$REA" ]]; then
  echo "[STOP] REA original Ghidra host entrypoint missing/unsafe: $REA" >&2
  exit 2
fi
REPORT="$HOME/s20-artifacts/hxl1-research/stage3-offset-verification-20261012T152423477542Z.json"
if [[ ! -f "$REPORT" || -L "$REPORT" ]]; then
  echo "[STOP] Original authenticated Stage3 owner report missing/unsafe: $REPORT" >&2
  exit 2
fi
exec python3 tools/y2q_hxl1_rea_member_abi.py \
  --verified-stage3-report "$REPORT" \
  --rea "$REA" --execute "$@"
