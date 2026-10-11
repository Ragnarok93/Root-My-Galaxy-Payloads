#!/usr/bin/env bash
# Run only SHA256-attested offline HXL1 REA/Ghidra HighFunction value tracing.
set -euo pipefail
cd "$(dirname "$0")/.."

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
test -f "$REA" && test ! -L "$REA" || {
  echo "[STOP] REA script missing at $REA" >&2
  exit 2
}
command -v node >/dev/null || { echo "[STOP] Node unavailable" >&2; exit 2; }

python3 -m unittest -q \
  tools.test_y2q_hxl1_rea_decision_path_review \
  tools.test_y2q_hxl1_rea_semantic_roots

echo "[RUN] HXL1 exact original-Evidence semantic tracing, default 2 targets"
python3 tools/y2q_hxl1_rea_semantic_roots.py --execute --rea "$REA" "$@"

cat "$HOME/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/semantic-roots.md"

echo "[LIMIT] No OEM unlock state transition or vulnerability established"
