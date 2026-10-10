#!/usr/bin/env bash
# One-time Linux Node environment repair for Ragnarok93/rea on Ubuntu/WSL2.
# Explicitly run by the operator. No firmware execution or device operations.
set -euo pipefail

REA_DIR="$HOME/src/rea"
NVM_DIR="$HOME/.nvm"
OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
mkdir -p "$OUT"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[STOP] This bootstrap must run inside Linux/WSL2" >&2
  exit 2
fi
if [[ ! -f "$REA_DIR/scripts/rea.mjs" || ! -f "$REA_DIR/package-lock.json" ]]; then
  echo "[STOP] Existing REA fork checkout missing at $REA_DIR" >&2
  echo "Do not clone into an already occupied directory." >&2
  exit 2
fi
if ! git -C "$REA_DIR" rev-parse --is-inside-work-tree >/dev/null; then
  echo "[STOP] REA checkout is not a Git repository" >&2
  exit 2
fi

echo "=== Previously mixed PATH ==="
type -a node npm || true
node --version 2>/dev/null || true

echo "=== Activate genuine Linux Node.js via pinned nvm ==="
if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
  if [[ -e "$NVM_DIR" ]]; then
    echo "[STOP] $NVM_DIR exists but nvm.sh is missing; inspect rather than overwrite" >&2
    exit 2
  fi
  git clone --depth 1 --branch v0.40.3 https://github.com/nvm-sh/nvm.git "$NVM_DIR"
fi
export NVM_DIR
# shellcheck source=/dev/null
. "$NVM_DIR/nvm.sh"
nvm install 24
nvm alias default 24
nvm use 24 >/dev/null
hash -r

NODE_BIN="$(command -v node)"
NPM_BIN="$(command -v npm)"
case "$NODE_BIN" in
  "$NVM_DIR"/versions/node/*/bin/node) ;;
  *) echo "[STOP] node is not Linux nvm: $NODE_BIN" >&2; exit 2 ;;
esac
case "$NPM_BIN" in
  "$NVM_DIR"/versions/node/*/bin/npm) ;;
  *) echo "[STOP] npm is not Linux nvm: $NPM_BIN" >&2; exit 2 ;;
esac
if ! node -e 'const v=process.versions.node.split(".").map(Number);process.exit(process.platform==="linux"&&v[0]===24&&v[1]>=11?0:1)'; then
  echo "[STOP] Node 24.11+ Linux requirement not met" >&2
  exit 2
fi
printf 'node: %s (%s)\n' "$(node --version)" "$NODE_BIN"
printf 'npm: %s (%s)\n' "$(npm --version)" "$NPM_BIN"
echo "Runtime: $(node -p 'process.platform+" "+process.arch+" "+process.execPath')"

echo "=== Build existing REA fork with Linux Node/npm only ==="
cd "$REA_DIR"
echo "REA current commit: $(git rev-parse HEAD)"
# npm ci intentionally replaces partial Windows-created node_modules.
npm ci --no-audit --no-fund
npm run build
node scripts/rea.mjs providers --json > "$OUT/rea-providers.json"
echo "[PASS] REA built with native Linux Node/npm"
echo "[PROVIDERS] $OUT/rea-providers.json"

if node scripts/rea.mjs doctor --provider ghidra --json > "$OUT/rea-ghidra-doctor.json"; then
  echo "[PASS] REA Ghidra provider doctor returned ready"
else
  echo "[NEXT BLOCKER] Ghidra provider not ready; inspect $OUT/rea-ghidra-doctor.json"
  echo "[NOTE] REA 6.3.0 expects Ghidra 12.1.x and a compatible full JDK."
  echo "[NOTE] Configure GHIDRA_INSTALL_DIR after installing Ghidra."
fi
echo "[NEXT] cd ~/src/Root-My-Galaxy-Payloads && bash tools/analyze_y2q_hxl1_linuxloader_rea.sh"
