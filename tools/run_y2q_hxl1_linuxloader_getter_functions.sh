#!/usr/bin/env bash
# Run two isolated original-HXL1 getter function dossiers. NO native value trace.
# REA only on explicit invocation, with strict per-operation bound and fresh outputs.
set -euo pipefail

BASE="${HXL1_LOADER_BASE:-$HOME/s20-artifacts/hxl1-research/abl-linuxloader}"
CACHE="${HXL1_GETTER_CACHE:-$HOME/s20-artifacts/hxl1-research/linuxloader-index-cache-20261014T052820Z.json}"
EFI="$BASE/LinuxLoader-HXL1.efi"
REA="${REA_SCRIPT:-$HOME/src/rea/scripts/rea.mjs}"
DIR="${1:-$HOME/s20-artifacts/hxl1-research/targeted-dtb-dtbo-getters-$(date -u +%Y%m%dT%H%M%SZ)}"
PIN="5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"

cd "$(dirname "$0")/.."
test -f "$EFI" && test ! -L "$EFI"
test -f "$REA"
test -s "$CACHE" && test ! -L "$CACHE"
printf '%s  %s\n' "$PIN" "$EFI" | sha256sum -c

# Verify cached callsite provenance without invoking REA.
test ! -e "$DIR"
mkdir -m 700 "$DIR"
python3 -m tools.y2q_hxl1_linuxloader_getter_callsites \
  --cached-report "$CACHE" --output "$DIR/callsite-evidence.json"

if test -s "$HOME/.nvm/nvm.sh"; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
fi
if test -s "$BASE/rea-ghidra-env.sh"; then
  . "$BASE/rea-ghidra-env.sh"
fi

FAILED=0
for item in "dtbo 0x23b00" "dtb 0x23b40"; do
  read -r label address <<< "$item"
  partial="$DIR/$label-getter.partial.json"
  stderr="$DIR/$label-getter.stderr.txt"
  final="$DIR/$label-getter.json"
  echo "[TARGETED FUNCTION] $label $address"
  status=0
  timeout --signal=TERM --kill-after=5s 100s \
    node "$REA" function "$EFI" "$address" --provider ghidra --json \
      > "$partial" 2> "$stderr" || status=$?
  echo "$status" > "$DIR/$label-getter.exitcode.txt"

  if test "$status" -ne 0; then
    echo "[SAVED PARTIAL] $label exit=$status $partial"
    FAILED=1
    continue
  fi

  if python3 - "$partial" "$address" "$PIN" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
addr=sys.argv[2]
pin=sys.argv[3]
if p.stat().st_size<=0 or p.stat().st_size>12_000_000 or p.is_symlink():
    raise SystemExit("Unsafe/empty/oversized REA result")
d=json.loads(p.read_text(encoding="utf-8"))
if not isinstance(d,dict) or "error" in d:
    raise SystemExit("REA did not provide a successful dossier")
if d.get("operation")!="analyze_function" or d.get("provider",{}).get("id")!="ghidra":
    raise SystemExit("Wrong REA operation/provider")
if d.get("subject",{}).get("digest",{}).get("sha256")!=pin:
    raise SystemExit("Wrong original LinuxLoader hash")
if d.get("parameters",{}).get("procedure")!=addr:
    raise SystemExit("REA requested procedure differs from target")
n=d.get("normalized_result",{})
fn=n.get("procedure",{}) if isinstance(n,dict) else {}
if not isinstance(fn.get("address"),str) or not fn["address"].startswith("0x"):
    raise SystemExit("Missing Ghidra function identity")
if not isinstance(n.get("pseudocode"),str):
    raise SystemExit("Missing Ghidra decompilation text")
print("[VERIFIED STATIC DOSSIER]",addr,"entry=",fn["address"])
PY
  then
    mv "$partial" "$final"
    echo "[PRESERVED RESULT] $final"
  else
    echo "[VALIDATION FAILED, PARTIAL PRESERVED] $partial"
    FAILED=1
  fi
done
echo "[OUTPUT DIRECTORY] $DIR"
echo "[SCOPE] two original static getter functions only; no selector proven"
echo "[PHYSICAL HANDOFF / ROOT / KERNELSU] NOT VERIFIED"
exit "$FAILED"
