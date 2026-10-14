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
from tools import y2q_hxl1_linuxloader_getter_callsites as attestation

p=Path(sys.argv[1])
if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= 12_000_000:
    raise SystemExit("Unsafe/empty/oversized REA result")
result=attestation.verify_getter_dossier(
    json.loads(p.read_text(encoding="utf-8")), sys.argv[2], sys.argv[3])
print("[VERIFIED STATIC GETTER IDENTITY]", result["requestedAddress"],
      "=", result["returnedFunctionEntry"])
print("[SELECTOR ALGORITHM / PHYSICAL HANDOFF] NOT VERIFIED")
PY
  then
    mv "$partial" "$final"
    echo "[PRESERVED RESULT] $final"
  else
    echo "[VALIDATION FAILED, PARTIAL PRESERVED] $partial"
    FAILED=1
  fi
done

# Produce ONE small, self-contained source package only after both original
# Ghidra getter entries have passed exact SHA and function-entry validation.
# No additional provider request is made; full raw dossiers remain saved.
if test "$FAILED" -eq 0; then
  if python3 - "$DIR" > "$DIR/verified-getter-packet.partial.json" <<'PY'
import json,sys
from pathlib import Path
from tools import y2q_hxl1_linuxloader_getter_callsites as audit

base=Path(sys.argv[1])
input_files={kind:base/(kind+"-getter.json") for kind in ("dtbo","dtb")}
original={kind:json.loads(path.read_text(encoding="utf-8"))
          for kind,path in input_files.items()}
packet=audit.package_verified_getter_dossiers(original)
print(json.dumps(packet,indent=2))
PY
  then
    mv "$DIR/verified-getter-packet.partial.json" "$DIR/verified-getter-packet.json"
    echo "[PORTABLE TWO-GETTER EVIDENCE] $DIR/verified-getter-packet.json"
  else
    echo "[TWO-GETTER PACKET REJECTED; PARTIAL PRESERVED]"
    FAILED=1
  fi
else
  echo "[TWO-GETTER PACKET SKIPPED: incomplete verified inputs]"
fi
echo "[OUTPUT DIRECTORY] $DIR"
echo "[SCOPE] two original static getter functions only; no selector proven"
echo "[PHYSICAL HANDOFF / ROOT / KERNELSU] NOT VERIFIED"
exit "$FAILED"
