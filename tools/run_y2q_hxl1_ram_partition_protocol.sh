#!/usr/bin/env bash
# HXL1: one exact original EFI_RAMPARTITION protocol GUID read, no device calls.
# The already verified RAM-partition reader/caller Ghidra dossiers are reused.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN="5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"
GUID_OUTPUT="$OUT/rea-stage4-ram-partition-protocol-guid.json"

echo "=== Regression: exact original EFI RAM ABI ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_ram_partition_protocol_audit.py \
  tools/test_y2q_linuxloader_rea_ram_partition_chain.py
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing original HXL1 LinuxLoader or existing REA fork" >&2; exit 2;
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original EFI digest mismatch" >&2; exit 2;
}

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
if [[ -s "$OUT/rea-ghidra-env.sh" ]]; then
  # shellcheck source=/dev/null
  . "$OUT/rea-ghidra-env.sh"
fi
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0:1)' || {
  echo "[STOP] Native Linux Node 24 is required" >&2; exit 2;
}

if [[ -e "$GUID_OUTPUT" ]]; then
  echo "[REUSE] Existing original GUID Evidence, verifying instead of re-querying"
else
  echo "[GHIDRA] Reading precisely 16 original EFI bytes at 0xef880"
  tmp="$OUT/rea-stage4-ram-partition-protocol-guid.partial.json"
  if [[ -e "$tmp" ]]; then
    echo "[STOP] Existing partial Evidence; refusing overwrite: $tmp" >&2
    exit 2
  fi
  if ! node "$REA" read-bytes "$EFI" 0xef880 --length 16 \
      --provider ghidra --json > "$tmp" \
      2> "$OUT/rea-stage4-ram-partition-protocol-guid-stderr.txt"; then
    echo "[STOP] REA GUID read failed; inspect $tmp and stderr" >&2
    exit 2
  fi
  # The audit rejects untrusted/mismatched results before any PASS message.
  mv "$tmp" "$GUID_OUTPUT"
fi

python3 tools/y2q_hxl1_ram_partition_protocol_audit.py --out "$OUT"
cat "$OUT/rea-stage4-ram-partition-protocol.md"
echo "[LIMIT] Original protocol ABI proven; live physical RAM layout still unavailable"
