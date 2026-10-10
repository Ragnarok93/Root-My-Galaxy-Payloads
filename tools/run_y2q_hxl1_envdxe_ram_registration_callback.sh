#!/usr/bin/env bash
# Stage 4: doubled substantive work in one run.
# 121 offline tests; upstream+registration+interface+8 xrefs+callback raw recovery.
# Original firmware from pinned HXL1 XBL only; NO ADB/phone/root/flash.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== 121 offline original EnvDxe RAM-registration/callback tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_ram_registration_interface.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_callback.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py \
  tools/test_y2q_hxl1_envdxe_callback_raw_proof.py \
  tools/test_y2q_hxl1_envdxe_callback_mutations.py

echo "=== Authenticate exact original EnvDxe and previously verified registration ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing original stock EnvDxe PE or local REA" >&2
  exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original EnvDxe PE SHA256 mismatch" >&2
  exit 2
}
python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
  --out "$OUT" --verify-single registration

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
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0:1)' || {
  echo "[STOP] Native Linux Node 24 required" >&2
  exit 2
}

echo "=== Read exactly 48 original Ghidra protocol interface bytes at 0xd1d0 ==="
f="$OUT/rea-envdxe-ram-protocol-interface-read.json"
if python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
    --out "$OUT" --verify-single interface >/dev/null 2>&1; then
  echo "[REUSE] Validated original 48-byte RAM protocol table"
else
  [[ ! -e "$f" ]] || {
    echo "[STOP] Invalid existing table-read evidence: $f" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-ram-protocol-interface-read.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Previous partial table evidence: $tmp" >&2
    exit 2
  }
  echo "[GHIDRA] Protocol interface 0xd1d0; GetRamPartitions at +0x18"
  if ! node "$REA" read-bytes "$EFI" 0xd1d0 --length 48 \
      --provider ghidra --json > "$tmp" \
      2> "$OUT/rea-envdxe-ram-protocol-interface-read-stderr.txt"; then
    echo "[STOP] Original Ghidra table read failed; inspect partial and stderr" >&2
    exit 2
  fi
  mv "$tmp" "$f"
  python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
      --out "$OUT" --verify-single interface
fi

echo "=== Eight original targeted reference checks ==="
while IFS='|' read -r label address; do
  f="$OUT/rea-envdxe-ram-protocol-xrefs-$label.json"
  if python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
      --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Authenticated original xrefs: $label"
    continue
  fi
  [[ ! -e "$f" ]] || {
    echo "[STOP] Invalid existing xref evidence: $f" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-ram-protocol-xrefs-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Existing partial reference evidence: $tmp" >&2
    exit 2
  }
  echo "[GHIDRA XREFS] $label at $address"
  if ! node "$REA" xrefs "$EFI" "$address" --provider ghidra --json \
       > "$tmp" 2> "$OUT/rea-envdxe-ram-protocol-xrefs-$label-stderr.txt"; then
    echo "[STOP] Ghidra xrefs failed: $label; see partial and stderr" >&2
    exit 2
  fi
  mv "$tmp" "$f"
  python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
      --out "$OUT" --verify-single "$label"
done <<'XREFS'
protocol-interface|0xd1d0
get-ram-partitions-slot|0xd1e8
registration-function|0x205c
smem402-table-supplier|0x53b0
ram-table-v1-parser|0x5430
ram-table-header-validator|0x5288
smem-generic-item-accessor|0x7d08
other-protocol-installer|0x23b0
XREFS

echo "=== Independently validate candidate callback 64 original PE code bytes ==="
CALLBACK="$(python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_ram_registration_callback import interface_readback
doc=interface_readback(Path(sys.argv[1]))
print(doc["unrelocatedStaticFunctionCoordinateCandidate"] or "UNRESOLVED")
PY
)"
if [[ "$CALLBACK" == "UNRESOLVED" ]]; then
  echo "[LIMIT] No statically usable callback pointer: PE relocation or runtime initialization may be needed"
elif [[ "$CALLBACK" =~ ^0x[[:xdigit:]]+$ ]]; then
  python3 - "$OUT" "$CALLBACK" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_callback_raw_proof import original_code
info=original_code(Path(sys.argv[1]),sys.argv[2])
print("[VERIFIED ORIGINAL PE EXECUTABLE]",info["coordinate"],
      info["sectionName"],"file",info["fileOffset"],
      "64-byte sha256",info["bytesSha256"])
PY
  bytes_file="$OUT/rea-envdxe-ram-protocol-callback-code-read.json"
  if python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
       --out "$OUT" --verify-single callback-bytes >/dev/null 2>&1; then
    echo "[REUSE] Original callback imported code bytes match pinned PE"
  elif [[ -e "$bytes_file" ]]; then
    echo "[STOP] Existing raw callback Ghidra evidence conflicts with original PE: $bytes_file" >&2
    exit 2
  else
    partial="$OUT/rea-envdxe-ram-protocol-callback-code-read.partial.json"
    if [[ -e "$partial" ]]; then
      echo "[LIMIT] Previous incomplete raw callback read preserved: $partial"
    else
      echo "[GHIDRA BYTES] Read 64 code bytes at $CALLBACK"
      if node "$REA" read-bytes "$EFI" "$CALLBACK" --length 64 \
          --provider ghidra --json > "$partial" \
          2> "$OUT/rea-envdxe-ram-protocol-callback-code-read-stderr.txt"; then
        mv "$partial" "$bytes_file"
        python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
          --out "$OUT" --verify-single callback-bytes
      else
        echo "[LIMIT] Imported callback byte read failed; original PE executable proof retained"
      fi
    fi
  fi

  echo "=== Optional callback decompilation; preserve prior failure ==="
  function_file="$OUT/rea-envdxe-ram-protocol-callback-function.json"
  function_partial="$OUT/rea-envdxe-ram-protocol-callback-function.partial.json"
  if python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
      --out "$OUT" --verify-single callback >/dev/null 2>&1; then
    echo "[REUSE] Verified original Ghidra callback decompilation $CALLBACK"
  elif [[ -e "$function_file" ]]; then
    echo "[STOP] Existing callback function evidence is invalid: $function_file" >&2
    exit 2
  elif [[ -e "$function_partial" ]]; then
    echo "[PRESERVED] Earlier failed Ghidra callback function analysis; collecting independent proof"
  else
    echo "[GHIDRA FUNCTION] Attempt original callback $CALLBACK"
    if node "$REA" function "$EFI" "$CALLBACK" --provider ghidra --json \
        > "$function_partial" \
        2> "$OUT/rea-envdxe-ram-protocol-callback-function-stderr.txt"; then
      mv "$function_partial" "$function_file"
      python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py \
          --out "$OUT" --verify-single callback
    else
      echo "[LIMIT] Callback function analysis failed; partial and stderr preserved, continuing"
    fi
  fi
else
  echo "[STOP] Invalid static callback address returned by original PE" >&2
  exit 2
fi

python3 tools/y2q_hxl1_envdxe_ram_registration_callback.py --out "$OUT"
cat "$OUT/rea-envdxe-ram-registration-callback.md"
echo "[LIMIT] Static provider contract only; no actual kernel physical load or root"
