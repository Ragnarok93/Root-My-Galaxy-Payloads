#!/usr/bin/env bash
# Focused HXL1 Stage 4: original BootLinux omitted tail and 16 OEM fallback bytes.
# Reuses authenticated Ghidra dossiers; static provider memory only; no device.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN="5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"

echo "=== Original REA/Ghidra dossier evidence and offline regression checks ==="
python3 -m unittest -q tools/test_y2q_linuxloader_rea_stage4_placement.py
python3 tools/y2q_linuxloader_rea_stage4_placement.py --out "$OUT"

echo "=== Previously omitted ending of BootLinux (static Ghidra code) ==="
sed -n '/## Previously omitted BootLinux pseudocode tail/,/## Still unknown/p' \
  "$OUT/rea-stage4-placement-tail.md"

echo "=== Authenticate original PE before reading exact fallback offset words ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing original EFI or user REA fork" >&2; exit 2;
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] HXL1 LinuxLoader hash changed" >&2; exit 2;
}
if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
fi
if [[ -s "$OUT/rea-ghidra-env.sh" ]]; then
  # shellcheck source=/dev/null
  . "$OUT/rea-ghidra-env.sh"
fi

for request in "oem-offset-words 0xb2210 16" "kaslr-static-word 0x32a4c8 4"; do
  read -r label address bytes <<< "$request"
  output="$OUT/rea-stage4-$label.json"
  node "$REA" read-bytes "$EFI" "$address" \
    --length "$bytes" --provider ghidra --json \
    > "$output" 2> "$OUT/rea-stage4-$label-stderr.txt" || true
  python3 - "$output" "$address" "$bytes" "$PIN" <<'PY'
import json,sys
from pathlib import Path
path,addr,size,pin=sys.argv[1:5]
try:
    doc=json.loads(Path(path).read_text())
except (OSError,ValueError) as exc:
    raise SystemExit("[STOP] No valid REA read-bytes JSON: "+str(exc))
if (not isinstance(doc,dict) or "error" in doc
        or doc.get("operation")!="read_bytes"
        or doc.get("provider",{}).get("id")!="ghidra"
        or doc.get("subject",{}).get("digest",{}).get("sha256")!=pin
        or doc.get("parameters",{}).get("address")!=addr
        or doc.get("parameters",{}).get("length")!=int(size)
        or doc.get("normalized_result") is None):
    raise SystemExit("[STOP] REA bytes missing, untrusted, or from wrong original binary")
print("[VERIFIED STATIC BYTES]",addr,"length",size,
      "result",json.dumps(doc["normalized_result"],ensure_ascii=True)[:3500])
print("[EVIDENCE]",doc.get("evidence_id"))
PY
done

echo "[REPORT] $OUT/rea-stage4-placement-tail.md"
echo "[LIMIT] Ghidra static words are NOT measured BootLinux UEFI variables or runtime KASLR"
