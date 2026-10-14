#!/usr/bin/env bash
# Offline HXL1 original sendmsg instruction verification (NO phone or exploit).
# Finds exactly the owner's SHA-verified manifest and uses its saved binaries.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EVIDENCE="${HXL1_EVIDENCE_DIR:-$HOME/s20-artifacts/hxl1-research}"
KERNEL="${HXL1_KERNEL:-$HOME/s20-artifacts/kernel.bin}"
NM="${HXL1_NM:-$EVIDENCE/vmlinux-stock.nm}"

echo "[TEST] Fail-closed original Image and ARM64 disassembly regressions"
python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_sendmsg_frame_attest

echo "[LOCATE] Exact owner-supplied original sendmsg manifest"
REPORT="$(python3 - "$EVIDENCE" <<'PY'
import hashlib
from pathlib import Path
import sys
root=Path(sys.argv[1])
expected="8b95591b0da9b8645db862c0d3c2e8b8d9646492fd3dcdb32227dce4a466c7e8"
matches=[]
for path in root.glob("ghostlock-original-sendmsg-*/original-sendmsg-windows.json"):
    if not path.is_file() or path.is_symlink() or path.stat().st_size>200000:
        continue
    if hashlib.sha256(path.read_bytes()).hexdigest()==expected:
        matches.append(path)
if len(matches)!=1:
    raise SystemExit(
       f"Expected one exact original manifest under {root}, found {len(matches)}. "
       "Do not substitute a different firmware report.")
print(matches[0])
PY
)"

OUT="$EVIDENCE/ghostlock-sendmsg-frame-$(date -u +%Y%m%dT%H%M%S%NZ).json"
echo "[ORIGINAL MANIFEST] $REPORT"
python3 -m tools.y2q_hxl1_ghostlock_sendmsg_frame_attest \
  --report "$REPORT" \
  --kernel "$KERNEL" \
  --nm "$NM" \
  --output "$OUT"

python3 - "$OUT" <<'PY'
import json
from pathlib import Path
import sys
d=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print("[STOCK WINDOWS]",d["codeWindowsVerified"],"/",d["requestedSymbols"])
for item in d["functions"]:
    if item["status"]=="NOT_FOUND_IN_RECOVERED_NM":
        print("[UNRESOLVED NAME]",item["symbol"],"not proof of compiled absence")
        continue
    features=item["features"]
    literal=features["literalSpAdjustments"]
    print("[STATIC FRAME]",item["symbol"],
          "literalEntryBytes=",literal["staticEntryBytes"],
          "instructions=",features["instructionSlotsChecked"],
          "sourceLocalsVerified=NO")
print("[WAITER-TO-SENDMSG ALIAS / GHOSTLOCK ROOT / KERNELSU] NOT VERIFIED")
print("[FULL REPORT]",sys.argv[1])
PY
