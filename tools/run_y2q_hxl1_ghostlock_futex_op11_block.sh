#!/usr/bin/env bash
# Offline original HXL1 operation-11 compiler evidence; no device/exploit actions.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "[TEST] Original operation-11 branch analysis regressions"
python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_futex_op11_block

EVIDENCE="${HXL1_EVIDENCE_DIR:-$HOME/s20-artifacts/hxl1-research}"
NM="${HXL1_NM:-$EVIDENCE/vmlinux-stock.nm}"
ARCHIVE="${HXL1_DISASSEMBLY_ARCHIVE:-}"

if [[ -z "$ARCHIVE" ]]; then
  ARCHIVE="$(python3 - "$HOME" "$EVIDENCE" <<'PY'
from pathlib import Path
import hashlib
import sys
home=Path(sys.argv[1])
research=Path(sys.argv[2])
required="20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997"
candidates=[
 home/"hxl1-disassembly-review.tar.gz",
 home/"s20-artifacts/hxl1-disassembly-review.tar.gz",
 research/"hxl1-disassembly-review.tar.gz",
 *research.glob("*/hxl1-disassembly-review.tar.gz"),
]
matches=[]
for p in candidates:
    if not p.is_file() or p.is_symlink() or not 0<p.stat().st_size<4_000_000:
        continue
    if hashlib.sha256(p.read_bytes()).hexdigest()==required:
        matches.append(p)
if not matches:
    raise SystemExit(
       "[STOP] Exact archived original disassembly not found. "
       "Provide HXL1_DISASSEMBLY_ARCHIVE=/exact/path/to/hxl1-disassembly-review.tar.gz")
print(sorted(set(matches))[0])
PY
  )"
fi

OUT="$EVIDENCE/ghostlock-original-futex-op11-$(date -u +%Y%m%dT%H%M%S%NZ).json"
python3 -m tools.y2q_hxl1_ghostlock_futex_op11_block \
  --archive "$ARCHIVE" \
  --nm "$NM" \
  --output "$OUT"

python3 - "$OUT" <<'PY'
import json,sys
from pathlib import Path
r=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
b=r["operation11LinearBlock"]
print("[ORIGINAL COMPILED CASE-11 BLOCK]",b["case11BlockStartRelativeToDoFutexEntry"])
print("[LINEAR INSTRUCTIONS]",b["originalLinearInstructionSlotsReviewed"])
print("[STOP REASON]",b["stopReason"])
for call in b["callTargetsInFirstBlock"]:
    target=call["recoveredTextTarget"]
    print("[DIRECT CALL]",call["relativeToDoFutexEntry"],
          target.get("status"),target.get("labels",target.get("lowerLabels",[])))
print("[FIRST BLOCK TERMINAL]",b["terminalControlTransfer"])
for x in b["immediateSuccessorBlocks"]:
    print("[ONE-HOP]",x["relativeToDoFutexEntry"],x["status"],
          x.get("instructionSlots"),x.get("stopReason"),
          "BL=",len(x.get("directCalls",[])))
for x in b["twoHopSuccessorBlocks"]:
    print("[TWO-HOP]",x["relativeToDoFutexEntry"],"instructions=",
          x["instructionSlots"],"stop=",x["stopReason"],
          "BL=",len(x["directCalls"]))
    for c in x["directCalls"]:
        print("   [CALL]",c["relativeToDoFutexEntry"],
              c["directCallTargetStaticVA"],
              c["recoveredTarget"].get("status"),
              c["recoveredTarget"].get("labels",
                                        c["recoveredTarget"].get("lowerLabels",[])))
print("[TWO-HOP DIRECT CALLS]",b["twoHopDirectCalls"])
print("[FACTORY WAITER SLOT / KERNEL STACK REUSE / ROOT] UNVERIFIED")
print("[FULL REPORT]",sys.argv[1])
PY
