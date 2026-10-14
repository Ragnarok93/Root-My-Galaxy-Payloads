#!/usr/bin/env bash
# Read-only HXL1 source-and-original-instruction waiter argument audit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python3 -m unittest -v tools.test_y2q_hxl1_waiter_argument_lifetime_audit
python3 -m unittest -v tools.test_y2q_hxl1_waiter_store_load_cfg
python3 -m unittest -v tools.test_y2q_hxl1_waiter_store_load_witness

EVIDENCE="${HXL1_EVIDENCE_DIR:-$HOME/s20-artifacts/hxl1-research}"

find_pinned() {
  python3 - "$1" "$2" "$HOME" "$EVIDENCE" <<'PY'
import hashlib
from pathlib import Path
import sys
name,wanted,home,research=sys.argv[1:]
home=Path(home);research=Path(research)
candidates=[
  home/name,home/"s20-artifacts"/name,research/name,
  *research.glob("*/"+name),
  *research.glob("*/*/"+name),
]
matches=[]
for path in candidates:
    if path.is_file() and not path.is_symlink() and 0<path.stat().st_size<4_000_000:
        if hashlib.sha256(path.read_bytes()).hexdigest()==wanted:
            matches.append(path)
if not matches:
    raise SystemExit("[STOP] Exact SHA-matching "+name+
        " not found. Set HXL1_SOURCE_ARCHIVE or HXL1_DISASSEMBLY_ARCHIVE.")
print(sorted(set(matches))[0])
PY
}

SOURCE="${HXL1_SOURCE_ARCHIVE:-}"
DISASM="${HXL1_DISASSEMBLY_ARCHIVE:-}"
if [[ -z "$SOURCE" ]]; then
  SOURCE="$(find_pinned hxl1-source-dispatch-review.tar.gz deac172780286aeca1d3b1d9ab7f036e84532a6d087cc89721fd5cc7d16fe1a3)"
fi
if [[ -z "$DISASM" ]]; then
  DISASM="$(find_pinned hxl1-disassembly-review.tar.gz 20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997)"
fi

OUT="$EVIDENCE/hxl1-waiter-source-compiled-$(date -u +%Y%m%dT%H%M%S%NZ).json"
OPTIONS=()
NM="${HXL1_NM:-$EVIDENCE/vmlinux-stock.nm}"
if [[ -f "$NM" ]]; then OPTIONS+=(--nm "$NM"); fi

python3 -m tools.y2q_hxl1_waiter_argument_lifetime_audit \
  --source-archive "$SOURCE" \
  --disassembly-archive "$DISASM" \
  "${OPTIONS[@]}" \
  --output "$OUT"

python3 - "$OUT" <<'PY'
import json,sys
from pathlib import Path
r=json.loads(Path(sys.argv[1]).read_text())
frame=r["compiledSpFrameInventory"]
print("[ORIGINAL DO_FUTEX INSTRUCTIONS]",frame["originalFunctionInstructionSlots"])
print("[ORIGINAL SP REFERENCES]",frame["observedInstructionsReferencingSp"])
print("[SP WRITES]",frame["observedSpWrites"],frame["observedSpWriteOffsets"])
print("[ENTRY FRAME BYTES]",frame["frameAllocationBytes"])
print("[OTHER SP MODIFICATIONS / WRITEBACKS]",frame["unexpectedSpInstructionForms"],frame["writebackMemoryInstructionsTouchingSp"])
print("[C-LOCAL LIFETIME / CROSS-SYSCALL OVERLAP] NOT PROVEN")
store=r["conditionalWaiterDerivedPointerStore"]
print("[CONDITIONAL POINTER STORE]",store["storeRelativeOffset"],
      "source=",store["sourcePointerExpression"],
      "stackDestination=",store["firstStoredValueStackOffset"])
print("[SOURCE OBJECT FIELD ATTRIBUTION]",store["queuePointerFieldProven"])
print("[SOURCE LANDMARKS]",len(r["waiterSourceMarkers"]))
print("[ORIGINAL COMPILED ARGUMENT SITES]",len(r["compiledCallArgumentSites"]))
for x in r["compiledCallArgumentSites"]:
    print(x["role"],x["argumentRegister"],x["literalArgumentExpression"],
          x["calleeRecoveredLabelFromPriorOwnerNm"],
          "relative-callsite="+x["calleeCallRelativeVA"])
print("[COMPILER OBJECT LIFETIME / CROSS-SYSCALL OVERLAP / ROOT] UNVERIFIED")
print("[REPORT]",sys.argv[1])
PY


# Independent, bounded static source/compiled store-load correlation.
# Preserves the original report and never mutates source or device.
NEXT="$EVIDENCE/hxl1-waiter-store-load-cfg-$(date -u +%Y%m%dT%H%M%S%NZ).json"
python3 -m tools.y2q_hxl1_waiter_store_load_cfg \
  --source-archive "$SOURCE" \
  --disassembly-archive "$DISASM" \
  --output "$NEXT"

python3 - "$NEXT" <<'PY'
import json,sys
from pathlib import Path
r=json.loads(Path(sys.argv[1]).read_text())
print("[STATIC POINTER STORE]",r["firstStoreRelativeOffset"],r["storeFirstMemorySlot"])
print("[STATIC POINTER LOAD]",r["laterLoadRelativeOffset"],r["laterLoadedRegisterOrigin"])
print("[STATIC REACHABILITY]",r["staticControlFlowPathStoreToLoadFound"],
      "shortest path steps:",r["shortestStoreToLoadPathInstructions"])
print("[OEM q.rt_waiter LAYOUT]",r["calleeSourceFieldQrtWaiterMapping"])
print("[LIFETIME / CROSS-SYSCALL REUSE / ROOT] UNVERIFIED")
print("[FULL STORE-LOAD REPORT]",sys.argv[1])
PY


# One bounded static witness: four direct calls, five branches, no runtime claims.
WITNESS="$EVIDENCE/hxl1-waiter-store-load-witness-$(date -u +%Y%m%dT%H%M%S%NZ).json"
python3 -m tools.y2q_hxl1_waiter_store_load_witness \
  --source-archive "$SOURCE" \
  --disassembly-archive "$DISASM" \
  "${OPTIONS[@]}" \
  --output "$WITNESS"
python3 - "$WITNESS" <<'PY'
import json,sys
from pathlib import Path
w=json.loads(Path(sys.argv[1]).read_text())["witness"]
print("[STORE-LOAD SHORTEST STATIC WITNESS STEPS]",w["staticInstructionCount"])
print("[CONDITIONAL BRANCHES; PREDICATES NOT PROVEN]",len(w["conditionalBranches"]))
print("[INTERPROCEDURAL CALLS; SIDE EFFECTS UNKNOWN]",len(w["directCalls"]))
ledger=json.loads(Path(sys.argv[1]).read_text())['originalCalleeLabelLedger']
print('[NM REHASHED FOR FOUR CALLS]',ledger['recoveredNmIndependentlyRehashed'])
for c in ledger['namedCalls']:
    l=c.get('recoveredLabel',{})
    print('[ORIGINAL CALLEE LABEL]',c['relativeVA'],l.get('status','NM_NOT_PRESENT'),l.get('labels',l.get('lowerLabels',[])))
print("[EXPLICIT STORES ON WITNESS]",len(w["explicitStores"]))
print("[LIFETIME / STACK REUSE / ROOT] UNVERIFIED")
print("[WITNESS REPORT]",sys.argv[1])
PY
