#!/usr/bin/env bash
# Run two isolated original-HXL1 getter function dossiers. NO native value trace.
# REA only on explicit invocation, with strict per-operation bound and fresh outputs.
set -euo pipefail

BASE="${HXL1_LOADER_BASE:-$HOME/s20-artifacts/hxl1-research/abl-linuxloader}"
CACHE="${HXL1_GETTER_CACHE:-$HOME/s20-artifacts/hxl1-research/linuxloader-index-cache-20261014T052820Z.json}"
EFI="$BASE/LinuxLoader-HXL1.efi"
REA="${REA_SCRIPT:-$HOME/src/rea/scripts/rea.mjs}"
# --resume checks previously saved verified results; it never relaunches
# Ghidra for an already authenticated getter. The existing run is unchanged.
MODE=fresh
if [[ "${1:-}" == "--resume" ]]; then
  [[ $# -eq 2 ]] || { echo "Usage: $0 --resume EXISTING_RUN_DIR" >&2; exit 2; }
  MODE=resume
  DIR="$2"
else
  [[ $# -le 1 ]] || { echo "Usage: $0 [NEW_RUN_DIR]" >&2; exit 2; }
  DIR="${1:-$HOME/s20-artifacts/hxl1-research/targeted-dtb-dtbo-getters-$(date -u +%Y%m%dT%H%M%SZ)}"
fi
PIN="5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"

cd "$(dirname "$0")/.."
test -f "$EFI" && test ! -L "$EFI"
test -f "$REA"
test -s "$CACHE" && test ! -L "$CACHE"
printf '%s  %s\n' "$PIN" "$EFI" | sha256sum -c

# Verify cached callsite provenance without invoking REA.
if [[ "$MODE" == fresh ]]; then
  test ! -e "$DIR" && test ! -L "$DIR"
  mkdir -m 700 "$DIR"
  python3 -m tools.y2q_hxl1_linuxloader_getter_callsites \
    --cached-report "$CACHE" --output "$DIR/callsite-evidence.json"
else
  test -d "$DIR" && test ! -L "$DIR" && test -s "$DIR/callsite-evidence.json"
  # Fail closed if source cache or previous callsite evidence differs.
  python3 - "$CACHE" "$DIR/callsite-evidence.json" <<'PY'
import json,sys
from pathlib import Path
from tools import y2q_hxl1_linuxloader_getter_callsites as check
report=Path(sys.argv[2])
if report.is_symlink() or report.stat().st_size > 2_000_000:
    raise SystemExit("Untrusted callsite evidence on resume")
expected=check.analyze(json.loads(Path(sys.argv[1]).read_text()))
actual=json.loads(report.read_text())
if actual != expected:
    raise SystemExit("Cached report and retained callsite evidence mismatch")
print("[REUSED VERIFIED CALLSITE]",report)
PY
fi

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
  if [[ "$MODE" == resume && -e "$final" ]]; then
    # The actual original EFI SHA was already checked above; also authenticate
    # the persisted provider subject and exact entry before deciding to skip.
    python3 - "$final" "$address" "$PIN" <<'PY'
import json,sys
from pathlib import Path
from tools import y2q_hxl1_linuxloader_getter_callsites as audit
p=Path(sys.argv[1])
if p.is_symlink() or not p.is_file() or not (0 < p.stat().st_size <= 12_000_000):
    raise SystemExit("Unsafe/empty prior getter")
result=audit.verify_getter_dossier(
    json.loads(p.read_text()),sys.argv[2],sys.argv[3])
print("[REUSED AUTHENTICATED GETTER]",result["requestedAddress"])
PY
    continue
  fi
  if [[ "$MODE" == resume && ( -e "$partial" || -e "$stderr" ) ]]; then
    retry="retry-$(date -u +%Y%m%dT%H%M%SZ)-$"
    partial="$DIR/$label-getter.$retry.partial.json"
    stderr="$DIR/$label-getter.$retry.stderr.txt"
  fi
  echo "[TARGETED FUNCTION] $label $address"
  status=0
  timeout --signal=TERM --kill-after=5s 100s \
    node "$REA" function "$EFI" "$address" --provider ghidra --json \
      > "$partial" 2> "$stderr" || status=$?
  if [[ "$MODE" == resume ]]; then
    echo "$status" > "$DIR/$label-getter.resume-$.exitcode.txt"
  else
    echo "$status" > "$DIR/$label-getter.exitcode.txt"
  fi

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
  if [[ -e "$DIR/verified-getter-packet.json" ]]; then
    python3 - "$DIR" <<'PY'
import json,sys
from pathlib import Path
from tools import y2q_hxl1_linuxloader_getter_callsites as audit
base=Path(sys.argv[1]); p=base/"verified-getter-packet.json"
if p.is_symlink() or not p.is_file():
    raise SystemExit("Unsafe existing getter packet")
getters={kind:json.loads((base/(kind+"-getter.json")).read_text())
         for kind in ("dtbo","dtb")}
expected=audit.package_verified_getter_dossiers(getters)
if json.loads(p.read_text())!=expected:
    raise SystemExit("Existing getter packet differs from verified source dossiers")
print("[REUSED VERIFIED TWO-GETTER PACKET]",p)
PY
  elif python3 - "$DIR" > "$DIR/verified-getter-packet.partial.json" <<'PY'
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
