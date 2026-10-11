#!/usr/bin/env bash
# Read-only X0/FDT-header capture at original ARM64 Image entry.
# Bounded LOCAL QEMU only: no physical handset and no guest-memory writes.
set -euo pipefail
IMAGE_SHA=ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
ENTRY_PC=0x40080000
PORT=12346
LIMIT_SECONDS=30
KERNEL="$HOME/s20-artifacts/kernel.bin"
OUT="$HOME/s20-artifacts/hxl1-research/qemu-entry-fdt-20261011"
if (( $# > 0 )); then OUT="$1"; fi
stop() { echo "[STOP] $*" >&2; exit 2; }
[[ ! -e "$OUT" && ! -L "$OUT" ]] || stop "Output exists: use a fresh directory"
[[ -f "$KERNEL" && ! -L "$KERNEL" ]] || stop "Exact HXL1 Image missing/symlink"
command -v sha256sum >/dev/null || stop "sha256sum unavailable"
printf '%s  %s\n' "$IMAGE_SHA" "$KERNEL" | sha256sum -c --status ||
  stop "Original HXL1 Image SHA mismatch"
for tool in qemu-system-aarch64 gdb-multiarch timeout; do
  command -v "$tool" >/dev/null || stop "Missing tool: $tool"
done
mkdir -p -- "$OUT"
printf '%s\n' "virt,gic-version=3 / cortex-a57 / smp=1 / m=2048" \
  > "$OUT/machine-profile.txt"
qemu-system-aarch64 --version > "$OUT/qemu-version.txt"
cat > "$OUT/entry-fdt-readonly.gdb" <<EOF
set pagination off
set confirm off
set architecture aarch64
set remotetimeout 5
target remote 127.0.0.1:$PORT
hbreak *$ENTRY_PC
continue
if \$pc == $ENTRY_PC
  printf "HXL1_ENTRY_BREAKPOINT_HIT PC=0x%lx\\n", \$pc
  printf "X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", \$x0, \$x1, \$x2, \$x3
  printf "FDT_HEADER_AT_X0_START\\n"
  x/16bx \$x0
  printf "FDT_HEADER_AT_X0_END\\n"
  x/1wx \$pc
else
  printf "HXL1_ENTRY_OTHER_STOP PC=0x%lx\\n", \$pc
end
quit
EOF
QEMU_PID=''
cleanup() {
  if [[ -n $QEMU_PID ]]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
qemu-system-aarch64 \
  -machine virt,gic-version=3 -cpu cortex-a57 -smp 1 -m 2048 \
  -kernel "$KERNEL" \
  -append "earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr" \
  -display none -serial "file:$OUT/serial-console.log" -monitor none \
  -no-reboot -nic none \
  -d int,guest_errors -D "$OUT/qemu-exceptions.log" \
  -S -gdb "tcp:127.0.0.1:$PORT" \
  > "$OUT/qemu-stdout.log" 2>&1 &
QEMU_PID=$!
sleep 1
kill -0 "$QEMU_PID" 2>/dev/null ||
  stop "QEMU terminated before GDB; see qemu-stdout.log"
set +e
timeout --signal=INT --kill-after=3s "$LIMIT_SECONDS"s \
  gdb-multiarch -q -nx -batch -x "$OUT/entry-fdt-readonly.gdb" \
  > "$OUT/gdb-session.log" 2>&1
STATUS=$?
set -e
printf '%s\n' "$STATUS" > "$OUT/gdb-exit-status.txt"
if grep -q '^HXL1_ENTRY_BREAKPOINT_HIT ' "$OUT/gdb-session.log"; then
  echo "[ENTRY] BREAKPOINT_HIT (FDT header requires separate verification)"
else
  echo "[ENTRY] INCONCLUSIVE (no verified entry breakpoint)"
fi
echo "[GDB] $OUT/gdb-session.log"
echo "[LIMIT] Read 16 bytes at X0 only; no guest writes or RAM reservations"
