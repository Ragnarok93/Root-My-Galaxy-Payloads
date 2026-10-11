#!/usr/bin/env bash
# Bounded, host-only original HXL1 secure-monitor-call breakpoint capture.
# Output path may be given as argument 1; the default will never overwrite.
set -euo pipefail
EXPECT_SHA=ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
SMC_PC=0xffffff80080a5794
KERNEL="$HOME/s20-artifacts/kernel.bin"
OUT="$HOME/s20-artifacts/hxl1-research/qemu-smc-registers-20261011"
if (( $# > 0 )); then OUT="$1"; fi
PORT=12345
MAX_SECONDS=30

fail() { printf '[STOP] %s\n' "$*" >&2; exit 2; }
[[ ! -e $OUT && ! -L $OUT ]] || fail "Output exists. Pass a fresh output directory as the first argument"
[[ -f $KERNEL && ! -L $KERNEL ]] || fail "Original kernel missing or symlinked"
for tool in qemu-system-aarch64 gdb-multiarch sha256sum timeout; do
  command -v "$tool" >/dev/null || fail "Required host tool missing: $tool"
done
printf '%s  %s\n' "$EXPECT_SHA" "$KERNEL" | sha256sum -c --status ||
  fail "Original HXL1 kernel SHA256 mismatch"

mkdir -p -- "$OUT"
cat > "$OUT/break-on-original-smc.gdb" <<EOF
set pagination off
set confirm off
set architecture aarch64
set remotetimeout 5
target remote 127.0.0.1:$PORT
hbreak *$SMC_PC
continue
if \$pc == $SMC_PC
  printf "HXL1_SMC_BREAKPOINT_HIT PC=0x%lx\\n", \$pc
  printf "X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", \$x0, \$x1, \$x2, \$x3
  printf "X4=0x%lx X5=0x%lx X6=0x%lx\\n", \$x4, \$x5, \$x6
  x/1wx \$pc
else
  printf "HXL1_SMC_OTHER_STOP PC=0x%lx\\n", \$pc
end
detach
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
printf '[INPUT] Original SHA-pinned HXL1 Image; only emulated RAM is touched\n'
printf '[TARGET] SMC #0 at %s\n' "$SMC_PC"
printf '[OUTPUT] %s\n' "$OUT"

qemu-system-aarch64 \
  -machine virt,gic-version=3 \
  -cpu cortex-a57 -smp 1 -m 2048 \
  -kernel "$KERNEL" \
  -append "earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr" \
  -display none -serial "file:$OUT/serial-console.log" -monitor none \
  -no-reboot -nic none \
  -d "int,guest_errors" -D "$OUT/qemu-exceptions.log" \
  -S -gdb "tcp:127.0.0.1:$PORT" \
  > "$OUT/qemu-stdout.log" 2>&1 &
QEMU_PID=$!
sleep 1
if ! kill -0 "$QEMU_PID" 2>/dev/null; then
  fail "QEMU exited before debugger connection; inspect qemu-stdout.log"
fi

set +e
timeout --signal=INT --kill-after=3s "$MAX_SECONDS"s \
  gdb-multiarch -q -nx -batch -x "$OUT/break-on-original-smc.gdb" \
  > "$OUT/gdb-session.log" 2>&1
GDB_STATUS=$?
set -e
printf '%s\n' "$GDB_STATUS" > "$OUT/gdb-exit-status.txt"
if grep -q '^HXL1_SMC_BREAKPOINT_HIT ' "$OUT/gdb-session.log"; then
  echo "[PASS] GDB stopped at original HXL1 SMC callsite; X0..X6 captured"
elif [[ $GDB_STATUS -eq 124 || $GDB_STATUS -eq 137 ]]; then
  echo "[INCONCLUSIVE] GDB timed out without a verified SMC breakpoint"
else
  echo "[INCONCLUSIVE] GDB did not verify the callsite; inspect logs"
fi
echo "[GDB]" "$OUT/gdb-session.log"
echo "[EXCEPTIONS]" "$OUT/qemu-exceptions.log"
echo "[LIMIT] No kernel boot, UH ABI compatibility, root or KernelSU inferred"
