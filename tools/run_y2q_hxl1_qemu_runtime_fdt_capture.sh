#!/usr/bin/env bash
# Host-only read-only FULL runtime FDT snapshot at original HXL1 kernel entry.
set -euo pipefail
readonly IMAGE_SHA=ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
readonly ENTRY_PC=0x40080000
readonly GUEST_X0=0x48000000
readonly FDT_BYTES=1048576
readonly GDB_PORT=12347
readonly TIME_LIMIT=60
KERNEL="$HOME/s20-artifacts/kernel.bin"
OUT="$HOME/s20-artifacts/hxl1-research/qemu-runtime-fdt-20261011"
if (( $# > 0 )); then OUT="$1"; fi
stop() { echo "[STOP] $*" >&2; exit 2; }
[[ ! -e "$OUT" && ! -L "$OUT" ]] ||
    stop "Output path already exists; use a fresh output directory"
[[ -f "$KERNEL" && ! -L "$KERNEL" ]] ||
    stop "Original HXL1 Image missing or symlinked"
command -v sha256sum >/dev/null || stop "sha256sum unavailable"
printf '%s  %s\n' "$IMAGE_SHA" "$KERNEL" | sha256sum -c --status ||
    stop "Original HXL1 Image SHA mismatch"
for program in qemu-system-aarch64 gdb-multiarch timeout; do
    command -v "$program" >/dev/null || stop "Host tool missing: $program"
done
# GDB command files require a safe absolute output filename.
[[ "$OUT" =~ ^[a-zA-Z0-9_./-]+$ ]] ||
    stop "Output dir accepts only letters, digits, underscore, slash, dot, hyphen"
mkdir -p -- "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
qemu-system-aarch64 --version > "$OUT/qemu-version.txt"
printf '%s\n' \
    "virt,gic-version=3 / cortex-a57 / smp=1 / ram=2048MiB" \
    > "$OUT/machine-profile.txt"
cat > "$OUT/runtime-fdt-readonly.gdb" <<EOF
set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:$GDB_PORT
hbreak *$ENTRY_PC
continue
if \$pc == $ENTRY_PC && \$x0 == $GUEST_X0
  printf "HXL1_RUNTIME_FDT_BREAKPOINT_HIT PC=0x%lx X0=0x%lx\\n", \$pc, \$x0
  printf "HXL1_RUNTIME_FDT_HEADER_START\\n"
  x/16bx \$x0
  printf "HXL1_RUNTIME_FDT_HEADER_END\\n"
  dump binary memory $OUT/runtime-fdt.dtb \$x0 (\$x0 + $FDT_BYTES)
  printf "HXL1_RUNTIME_FDT_DUMP_COMPLETED BYTES=$FDT_BYTES\\n"
else
  printf "HXL1_RUNTIME_FDT_BREAKPOINT_MISMATCH PC=0x%lx X0=0x%lx\\n", \$pc, \$x0
end
quit
EOF

QEMU_PID=''
cleanup() {
    if [[ -n "$QEMU_PID" ]]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

qemu-system-aarch64 \
  -machine virt,gic-version=3 -cpu cortex-a57 -smp 1 -m 2048 \
  -kernel "$KERNEL" \
  -append "earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr" \
  -display none -serial "file:$OUT/serial-console.log" \
  -monitor none -no-reboot -nic none \
  -d int,guest_errors -D "$OUT/qemu-exceptions.log" \
  -S -gdb "tcp:127.0.0.1:$GDB_PORT" \
  > "$OUT/qemu-stdout.log" 2>&1 &
QEMU_PID=$!
sleep 1
kill -0 "$QEMU_PID" 2>/dev/null ||
    stop "QEMU terminated before GDB connected; inspect qemu-stdout.log"

set +e
timeout --signal=INT --kill-after=3s "$TIME_LIMIT"s \
  gdb-multiarch -q -nx -batch -x "$OUT/runtime-fdt-readonly.gdb" \
  > "$OUT/gdb-session.log" 2>&1
GDB_STATUS=$?
set -e
printf '%s\n' "$GDB_STATUS" > "$OUT/gdb-exit-status.txt"
if grep -q '^HXL1_RUNTIME_FDT_DUMP_COMPLETED BYTES=1048576$' \
    "$OUT/gdb-session.log" &&
   [[ -f "$OUT/runtime-fdt.dtb" ]] &&
   [[ "$(stat -c %s "$OUT/runtime-fdt.dtb")" = "$FDT_BYTES" ]]; then
    sha256sum "$OUT/runtime-fdt.dtb" > "$OUT/runtime-fdt.sha256"
    echo "[CAPTURED] Complete 1MiB runtime FDT read from paused guest memory"
    echo "[FDT] $OUT/runtime-fdt.dtb"
else
    echo "[INCONCLUSIVE] Incomplete/unavailable FDT; inspect GDB log; preserve output" >&2
    echo "[GDB] $OUT/gdb-session.log"
    exit 3
fi
echo "[LIMIT] QEMU guest read-only; no protected pool, guest write, root or KernelSU"
