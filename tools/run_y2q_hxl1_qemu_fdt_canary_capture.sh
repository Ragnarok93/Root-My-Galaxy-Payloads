#!/usr/bin/env bash
# Isolated LOCAL QEMU direct-Linux -dtb test, original stock Image unchanged.
# Reads a complete FDT from a paused guest at original boot entry, NO writes.
set -euo pipefail
readonly IMAGE_SHA=ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
readonly ENTRY_PC=0x40080000
readonly FDT_PA=0x48000000
readonly MAX_FDT_LENGTH=8388608
readonly GDB_PORT=12348
readonly TIME_LIMIT=60
KERNEL="$HOME/s20-artifacts/kernel.bin"
CANARY_DIR="$HOME/s20-artifacts/hxl1-research/qemu-memreserve-canary-20261011"
OUT="$HOME/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-20261011"
if (( $# > 0 )); then CANARY_DIR="$1"; fi
if (( $# > 1 )); then OUT="$2"; fi
stop() { echo "[STOP] $*" >&2; exit 2; }
[[ ! -e "$OUT" && ! -L "$OUT" ]] ||
    stop "Output exists: use a fresh directory; preserve prior evidence"
[[ -f "$KERNEL" && ! -L "$KERNEL" ]] || stop "Stock HXL1 kernel missing/symlinked"
[[ -f "$CANARY_DIR/canary-override.dtb" && ! -L "$CANARY_DIR/canary-override.dtb" ]] ||
    stop "Source-only canary FDT missing or symlinked"
[[ -f "$CANARY_DIR/canary-construction.json" && ! -L "$CANARY_DIR/canary-construction.json" ]] ||
    stop "Canary manifest missing or symlinked"
command -v sha256sum >/dev/null || stop "sha256sum unavailable"
printf '%s  %s\n' "$IMAGE_SHA" "$KERNEL" | sha256sum -c --status ||
    stop "Stock kernel SHA256 mismatch"
for tool in python3 qemu-system-aarch64 gdb-multiarch timeout; do
    command -v "$tool" >/dev/null || stop "Missing host dependency: $tool"
done
[[ "$OUT" =~ ^[a-zA-Z0-9_./-]+$ ]] ||
    stop "Output path contains GDB-unsafe characters"
# Verify the byte-exact source, manifest and optional measured reserve.
# The old validator wrongly required reserve=align_up(override totalsize,4KiB);
# explicit measured guest FDT sizes can legitimately reserve more.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
python3 "$SCRIPT_DIR/y2q_hxl1_qemu_fdt_canary.py" \
    --verify-dir "$CANARY_DIR" ||
    stop "Canary FDT manifest/content mismatch"
mkdir -p -- "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
CANARY_DIR="$(cd "$CANARY_DIR" && pwd -P)"
qemu-system-aarch64 --version > "$OUT/qemu-version.txt"
printf '%s\n' "virt,gic-version=3 / cortex-a57 / 1 CPU / 2048MiB / -dtb custom canary" \
    > "$OUT/machine-profile.txt"
sha256sum "$CANARY_DIR/canary-override.dtb" > "$OUT/override-fdt.sha256"
cat > "$OUT/fdt-canary-readonly.gdb" <<EOF
set pagination off
set confirm off
set architecture aarch64
set remotetimeout 8
target remote 127.0.0.1:$GDB_PORT
hbreak *$ENTRY_PC
continue
if \$pc == $ENTRY_PC && \$x0 == $FDT_PA
  printf "HXL1_ENTRY_BREAKPOINT_HIT PC=0x%lx\\n", \$pc
  printf "X0=0x%lx X1=0x%lx X2=0x%lx X3=0x%lx\\n", \$x0, \$x1, \$x2, \$x3
  printf "FDT_HEADER_AT_X0_START\\n"
  x/16bx \$x0
  printf "FDT_HEADER_AT_X0_END\\n"
  set \$fdt_declared = (((unsigned long long)*(unsigned char*)(\$x0+4)) << 24) | (((unsigned long long)*(unsigned char*)(\$x0+5)) << 16) | (((unsigned long long)*(unsigned char*)(\$x0+6)) << 8) | ((unsigned long long)*(unsigned char*)(\$x0+7))
  printf "HXL1_CANARY_GUEST_FDT_DECLARED_BYTES=%llu\\n", \$fdt_declared
  if \$fdt_declared >= 40 && \$fdt_declared <= $MAX_FDT_LENGTH && (\$x0 + \$fdt_declared) <= 0xc0000000
    dump binary memory $OUT/delivered-fdt.dtb \$x0 (\$x0 + \$fdt_declared)
    printf "HXL1_CANARY_DUMP_COMPLETED BYTES=%llu\\n", \$fdt_declared
  else
    printf "HXL1_CANARY_INVALID_FDT_LENGTH=%llu\\n", \$fdt_declared
  end
else
  printf "HXL1_CANARY_ENTRY_MISMATCH PC=0x%lx X0=0x%lx\\n", \$pc, \$x0
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
    -kernel "$KERNEL" -dtb "$CANARY_DIR/canary-override.dtb" \
    -append "earlycon=pl011,0x09000000 console=ttyAMA0 loglevel=8 ignore_loglevel nokaslr" \
    -display none -serial "file:$OUT/serial-console.log" \
    -monitor none -no-reboot -nic none \
    -d int,guest_errors -D "$OUT/qemu-exceptions.log" \
    -S -gdb "tcp:127.0.0.1:$GDB_PORT" \
    > "$OUT/qemu-stdout.log" 2>&1 &
QEMU_PID=$!
sleep 1
kill -0 "$QEMU_PID" 2>/dev/null ||
    stop "QEMU exited before GDB; inspect qemu-stdout.log"
set +e
timeout --signal=INT --kill-after=3s "$TIME_LIMIT"s \
    gdb-multiarch -q -nx -batch -x "$OUT/fdt-canary-readonly.gdb" \
    > "$OUT/gdb-session.log" 2>&1
STATUS=$?
set -e
printf '%s\n' "$STATUS" > "$OUT/gdb-exit-status.txt"
# Validate guest-declared totalsize, actual dump byte count and GDB marker.
# Inserting a 16-byte FDT reserve record can grow a 1MiB DTB beyond 1MiB.
if [[ "$STATUS" -eq 0 ]] && python3 - "$OUT" "$MAX_FDT_LENGTH" <<'PY'
import pathlib,re,struct,sys
p=pathlib.Path(sys.argv[1])
maximum=int(sys.argv[2])
session=(p/"gdb-session.log").read_text(errors="replace")
m=re.findall(r"(?m)^HXL1_CANARY_DUMP_COMPLETED BYTES=(\d+)$",session)
decl=re.findall(r"(?m)^HXL1_CANARY_GUEST_FDT_DECLARED_BYTES=(\d+)$",session)
if len(m)!=1 or len(decl)!=1:raise SystemExit(3)
dump=p/"delivered-fdt.dtb"
if not dump.is_file():raise SystemExit(3)
raw=dump.read_bytes()
if len(raw)<40:raise SystemExit(3)
magic,total=struct.unpack_from(">II",raw)
if not (magic==0xd00dfeed and 40<=total<=maximum and
        len(raw)==total==int(m[0])==int(decl[0])):
    raise SystemExit(3)
print("[GUEST DECLARED FDT BYTES]",total)
PY
then
    sha256sum "$OUT/delivered-fdt.dtb" > "$OUT/delivered-fdt.sha256"
    echo "[CAPTURE] Complete guest-declared FDT read at original entry via custom -dtb"
    echo "[DTB] $OUT/delivered-fdt.dtb"
else
    echo "[INCONCLUSIVE] DTB header totalsize/dump mismatch; see GDB/QEMU logs" >&2
    echo "[GDB] $OUT/gdb-session.log"
    exit 3
fi
echo "[LIMIT] Self-reservation diagnostic only; no UH/RKP pool or memblock proof"
