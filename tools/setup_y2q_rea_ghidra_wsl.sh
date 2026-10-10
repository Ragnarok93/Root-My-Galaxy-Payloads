#!/usr/bin/env bash
# Resolve the exact Ghidra prerequisite for the verified HXL1 LinuxLoader.
# Diagnose by default; --install opts in to official release + Ubuntu full JDK.
# This script never executes firmware, uses ADB, or modifies Samsung partitions.
set -euo pipefail
MODE=diagnose
if [[ "$#" -ne 0 ]]; then
  if [[ "$#" -eq 1 && "$1" == "--install" ]]; then
    MODE=install
  else
    echo "Usage: bash tools/setup_y2q_rea_ghidra_wsl.sh [--install]" >&2
    exit 2
  fi
fi

OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
REA="$HOME/src/rea"
VERSION=12.1.4
ZIP=ghidra_12.1.4_PUBLIC_20260921.zip
GHIDRA_SHA=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/$ZIP"
TARGET="$HOME/opt/ghidra_12.1.4_PUBLIC"
ARCHIVE="$HOME/s20-artifacts/hxl1-research/official-downloads/$ZIP"
mkdir -p "$OUT"

if [[ "$(uname -s)" != Linux || ! -f "$REA/scripts/rea.mjs" ]]; then
  echo "[STOP] Requires Ubuntu/WSL2 with existing Ragnarok93/rea checkout" >&2
  exit 2
fi
if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
if ! node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0:1)'; then
  echo "[STOP] Native Linux Node 24 unavailable; REA bootstrap must succeed first" >&2
  exit 2
fi
if [[ -f "$OUT/rea-ghidra-doctor.json" ]]; then
  echo "[EXISTING REA DOCTOR] $OUT/rea-ghidra-doctor.json"
  python3 - "$OUT/rea-ghidra-doctor.json" <<'PY'
import json,sys
try: doc=json.load(open(sys.argv[1]))
except (ValueError,OSError) as e: print("[NOTE] Doctor file not JSON:",str(e))
else: print(json.dumps(doc,indent=2)[:4500])
PY
fi

echo "=== Find existing Linux Ghidra 12.1.x ==="
candidate=""
if [[ -n "$GHIDRA_INSTALL_DIR" ]] 2>/dev/null && [[ -f "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]]; then
  candidate="$GHIDRA_INSTALL_DIR"
elif [[ -f "$TARGET/support/analyzeHeadless" ]]; then
  candidate="$TARGET"
else
  for parent in "$HOME/opt" "$HOME/tools" "$HOME/src" /opt; do
    [[ -d "$parent" ]] || continue
    while IFS= read -r dir; do
      if [[ -f "$dir/support/analyzeHeadless" ]]; then
        candidate="$dir"
        break
      fi
    done < <(find "$parent" -maxdepth 2 -type d -name 'ghidra_12.1.*_PUBLIC' 2>/dev/null)
    [[ -z "$candidate" ]] || break
  done
fi

echo "=== Locate a compatible full Linux JDK ==="
java_home=""
for dir in /usr/lib/jvm/java-21-openjdk-amd64 /usr/lib/jvm/java-25-openjdk-amd64; do
  if [[ -f "$dir/bin/java" && -f "$dir/bin/javac" ]]; then java_home="$dir"; break; fi
done
if [[ -z "$java_home" ]] && command -v javac >/dev/null 2>&1; then
  current_home="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
  if [[ -f "$current_home/bin/java" ]]; then java_home="$current_home"; fi
fi
has_jdk=false
if [[ -n "$java_home" ]]; then
  version="$("$java_home/bin/javac" -version 2>&1 | sed -nE 's/^javac ([0-9]+).*/\1/p')"
  if [[ "$version" =~ ^[0-9]+$ ]] && ((version >= 21)); then
    has_jdk=true
    echo "[FOUND] Full JDK $version at $java_home"
  fi
fi
if [[ "$has_jdk" != true && "$MODE" == install ]]; then
  echo "[INSTALL] Ubuntu OpenJDK 21 full JDK; sudo may ask for password"
  sudo apt-get update
  sudo apt-get install -y openjdk-21-jdk
  java_home=/usr/lib/jvm/java-21-openjdk-amd64
  if [[ ! -f "$java_home/bin/javac" ]]; then
    echo "[STOP] JDK 21 not found after apt installation" >&2; exit 2
  fi
  has_jdk=true
fi
if [[ "$has_jdk" != true ]]; then
  echo "[BLOCKED] Full Linux JDK >=21 not detected"
  echo "  sudo apt-get update && sudo apt-get install -y openjdk-21-jdk"
fi

if [[ -z "$candidate" && "$MODE" == install ]]; then
  echo "=== Download official Ghidra 12.1.4, SHA256 pin ==="
  mkdir -p "$(dirname "$ARCHIVE")" "$(dirname "$TARGET")"
  if [[ -f "$ARCHIVE" ]]; then
    if ! echo "$GHIDRA_SHA  $ARCHIVE" | sha256sum -c --status; then
      echo "[STOP] Existing archive checksum disagrees with official release" >&2; exit 2
    fi
  else
    partial="$ARCHIVE.partial"
    if [[ -e "$partial" ]]; then
      echo "[STOP] Existing interrupted download $partial; inspect it before retrying" >&2; exit 2
    fi
    curl --fail --location --retry 3 --output "$partial" "$URL"
    if ! echo "$GHIDRA_SHA  $partial" | sha256sum -c --status; then
      echo "[STOP] Official Ghidra archive digest mismatch" >&2; exit 2
    fi
    mv "$partial" "$ARCHIVE"
  fi
  echo "[PASS] Official GitHub release archive SHA256 matched"
  if [[ -e "$TARGET" ]]; then
    echo "[STOP] Refusing to overwrite existing target $TARGET" >&2; exit 2
  fi
  python3 - "$ARCHIVE" "$(dirname "$TARGET")" "$(basename "$TARGET")" <<'PY'
from pathlib import Path, PurePosixPath
import stat,sys,zipfile
archive=Path(sys.argv[1])
parent=Path(sys.argv[2]).resolve()
expected=sys.argv[3]
with zipfile.ZipFile(archive) as z:
    infos=z.infolist()
    if not infos: raise SystemExit("[STOP] Empty release archive")
    for info in infos:
        path=PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0]!=expected:
            raise SystemExit("[STOP] Unexpected ZIP path: "+info.filename)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise SystemExit("[STOP] ZIP symlink: "+info.filename)
    z.extractall(parent)
print("[PASS] Extracted official release into",parent/expected)
PY
  candidate="$TARGET"
fi

if [[ -z "$candidate" ]]; then
  echo "[BLOCKED] No compatible local Linux Ghidra found."
  echo "Run with --install for pinned official Ghidra 12.1.4 (~543 MiB zip)."
  exit 2
fi
if [[ ! -f "$candidate/support/analyzeHeadless" || ! -f "$candidate/Ghidra/application.properties" ]]; then
  echo "[STOP] Incomplete Ghidra installation: $candidate" >&2; exit 2
fi
if ! grep -Eq '^application.version[[:space:]]*=[[:space:]]*12\.1\.' "$candidate/Ghidra/application.properties"; then
  echo "[STOP] Selected Ghidra is not 12.1.x; inspect $candidate" >&2; exit 2
fi

export GHIDRA_INSTALL_DIR="$candidate"
if [[ "$has_jdk" == true ]]; then
  export JAVA_HOME="$java_home"
  export PATH="$JAVA_HOME/bin:$PATH"
fi
ENV_FILE="$OUT/rea-ghidra-env.sh"
printf 'export GHIDRA_INSTALL_DIR=%q\n' "$GHIDRA_INSTALL_DIR" > "$ENV_FILE"
if [[ -n "$java_home" && "$has_jdk" == true ]]; then
  printf 'export JAVA_HOME=%q\n' "$JAVA_HOME" >> "$ENV_FILE"
  echo 'export PATH="$JAVA_HOME/bin:$PATH"' >> "$ENV_FILE"
fi
echo "[GHIDRA] $GHIDRA_INSTALL_DIR"
echo "[JDK] $java_home"
echo "=== REA fork Ghidra provider doctor (authoritative) ==="
cd "$REA"
if node scripts/rea.mjs doctor --provider ghidra --json \
  > "$OUT/rea-ghidra-doctor.json" \
  2> "$OUT/rea-ghidra-doctor-errors.txt"; then
  echo "[PASS] Ghidra provider doctor succeeded"
else
  echo "[BLOCKED] Ghidra provider still reports a prerequisite/compatibility issue"
  echo "[DOCTOR] $OUT/rea-ghidra-doctor.json"
  echo "[STDERR] $OUT/rea-ghidra-doctor-errors.txt"
  exit 2
fi
echo "[NEXT] cd ~/src/Root-My-Galaxy-Payloads && bash tools/analyze_y2q_hxl1_linuxloader_rea.sh"
