#!/usr/bin/env bash
# One-command original HXL1 porting evidence pass. Host only. No phone access.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
# Stay on the configured current branch; never merge or reset local work.
git pull --ff-only
export PYTHONDONTWRITEBYTECODE=1
exec python3 tools/y2q_hxl1_porting_automation.py --mode run "$@"
