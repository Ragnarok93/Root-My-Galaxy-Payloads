#!/usr/bin/env python3
"""Audit or enlarge a pinned local REA Ghidra export budget, without running it."""
import argparse
import hashlib
import json
from pathlib import Path

BRIDGE = Path("bridge/ghidra/ReaGhidraBridge.java")
PIN = "ea1b8d2d60d66c8cedba5893dda38fb50c14559d"
REPLACEMENTS = {
    b"private static final int MAX_HIGH_PCODE_OPS = 3000;":
        b"private static final int MAX_HIGH_PCODE_OPS = 12000;",
    b"private static final int MAX_HIGH_PCODE_DEF_USE_EDGES = 12000;":
        b"private static final int MAX_HIGH_PCODE_DEF_USE_EDGES = 48000;",
}

def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def enlarge(data):
    if git_blob_sha(data) != PIN:
        raise ValueError("REA bridge differs from reviewed source; refusing to patch")
    for old, new in REPLACEMENTS.items():
        if data.count(old) != 1:
            raise ValueError("Expected exactly one export-budget declaration")
        data = data.replace(old, new)
    return data

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rea-root", type=Path, default=Path.home()/"src/rea")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    bridge = args.rea_root/BRIDGE
    try:
        if bridge.is_symlink() or not bridge.is_file() or bridge.stat().st_size > 2_000_000:
            raise ValueError("Missing, symlinked or oversized REA bridge")
        before = bridge.read_bytes()
        after = enlarge(before)
        receipt = {"mode": "APPLY" if args.apply else "AUDIT_ONLY",
                   "bridge": str(bridge), "reviewedGitBlobSha": PIN,
                   "beforeSha256": hashlib.sha256(before).hexdigest(),
                   "afterSha256": hashlib.sha256(after).hexdigest(),
                   "operations": 12000, "defUseEdges": 48000,
                   "analysisExecuted": False}
        if args.apply:
            backup = bridge.with_suffix(".java.pre-export-budget")
            with backup.open("xb") as f:
                f.write(before)
            bridge.write_bytes(after)
            receipt["originalBackup"] = str(backup)
        print(json.dumps(receipt, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, f"[STOP] {exc}\n")

if __name__ == "__main__":
    raise SystemExit(main())
