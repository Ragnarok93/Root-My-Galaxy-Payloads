#!/usr/bin/env python3
"""Verify local, read-only Samsung firmware research artifacts against evidence.json."""
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_FILES = {
    "boot.img.lz4": "boot.img.lz4",
    "boot.img": "boot.img",
    "kernel.bin": "kernel.bin",
    "config.gz": "config.gz",
    "ramdisk.img": "ramdisk.img",
    "dtb.img": "dtb.img",
}

def verify_file(path, expected):
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            length += len(block)
    return length == expected["sizeBytes"] and digest.hexdigest() == expected["sha256"]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default="research/y2q-G986U1UESCHXL1/evidence.json")
    parser.add_argument("--files", required=True, help="Folder with the extracted component files")
    args = parser.parse_args()
    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    folder = Path(args.files)
    checked = 0
    for name, filename in EXPECTED_FILES.items():
        path = folder / filename
        if not path.exists():
            print(f"SKIP {filename} (not supplied)")
            continue
        if not verify_file(path, evidence["artifacts"][name]):
            print(f"FAIL {filename}: incorrect size or SHA256")
            return 1
        print(f"PASS {filename}: size and SHA256 match")
        checked += 1
    if checked == 0:
        print("FAIL: no expected input files found")
        return 1
    print(f"Verified {checked} input artifact(s).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
