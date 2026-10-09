#!/usr/bin/env python3
"""Inspect an official Samsung kernel-source ZIP without extracting it.

Reads ZIP metadata, streams SHA-256, and optionally searches nested kernel
tarballs for Makefiles/config/build documentation. Never executes source code,
modifies the source archive, or extracts files.
"""
import argparse
import hashlib
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

IMPORTANT = re.compile(
    r"(^|/)(Makefile|Kbuild|Kconfig|README[^/]*|.*defconfig|"
    r".*\.config|build\.config[^/]*|clang-version|.*\.mk)$",
    re.IGNORECASE,
)
NESTED_TAR = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def scan_tar(stream, limit):
    """Stream nested tar metadata; do not expand files into memory or disk."""
    candidates = []
    count = 0
    truncated = False
    version = None
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        while count < limit:
            member = archive.next()
            if member is None:
                break
            count += 1
            if not member.isfile():
                continue
            name = member.name
            if IMPORTANT.search(name):
                if len(candidates) < 80:
                    candidates.append({"path": name, "sizeBytes": member.size})
                # Only inspect the root kernel Makefile, never execute it.
                if name.lstrip("./") in ("Makefile", "kernel/Makefile") and member.size <= 64 * 1024:
                    source = archive.extractfile(member)
                    if source:
                        text = source.read().decode("utf-8", "replace")
                        m = re.findall(
                            r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*[:?+]?=\s*(.*)$",
                            text, flags=re.MULTILINE,
                        )
                        if m:
                            version = dict(m)
        else:
            truncated = True
    return {"membersExamined": count, "limitReached": truncated,
            "versionFromMakefile": version, "importantPaths": candidates}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source_zip", type=Path)
    p.add_argument("--scan-nested", action="store_true",
                   help="Read nested tar metadata (slower for large archives)")
    p.add_argument("--max-tar-members", type=int, default=20000)
    p.add_argument("--json", type=Path, help="Write a provenance report JSON")
    args = p.parse_args(argv)
    if not 1 <= args.max_tar_members <= 200000:
        p.error("--max-tar-members must be between 1 and 200000")
    path = args.source_zip
    if not path.is_file() or not zipfile.is_zipfile(path):
        p.error("Source must be a readable local Samsung ZIP archive")
    with zipfile.ZipFile(path) as z:
        members = z.infolist()
        report = {
            "sourceFile": path.name,
            "sizeBytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "entries": len(members),
            "totalDeclaredUncompressedBytes": sum(x.file_size for x in members),
            "outerEntries": [
                {"name": x.filename, "sizeBytes": x.file_size,
                 "compressedBytes": x.compress_size}
                for x in members[:250]
            ],
            "outerEntriesTruncated": len(members) > 250,
            "nestedArchives": [],
            "notes": [
                "Listing ZIP metadata does not validate every ZIP entry CRC.",
                "Named firmware match alone does not prove exact kernel-source correspondence.",
                "Nested archive scanning is read-only and limited by --max-tar-members.",
            ],
        }
        if args.scan_nested:
            for member in members:
                if member.is_dir() or not member.filename.lower().endswith(NESTED_TAR):
                    continue
                detail = {"name": member.filename}
                try:
                    with z.open(member) as stream:
                        detail.update(scan_tar(stream, args.max_tar_members))
                except (OSError, EOFError, ValueError, RuntimeError, tarfile.TarError) as error:
                    detail["scanError"] = f"{type(error).__name__}: {error}"
                report["nestedArchives"].append(detail)
    print("Source file:", report["sourceFile"])
    print("Size bytes:", report["sizeBytes"])
    print("SHA-256:", report["sha256"])
    print("Outer ZIP entries:", report["entries"])
    print("Declared uncompressed bytes:", report["totalDeclaredUncompressedBytes"])
    for entry in report["outerEntries"]:
        print("  ZIP:", entry["name"], f"({entry['sizeBytes']} bytes)")
    if report["outerEntriesTruncated"]:
        print("  ...more outer entries omitted")
    for nested in report["nestedArchives"]:
        print("  TAR:", nested["name"], "inspected:", nested.get("membersExamined", 0),
              "truncated:", nested.get("limitReached"), "error:", nested.get("scanError"))
        if nested.get("versionFromMakefile"):
            print("    Makefile version:", nested["versionFromMakefile"])
        for candidate in nested.get("importantPaths", [])[:30]:
            print("    candidate:", candidate["path"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Wrote report:", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
