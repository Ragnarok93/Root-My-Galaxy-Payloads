#!/usr/bin/env python3
"""Read-only Samsung source ZIP inventory, including ZIP-in-ZIP packaging.

Inspects archive metadata and bounded excerpts of kernel Makefiles; optionally
scans nested ZIP/TAR members. No extraction to user-selected directories,
script execution, or modification of supplied source archives.
"""
import argparse
import hashlib
import json
import re
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

IMPORTANT = re.compile(
    r"(^|/)(Makefile|Kbuild|Kconfig|README[^/]*|.*defconfig|"
    r".*\.config|build\.config[^/]*|clang-version|.*\.mk)$",
    re.IGNORECASE,
)
NESTED_TAR = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")
MAX_CANDIDATES = 80
MAX_LISTED = 250
CHUNK_SIZE = 1024 * 1024


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def parse_makefile(contents):
    text = contents.decode("utf-8", "replace")
    pairs = re.findall(
        r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*[:?+]?=\s*(.*)$",
        text, flags=re.MULTILINE,
    )
    return dict(pairs) or None


def is_kernel_makefile(path):
    # A kernel source ZIP may have a source-directory prefix.
    parts = path.lstrip("./").split("/")
    return parts[-1] == "Makefile" and (
        len(parts) == 1 or len(parts) == 2 and parts[0].lower() in ("kernel", "kernel-4.19")
    )


def scan_tar(stream, limit, path_regex=None, max_matched_paths=120):
    """Read TAR metadata; optionally report path-regex matches without extraction."""
    candidates = []
    matched_paths = []
    match_count = 0
    count = 0
    version = None
    truncated = False
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            if count >= limit:
                truncated = True
                break
            count += 1
            if path_regex is not None and path_regex.search(member.name):
                match_count += 1
                if len(matched_paths) < max_matched_paths:
                    matched_paths.append({
                        "path": member.name, "sizeBytes": member.size,
                        "type": "file" if member.isfile() else
                                "directory" if member.isdir() else "other",
                    })
            if not member.isfile():
                continue
            if IMPORTANT.search(member.name):
                if len(candidates) < MAX_CANDIDATES:
                    candidates.append({"path": member.name, "sizeBytes": member.size})
                if is_kernel_makefile(member.name) and member.size <= 64 * 1024:
                    reader = archive.extractfile(member)
                    if reader:
                        version = parse_makefile(reader.read()) or version
    return {
        "membersExamined": count, "limitReached": truncated,
        "versionFromMakefile": version, "importantPaths": candidates,
        "matchedPathCount": match_count, "matchedPaths": matched_paths,
        "matchedPathsTruncated": match_count > len(matched_paths),
    }


def scan_zip(z, depth, args):
    members = z.infolist()
    info = {
        "entries": len(members),
        "totalDeclaredUncompressedBytes": sum(x.file_size for x in members),
        "importantPaths": [],
        "versionFromMakefile": None,
        "nestedArchives": [],
    }
    for member in members:
        if member.is_dir():
            continue
        if IMPORTANT.search(member.filename):
            if len(info["importantPaths"]) < MAX_CANDIDATES:
                info["importantPaths"].append(
                    {"path": member.filename, "sizeBytes": member.file_size}
                )
            if is_kernel_makefile(member.filename) and member.file_size <= 64 * 1024:
                try:
                    info["versionFromMakefile"] = (
                        parse_makefile(z.read(member)) or info["versionFromMakefile"]
                    )
                except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                    pass

        if not args.scan_nested or depth >= args.max_depth:
            continue
        name = member.filename
        lower = name.lower()
        if lower.endswith(".zip"):
            if depth == 0 and args.select_zip_regex and not args.select_zip_regex.search(name):
                continue
            detail = {"name": name, "type": "zip"}
            try:
                if member.file_size > args.max_nested_zip_bytes:
                    detail["scanSkipped"] = "declared size exceeds nested ZIP size limit"
                else:
                    # ZIP readers require seeking. Stage only one nested ZIP at
                    # a time in bounded-memory temporary storage, then delete it.
                    # No archive path is written to or extracted in the source tree.
                    with tempfile.SpooledTemporaryFile(max_size=8 * CHUNK_SIZE) as spool:
                        sha = hashlib.sha256()
                        total = 0
                        with z.open(member) as stream:
                            for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                                total += len(chunk)
                                if total > args.max_nested_zip_bytes:
                                    raise ValueError("nested ZIP decompressed beyond size limit")
                                sha.update(chunk)
                                spool.write(chunk)
                        detail["sizeBytes"] = total
                        detail["sha256"] = sha.hexdigest()
                        spool.seek(0)
                        with zipfile.ZipFile(spool) as child:
                            detail.update(scan_zip(child, depth + 1, args))
            except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile,
                    zipfile.LargeZipFile, NotImplementedError) as error:
                detail["scanError"] = f"{type(error).__name__}: {error}"
            info["nestedArchives"].append(detail)
        elif lower.endswith(NESTED_TAR):
            detail = {"name": name, "type": "tar"}
            try:
                with z.open(member) as stream:
                    detail.update(scan_tar(stream, args.max_tar_members, args.tar_path_regex, args.max_matched_paths))
            except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile,
                    tarfile.TarError, NotImplementedError) as error:
                detail["scanError"] = f"{type(error).__name__}: {error}"
            info["nestedArchives"].append(detail)
    return info


def print_nested(detail, indent=2):
    prefix = " " * indent
    print(prefix + detail["type"].upper() + ":", detail["name"])
    if detail.get("scanSkipped"):
        print(prefix + "  skipped:", detail["scanSkipped"])
    if detail.get("scanError"):
        print(prefix + "  error:", detail["scanError"])
    if detail.get("sha256"):
        print(prefix + "  SHA-256:", detail["sha256"])
    if "entries" in detail:
        print(prefix + "  entries:", detail["entries"])
    if "membersExamined" in detail:
        print(prefix + "  members examined:", detail["membersExamined"],
              "limited:", detail.get("limitReached"))
    if detail.get("versionFromMakefile"):
        print(prefix + "  Makefile kernel version:", detail["versionFromMakefile"])
    for candidate in detail.get("importantPaths", [])[:30]:
        print(prefix + "  candidate:", candidate["path"])
    if detail.get("matchedPaths"):
        print(prefix + "  matched TAR paths:", detail.get("matchedPathCount"),
              "truncated:", detail.get("matchedPathsTruncated"))
        for candidate in detail["matchedPaths"]:
            print(prefix + "    match:", candidate["path"],
                  f"({candidate['sizeBytes']} bytes)")
    for child in detail.get("nestedArchives", []):
        print_nested(child, indent + 2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("--scan-nested", action="store_true",
                        help="Inspect ZIP-in-ZIP contents and nested TAR metadata")
    parser.add_argument("--max-tar-members", type=int, default=20000)
    parser.add_argument("--tar-path-regex",
                        help="Report TAR members matching this regex, even if not Makefiles")
    parser.add_argument("--max-matched-paths", type=int, default=120,
                        help="Maximum matching TAR paths included per TAR in JSON/output")

    parser.add_argument("--max-depth", type=int, default=3,
                        help="Maximum archive nesting level (outer ZIP is level 0)")
    parser.add_argument("--max-nested-zip-mib", type=int, default=512,
                        help="Decompressed size cap per nested ZIP")
    parser.add_argument("--select-zip-regex",
                        help="Only scan outer ZIP's nested ZIPs matching this regex")
    parser.add_argument("--json", type=Path, help="Write a provenance report JSON")
    args = parser.parse_args(argv)
    if not 1 <= args.max_tar_members <= 200000:
        parser.error("--max-tar-members must be between 1 and 200000")
    if not 1 <= args.max_depth <= 6:
        parser.error("--max-depth must be between 1 and 6")
    if not 1 <= args.max_nested_zip_mib <= 2048:
        parser.error("--max-nested-zip-mib must be between 1 and 2048")
    if not 1 <= args.max_matched_paths <= 1000:
        parser.error("--max-matched-paths must be between 1 and 1000")
    if args.tar_path_regex:
        try:
            args.tar_path_regex = re.compile(args.tar_path_regex, re.IGNORECASE)
        except re.error as exc:
            parser.error(f"invalid --tar-path-regex: {exc}")
    args.max_nested_zip_bytes = args.max_nested_zip_mib * 1024 * 1024
    if args.select_zip_regex:
        try:
            args.select_zip_regex = re.compile(args.select_zip_regex, re.IGNORECASE)
        except re.error as exc:
            parser.error(f"invalid --select-zip-regex: {exc}")
    path = args.source_zip
    if not path.is_file() or not zipfile.is_zipfile(path):
        parser.error("Source must be a readable local Samsung ZIP archive")

    with zipfile.ZipFile(path) as archive:
        root = scan_zip(archive, 0, args)
        members = archive.infolist()
    report = {
        "sourceFile": path.name,
        "sizeBytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "entries": root["entries"],
        "totalDeclaredUncompressedBytes": root["totalDeclaredUncompressedBytes"],
        "outerEntries": [
            {"name": x.filename, "sizeBytes": x.file_size,
             "compressedBytes": x.compress_size}
            for x in members[:MAX_LISTED]
        ],
        "outerEntriesTruncated": len(members) > MAX_LISTED,
        "importantPaths": root["importantPaths"],
        "versionFromMakefile": root["versionFromMakefile"],
        "nestedArchives": root["nestedArchives"],
        "notes": [
            "Listing ZIP metadata does not establish member CRC integrity.",
            "An HXL1 token in a source archive name alone does not prove binary correspondence.",
            "Nested ZIPs are temporarily spooled; never extracted persistently.",
            "Limits can truncate TAR traversal or skip oversized ZIPs.",
        ],
    }
    print("Source file:", report["sourceFile"])
    print("Size bytes:", report["sizeBytes"])
    print("SHA-256:", report["sha256"])
    print("Outer ZIP entries:", report["entries"])
    print("Declared uncompressed bytes:", report["totalDeclaredUncompressedBytes"])
    for entry in report["outerEntries"]:
        print("  ZIP:", entry["name"], f"({entry['sizeBytes']} bytes)")
    if report["outerEntriesTruncated"]:
        print("  ...more outer entries omitted")
    for candidate in report["importantPaths"][:30]:
        print("  candidate:", candidate["path"])
    for nested in report["nestedArchives"]:
        print_nested(nested)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Wrote report:", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
