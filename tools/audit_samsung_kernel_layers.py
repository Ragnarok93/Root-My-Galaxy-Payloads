#!/usr/bin/env python3
"""Audit Samsung's SM-G986U Android 13 kernel source layers without extraction.

Reads an outer Samsung ZIP containing a base source ZIP, U1 device-source ZIP,
and incremental revision ZIPs. Reports selected kernel Makefile, matching
defconfigs and source-file override provenance through a named target build.
Reads all compressed data from owner-provided archives, never executes source.
"""
import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

BLOCK = 1024 * 1024
BASE = "SM-G986U_NA_13_Opensource.zip"
U1 = "SM-G986U1_NA_13_Opensource_dts.zip"
CONFIG_SOURCE_PATHS = {
    "Makefile",
    "arch/arm64/configs/vendor/y2q_usa_singlew_defconfig",
    "arch/arm64/configs/vendor/y2q_usa_openw_defconfig",
}
MAX_FILE_SIZE = 4 * BLOCK
MAX_OVERLAY_FILES = 1500


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def relative_name(name):
    path = name.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if path.startswith("Kernel/"):
        path = path[7:]
    if not path or path.startswith("/") or ".." in path.split("/"):
        return None
    return path


def read_nested_zip(parent, member):
    # ZIP requires seeking, so use bounded memory with a tempfile fallback.
    if member.file_size > 512 * BLOCK:
        raise ValueError("nested ZIP is larger than the 512 MiB safety limit")
    with tempfile.SpooledTemporaryFile(max_size=8 * BLOCK) as spool:
        digest = hashlib.sha256()
        total = 0
        with parent.open(member) as stream:
            for data in iter(lambda: stream.read(BLOCK), b""):
                total += len(data)
                if total > 512 * BLOCK:
                    raise ValueError("nested ZIP exceeds safety limit during reading")
                spool.write(data)
                digest.update(data)
        spool.seek(0)
        with zipfile.ZipFile(spool) as nested:
            yield_summary = process_inner_zip(nested, member.filename)
        yield_summary["zipSha256"] = digest.hexdigest()
        yield_summary["zipSizeBytes"] = total
        return yield_summary


def makefile_version(data):
    text = data.decode("utf-8", "replace")
    match = re.findall(
        r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*[:?+]?=\s*(.*)$",
        text, flags=re.MULTILINE,
    )
    return dict(match)


def config_values(data):
    assignments = {}
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            assignments[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2:-len(" is not set")]
            assignments[key] = "n"
    return assignments


def process_inner_zip(archive, zip_name):
    # Do not scan Platform.tar.gz: it is not a kernel source input.
    entries = archive.infolist()
    summary = {
        "name": zip_name,
        "entries": len(entries),
        "tarFiles": [],
        "sourceFiles": {},
        "selectedSourceText": {},
        "memberCount": 0,
        "skippedNonRegular": 0,
    }
    is_base = zip_name == BASE
    is_u1 = zip_name == U1
    for entry in entries:
        if not entry.filename.lower().endswith((".tar", ".tar.gz", ".tgz", ".tar.xz")):
            continue
        if is_base and Path(entry.filename).name != "Kernel.tar.gz":
            continue
        summary["tarFiles"].append(entry.filename)
        with archive.open(entry) as stream:
            with tarfile.open(fileobj=stream, mode="r|*") as tar:
                for member in tar:
                    summary["memberCount"] += 1
                    if not member.isfile():
                        summary["skippedNonRegular"] += 1
                        continue
                    name = relative_name(member.name)
                    if name is None:
                        continue
                    if is_base or is_u1:
                        if name not in CONFIG_SOURCE_PATHS:
                            continue
                        if member.size > MAX_FILE_SIZE:
                            summary["selectedSourceText"][name] = {"error": "oversized"}
                            continue
                        fileobj = tar.extractfile(member)
                        if fileobj is None:
                            continue
                        data = fileobj.read()
                        summary["selectedSourceText"][name] = {
                            "sha256": sha256_bytes(data),
                            "sizeBytes": len(data),
                            "kernelVersion": makefile_version(data) if name == "Makefile" else None,
                            "configValues": config_values(data) if name.endswith("defconfig") else None,
                        }
                    else:
                        # Incremental overlays are small; only hash regular files.
                        # Avoid large or untrusted payloads.
                        if len(summary["sourceFiles"]) >= MAX_OVERLAY_FILES:
                            raise ValueError("overlay has too many source files")
                        if member.size > MAX_FILE_SIZE:
                            summary["sourceFiles"][name] = {"sizeBytes": member.size, "sha256": None,
                                                            "note": "oversized; not hashed"}
                            continue
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        digest = hashlib.sha256()
                        for data in iter(lambda: f.read(BLOCK), b""):
                            digest.update(data)
                        summary["sourceFiles"][name] = {
                            "sizeBytes": member.size,
                            "sha256": digest.hexdigest(),
                        }
    return summary


def compare_config(source, observed, sample_limit):
    common = set(source) & set(observed)
    diffs = [
        {"symbol": k, "source": source[k], "device": observed[k]}
        for k in sorted(common) if source[k] != observed[k]
    ]
    missing = sorted(set(source) - set(observed))
    return {
        "sourceSymbols": len(source),
        "deviceSymbols": len(observed),
        "matchingExplicitSymbols": len(common) - len(diffs),
        "differentExplicitSymbols": len(diffs),
        "sourceSymbolsAbsentFromDevice": len(missing),
        "differentExamples": diffs[:sample_limit],
        "absentExamples": missing[:sample_limit],
        "note": "Differences do not establish build mismatch: defconfig precedes Kconfig defaults, symbol dependencies and Samsung generated configuration.",
    }


def run(args):
    archive_path = Path(args.source_zip)
    if not zipfile.is_zipfile(archive_path):
        raise ValueError("not a ZIP archive")
    with zipfile.ZipFile(archive_path) as outer:
        members = {m.filename: m for m in outer.infolist() if not m.is_dir()}
        versions = [n for n in members if n.startswith("SM-G986U_13_Opensource_")
                    and n.endswith(".zip")]
        targets = [n for n in versions if args.target_firmware in n]
        if len(targets) != 1:
            raise ValueError(f"expected exactly one source update for {args.target_firmware}; found {targets}")
        target = targets[0]
        if BASE not in members or U1 not in members:
            raise ValueError("Samsung base ZIP or U1-specific DTS ZIP missing")
        # Vendor ZIP's ordering is recorded rather than silently inferred
        # from lexical package names. Never include revisions after HXL1.
        overlays = versions[:versions.index(target) + 1]
        selected_names = [BASE, U1] + overlays
        packages = [read_nested_zip(outer, members[name]) for name in selected_names]
    by_name = {p["name"]: p for p in packages}
    changes = {}
    stage_summary = []
    for stage in overlays:
        files = by_name[stage]["sourceFiles"]
        newly_seen = 0
        overwritten = 0
        different = 0
        for name, data in files.items():
            previous = changes.get(name)
            if previous is None:
                newly_seen += 1
            else:
                overwritten += 1
                if previous["sha256"] != data["sha256"]:
                    different += 1
            changes[name] = {"source": stage, "sha256": data["sha256"],
                             "sizeBytes": data["sizeBytes"]}
        stage_summary.append({
            "archive": stage,
            "regularSourceFiles": len(files),
            "newSincePreviousLayers": newly_seen,
            "pathsOverridingPreviousLayer": overwritten,
            "contentDifferentWhenOverridden": different,
        })
    final_layer = by_name[target]
    earlier_only = sorted(set(changes) - set(final_layer["sourceFiles"]))

    source_configs = {}
    for package in (by_name[BASE], by_name[U1]):
        for name, data in package["selectedSourceText"].items():
            if name.endswith("defconfig") and data.get("configValues"):
                source_configs[name] = data["configValues"]
    config_comparisons = {}
    if args.device_config_gz:
        device_config = config_values(gzip.decompress(Path(args.device_config_gz).read_bytes()))
        if not device_config:
            raise ValueError("provided kernel config.gz has no CONFIG_* assignments")
        config_comparisons = {
            name: compare_config(values, device_config, args.sample_limit)
            for name, values in source_configs.items()
        }
    report = {
        "targetFirmware": args.target_firmware,
        "selectedTargetArchive": target,
        "sourceLayeringAssumption": "Base + model-specific DTS + updates in Samsung wrapper listing order through target; ordering must be validated from README/build provenance before assembling source.",
        "sourcePackages": [
            {"name": p["name"], "zipSha256": p["zipSha256"],
             "zipSizeBytes": p["zipSizeBytes"], "entries": p["entries"],
             "tarFiles": p["tarFiles"], "tarMemberCount": p["memberCount"],
             "selectedSourceText": {name: {k: v for k, v in entry.items() if k != "configValues"}
                                    for name, entry in p["selectedSourceText"].items()}}
            for p in packages
        ],
        "overlayStages": stage_summary,
        "uniqueOverlaySourcePaths": len(changes),
        "earlierSourcePathsNotInHXL1Update": len(earlier_only),
        "earlierOnlyExamples": earlier_only[:args.sample_limit],
        "finalSourceProvenance": changes,
        "configComparisons": config_comparisons,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("--target-firmware", default="G986U1UESCHXL1")
    parser.add_argument("--device-config-gz", type=Path)
    parser.add_argument("--json", type=Path, help="Save structured provenance report")
    parser.add_argument("--sample-limit", type=int, default=20)
    args = parser.parse_args(argv)
    if not 1 <= args.sample_limit <= 200:
        parser.error("--sample-limit must be 1..200")
    try:
        report = run(args)
    except (OSError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile,
            tarfile.TarError, gzip.BadGzipFile) as exc:
        parser.error(f"source audit failed: {exc}")
    print("Target:", report["targetFirmware"])
    print("Matched update:", report["selectedTargetArchive"])
    print("Selected ZIPs:", len(report["sourcePackages"]))
    for p in report["sourcePackages"]:
        print("  ZIP:", p["name"], "SHA256:", p["zipSha256"],
              "TAR members:", p["tarMemberCount"])
        for path, selected in p["selectedSourceText"].items():
            print("    source:", path, "SHA256:", selected.get("sha256"))
            if selected.get("kernelVersion"):
                print("      kernel Makefile:", selected["kernelVersion"])
    for stage in report["overlayStages"]:
        print("  UPDATE:", stage["archive"])
        print("    files:", stage["regularSourceFiles"],
              "new paths:", stage["newSincePreviousLayers"],
              "overridden paths:", stage["pathsOverridingPreviousLayer"])
    print("Unique firmware-update paths through HXL1:", report["uniqueOverlaySourcePaths"])
    print("Earlier updates contain paths absent from HXL1:",
          report["earlierSourcePathsNotInHXL1Update"])
    for name, cmp in report["configComparisons"].items():
        print("  CONFIG:", name, "explicit matching:", cmp["matchingExplicitSymbols"],
              "different:", cmp["differentExplicitSymbols"],
              "missing in running:", cmp["sourceSymbolsAbsentFromDevice"])
        for entry in cmp["differentExamples"]:
            print("    DIFFERENCE", entry["symbol"],
                  "source:", entry["source"], "running:", entry["device"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Saved JSON:", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
