#!/usr/bin/env python3
"""Research-only reconstruction of Samsung SM-G986U1 Android 13 kernel source.

Use the JSON produced by audit_samsung_kernel_layers.py and the *unmodified*
Samsung source wrapper ZIP. Defaults to preflight ONLY; extraction requires an
explicit acceptance of the unverified source-overlay ordering hypothesis.

No phone I/O, no patching of binaries, no KernelSU/root payload, no flashing.
Never extracts Platform.tar.gz. Refuses existing output paths and ZIP/TAR
traversal, and verifies source archive hashes and final overlay file hashes.
"""
import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

BLOCK = 1024 * 1024
GIB = 1024 ** 3
PROFILE_FIRMWARE = "G986U1UESCHXL1"
PROFILE_WRAPPER_SHA256 = "940fe6bbcfe3dcd372ad662dd24b56e0a3ba1a965666b04051fe9941bab4986d"
BASE_ZIP = "SM-G986U_NA_13_Opensource.zip"
MODEL_ZIP = "SM-G986U1_NA_13_Opensource_dts.zip"
MAX_NESTED_ZIP = 512 * BLOCK
MAX_REGULAR_FILE = 256 * BLOCK
MAX_TAR_MEMBERS = 200000
MAX_TOTAL_OUTPUT = 12 * GIB


def sha256_path(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(BLOCK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_source_path(name):
    """Normalize a TAR path; fail closed on path traversal or absolute paths."""
    if not name or "\\" in name or "\x00" in name:
        raise ValueError("unsafe TAR member path")
    if name.startswith("/") or name.startswith("//"):
        raise ValueError("absolute TAR member path")
    raw = PurePosixPath(name)
    if ".." in raw.parts or raw.is_absolute():
        raise ValueError("TAR parent traversal")
    parts = [part for part in raw.parts if part not in (".", "")]
    if parts and parts[0] == "Kernel":
        parts = parts[1:]
    if not parts:
        return None
    return Path(*parts)


def path_within(base, path):
    return path == base or base in path.parents


def check_parent_tree(root, destination):
    if not path_within(root, destination):
        raise ValueError("destination escaped extraction root")
    relative = destination.relative_to(root)
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ValueError("symlink in destination parent chain: " + str(current))
        if current.exists() and not current.is_dir():
            raise ValueError("non-directory in destination parent chain: " + str(current))
        current.mkdir(exist_ok=True)


def ensure_target_slot(path):
    if path.is_symlink() or path.exists():
        if path.is_dir() and not path.is_symlink():
            raise ValueError("source path would replace directory: " + str(path))
        path.unlink()


def valid_symlink_target(root, destination, linkname):
    if not linkname or "\\" in linkname or "\x00" in linkname:
        raise ValueError("unsafe symlink target")
    if PurePosixPath(linkname).is_absolute():
        raise ValueError("absolute symlink target")
    resolved = (destination.parent / linkname).resolve(strict=False)
    if not path_within(root, resolved):
        raise ValueError("symlink target escapes kernel source root")


def valid_hardlink_target(root, linkname):
    relative = normalized_source_path(linkname)
    if relative is None:
        raise ValueError("empty TAR hardlink target")
    return root / relative


def restore_one_tar(root, tar_stream, label, state):
    stats = {"label": label, "entries": 0, "files": 0,
             "directories": 0, "symlinks": 0, "hardlinks": 0,
             "extractedBytes": 0}
    deferred_hardlinks = []
    with tarfile.open(fileobj=tar_stream, mode="r|*") as tar:
        for member in tar:
            stats["entries"] += 1
            if stats["entries"] > MAX_TAR_MEMBERS:
                raise ValueError("TAR member limit exceeded in " + label)
            relative = normalized_source_path(member.name)
            if relative is None:
                continue
            destination = root / relative
            check_parent_tree(root, destination)
            if member.isdir():
                if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
                    raise ValueError("directory replaces non-directory: " + str(relative))
                destination.mkdir(exist_ok=True)
                stats["directories"] += 1
            elif member.isfile():
                if member.size > MAX_REGULAR_FILE:
                    raise ValueError("oversized source member: " + str(relative))
                state["totalBytes"] += member.size
                if state["totalBytes"] > MAX_TOTAL_OUTPUT:
                    raise ValueError("total extracted bytes exceeded")
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError("TAR regular file unreadable: " + str(relative))
                ensure_target_slot(destination)
                # Unlink-before-write above avoids following stale symlinks or
                # mutating another source path through a hardlink.
                with destination.open("xb") as target:
                    shutil.copyfileobj(source, target, BLOCK)
                destination.chmod(member.mode & 0o777)
                stats["files"] += 1
                stats["extractedBytes"] += member.size
            elif member.issym():
                valid_symlink_target(root, destination, member.linkname)
                ensure_target_slot(destination)
                destination.symlink_to(member.linkname)
                stats["symlinks"] += 1
            elif member.islnk():
                target = valid_hardlink_target(root, member.linkname)
                deferred_hardlinks.append((destination, target))
                stats["hardlinks"] += 1
            else:
                raise ValueError("unsupported TAR member type: " + str(relative))
    for destination, target in deferred_hardlinks:
        if not target.is_file() or target.is_symlink():
            raise ValueError("TAR hardlink target missing/not regular: " + str(target))
        check_parent_tree(root, destination)
        ensure_target_slot(destination)
        os.link(target, destination)
    return stats


def read_and_apply_inner_zip(outer, outer_member, package, root, state):
    name = package["name"]
    if outer_member.file_size > MAX_NESTED_ZIP:
        raise ValueError("nested ZIP above 512-MiB cap: " + name)
    with tempfile.SpooledTemporaryFile(max_size=8 * BLOCK) as spool:
        digest = hashlib.sha256()
        total = 0
        with outer.open(outer_member) as input_stream:
            for data in iter(lambda: input_stream.read(BLOCK), b""):
                total += len(data)
                if total > MAX_NESTED_ZIP:
                    raise ValueError("ZIP expanded beyond 512-MiB cap: " + name)
                digest.update(data)
                spool.write(data)
        observed = digest.hexdigest()
        if observed != package["zipSha256"]:
            raise ValueError("inner ZIP checksum mismatch: " + name)
        spool.seek(0)
        report = []
        with zipfile.ZipFile(spool) as nested:
            for tar_member in nested.infolist():
                if tar_member.is_dir() or not tar_member.filename.lower().endswith(
                    (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")
                ):
                    continue
                if name == BASE_ZIP and Path(tar_member.filename).name != "Kernel.tar.gz":
                    continue
                with nested.open(tar_member) as stream:
                    report.append(restore_one_tar(root, stream,
                                                  name + "::" + tar_member.filename,
                                                  state))
        if not report:
            raise ValueError("no eligible kernel TAR archive in " + name)
        return {"package": name, "sha256": observed, "zipSizeBytes": total,
                "tarResults": report}


def preflight(args, audit, wrapper):
    if audit.get("targetFirmware") != PROFILE_FIRMWARE:
        raise ValueError("source audit does not describe exact HXL1 firmware")
    packages = audit.get("sourcePackages", [])
    if len(packages) != 11 or packages[0]["name"] != BASE_ZIP or packages[1]["name"] != MODEL_ZIP:
        raise ValueError("expected base + U1 DTS + nine HXL1 source updates")
    names = [p["name"] for p in packages]
    if len(names) != len(set(names)) or "G986U1UESCHXL1" not in names[-1]:
        raise ValueError("invalid HXL1 archive identity/order")
    if any("HYC1" in n for n in names):
        raise ValueError("HYC1 revisions must not be applied to HXL1")
    if any(not isinstance(p.get("zipSha256"), str)
           or len(p["zipSha256"]) != 64 for p in packages):
        raise ValueError("missing package ZIP digest in source audit")
    if not zipfile.is_zipfile(wrapper):
        raise ValueError("Samsung wrapper is not a ZIP")
    checksum = sha256_path(wrapper)
    if checksum != PROFILE_WRAPPER_SHA256:
        raise ValueError("wrong Samsung source wrapper SHA-256: " + checksum)
    with zipfile.ZipFile(wrapper) as outer:
        members = {m.filename: m for m in outer.infolist() if not m.is_dir()}
        if not all(name in members for name in names):
            raise ValueError("missing selected source ZIP in Samsung wrapper")
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink() or output == Path("/"):
        raise ValueError("output already exists or is invalid: " + str(output))
    if args.assemble_experimental:
        if not output.parent.is_dir() or output.parent.is_symlink():
            raise ValueError("create a regular output parent directory first")
        if output.as_posix().startswith("/mnt/"):
            raise ValueError("assemble under the Linux WSL filesystem (~), not /mnt/ drive mounts")
        free = shutil.disk_usage(output.parent).free
        if free < 3 * GIB:
            raise ValueError("under 3 GiB free on source filesystem; need scratch room")
    return {
        "targetFirmware": PROFILE_FIRMWARE,
        "wrapperSha256": checksum,
        "selectedSourceArchives": names,
        "assumedOrder": "Samsung ZIP listing order through HXL1, not independently documented by README",
        "proposedOutput": str(output),
        "assembleRequested": bool(args.assemble_experimental),
    }


def validate_final_overlays(root, audit):
    expected = audit.get("finalSourceProvenance")
    if not isinstance(expected, dict) or len(expected) != 40:
        raise ValueError("source audit must contain exactly 40 final file origins")
    errors = []
    for name, record in expected.items():
        relative = normalized_source_path(name)
        if relative is None:
            errors.append({"path": name, "error": "invalid path"})
            continue
        path = root / relative
        if not path.is_file() or path.is_symlink():
            errors.append({"path": name, "error": "missing / not a regular file"})
            continue
        if record.get("sha256") is None:
            errors.append({"path": name, "error": "audit lacked file hash"})
            continue
        observed = sha256_path(path)
        if observed != record["sha256"]:
            errors.append({"path": name, "error": "checksum mismatch",
                           "actual": observed, "expected": record["sha256"]})
    if errors:
        raise ValueError("assembled overlay validation failed: " + json.dumps(errors[:8]))
    return {"verifiedFinalOverlayFiles": len(expected), "errors": 0}


def run(args):
    audit = json.loads(args.audit_json.read_text(encoding="utf-8"))
    wrapper = args.source_zip.expanduser().absolute()
    result = preflight(args, audit, wrapper)
    if not args.assemble_experimental:
        return result
    root = args.output.expanduser().absolute()
    # Never touch pre-existing output. Build a private staging directory
    # alongside final output, then atomically rename upon full validation.
    staging = Path(tempfile.mkdtemp(prefix=".s20-hxl1-stage-", dir=root.parent))
    layer_stats = []
    try:
        with zipfile.ZipFile(wrapper) as outer:
            by_name = {m.filename: m for m in outer.infolist() if not m.is_dir()}
            state = {"totalBytes": 0}
            for package in audit["sourcePackages"]:
                label = package["name"]
                print("Restoring stock source layer:", label, flush=True)
                layer_stats.append(read_and_apply_inner_zip(
                    outer, by_name[label], package, staging, state
                ))
        verification = validate_final_overlays(staging, audit)
        # The source tree may contain safe symlinks. Do not follow them while
        # selecting or overwriting extraction destinations.
        manifest = {
            **result, "layerStats": layer_stats,
            "totalWrittenRegularBytesIncludingOverwrites": state["totalBytes"],
            "finalFileVerification": verification,
            "status": "research-only HXL1 stock source reconstruction; build/boot unverified",
        }
        # Keep manifest outside kernel source so no additional source files
        # can affect the kernel build or config.
        manifest_path = root.with_name(root.name + ".source-manifest.json")
        if manifest_path.exists() or manifest_path.is_symlink():
            raise ValueError("source manifest already exists: " + str(manifest_path))
        staging.rename(root)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print("Assembled candidate source tree:", root)
        print("Verified final overlay source files:", verification["verifiedFinalOverlayFiles"])
        print("PROVENANCE NOTE: ZIP listing order is a reconstruction assumption.")
        print("NOT a signed or flashable image; no kernel compiled yet.")
        return manifest
    except Exception:
        # Refuse silent cleanup of partial source data; preserving it is
        # valuable for diagnosing malformed archives. Operator may delete
        # this staging directory explicitly after inspection.
        print("Extraction interrupted; inspect/remove stage manually:", staging,
              file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--assemble-experimental", action="store_true",
                        help="Opt into off-device stock source assembly using unconfirmed overlay ordering")
    parser.add_argument("--json", type=Path, help="Save dry-run verification report")
    args = parser.parse_args()
    try:
        report = run(args)
    except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.error(str(error))
    print("Target:", report["targetFirmware"])
    print("Samsung source wrapper SHA-256:", report["wrapperSha256"])
    print("Selected source layers:", len(report["selectedSourceArchives"]))
    for name in report["selectedSourceArchives"]:
        print("  ", name)
    print("Proposed output:", report["proposedOutput"])
    print("Assumption:", report["assumedOrder"])
    print("Mode:", "ASSEMBLED, OFF-DEVICE" if args.assemble_experimental else "PREFLIGHT ONLY")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Saved:", args.json)


if __name__ == "__main__":
    main()
