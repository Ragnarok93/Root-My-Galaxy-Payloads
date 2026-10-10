#!/usr/bin/env python3
"""Repair execute permissions lost to zipfile.extractall on official Ghidra.

The exact official release archive must match its pinned SHA256; every repaired
installed file must be byte-identical to the corresponding ZIP member.
Only install-tree permissions change; no firmware code is executed or modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

PINNED_SHA = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
ZIP_NAME = "ghidra_12.1.4_PUBLIC_20260921.zip"
ZIP_ROOT = "ghidra_12.1.4_PUBLIC"
DEFAULT_ARCHIVE = Path.home() / "s20-artifacts/hxl1-research/official-downloads" / ZIP_NAME
DEFAULT_ROOT = Path.home() / "opt" / ZIP_ROOT
# Minimum required Linux x86-64 files. Other archive members marked executable
# by the publisher are restored as such after independent byte identity checks.
REQUIRED_EXECUTABLES = {
    "support/analyzeHeadless",
    "support/launch.sh",
    "Ghidra/Features/Decompiler/os/linux_x86_64/decompile",
}
MAX_REPAIR = 2000


class ModeRepairError(Exception):
    pass


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def restore(archive: Path, root: Path, *, expected_sha: str = PINNED_SHA,
            apply: bool = True) -> dict:
    if archive.is_symlink() or not archive.is_file():
        raise ModeRepairError("Expected regular official Ghidra ZIP archive")
    if root.is_symlink() or not root.is_dir():
        raise ModeRepairError("Expected existing non-symlinked Ghidra installation")
    actual = sha256_path(archive)
    if actual != expected_sha:
        raise ModeRepairError(f"Official release archive SHA256 mismatch: {actual}")
    root = root.resolve()
    selected = []
    seen = set()
    found_required = set()
    with zipfile.ZipFile(archive) as z:
        for member in z.infolist():
            member_path = PurePosixPath(member.filename)
            if (member_path.is_absolute() or ".." in member_path.parts or
                    not member_path.parts or member_path.parts[0] != ZIP_ROOT):
                raise ModeRepairError(f"ZIP contains invalid path: {member.filename}")
            if member.is_dir():
                continue
            relative = PurePosixPath(*member_path.parts[1:])
            if not relative.parts:
                continue
            unix_mode = member.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                raise ModeRepairError(f"ZIP symlink forbidden: {member.filename}")
            if not (unix_mode & stat.S_IXUSR or relative.as_posix() in REQUIRED_EXECUTABLES):
                continue
            if relative.as_posix() in seen:
                raise ModeRepairError(f"Duplicate executable ZIP member: {relative}")
            seen.add(relative.as_posix())
            if relative.as_posix() in REQUIRED_EXECUTABLES:
                found_required.add(relative.as_posix())
            path = root.joinpath(*relative.parts)
            if not path.is_relative_to(root) or path.is_symlink() or not path.is_file():
                raise ModeRepairError(f"Executable missing or symlinked: {path}")
            # Do not follow symlinked ancestors; only files in the installed tree.
            p = path.parent
            while p != root:
                if p.is_symlink():
                    raise ModeRepairError(f"Symlinked installed directory: {p}")
                p = p.parent
            if path.stat().st_size != member.file_size:
                raise ModeRepairError(f"Installed byte length disagrees with archive: {relative}")
            with z.open(member) as stream:
                expected = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    expected.update(chunk)
            if sha256_path(path) != expected.hexdigest():
                raise ModeRepairError(f"Installed bytes differ from pinned ZIP: {relative}")
            current = stat.S_IMODE(path.stat().st_mode)
            archive_exec = unix_mode & 0o111
            required_exec = 0o111 if relative.as_posix() in REQUIRED_EXECUTABLES else 0
            desired = current | archive_exec | required_exec
            selected.append((path, relative.as_posix(), current, desired))
            if len(selected) > MAX_REPAIR:
                raise ModeRepairError("Excessive number of executable archive members")
    missing = REQUIRED_EXECUTABLES - found_required
    if missing:
        raise ModeRepairError("Pinned release missing expected Linux executable: " +
                              ", ".join(sorted(missing)))
    # Validate everything before changing any permissions.
    updated = []
    for path, relative, before, after in selected:
        if apply and after != before:
            path.chmod(after)
        updated.append({
            "path": relative, "originalMode": oct(before), "restoredMode": oct(after),
            "changed": after != before,
        })
    return {
        "status": "VERIFIED_GHIDRA_ZIP_EXECUTABLE_MODES_RESTORED" if apply else "DRY_RUN",
        "pinnedOfficialArchiveSha256": actual,
        "installedReleaseRoot": str(root),
        "verifiedExecutableFiles": len(selected),
        "changedFiles": sum(item["changed"] for item in updated),
        "executables": updated,
        "firmwareModified": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    p.add_argument("--ghidra", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--output", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/abl-linuxloader/ghidra-executable-mode-audit.json")
    args = p.parse_args()
    try:
        result = restore(args.archive, args.ghidra, apply=not args.dry_run)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    except (OSError, ModeRepairError, zipfile.BadZipFile) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[PASS] Original official Ghidra release ZIP SHA256")
    print("[PASS] All targeted installed executables match original ZIP bytes")
    print("[PASS]" if not args.dry_run else "[CHECK]",
          f"Executable mode update: {result['changedFiles']} of "
          f"{result['verifiedExecutableFiles']} files")
    print("[REPORT]", args.output)
    print("[LIMIT] Ghidra provider still requires its own REA doctor verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
