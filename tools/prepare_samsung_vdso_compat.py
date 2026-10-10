#!/usr/bin/env python3
"""Create an auditable, separate HXL1 kernel-source copy with TWO upstream fixes.

DRY RUN by default. Never edits original Samsung source, firmware, or phone.
Only:
  arch/arm64/kernel/vdso/gettimeofday.S (three macro invocations)
  include/linux/elfnote.h (one ELFNOTE allocation flag)
Source tree copy uses distinct file inodes, not hardlinks.
The manifest records SHA-256s and a whole-tree digest for both trees.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from preflight_samsung_stock_build import run as preflight_run

FIRMWARE = "G986U1UESCHXL1"
MANIFEST = ".samsung-vdso-compat.json"
VDSO = "arch/arm64/kernel/vdso/gettimeofday.S"
ELFNOTE = "include/linux/elfnote.h"
INIT_MAIN = "init/main.c"
PATCHES = {
    VDSO: {
        "patch": "linux-4.19-stable-vdso-macro-args",
        "upstream": "https://www.spinics.net/lists/arm-kernel/msg893332.html",
        "expectedReplacements": 3,
    },
    ELFNOTE: {
        "patch": "elfnote-shf-alloc-51da9dfb7f20911ae4e79e9b412a9c2d4c373d4b",
        "upstream": "https://lists.openwall.net/linux-kernel/2020/03/25/1250",
        "expectedReplacements": 1,
    },
}


# This additional patch is NOT an upstream VDSO fix. It is a one-line
# source-level correction verified against the owner's HXL1 source and
# the exact Clang 18 -Wformat diagnostic (init/main.c:720:60).
FORMAT_PATCH = {
    INIT_MAIN: {
        "patch": "samsung-hxl1-ropp-master-key-pr-info-format-u64",
        "origin": "owner log build-09: init/main.c:720 u64 passed to %lx",
        "expectedReplacements": 1,
    },
}
FORMAT_KIND = "OFF_DEVICE_EXPERIMENTAL_VDSO_AND_INIT_FORMAT_COMPAT_NOT_SAMSUNG_STOCK"
VDSO_KIND = "OFF_DEVICE_EXPERIMENTAL_VDSO_COMPAT_SOURCE_NOT_SAMSUNG_STOCK"


def patch_catalog(format_fix):
    return {**PATCHES, **FORMAT_PATCH} if format_fix else dict(PATCHES)


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest_file(path):
    hasher = hashlib.sha256()
    with path.open("rb") as input_file:
        for block in iter(lambda: input_file.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def tree_digest(root, substituted=None):
    """Complete ordered digest of relative paths, symlink targets and file bytes."""
    substituted = substituted or {}
    hasher = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST:
            continue
        if path.is_symlink():
            kind, fingerprint = "link", os.readlink(path)
        elif path.is_dir():
            kind, fingerprint = "dir", ""
        elif path.is_file():
            kind, fingerprint = "file", substituted.get(relative) or digest_file(path)
        else:
            raise ValueError("unsupported special file in source snapshot: " + relative)
        hasher.update(json.dumps([kind, relative, fingerprint],
                                 ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n")
    return hasher.hexdigest()


def upstream_fixes(source_text, path):
    if path == VDSO:
        changed, n = re.subn(
            r"^([ \t]*)clock_gettime_return,[ \t]*shift=1([ \t]*)$",
            r"\1clock_gettime_return shift=1\2",
            source_text, flags=re.MULTILINE,
        )
    elif path == ELFNOTE:
        changed, n = re.subn(
            r'ELFNOTE_START\(name,[ \t]*type,[ \t]*""\)',
            'ELFNOTE_START(name, type, "a")',
            source_text,
        )
    elif path == INIT_MAIN:
        # Preserve the log message and all security initialization logic.
        # Match the complete existing expression exactly once.
        before = 'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);'
        after = 'pr_info("SYSREG, after zeroing out master key, mk=%llx\\n", (unsigned long long)ropp_master_key);'
        n = source_text.count(before)
        changed = source_text.replace(before, after)
    else:
        raise ValueError("unsupported compatibility patch: " + path)
    expected = {**PATCHES, **FORMAT_PATCH}[path]['expectedReplacements']
    if n != expected:
        raise ValueError(f"refusing compatibility patch {path}: expected {expected} exact matches, found {n}")
    if changed == source_text:
        raise ValueError("compatibility patch did not modify " + path)
    return changed, n


def source_gate(stock, audit):
    preflight = preflight_run(argparse.Namespace(
        source_dir=stock, audit_json=audit, clang_path=None,
        gcc_prefix="/usr/bin/aarch64-linux-gnu-", linker_path=None,
    ))
    if (not preflight["makefileVersion"]["matchesExpected"]
            or preflight["overlayVerification"]["verified"] != 40
            or not all(x["matchesOfficialAudit"] for x in preflight["deviceConfigs"].values())):
        raise ValueError("stock Samsung source integrity check failed")
    return preflight


def plan(stock, dest, audit, format_fix=False):
    stock = stock.expanduser().resolve()
    dest = dest.expanduser().absolute()
    if not stock.is_dir() or not (stock / "Makefile").is_file():
        raise ValueError("missing assembled Samsung stock source")
    if (dest == stock or dest in stock.parents or stock in dest.parents):
        raise ValueError("compatibility tree must be separate from stock source")
    if dest.exists() or dest.is_symlink():
        raise ValueError("refusing to overwrite existing compatibility tree " + str(dest))
    if not dest.parent.is_dir() or dest.parent.is_symlink():
        raise ValueError("destination parent must be an existing normal directory")
    if dest.as_posix().startswith("/mnt/"):
        raise ValueError("keep compatibility source on native WSL Linux filesystem")
    source_gate(stock, audit)
    patches = {}
    for path, meta in patch_catalog(format_fix).items():
        file = stock / path
        if file.is_symlink() or not file.is_file():
            raise ValueError("required unmodified Samsung source file not found: " + path)
        original = file.read_text(encoding="utf-8")
        updated, count = upstream_fixes(original, path)
        patches[path] = {
            **meta,
            "replacements": count,
            "originalSha256": digest_bytes(original.encode("utf-8")),
            "updatedSha256": digest_bytes(updated.encode("utf-8")),
        }
    return stock, dest, patches


def create(stock, dest, patches):
    staged = Path(tempfile.mkdtemp(prefix=".samsung-vdso-stage-", dir=dest.parent))
    try:
        # Copy, do not hard-link: no edits made to the source or existing O= tree.
        shutil.copytree(stock, staged, symlinks=True, dirs_exist_ok=True)
        for path, hashes in patches.items():
            copy = staged / path
            if copy.is_symlink() or not copy.is_file():
                raise ValueError("staged file not regular: " + path)
            original = copy.read_text(encoding="utf-8")
            if digest_bytes(original.encode("utf-8")) != hashes["originalSha256"]:
                raise ValueError("staged file not identical to original Samsung source: " + path)
            changed, count = upstream_fixes(original, path)
            if count != hashes["replacements"]:
                raise ValueError("staged patch count changed for " + path)
            copy.write_text(changed, encoding="utf-8")
            if digest_file(copy) != hashes["updatedSha256"]:
                raise ValueError("patched file checksum mismatch " + path)

        base_tree_sha = tree_digest(stock)
        # Compare every entry of the copied tree against the original, with
        # just the two patched file hashes normalized to their stock hashes.
        normalized = tree_digest(
            staged, {path: meta["originalSha256"] for path, meta in patches.items()}
        )
        if normalized != base_tree_sha:
            raise ValueError("copied source differs from stock outside two upstream patches")
        compat_tree_sha = tree_digest(staged)
        manifest = {
            "schema": 2 if INIT_MAIN in patches else 1,
            "firmware": FIRMWARE,
            "kind": FORMAT_KIND if INIT_MAIN in patches else VDSO_KIND,
            "originalSource": str(stock),
            "compatSource": str(dest),
            "stockTreeSha256": base_tree_sha,
            "compatTreeSha256": compat_tree_sha,
            "patches": patches,
            "sourceUnmodified": True,
            "kernelCompiled": False,
            "signedOrFlashable": False,
        }
        (staged / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.replace(staged, dest)
        return manifest
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def verify_compat(stock, compat):
    """Fail-closed verification of the complete experimental copied tree."""
    stock = stock.expanduser().resolve()
    compat = compat.expanduser().absolute()
    if compat.is_symlink() or not compat.is_dir() or compat == stock:
        raise ValueError("separate normal compatibility source tree required")
    manifest_path = compat / MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("missing isolated compatibility provenance manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual_patches = manifest.get("patches", {})
    if not isinstance(actual_patches, dict):
        raise ValueError("missing compatibility patch manifest")
    format_fix = INIT_MAIN in actual_patches
    allowed = patch_catalog(format_fix)
    expected_kind = FORMAT_KIND if format_fix else VDSO_KIND
    if (manifest.get("schema") != (2 if format_fix else 1)
            or manifest.get("firmware") != FIRMWARE
            or manifest.get("originalSource") != str(stock)
            or manifest.get("compatSource") != str(compat)
            or manifest.get("kind") != expected_kind
            or set(actual_patches) != set(allowed)):
        raise ValueError("wrong stock origin, firmware or compatibility manifest")
    for path, metadata in allowed.items():
        item = manifest["patches"][path]
        if any(item.get(k) != v for k, v in metadata.items()):
            raise ValueError("unexpected upstream patch metadata for " + path)
        if item.get("replacements") != metadata["expectedReplacements"]:
            raise ValueError("unexpected upstream patch count " + path)
        if digest_file(stock / path) != item.get("originalSha256"):
            raise ValueError("stock source changed since compatibility snapshot " + path)
        if digest_file(compat / path) != item.get("updatedSha256"):
            raise ValueError("patched compatibility file changed " + path)
    if tree_digest(stock) != manifest.get("stockTreeSha256"):
        raise ValueError("stock source changed since isolated compatibility snapshot")
    if tree_digest(compat) != manifest.get("compatTreeSha256"):
        raise ValueError("compatibility source tree mutated since creation")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--compat-source-dir", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--init-format-fix", action="store_true",
                        help="Opt into one extra exact init/main.c u64/%lx compatibility correction in a NEW isolated copy")
    parser.add_argument("--execute", action="store_true", help="copy and patch separate tree")
    args = parser.parse_args()
    try:
        stock, dest, patches = plan(args.source_dir, args.compat_source_dir,
                                    args.audit_json.expanduser(), args.init_format_fix)
        print("Samsung stock source (never modified):", stock)
        print("Experimental compatibility destination:", dest)
        for path, patch in patches.items():
            print("Exact upstream patch:", path, "| replacements:", patch["replacements"])
            print("  original SHA256:", patch["originalSha256"])
            print("  patched  SHA256:", patch["updatedSha256"])
            print("  reference:", patch.get("upstream", patch.get("origin", "local precise correction")))
        if args.execute:
            manifest = create(stock, dest, patches)
            print("COMPATIBILITY SOURCE READY:", dest)
            print("Original source full-tree SHA256:", manifest["stockTreeSha256"])
            print("Experimental copy full-tree SHA256:", manifest["compatTreeSha256"])
            print("NOTE: kernel not built, signed or flashed.")
        else:
            print("DRY RUN PASSED; no source files copied or modified.")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
