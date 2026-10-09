#!/usr/bin/env python3
"""Read-only off-device build readiness report for SM-G986U1 HXL1 stock kernel.

Checks extracted Samsung source, provenance manifest, optional layer audit,
toolchain executables, compiler version, device config and 40 overlay hashes.
Never invokes make, modifies source files, writes firmware, or contacts a phone.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

EXPECTED_VERSION = (4, 19, 113)
EXPECTED_CONFIG_SHA256 = "61f109752d3c91a5167dddcb05f79707f04f09edd2d4161a384fefa6fa35b5b8"
EXPECTED_FIRMWARE = "G986U1UESCHXL1"
CONFIGS = (
    "arch/arm64/configs/vendor/y2q_usa_singlew_defconfig",
    "arch/arm64/configs/vendor/y2q_usa_openw_defconfig",
)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_makefile_version(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    pairs = dict(re.findall(
        r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)[ \t]*[:?+]?=[ \t]*([^\r\n]*)$",
        text, re.MULTILINE,
    ))
    try:
        version = tuple(int(pairs[k]) for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL"))
    except (ValueError, KeyError) as error:
        raise ValueError("source Makefile lacks Linux version fields") from error
    return {"major": version[0], "minor": version[1], "patch": version[2],
            "extra": pairs.get("EXTRAVERSION", ""), "matchesExpected": version == EXPECTED_VERSION}


def binary_version(path):
    # shutil.which() returns a str; callers may also supply pathlib.Path.
    path = Path(path)
    try:
        p = subprocess.run(
            [str(path), "version" if path.name == "openssl" else "--version"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"cannot execute: {type(error).__name__}: {error}"
    line = (p.stdout or p.stderr).splitlines()
    return (line[0][:240] if line else "no output") + f" (exit {p.returncode})"


def find_exe(candidates):
    for item in candidates:
        if not item:
            continue
        p = Path(item).expanduser()
        executable = shutil.which(item) if len(p.parts) == 1 else str(p)
        if executable and Path(executable).is_file() and (
                Path(executable).stat().st_mode & 0o111):
            return {"path": executable, "version": binary_version(executable)}
    return None


def check_overlay_files(root, audit):
    provenance = audit.get("finalSourceProvenance", {})
    if not isinstance(provenance, dict) or len(provenance) != 40:
        raise ValueError("expected 40 source file hashes in audit report")
    mismatch = []
    for relative, entry in provenance.items():
        parts = Path(relative).parts
        if not parts or Path(relative).is_absolute() or ".." in parts:
            mismatch.append({"path": relative, "error": "invalid relative path"})
            continue
        file = root.joinpath(*parts)
        if file.is_symlink() or not file.is_file():
            mismatch.append({"path": relative, "error": "missing or symlink"})
            continue
        observed = digest(file)
        if observed != entry.get("sha256"):
            mismatch.append({"path": relative, "error": "hash mismatch"})
    return {"verified": len(provenance) - len(mismatch), "total": len(provenance),
            "failed": mismatch[:10]}


def run(args):
    root = args.source_dir.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("source directory missing: " + str(root))
    audit = json.loads(args.audit_json.read_text(encoding="utf-8"))
    if audit.get("targetFirmware") != EXPECTED_FIRMWARE:
        raise ValueError("source audit firmware mismatch")
    manifest_path = Path(str(root) + ".source-manifest.json")
    if not manifest_path.is_file():
        raise ValueError("source manifest missing: " + str(manifest_path))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("targetFirmware") != EXPECTED_FIRMWARE:
        raise ValueError("source manifest firmware mismatch")
    if manifest.get("finalFileVerification", {}).get("verifiedFinalOverlayFiles") != 40:
        raise ValueError("source assembly manifest lacks 40 validated overlay files")

    config_hashes = {}
    for relative in CONFIGS:
        location = root / relative
        config_hashes[relative] = {
            "exists": location.is_file() and not location.is_symlink(),
            "sha256": digest(location) if location.is_file() and not location.is_symlink() else None,
        }
        config_hashes[relative]["matchesOfficialAudit"] = (
            config_hashes[relative]["sha256"] == EXPECTED_CONFIG_SHA256
        )
    version = parse_makefile_version(root / "Makefile")
    layers = check_overlay_files(root, audit)
    tool_candidates = {
        "host_make": ["make"],
        "host_python3": ["python3"],
        "host_flex": ["flex"],
        "host_bison": ["bison"],
        "host_bc": ["bc"],
        "host_openssl": ["openssl"],
        "host_dtc": ["dtc"],
        "host_pahole": ["pahole"],
        "host_gcc": ["gcc"],
        "aarch64_gcc": [
            args.gcc_prefix + "gcc" if args.gcc_prefix else "",
            "aarch64-linux-android-gcc", "aarch64-linux-gnu-gcc",
        ],
        "clang": [
            str(args.clang_path) if args.clang_path else "",
            "clang-10", "clang",
        ],
        "linker": [
            str(args.linker_path) if args.linker_path else "",
            "ld.lld",
        ],
        "kernel_dtc_path": [str(root / "tools/dtc")],
    }
    toolchains = {name: find_exe(candidates) for name, candidates in tool_candidates.items()}
    android_ndk = Path.home() / "opt/android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
    if android_ndk.is_file():
        toolchains["ndk_r30_clang_userspace_reference_only"] = {
            "path": str(android_ndk), "version": binary_version(android_ndk)
        }
    blockers = []
    if not version["matchesExpected"]:
        blockers.append("source Makefile version differs from 4.19.113")
    if not all(v["matchesOfficialAudit"] for v in config_hashes.values()):
        blockers.append("device defconfig checksum differs from Samsung source audit")
    if layers["verified"] != 40:
        blockers.append("final stock overlay files have mismatched SHA256 fingerprints")
    if not toolchains["clang"]:
        blockers.append("a kernel-capable Clang executable has not been located")
    if not toolchains["aarch64_gcc"]:
        blockers.append("AArch64 supporting GCC 4.9-style compiler/prefix not located")
    if not toolchains["host_make"]:
        blockers.append("GNU make is missing")
    if not toolchains["host_flex"] or not toolchains["host_bison"]:
        blockers.append("flex/bison are missing")
    blockers.append("Original Qualcomm llvm-arm-toolchain-ship/10.0 compiler revision and build metadata have not been verified")
    return {
        "targetFirmware": EXPECTED_FIRMWARE, "sourceDirectory": str(root),
        "manifest": str(manifest_path), "makefileVersion": version,
        "deviceConfigs": config_hashes, "overlayVerification": layers,
        "toolchainExecutables": toolchains, "buildReadinessBlockers": blockers,
        "sourceAssembled": True,
        "kernelCompiled": False, "kernelBootable": "not tested",
        "notes": "This report is read-only. Compiler detection is not a guarantee of Samsung compatibility or reproducibility.",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-dir", type=Path, required=True)
    p.add_argument("--audit-json", type=Path, required=True)
    p.add_argument("--clang-path", type=Path)
    p.add_argument("--gcc-prefix", default="")
    p.add_argument("--linker-path", type=Path)
    p.add_argument("--json", type=Path)
    args = p.parse_args()
    try:
        report = run(args)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        p.error(str(e))
    print("Target firmware:", report["targetFirmware"])
    version = report["makefileVersion"]
    print("Source kernel Makefile: %s.%s.%s" %
          (version["major"], version["minor"], version["patch"]),
          "matches:", version["matchesExpected"])
    for name, status in report["deviceConfigs"].items():
        print("CONFIG:", name, "checksum match:", status["matchesOfficialAudit"])
    over = report["overlayVerification"]
    print("Final overlay files:", over["verified"], "/", over["total"])
    for name, tool in report["toolchainExecutables"].items():
        print("TOOL:", name, tool["path"] if tool else "NOT FOUND")
        if tool:
            print("   ", tool["version"])
    print("BUILD BLOCKERS / UNCERTAINTIES:")
    for blocker in report["buildReadinessBlockers"]:
        print(" -", blocker)
    print("Status: READ-ONLY PREFLIGHT; NO KERNEL BUILD OR FLASH PERFORMED")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Saved:", args.json)


if __name__ == "__main__":
    main()
