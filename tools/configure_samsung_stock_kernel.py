#!/usr/bin/env python3
"""Configure a stock Samsung HXL1 kernel out-of-tree; NEVER compile or flash it.

Defaults to printing a checked command without invoking Make. An explicit
--execute configures only Kconfig from Samsung's unmodified source tree
using host Clang and a GCC prefix chosen by the operator. Uses the
known-good firmware evidence and 40 overlay hashes to reject stale source.
This is a modern-toolchain compatibility trial, not a Samsung factory build.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from preflight_samsung_stock_build import run as preflight_run

TARGET = "vendor/y2q_usa_singlew_defconfig"


def command_for(args):
    source = args.source_dir.expanduser().resolve()
    destination = args.output_dir.expanduser().absolute()
    if not source.is_dir():
        raise ValueError("source folder not present")
    if not (source / "Makefile").is_file():
        raise ValueError("kernel source Makefile missing")
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError("output must be separate from original Samsung source tree")
    if destination.exists() or destination.is_symlink():
        raise ValueError("refusing to re-use existing output path: " + str(destination))
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("output parent does not exist or is a symlink")
    if destination.as_posix().startswith("/mnt/"):
        raise ValueError("use Linux WSL filesystem for output, not /mnt/")
    clang = args.clang.expanduser().resolve()
    dtc = (source / "tools/dtc").resolve()
    gcc = Path(args.gcc_prefix + "gcc").expanduser()
    ld = Path(args.gcc_prefix + "ld").expanduser()
    for path, label in ((clang, "Clang"), (gcc, "AArch64 GCC"), (ld, "AArch64 ld"),
                        (dtc, "Samsung DTC")):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(label + " not executable at " + str(path))
    if args.gcc_prefix == "":
        raise ValueError("CROSS_COMPILE GCC prefix required")
    if not Path(args.gcc_prefix).is_absolute():
        raise ValueError("CROSS_COMPILE must be an absolute prefix")

    audit = preflight_run(argparse.Namespace(
        source_dir=source, audit_json=args.audit_json,
        clang_path=clang, gcc_prefix=args.gcc_prefix, linker_path=None
    ))
    if not audit["makefileVersion"]["matchesExpected"]:
        raise ValueError("kernel Makefile version mismatch")
    if audit["overlayVerification"]["verified"] != 40:
        raise ValueError("firmware source overlay integrity failed")
    if not all(v["matchesOfficialAudit"] for v in audit["deviceConfigs"].values()):
        raise ValueError("defconfig checksum mismatch")
    command = [
        "make", "-C", str(source), "O=" + str(destination),
        "ARCH=arm64",
        "CROSS_COMPILE=" + args.gcc_prefix,
        "CLANG_TRIPLE=aarch64-linux-gnu-",
        "REAL_CC=" + str(clang),
        "DTC_EXT=" + str(dtc),
        "CONFIG_BUILD_ARM64_DT_OVERLAY=y",
        TARGET,
    ]
    return command, source, destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--clang", type=Path, default=Path("/usr/bin/clang"))
    parser.add_argument("--gcc-prefix", default="/usr/bin/aarch64-linux-gnu-")
    parser.add_argument("--execute", action="store_true", help="Run ONLY stock defconfig target")
    parser.add_argument("--json", type=Path, help="Record plan/result JSON outside source")
    args = parser.parse_args()
    try:
        command, source, destination = command_for(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("Samsung stock source:", source)
    print("Output directory:", destination)
    print("Target:", TARGET)
    print("Mode:", "CONFIGURE ONLY" if args.execute else "DRY RUN")
    print("Command:", " ".join(command))
    report = {
        "firmware": "G986U1UESCHXL1",
        "source": str(source),
        "output": str(destination),
        "target": TARGET,
        "command": command,
        "mode": "configure_only" if args.execute else "dry_run",
        "kernelCompiled": False,
        "factoryToolchainVerified": False,
        "note": "Modern GNU/LLVM compatibility test only; no signing or flashing.",
    }
    if args.execute:
        destination.mkdir(mode=0o755)
        proc = subprocess.run(command, check=False)
        report["returncode"] = proc.returncode
        report["configCreated"] = (destination / ".config").is_file()
        if proc.returncode != 0 or not report["configCreated"]:
            print("Defconfig failed. Preserve output directory for build logs.",
                  file=sys.stderr)
    if args.json:
        path = args.json.expanduser().absolute()
        if path == source or source in path.parents or path == destination or destination in path.parents:
            parser.error("write report outside source and output directories")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Saved:", path)
    if args.execute and (report["returncode"] != 0 or not report["configCreated"]):
        sys.exit(1)
    if args.execute:
        print("SUCCESS: standalone Kconfig generated; kernel compilation NOT started.")


if __name__ == "__main__":
    main()
