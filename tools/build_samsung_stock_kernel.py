#!/usr/bin/env python3
"""Off-device stock Samsung HXL1 Image-only compatibility build, no flashing.

DRY RUN BY DEFAULT. Validates audited 11-layer source tree, exact generated
.config digest, original Samsung kernel Makefile, generated-vs-running
configuration comparison, and compiler executables before starting make.
Executes only the Image target into the existing, separate O= directory.
Captures stdout/stderr to a user-specified log. No root payload, module
install, boot image packing/signing, device connection or flash commands.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from preflight_samsung_stock_build import run as source_preflight_run

FIRMWARE = "G986U1UESCHXL1"
MAKEFILE_SHA256 = "d7f9cb790c68a280b20db07c7bcd3f8a3cce3ad99494f72f849c6f3a24a6b79d"
GENERATED_CONFIG_SHA256 = "97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09"
RUNNING_CONFIG_GZ_SHA256 = "1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd"
CRITICAL = (
    "CONFIG_ARM64", "CONFIG_ARCH_QCOM", "CONFIG_ARCH_KONA",
    "CONFIG_MODULES", "CONFIG_MODULE_SIG", "CONFIG_MODULE_SIG_FORCE",
    "CONFIG_UH_RKP", "CONFIG_KDP_CRED", "CONFIG_KDP_NS",
    "CONFIG_SECURITY_DEFEX", "CONFIG_RANDOMIZE_BASE", "CONFIG_KPROBES",
    "CONFIG_FUTEX_PI", "CONFIG_RT_MUTEXES", "CONFIG_MODVERSIONS",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_python2(explicit=None):
    """Find genuine Python 2.7; never accept a Python 3 compatibility symlink."""
    if explicit is not None:
        binary = Path(explicit).expanduser().absolute()
        if binary.name != "python2":
            raise ValueError("--python2 must name an executable 'python2' (for /usr/bin/env python2)")
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("Python 2 executable not found: " + str(binary))
        executable = str(binary)
    else:
        executable = shutil.which("python2")
        if not executable:
            raise ValueError(
                "Samsung's kernel invokes /usr/bin/env python2. "
                "Install real Python 2.7 in an isolated prefix; do NOT alias python2 to python3."
            )
    try:
        probe = subprocess.run(
            [executable, "-c",
             "import sys; sys.stdout.write('%d.%d' % sys.version_info[:2])"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("could not run Python 2: " + str(error)) from error
    if probe.returncode != 0 or probe.stdout.strip() != "2.7":
        raise ValueError("python2 must be a genuine Python 2.7 runtime, observed: " +
                         (probe.stdout + " " + probe.stderr).strip()[:200])
    return executable


def valid_external_path(root, output, candidate):
    path = candidate.expanduser().absolute()
    if (path == root or root in path.parents or path == output
            or output in path.parents):
        raise ValueError("log/report path must be outside kernel source and output")
    if path.is_symlink():
        raise ValueError("refusing symlink log/report path")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("log/report parent must be an existing, normal directory")
    return path


def check_comparison(comparison, output):
    expected_config = output / ".config"
    if (comparison.get("firmware") != FIRMWARE
            or Path(comparison.get("generatedConfig", "")).expanduser().absolute() != expected_config
            or comparison.get("generatedSha256") != GENERATED_CONFIG_SHA256
            or comparison.get("runningConfigGzSha256") != RUNNING_CONFIG_GZ_SHA256):
        raise ValueError("generated-versus-running config audit does not match HXL1")
    delta = comparison.get("generatedVsRunning", {})
    differing = delta.get("different")
    if (delta.get("matchingExplicitSymbols") != 5790
            or delta.get("differentExplicitSymbols") != 1
            or not isinstance(differing, list)
            or differing != [{"symbol": "CONFIG_CLANG_VERSION",
                              "generated": "180103", "running": "100006"}]
            or delta.get("leftOnly") != []
            or len(delta.get("rightOnly", [])) != 18):
        raise ValueError("generated .config differences exceed audited Clang version mismatch")
    checks = comparison.get("critical", {})
    if any(not isinstance(checks.get(name), dict) or
           checks[name].get("match") is not True for name in CRITICAL):
        raise ValueError("important kernel platform/security config differs from running device")


def check_arm64_external_assembler(compiler, prefix):
    """Inspect Clang's external AArch64 assembler selection without compiling.

    Include the vendor's real --prefix=/usr/bin/ and -no-integrated-as
    options. Clang may prioritize the host-prefix as /usr/bin/as even
    when a cross-as prefix is supplied with -B. Never trust a simplified
    driver-only test without Samsung's extra compiler flags.
    """
    assembler = Path(prefix + "as")
    if not assembler.is_file() or not os.access(assembler, os.X_OK):
        raise ValueError("AArch64 GNU assembler not executable: " + str(assembler))
    probe = [
        str(compiler), "--target=aarch64-linux-gnu",
        "--prefix=/usr/bin/", "-no-integrated-as", "-EL", "-B" + prefix,
        "-###", "-x", "c", "-c", "/dev/null", "-o", "/dev/null",
    ]
    try:
        process = subprocess.run(
            probe, capture_output=True, text=True, timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("could not inspect Clang assembler command: " + str(error)) from error
    output = process.stdout + process.stderr
    intended_invocation = '"' + str(assembler) + '"'
    selected_cross_as = any(
        line.strip().startswith(intended_invocation)
        for line in output.splitlines()
    )
    if process.returncode or not selected_cross_as:
        raise ValueError(
            "Samsung's --prefix=/usr/bin/ still routes the external assembler "
            "away from " + str(assembler) +
            "; use --integrated-arm64-as instead. Clang driver: " + output[-600:]
        )
    return {"assembler": str(assembler), "clangDryRun": probe,
            "outputExcerpt": output[-1200:]}


def check_arm64_integrated_assembler(compiler):
    """Prove Clang can emit a real ELF64 AArch64 object with vendor-like flags.

    The later -integrated-as cancels Samsung's earlier -no-integrated-as,
    so the LLVM AArch64 integrated assembler is used instead of /usr/bin/as.
    Both tests write only to a disposable temporary directory.
    """
    base = [
        str(compiler), "--target=aarch64-linux-gnu",
        "--prefix=/usr/bin/", "-no-integrated-as", "-EL",
        "-integrated-as",
    ]
    explain = base + ["-###", "-x", "c", "-c", "/dev/null", "-o", "/dev/null"]
    try:
        driver = subprocess.run(
            explain, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Clang ARM64 integrated assembler inspection failed: " + str(error)) from error
    text = driver.stdout + driver.stderr
    emit_obj = any(
        '"-cc1"' in line and '"-emit-obj"' in line
        and '"-triple"' in line and "aarch64" in line
        and '"-no-integrated-as"' not in line
        for line in text.splitlines()
    )
    external_as = any(line.lstrip().startswith('"/usr/bin/as"')
                      for line in text.splitlines())
    if driver.returncode != 0 or not emit_obj or external_as:
        raise ValueError("Clang did not select integrated AArch64 object emission: " +
                         text[-900:])
    with tempfile.TemporaryDirectory(prefix="samsung-y2q-ias-probe-") as folder:
        obj = Path(folder) / "probe.o"
        command = base + ["-x", "c", "-c", "-", "-o", str(obj)]
        try:
            result = subprocess.run(
                command, input="int samsung_y2q_assembler_probe(void) { return 1; }\n",
                capture_output=True, text=True, timeout=20, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Clang ARM64 test-object compile failed: " + str(error)) from error
        if result.returncode != 0 or not obj.is_file():
            raise ValueError("Clang failed disposable ARM64 object compile: " +
                             (result.stdout + result.stderr)[-800:])
        with obj.open("rb") as stream:
            elf = stream.read(20)
        if (len(elf) != 20 or elf[:4] != b"\\x7fELF" or elf[4] != 2
                or elf[5] != 1 or elf[18:20] != b"\\xb7\\x00"):
            raise ValueError("Clang assembler probe did not produce little-endian ELF64 AArch64")
    return {"mode": "clang-integrated-aarch64",
            "driverInspect": explain, "actualObjectCompiled": True,
            "validatedElfMachine": "EM_AARCH64 (183)",
            "vendorPrefixReplicated": "/usr/bin/",
            "driverExcerpt": text[-900:]}


def plan(args):
    source = args.source_dir.expanduser().resolve()
    output = args.output_dir.expanduser().absolute()
    if not source.is_dir() or not output.is_dir():
        raise ValueError("stock source or existing configured O= directory missing")
    if (output == source or source in output.parents or output in source.parents
            or output.is_symlink()):
        raise ValueError("source and output must be distinct real directories")
    if output.as_posix().startswith("/mnt/"):
        raise ValueError("keep kernel output on WSL Linux filesystem")
    if not (1 <= args.jobs <= 16):
        raise ValueError("job count must be between 1 and 16")
    if not (output / ".config").is_file() or (output / ".config").is_symlink():
        raise ValueError("missing normal generated stock .config")
    config_sha256 = sha256_file(output / ".config")
    if config_sha256 != GENERATED_CONFIG_SHA256:
        raise ValueError(f"unexpected .config checksum {config_sha256}; do not build altered config")
    if sha256_file(source / "Makefile") != MAKEFILE_SHA256:
        raise ValueError("stock Samsung kernel Makefile changed")
    artifact = output / "arch/arm64/boot/Image"
    if artifact.exists() or artifact.is_symlink():
        raise ValueError("Image already exists; refuse to overwrite previous build")
    comparison = json.loads(args.comparison_json.expanduser().read_text(encoding="utf-8"))
    check_comparison(comparison, output)

    compiler = args.clang.expanduser().resolve()
    cross_prefix = args.gcc_prefix
    if not Path(cross_prefix).is_absolute():
        raise ValueError("use an absolute AArch64 GCC tool prefix")
    gcc = Path(cross_prefix + "gcc")
    ld = Path(cross_prefix + "ld")
    dtc = source / "tools/dtc"
    for path, label in ((compiler, "Clang"), (gcc, "AArch64 GCC"),
                        (ld, "AArch64 GNU linker"), (dtc, "Samsung DTC")):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f"{label} unavailable: {path}")
    if not shutil.which("python"):
        raise ValueError("Samsung's older kernel build scripts require unversioned python")
    python2 = find_python2(getattr(args, "python2", None))

    source_audit = source_preflight_run(argparse.Namespace(
        source_dir=source,
        audit_json=args.audit_json.expanduser(),
        clang_path=compiler, gcc_prefix=cross_prefix, linker_path=ld,
    ))
    if (not source_audit["makefileVersion"]["matchesExpected"]
            or source_audit["overlayVerification"]["verified"] != 40
            or any(not x["matchesOfficialAudit"]
                   for x in source_audit["deviceConfigs"].values())):
        raise ValueError("source preflight failed before Image compatibility build")

    assembler_probe = None
    if getattr(args, "external_arm64_as", False) and getattr(args, "integrated_arm64_as", False):
        raise ValueError("choose one assembler mode: --external-arm64-as OR --integrated-arm64-as")
    if getattr(args, "external_arm64_as", False):
        assembler_probe = check_arm64_external_assembler(compiler, cross_prefix)
    if getattr(args, "integrated_arm64_as", False):
        assembler_probe = check_arm64_integrated_assembler(compiler)
    if args.execute and args.log is None:
        raise ValueError("--execute requires --log outside the source and output directories")
    log = valid_external_path(source, output, args.log) if args.log else None
    if args.execute and (log.exists() or log.is_symlink()):
        raise ValueError("build log already exists; use a new log path")
    report = valid_external_path(source, output, args.json) if args.json else None
    if args.execute and report is not None and (report.exists() or report.is_symlink()):
        raise ValueError("build report already exists; use a new report path")

    cmd = [
        "make", "-C", str(source),
        "O=" + str(output), "ARCH=arm64",
        "CROSS_COMPILE=" + cross_prefix,
        "CLANG_TRIPLE=aarch64-linux-gnu-",
        "REAL_CC=" + str(compiler),
        # Samsung's later CFP compiler path selects scripts/gcc-wrapper.py
        # with $(CFP_CC), independent of REAL_CC. Make command-line values
        # override ordinary Makefile assignments without editing vendor files.
        "CFP_CC=" + str(compiler),
        "DTC_EXT=" + str(dtc),
        "CONFIG_BUILD_ARM64_DT_OVERLAY=y",
    ]
    if assembler_probe:
        # KCFLAGS is appended to target C flags, KAFLAGS to assembler flags.
        # The explicit trailing -integrated-as must override vendor Kbuild's
        # -no-integrated-as; this avoids --prefix=/usr/bin/ choosing native as.
        if getattr(args, "integrated_arm64_as", False):
            extra = "--target=aarch64-linux-gnu -integrated-as"
        else:
            extra = "--target=aarch64-linux-gnu -B" + cross_prefix
        cmd.extend(["KCFLAGS=" + extra, "KAFLAGS=" + extra])
    if getattr(args, "verbose", False):
        cmd.append("V=1")
    cmd.extend(["-j" + str(args.jobs), "Image"])
    return {
        "firmware": FIRMWARE,
        "source": str(source),
        "output": str(output),
        "configSha256": config_sha256,
        "command": cmd,
        "image": str(artifact),
        "log": str(log) if log else None,
        "python2": python2,
        "status": "dry_run",
        "kernelCompiled": False,
        "signed": False,
        "flashable": False,
        "compilerRouting": {"REAL_CC": str(compiler), "CFP_CC": str(compiler)},
        "crossAssemblerProbe": assembler_probe,
        "note": "Experimental Clang18/GCC13 stock Image compatibility build with CFP compiler override, not a Samsung factory-identical binary.",
    }, report


def execute_build(info):
    log = Path(info["log"])
    with log.open("x", encoding="utf-8", errors="replace") as logfile:
        logfile.write("COMMAND: " + " ".join(info["command"]) + "\n")
        logfile.flush()
        environment = dict(os.environ)
        # /usr/bin/env python2 follows PATH, even when build scripts have
        # hard-coded shebangs. Scope overrides to this subprocess ONLY.
        environment["PATH"] = str(Path(info["python2"]).parent) + os.pathsep + environment.get("PATH", "")
        proc = subprocess.Popen(info["command"], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, errors="replace",
                                bufsize=1, env=environment)
        try:
            for line in proc.stdout:
                logfile.write(line)
                print(line, end="", flush=True)
            rc = proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait()
            raise
        logfile.write(f"\nMAKE_EXIT_CODE={rc}\n")
    info["returncode"] = rc
    image = Path(info["image"])
    if rc == 0 and image.is_file() and not image.is_symlink():
        info["imageSizeBytes"] = image.stat().st_size
        info["imageSha256"] = sha256_file(image)
        info["kernelCompiled"] = True
        info["status"] = "image_compiled_off_device_not_signed_or_tested"
    else:
        info["status"] = "compile_failed_or_image_missing"
        info["imageExists"] = image.is_file()
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--comparison-json", type=Path, required=True)
    parser.add_argument("--clang", type=Path, default=Path("/usr/bin/clang"))
    parser.add_argument("--gcc-prefix", default="/usr/bin/aarch64-linux-gnu-")
    parser.add_argument("--external-arm64-as", action="store_true",
                        help="Experimental external GNU assembler: fail closed if Samsung --prefix selects /usr/bin/as")
    parser.add_argument("--integrated-arm64-as", action="store_true",
                        help="Probe Clang's integrated AArch64 assembler with vendor flags and test ELF, then override KCFLAGS/KAFLAGS")
    parser.add_argument("--verbose", action="store_true",
                        help="Log complete Make/compiler commands (V=1)")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--python2", type=Path,
                        help="Path to genuine Python 2.7 named python2; added to build subprocess PATH only")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        info, report = plan(args)
        print("Firmware:", info["firmware"])
        print("Source:", info["source"])
        print("Output:", info["output"])
        print("Known generated config SHA-256:", info["configSha256"])
        print("Mode:", "EXPERIMENTAL STOCK Image COMPILE" if args.execute else "DRY RUN")
        print("Command:", " ".join(info["command"]))
        if args.execute:
            info = execute_build(info)
        if report:
            with report.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(info, indent=2) + "\n")
            print("Saved build report:", report)
        if args.execute:
            print("Make status:", info["status"])
            print("Build log:", info["log"])
            if info["kernelCompiled"]:
                print("Output Image SHA-256:", info["imageSha256"])
                print("NOTE: NOT SIGNED, BOOT-VERIFIED OR FLASHABLE on locked S20+.")
            else:
                sys.exit(1)
        else:
            print("DRY RUN PASSED: No source, output, or phone modifications.")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
