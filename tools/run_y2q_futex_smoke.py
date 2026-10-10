#!/usr/bin/env python3
"""Automate the non-root, uncontended futex-PI smoke test on exact S20+ HXL1.

From WSL2, run:
    python3 tools/run_y2q_futex_smoke.py

Sources, in preference order: an existing local build; the GitHub Actions
artifact for the checked-out HEAD (requires 'gh'); or a fresh local Android NDK
build. Override with --binary, --source actions, or --source local.

The script verifies the Android AArch64 ELF, checks the exact stock firmware
and uid=2000 shell before upload, runs once under a host-side deadline, saves
a JSON report, and removes only the file it staged. It does not elevate
privileges, trigger PI requeue/races, load kernel code, or write boot partitions.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

REPO = "Ragnarok93/Root-My-Galaxy-Payloads"
BRANCH = "feature/s20plus-investigation-shizuku-20261009"
WORKFLOW = "y2q-identity-probe.yml"
ARTIFACT = "y2q-HXL1-futex-pi-smoke-NOT-ROOT"
EXE = "y2q-HXL1-futex-pi-smoke"
ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / "research/y2q-G986U1UESCHXL1"
LOCAL_EXE = PROJECT / "build" / EXE
BUILD_SH = PROJECT / "build_futex_pi_smoke.sh"

EXPECTED = {
    "ro.product.model": "SM-G986U1",
    "ro.product.device": "y2q",
    "ro.boot.bootloader": "G986U1UESCHXL1",
    "ro.build.fingerprint":
        "samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys",
    "ro.boot.flash.locked": "1",
    "ro.boot.vbmeta.device_state": "locked",
}
EXPECTED_KERNEL = "4.19.113-27095354"
EXPECTED_PAGE_SIZE = "4096"


class DiagnosticError(Exception):
    """A safe stop; never fall through to device execution."""


def command(args: list[str], *, timeout: int = 30,
            env: dict[str, str] | None = None,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    """Invoke a fixed argument vector, never a shell command string."""
    try:
        result = subprocess.run(
            args, text=True, capture_output=True,
            timeout=timeout, env=env, check=False,
        )
    except FileNotFoundError as exc:
        raise DiagnosticError(f"Missing executable: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiagnosticError(
            f"Timed out after {timeout}s: {args[0]} "
            "(do not automatically retry the device test)"
        ) from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-800:]
        raise DiagnosticError(
            f"Command failed (exit {result.returncode}): "
            f"{' '.join(args[:3])}\n{detail}"
        )
    return result


def require_arm64_android_elf(binary: Path) -> str:
    """Reject ZIPs, scripts, host x86 binaries and incorrectly linked ELF."""
    if not binary.is_file():
        raise DiagnosticError(f"Missing diagnostic executable: {binary}")
    if binary.stat().st_size > 5_000_000 or binary.stat().st_size < 64:
        raise DiagnosticError("Unexpected diagnostic ELF size; refusing to upload")
    with binary.open("rb") as file:
        hdr = file.read(64)
    if hdr[:4] != b"\x7fELF" or hdr[4] != 2 or hdr[5] != 1:
        raise DiagnosticError("Expected a little-endian 64-bit ELF executable")
    e_type, e_machine = struct.unpack_from("<HH", hdr, 16)
    if e_type != 3 or e_machine != 183:
        raise DiagnosticError(
            f"Expected PIE AArch64 ELF (ET_DYN/EM_AARCH64), "
            f"got type={e_type} machine={e_machine}"
        )
    digest = hashlib.sha256()
    with binary.open("rb") as inp:
        for block in iter(lambda: inp.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_ndk() -> Path | None:
    options: list[Path] = []
    if os.environ.get("ANDROID_NDK_HOME"):
        options.append(Path(os.environ["ANDROID_NDK_HOME"]).expanduser())
    if os.environ.get("ANDROID_HOME"):
        options += sorted((Path(os.environ["ANDROID_HOME"]) / "ndk").glob("*"),
                          reverse=True)
    for base in (
        Path.home() / "Android/Sdk/ndk",
        Path("/usr/local/lib/android/sdk/ndk"),
        Path("/opt/android-sdk/ndk"),
    ):
        options += sorted(base.glob("*"), reverse=True)
    for candidate in options:
        compiler = (candidate / "toolchains/llvm/prebuilt/linux-x86_64/bin/"
                    "aarch64-linux-android33-clang")
        if compiler.is_file() and os.access(compiler, os.X_OK):
            return candidate
    return None


def local_build() -> Path:
    ndk = find_ndk()
    if ndk is None:
        raise DiagnosticError(
            "No local Android NDK detected. Install/configure ANDROID_NDK_HOME, "
            "or install/authenticate GitHub CLI ('gh auth login') to use Actions."
        )
    print(f"[build] Android NDK: {ndk}", flush=True)
    env = os.environ.copy()
    env["ANDROID_NDK_HOME"] = str(ndk)
    result = command(["bash", str(BUILD_SH)], timeout=120, env=env)
    print(result.stdout.strip(), flush=True)
    return LOCAL_EXE


def actions_download(temp_dir: Path) -> Path:
    if not shutil.which("gh"):
        raise DiagnosticError(
            "GitHub CLI not found. Install 'gh' and run 'gh auth login', "
            "or use --source local with Android NDK, or --binary PATH."
        )
    head = command(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"]
    ).stdout.strip()
    output = command([
        "gh", "run", "list", "--repo", REPO, "--workflow", WORKFLOW,
        "--branch", BRANCH, "--limit", "50",
        "--json", "databaseId,headSha,status,conclusion",
    ], timeout=40).stdout
    try:
        runs = json.loads(output)
    except json.JSONDecodeError as exc:
        raise DiagnosticError("Could not parse GitHub Actions workflow list") from exc
    matching = [r for r in runs
                if r.get("headSha") == head
                and r.get("status") == "completed"
                and r.get("conclusion") == "success"]
    if not matching:
        raise DiagnosticError(
            "No successful GitHub Actions run for this exact checkout HEAD "
            f"({head[:12]}). Check {REPO} Actions for a passing "
            f"'{WORKFLOW}' build. Refusing to silently run a stale artifact."
        )
    run_id = str(matching[0]["databaseId"])
    print(f"[artifact] Downloading CI run {run_id}, HEAD {head[:12]}", flush=True)
    command([
        "gh", "run", "download", run_id, "--repo", REPO,
        "--name", ARTIFACT, "--dir", str(temp_dir),
    ], timeout=120)
    result = temp_dir / EXE
    if not result.is_file():
        raise DiagnosticError(f"Downloaded artifact lacks expected executable: {EXE}")
    return result


def select_binary(args: argparse.Namespace, temp_dir: Path) -> tuple[Path, str]:
    if args.binary:
        return args.binary.expanduser().resolve(), "explicit"
    if args.source == "local":
        return local_build(), "local-ndk"
    if args.source == "actions":
        return actions_download(temp_dir), "github-actions"
    if LOCAL_EXE.is_file():
        print("[artifact] Using existing local binary. Use --source actions "
              "for a fresh CI build or --source local to rebuild.", flush=True)
        return LOCAL_EXE, "existing-local"
    errors = []
    if shutil.which("gh"):
        try:
            return actions_download(temp_dir), "github-actions"
        except DiagnosticError as exc:
            errors.append(str(exc))
            print(f"[artifact] GitHub Actions unavailable: {exc}", flush=True)
    try:
        return local_build(), "local-ndk"
    except DiagnosticError as exc:
        errors.append(str(exc))
        raise DiagnosticError(
            "No usable binary was located. " + " | ".join(errors)
            + "\nYou may supply an already downloaded executable with --binary PATH."
        ) from exc


def connected_device(adb: str, serial: str | None) -> str:
    output = command([adb, "devices"], timeout=20).stdout
    online = []
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            online.append(fields[0])
    if serial is not None:
        if serial not in online:
            raise DiagnosticError(
                "Requested --serial is not an online ADB device; "
                "check 'adb devices' (including WSL USB/ADB access)"
            )
        return serial
    if len(online) != 1:
        raise DiagnosticError(
            f"Expected exactly one online ADB device, found {len(online)}. "
            "Use --serial SERIAL when more than one is connected."
        )
    return online[0]


def verify_device(adb: str, serial: str) -> dict[str, str]:
    base = [adb, "-s", serial, "shell"]
    observed = {}
    for key, expected in EXPECTED.items():
        actual = command(base + ["getprop", key], timeout=15).stdout.strip()
        observed[key] = actual
        if actual != expected:
            raise DiagnosticError(
                f"STOP: {key} mismatch: expected {expected!r}, "
                f"observed {actual!r}. No upload performed."
            )
    checks = [
        (["uname", "-r"], EXPECTED_KERNEL, "kernel release"),
        (["getconf", "PAGESIZE"], EXPECTED_PAGE_SIZE, "page size"),
        (["id", "-u"], "2000", "ADB shell uid"),
        (["getenforce"], "Enforcing", "SELinux enforcement"),
    ]
    for tokens, expected, label in checks:
        value = command(base + tokens, timeout=15).stdout.strip()
        observed[label] = value
        if value != expected:
            raise DiagnosticError(
                f"STOP: {label} mismatch: expected {expected!r}, "
                f"observed {value!r}. No upload performed."
            )
    return observed


def record_report(report: dict, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = directory / f"y2q-futex-pi-smoke-{stamp}.json"
    if output.exists():
        raise DiagnosticError(f"Refusing to overwrite an existing report: {output}")
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path,
                   help="Exact path to prebuilt y2q-HXL1-futex-pi-smoke ELF")
    p.add_argument("--source", choices=("auto", "actions", "local"),
                   default="auto", help="How to acquire/build the diagnostic")
    p.add_argument("--serial", help="ADB serial if several devices are connected")
    p.add_argument("--adb", default="adb", help="ADB executable or absolute path")
    p.add_argument("--run-timeout", type=int, default=12,
                   help="Host-side seconds for one device run (default: 12)")
    p.add_argument("--output-dir", type=Path,
                   default=Path.home() / "s20-artifacts",
                   help="Directory for JSON evidence reports")
    p.add_argument("--preflight-only", action="store_true",
                   help="Validate binary and phone, but do not upload or execute")
    args = p.parse_args()
    if args.run_timeout < 7 or args.run_timeout > 60:
        p.error("--run-timeout must be between 7 and 60 seconds")
    if args.binary and args.source != "auto":
        p.error("Specify either --binary or --source, not both")

    print("Root My Galaxy / S20+ HXL1 / SAFE FUTEX-PI / NOT ROOT", flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix="rmg-y2q-futex-") as temporary:
            binary, source = select_binary(args, Path(temporary))
            sha = require_arm64_android_elf(binary)
            print(f"[artifact] {binary}\n[sha256] {sha}", flush=True)
            serial = connected_device(args.adb, args.serial)
            observed = verify_device(args.adb, serial)
            print("[device] Exact stock HXL1 identity, UID 2000 and "
                  "SELinux Enforcing verified.", flush=True)

            report = {
                "schemaVersion": 1,
                "diagnostic": "safe-single-thread-uncontended-futex-pi",
                "firmware": EXPECTED["ro.boot.bootloader"],
                "kernel": EXPECTED_KERNEL,
                "status": "PREFLIGHT_ONLY" if args.preflight_only else "NOT_EXECUTED",
                "acquisition": source,
                "binarySha256": sha,
                "deviceIdentity": observed,
                "note": "NOT a GhostLock exploit, root or KernelSU verification",
            }
            if args.preflight_only:
                path = record_report(report, args.output_dir.expanduser())
                print(f"[report] {path}\nRESULT=PREFLIGHT_ONLY", flush=True)
                return 0

            remote = f"/data/local/tmp/{EXE}-{sha[:12]}"
            base = [args.adb, "-s", serial]
            check_existing = command(
                base + ["shell", "test", "-e", remote],
                timeout=15, check=False)
            if check_existing.returncode == 0:
                raise DiagnosticError(
                    f"Staging path already exists: {remote}. "
                    "Refusing to overwrite an existing file."
                )
            # POSIX test -e gives status 1 for nonexistence.
            if check_existing.returncode != 1:
                raise DiagnosticError(
                    "Cannot safely check whether the remote staging path exists"
                )

            staged = False
            try:
                staged = True  # clean up even after a partially completed push
                print("[device] Uploading one non-root user-space executable.", flush=True)
                command(base + ["push", str(binary), remote], timeout=60)
                command(base + ["shell", "chmod", "700", remote], timeout=15)
                print(f"[device] Executing once (timeout {args.run_timeout}s).",
                      flush=True)
                completed = command(
                    base + ["shell", remote], timeout=args.run_timeout,
                    check=False)
                stdout = completed.stdout
                stderr = completed.stderr
                exit_code = completed.returncode
                print(stdout, end="" if stdout.endswith("\n") else "\n",
                      flush=True)
                if stderr:
                    print(stderr, file=sys.stderr)
                labels = re.findall(r"^RESULT=([A-Z0-9_]+)$",
                                    stdout, flags=re.MULTILINE)
                label = labels[-1] if labels else "NO_RESULT_MARKER"
                report.update({
                    "status": label,
                    "exitCode": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                })
            except DiagnosticError as exc:
                report.update({
                    "status": "HOST_TIMEOUT_OR_ADB_FAILURE",
                    "error": str(exc),
                })
                print(f"[device] {exc}", file=sys.stderr)
            finally:
                if staged:
                    cleanup = command(base + ["shell", "rm", "-f", remote],
                                      timeout=15, check=False)
                    if cleanup.returncode != 0:
                        print("[cleanup] Remote removal did not succeed: "
                              f"{cleanup.stderr.strip()}", file=sys.stderr)
                        report["cleanupWarning"] = cleanup.stderr.strip()
                    else:
                        print("[cleanup] Staged executable removed.", flush=True)

            path = record_report(report, args.output_dir.expanduser())
            print(f"[report] {path}", flush=True)
            if report["status"] == "PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY" \
                    and report.get("exitCode") == 0:
                print("RESULT=SAFE_PI_PREREQUISITES_VERIFIED_NOT_ROOT", flush=True)
                return 0
            print("[STOP] No confirmed diagnostic pass. "
                  "Do not retry repeatedly or attempt a CVE trigger.",
                  file=sys.stderr)
            return 3
    except DiagnosticError as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
