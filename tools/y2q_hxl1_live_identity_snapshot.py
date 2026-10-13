#!/usr/bin/env python3
"""Collect one read-only, non-root HXL1 device identity snapshot via ADB.

A successful result confirms ONLY running device/kernel/firmware identity and
exposes a device-tree identity if readable. It cannot authenticate bootloader
physical handoff, GhostLock exploitability, credential writes, or KernelSU.
No adb root, su, reboot, exploit, flash, or device-side file modifications.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

TARGET = "SM-G986U1"
FIRMWARE = "G986U1UESCHXL1"
KERNEL = "4.19.113"
MAX_CAPTURE = 256 * 1024
PROPS = (
    "ro.product.model", "ro.product.device", "ro.build.fingerprint",
    "ro.build.display.id", "ro.bootloader", "ro.build.version.release",
    "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state", "ro.boot.dtbo_idx",
)
READS = {
    "kernelRelease": ("shell", "uname", "-r"),
    "kernelArchitecture": ("shell", "uname", "-m"),
    "kernelVersion": ("shell", "cat", "/proc/version"),
    "dtModel": ("exec-out", "cat", "/proc/device-tree/model"),
    "dtCompatible": ("exec-out", "cat", "/proc/device-tree/compatible"),
}
class SnapshotError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise SnapshotError(message)

def select_device(output: str, serial: str | None) -> str:
    found = {}
    for line in output.replace("\r", "").splitlines():
        fields = line.strip().split()
        if len(fields) < 2 or fields[0] == "List" or fields[0].startswith("*"):
            continue
        if fields[1] in ("device", "offline", "unauthorized"):
            found[fields[0]] = fields[1]
    if serial is not None:
        require(serial in found, "Specified ADB serial not found")
        require(found[serial] == "device", "Specified device is not authorized/online")
        return serial
    ready = [key for key, state in found.items() if state == "device"]
    require(len(ready) == 1, "Expected exactly one authorized online ADB device; use --serial")
    return ready[0]

def decode_value(name: str, data: bytes) -> str | list[str]:
    require(len(data) <= MAX_CAPTURE, "Oversize device response: " + name)
    if name == "dtCompatible":
        return [part.decode("utf-8", "replace").strip() for part in
                data.rstrip(b"\x00").split(b"\x00") if part]
    return data.decode("utf-8", "replace").replace("\x00", "").strip()

def run_cmd(adb: str, serial: str | None, args: tuple[str, ...], timeout: int):
    cmd = [adb]
    if serial is not None:
        cmd.extend(("-s", serial))
    cmd.extend(args)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    require(len(p.stdout) <= MAX_CAPTURE and len(p.stderr) <= MAX_CAPTURE,
            "Unbounded ADB response")
    return p.returncode, p.stdout, p.stderr

def check_identity(properties: dict[str, str], reads: dict) -> dict:
    model = properties.get("ro.product.model", "")
    fingerprint = properties.get("ro.build.fingerprint", "")
    display = properties.get("ro.build.display.id", "")
    release = reads.get("kernelRelease", {}).get("value", "")
    arch = reads.get("kernelArchitecture", {}).get("value", "")
    conditions = {
        "modelMatches": model == TARGET,
        "firmwareMatches": FIRMWARE in fingerprint or FIRMWARE in display,
        "kernelMatches": isinstance(release, str) and release.startswith(KERNEL),
        "arm64Matches": arch in ("aarch64", "arm64"),
    }
    return {
        "conditions": conditions,
        "identityConsistentWithTarget": all(conditions.values()),
        "stockImageByteIdentityEstablished": False,
        "bootloaderPhysicalKernelHandoffProven": False,
        "kernelRootOrKernelSuProven": False,
        "exploitationPerformed": False,
    }

def collect(adb: str, serial: str | None = None, timeout: int = 12) -> dict:
    rc, listing, stderr = run_cmd(adb, None, ("devices", "-l"), timeout)
    require(rc == 0, "adb devices failed: " + stderr.decode("utf-8", "replace")[-350:])
    selected = select_device(listing.decode("utf-8", "replace"), serial)
    props, reads = {}, {}
    for prop in PROPS:
        rc, value, err = run_cmd(adb, selected, ("shell", "getprop", prop), timeout)
        val = decode_value(prop, value)
        props[prop] = str(val) if rc == 0 else ""
        reads["getprop:" + prop] = {"state": "READ" if rc == 0 else "UNAVAILABLE",
                                    "value": props[prop],
                                    "error": err.decode("utf-8", "replace")[-300:] if rc else ""}
    device_reads = {}
    for name, command in READS.items():
        rc, value, err = run_cmd(adb, selected, command, timeout)
        decoded = decode_value(name, value)
        device_reads[name] = {"state": "READ" if rc == 0 else "UNAVAILABLE",
                              "value": decoded if rc == 0 else None,
                              "error": err.decode("utf-8", "replace")[-300:] if rc else ""}
    return {"schemaVersion": 1, "target": TARGET, "firmware": FIRMWARE,
            "scope": "READ_ONLY_UNPRIVILEGED_DEVICE_IDENTITY",
            "captureTimestampUTC": datetime.now(timezone.utc).isoformat(),
            "adbProgram": adb, "deviceSerialSha256": hashlib.sha256(selected.encode()).hexdigest(),
            "properties": props, "propertyReadOutcomes": reads,
            "deviceReads": device_reads,
            "checks": check_identity(props, device_reads),
            "stage4Complete": False, "stage5Complete": False, "rootVerified": False}

def resolve_adb(adb: str | None, serial: str | None = None, timeout: int = 12) -> str:
    """Prefer a client that actually sees the device, not merely one on PATH."""
    if adb:
        candidate = shutil.which(adb)
        require(candidate is not None, "Specified ADB binary does not exist")
        return candidate

    candidates = []
    for name in ("adb.exe", "adb"):
        candidate = shutil.which(name)
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    require(bool(candidates), "No adb.exe/adb executable on PATH; supply --adb")

    diagnostics = []
    for candidate in candidates:
        try:
            rc, listing, stderr = run_cmd(candidate, None, ("devices", "-l"), timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            diagnostics.append(f"{candidate}: unavailable ({type(exc).__name__})")
            continue
        if rc:
            diagnostics.append(f"{candidate}: ADB error (exit {rc})")
            continue
        text = listing.decode("utf-8", "replace")
        statuses = [line.strip().split()[1] for line in text.replace("\\r", "").splitlines()
                    if len(line.strip().split()) > 1
                    and line.strip().split()[1] in ("device", "offline", "unauthorized")]
        try:
            select_device(text, serial)
        except SnapshotError:
            diagnostics.append(f"{candidate}: online={statuses.count('device')}, "
                               f"unauthorized={statuses.count('unauthorized')}, "
                               f"offline={statuses.count('offline')}")
            continue
        return candidate

    raise SnapshotError(
        "No ADB backend sees the selected single authorized device. "
        + "; ".join(diagnostics)
        + ". Enable USB debugging, approve the USB authorization prompt, "
        "check the USB data connection, or specify --adb / --serial.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", help="Path to adb.exe or adb (auto-detected otherwise)")
    parser.add_argument("--serial", help="ADB serial if more than one device online")
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        require(2 <= args.timeout <= 60, "Timeout must be between 2 and 60 seconds")
        output = args.output_dir or (
            Path.home() / "s20-artifacts/hxl1-research" /
            ("device-identity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
        output = output.expanduser().absolute()
        require(not output.exists() and not output.is_symlink(),
                "A fresh output directory is required")
        result = collect(resolve_adb(args.adb, args.serial, args.timeout), args.serial, args.timeout)
        output.mkdir(parents=True, exist_ok=False)
        destination = output / "identity.json"
        destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("[DEVICE IDENTITY MATCHES HXL1]",
              "YES" if result["checks"]["identityConsistentWithTarget"] else "NO")
        print("[BOOTLOADER HANDOFF PROVEN] NO")
        print("[ROOT VERIFIED] NO")
        print("[SNAPSHOT]", destination)
        return 0 if result["checks"]["identityConsistentWithTarget"] else 2
    except (SnapshotError, OSError, subprocess.TimeoutExpired) as e:
        print("[STOP]", e, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
