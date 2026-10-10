#!/usr/bin/env python3
"""Read-only ADB boot-memory and DT evidence for exact HXL1 S20+.

Host writes only. No reboot, root, exploit, app install, adb push, pull,
partition write, kernel module, settings mutation or binary execution.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

EXPECTED = {
    "ro.product.model": "SM-G986U1",
    "ro.product.device": "y2q",
    "ro.boot.bootloader": "G986U1UESCHXL1",
    "ro.build.fingerprint": "samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys",
    "ro.boot.flash.locked": "1",
    "ro.boot.vbmeta.device_state": "locked",
}
KERNEL = "4.19.113-27095354"
OTHER_PROPERTIES = (
    "ro.build.version.release", "ro.build.version.sdk",
    "ro.boot.verifiedbootstate", "ro.boot.veritymode",
    "ro.boot.slot_suffix", "ro.boot.hardware", "ro.boot.bootreason",
    "ro.boot.dtbo_idx", "ro.boot.dtb_idx",
)
FILES = {
    "proc_cmdline": "/proc/cmdline",
    "proc_bootconfig": "/proc/bootconfig",
    "proc_iomem": "/proc/iomem",
    "proc_dt_bootargs": "/proc/device-tree/chosen/bootargs",
    "sys_dt_bootargs": "/sys/firmware/devicetree/base/chosen/bootargs",
    "proc_dt_model": "/proc/device-tree/model",
    "sys_dt_model": "/sys/firmware/devicetree/base/model",
    "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
    "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
}
# Never save unique IDs or entropy seeds from bootargs/cmdline.
SECRET = re.compile(
    r"(?i)(?<!\S)([A-Za-z0-9_.-]*(?:serial|imei|meid|macaddr|"
    r"wifimac|btmac|unique|hwuid|deviceid|chipid|seed|token|"
    r"secret|password|passwd|key)[A-Za-z0-9_.-]*)(=|:)(\S+)"
)
RANGE = re.compile(r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*)$")
MAX_OUTPUT = 262144


class Stop(RuntimeError):
    pass


def redact(text: str) -> str:
    clean = text.replace("\x00", " ").replace("\r", "")
    return SECRET.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", clean)


def command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    if not argv or argv[0] != "adb":
        raise Stop("Only local adb is allowed")
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              errors="replace", timeout=15, check=False)
    except FileNotFoundError as e:
        raise Stop("Linux adb missing from PATH") from e
    except subprocess.TimeoutExpired as e:
        raise Stop("ADB command timed out") from e


def choose(serial: str | None) -> str:
    r = command(["adb", "devices"])
    if r.returncode != 0:
        raise Stop("adb devices failed: " + redact(r.stderr)[:200])
    online = []
    for line in r.stdout.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 2 and cols[1] == "device":
            online.append(cols[0])
    if serial is not None:
        if serial not in online:
            raise Stop("Specified ADB serial not online or authorized")
        return serial
    if len(online) != 1:
        raise Stop("Expected one authorized device (or supply --serial); found " +
                   str(len(online)))
    return online[0]


def required(serial: str, args: list[str]) -> str:
    r = command(["adb", "-s", serial, "shell", *args])
    if r.returncode != 0:
        raise Stop("Required identity command failed: " +
                   redact(r.stderr or r.stdout)[:200])
    return r.stdout.strip()


def identity(serial: str) -> dict:
    values = {}
    for prop, expected in EXPECTED.items():
        actual = required(serial, ["getprop", prop])
        if actual != expected:
            raise Stop("Stock-HXL1 identity mismatch " + prop +
                       "; expected " + expected + ", observed " + redact(actual))
        values[prop] = actual
    release = required(serial, ["uname", "-r"])
    uid = required(serial, ["id", "-u"])
    if release != KERNEL or uid != "2000":
        raise Stop("Expected original kernel release and unprivileged uid 2000; "
                   "observed kernel=" + redact(release) + " uid=" + redact(uid))
    values["kernelRelease"] = release
    values["adbShellUid"] = uid
    return values


def optional_file(serial: str, path: str) -> dict:
    try:
        r = command(["adb", "-s", serial, "shell", "cat", path])
    except Stop as e:
        return {"status": "ADB_ERROR_OR_TIMEOUT", "error": str(e)}
    if r.returncode != 0:
        error = redact(r.stderr or r.stdout).strip()[:300]
        if "Permission denied" in error or "Operation not permitted" in error:
            status = "PERMISSION_DENIED"
        elif "No such file" in error:
            status = "NOT_PRESENT"
        else:
            status = "READ_FAILED"
        return {"status": status, "error": error}
    if len(r.stdout) > MAX_OUTPUT:
        return {"status": "OVER_LIMIT", "observedCharacters": len(r.stdout)}
    contents = redact(r.stdout).strip()
    return {"status": "READ_OK" if contents else "EMPTY", "text": contents}


def iomem_classification(result: dict) -> dict:
    if result.get("status") != "READ_OK":
        return {"status": "UNAVAILABLE", "kernelEntryVerified": False}
    ranges = []
    for line in result.get("text", "").splitlines():
        m = RANGE.match(line)
        if m:
            ranges.append((int(m.group(1),16), int(m.group(2),16), m.group(3)))
    if not ranges:
        label = "NO_PARSEABLE_RANGES"
    elif all(a == 0 and b == 0 for a,b,_ in ranges):
        label = "ALL_ZERO_RANGES_NOT_USABLE"
    else:
        label = "NONZERO_RANGES_VISIBLE_BUT_NOT_KERNEL_HANDOFF_PROOF"
    return {"status": label, "rangeCount": len(ranges),
            "kernelRegionLabels": [name for _,_,name in ranges
                                   if "kernel" in name.lower()][:20],
            "kernelEntryVerified": False}


def collect(serial: str) -> dict:
    verified = identity(serial)
    props = {}
    for name in OTHER_PROPERTIES:
        try:
            props[name] = redact(required(serial, ["getprop",name]))
        except Stop:
            props[name] = "[UNAVAILABLE]"
    def aux(args: list[str]) -> str:
        try:
            return redact(required(serial, args))
        except Stop:
            return "[UNAVAILABLE]"
    files = {key: optional_file(serial, path) for key,path in FILES.items()}
    return {
        "schema": 1,
        "status": "READ_ONLY_EXACT_HXL1_ANDROID_ADB_EVIDENCE",
        "identity": verified, "bootProperties": props,
        "selinux": aux(["getenforce"]), "pageSize": aux(["getconf","PAGESIZE"]),
        "fileObservations": files,
        "iomem": iomem_classification(files["proc_iomem"]),
        "bootloaderKernelBaseAddrObserved": False,
        "bootloaderBaseMemoryObserved": False,
        "runtimeKaslrMeasured": False,
        "physicalKernelEntryVerified": False,
        "runningDtbMatchedToBootloaderSelection": False,
        "deviceModified": False,
        "privacy": "Only allowlisted reads, identifiers and seed-like bootargs redacted.",
    }


def markdown(report: dict) -> str:
    text = ["# HXL1 S20+ live read-only ADB evidence", "",
            "Stock identity: SM-G986U1 / y2q / G986U1UESCHXL1",
            "Kernel: " + report["identity"]["kernelRelease"],
            "Shell UID: " + report["identity"]["adbShellUid"],
            "SELinux: " + report["selinux"],
            "Page size: " + report["pageSize"], "",
            "## Verified boot properties", ""]
    for k,v in report["bootProperties"].items():
        text.append("- " + k + ": " + v)
    for name,obs in report["fileObservations"].items():
        text.extend(["", "## " + name, "", "Status: " + obs["status"], ""])
        if obs.get("text"):
            text.extend(["~~~text", obs["text"], "~~~"])
        if obs.get("error"):
            text.append("Error: " + obs["error"])
    text.extend(["", "## IOMEM classification",
                 report["iomem"]["status"], "",
                 "A zero-valued or hidden memory map is not a physical address.",
                 "Even visible memory ranges alone do not establish the ABL kernel-entry target.", "",
                 "## Proof boundary",
                 "This ADB shell cannot directly observe bootloader UEFI runtime variables, "
                 "selected BaseMemory, per-boot KASLR, or actual kernel handoff. "
                 "No phone writes, privilege elevation, or exploit were performed.", ""])
    return "\n".join(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB serial if multiple devices")
    parser.add_argument("--out", type=Path, default=Path.home() /
                        "s20-artifacts/hxl1-research/live-adb")
    args = parser.parse_args()
    if shutil.which("adb") is None:
        print("[STOP] WSL2 adb not found", file=sys.stderr)
        return 2
    try:
        selected = choose(args.serial)
        report = collect(selected)
        folder = args.out / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        folder.mkdir(parents=True, exist_ok=False, mode=0o700)
        # Reports can contain non-unique memory-map addresses and build
        # arguments; protect all host-side evidence from other local users.
        json_report = folder / "live-boot-evidence.json"
        md_report = folder / "live-boot-evidence.md"
        with json_report.open("x") as sink:
            sink.write(json.dumps(report, indent=2) + "\n")
        with md_report.open("x") as sink:
            sink.write(markdown(report))
        json_report.chmod(0o600)
        md_report.chmod(0o600)
    except (Stop, OSError, ValueError) as e:
        print("[STOP]", redact(str(e)), file=sys.stderr)
        return 2
    print("[PASS] Exact S20+ HXL1 kernel/ADB shell identity")
    print("[IOMEM]", report["iomem"]["status"])
    for name,observation in report["fileObservations"].items():
        print("["+observation["status"]+"]", name)
    print("[REPORT]", folder/"live-boot-evidence.md")
    print("[LIMIT] No kernel physical load or bootloader KASLR value measured")
    return 0


if __name__ == "__main__":
    sys.exit(main())
