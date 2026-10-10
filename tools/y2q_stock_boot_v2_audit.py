#!/usr/bin/env python3
"""Read-only checksum-pinned Android boot image v2 header audit for HXL1.

Reported load addresses are header declarations, NOT measured Linux runtime
physical addresses, ABL handoff registers, or KASLR data.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

PINS = {
    "boot.img": "bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8",
    "kernel.bin": "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123",
    "ramdisk.img": "86b00ab1f20206ceedcc574423ef11417927aa1f773408ec2c2af4a855ea7586",
    "dtb.img": "a6104cdba11e0cd3d6ddaba6819098ab01f0dc0e8e7fd333137c88ad07d9d0ce",
}
EXPECTED_BOOT_BYTES = 67108864

class AuditError(ValueError):
    pass

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def pinned(path: Path, expected: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise AuditError("missing original artifact: " + str(path))
    data = path.read_bytes()
    if sha(data) != expected:
        raise AuditError("SHA256 mismatch: " + str(path))
    return data

def roundup(value: int, page: int) -> int:
    return (value + page - 1) // page * page

def boot_header(raw: bytes) -> dict:
    if len(raw) < 1660 or raw[:8] != b"ANDROID!":
        raise AuditError("invalid/truncated Android boot image")
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
     second_size, second_addr, tags_addr, page_size,
     version, os_version) = struct.unpack_from("<10I", raw, 8)
    recovery_size, recovery_offset, header_size, dtb_size, dtb_addr = (
        struct.unpack_from("<I", raw, 1632)[0],
        struct.unpack_from("<Q", raw, 1636)[0],
        struct.unpack_from("<I", raw, 1644)[0],
        struct.unpack_from("<I", raw, 1648)[0],
        struct.unpack_from("<Q", raw, 1652)[0],
    )
    if version != 2:
        raise AuditError("expected Android boot header v2")
    if page_size < 2048 or page_size > 65536 or page_size & (page_size-1):
        raise AuditError("invalid boot image page size")
    if not 1660 <= header_size <= page_size or not kernel_size or not ramdisk_size:
        raise AuditError("invalid header size or mandatory component")
    def clean(v: bytes) -> str:
        return v.split(b"\x00", 1)[0].decode("ascii", "replace")
    regions = {}
    cursor = page_size
    for name, size in (("kernel", kernel_size), ("ramdisk", ramdisk_size),
                       ("second", second_size)):
        regions[name] = {"offset": cursor, "size": size}
        cursor += roundup(size, page_size)
    if recovery_size:
        if cursor != recovery_offset:
            raise AuditError("recovery DTBO offset disagrees with page layout")
        regions["recovery_dtbo"] = {"offset": cursor, "size": recovery_size}
        cursor += roundup(recovery_size, page_size)
    regions["dtb"] = {"offset": cursor, "size": dtb_size}
    for part in regions.values():
        if part["offset"] > len(raw) or part["size"] > len(raw) - part["offset"]:
            raise AuditError("boot image component exceeds file bounds")
    return {
        "headerVersion": version, "headerSize": header_size, "pageSize": page_size,
        "boardName": clean(raw[48:64]),
        "cmdline": clean(raw[64:576]) + clean(raw[608:1632]),
        "osVersionRaw": os_version,
        "declaredAddressFields": {
            "kernel_addr": kernel_addr, "ramdisk_addr": ramdisk_addr,
            "second_addr": second_addr, "tags_addr": tags_addr,
            "dtb_addr": dtb_addr,
        },
        "regions": regions, "recoveryDtboOffset": recovery_offset,
        "recoveryDtboSize": recovery_size,
    }

def analyze(root: Path) -> dict:
    # boot.img is the only mandatory stand-alone artifact; its exact SHA256
    # always guards the header and embedded regions we inspect.
    boot = pinned(root / "boot.img", PINS["boot.img"])
    if len(boot) != EXPECTED_BOOT_BYTES:
        raise AuditError("original HXL1 boot.img size changed")
    h = boot_header(boot)
    checks = {}
    extracted = {"boot.img": "PRESENT_PIN_VERIFIED"}
    for component, filename in (("kernel", "kernel.bin"), ("ramdisk", "ramdisk.img"),
                                ("dtb", "dtb.img")):
        segment = h["regions"][component]
        data = boot[segment["offset"]:segment["offset"] + segment["size"]]
        embedded_hash = sha(data)
        reference = root / filename
        if reference.is_symlink():
            raise AuditError("original artifact is symlinked: " + str(reference))
        if reference.exists():
            external = pinned(reference, PINS[filename])
            file_status = "PRESENT_PIN_VERIFIED"
            exact_match = external == data
            external_size = len(external)
        else:
            file_status = "MISSING_OPTIONAL"
            exact_match = None  # Not False: absent separate copy cannot disagree.
            external_size = None
        extracted[filename] = file_status
        checks[component] = {
            "referenceArtifact": filename,
            "referenceFileStatus": file_status,
            "referenceSize": external_size,
            "headerDeclaredSize": len(data),
            "referenceEqualsImageRegion": exact_match,
            "imageRegionSha256": embedded_hash,
            "embeddedRegionMatchesPinnedSha256": embedded_hash == PINS[filename],
            "pinnedExpectedSha256": PINS[filename],
        }
    return {
        "firmware": "G986U1UESCHXL1",
        "originalBootImageHashVerified": True,
        "separateArtifactAvailability": extracted,
        "originalFileHashesVerified": all(
            state == "PRESENT_PIN_VERIFIED" for state in extracted.values()),
        "bootHeader": h,
        "payloadComparisons": checks,
        "runtimeKernelPhysicalAddressVerified": False,
        "originalBootloaderHandoffRegistersVerified": False,
        "deviceModified": False,
        "warning": "Header addresses are original boot.img declarations only. "
                   "An absent separately extracted component is not evidence "
                   "of corrupted boot.img; use embedded-region checksum separately. "
                   "ABL relocation and booted memory remain unverified.",
    }


def markdown(r: dict) -> str:
    h = r["bootHeader"]
    lines = ["# HXL1 original Android boot image v2", "",
             "**Original boot.img SHA-256 verified; no actual boot handoff measured.**",
             "", f"- Header: v{h['headerVersion']}",
             f"- Page size: {h['pageSize']} bytes",
             f"- Board name: {h['boardName']}",
             "", "## Original header declared addresses", "",
             "| Field | Value |", "|---|---|"]
    for name, value in h["declaredAddressFields"].items():
        lines.append(f"| {name} | 0x{value:x} |")
    lines += ["", "## Packed regions and independent artifact status", "",
              "| Region | Offset | Bytes | Separate file | Embedded SHA matches recorded pin | Same as separate file |",
              "|---|---|---:|---|---|---|"]
    for key in ("kernel", "ramdisk", "second", "dtb"):
        region = h["regions"][key]
        check = r["payloadComparisons"].get(key)
        status = check["referenceFileStatus"] if check else "NOT_APPLICABLE"
        pin_match = check["embeddedRegionMatchesPinnedSha256"] if check else "n/a"
        match = check["referenceEqualsImageRegion"] if check else "n/a"
        if match is None:
            match = "NOT_TESTED_MISSING_FILE"
        lines.append(f"| {key} | 0x{region['offset']:x} | {region['size']} | "
                     f"{status} | {pin_match} | {match} |")
    lines += ["", "An absent separately extracted component is not a checksum failure. "
              "If its embedded SHA matches the independently recorded pin, "
              "the original packed region is still verified. If it differs, "
              "report the discrepancy without calling it equivalent.",
              "Header fields do not establish Linux's true runtime physical base "
              "or Qualcomm ABL handoff.", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifacts", type=Path, default=Path.home()/"s20-artifacts")
    ap.add_argument("--output", type=Path, default=Path.home()
                    /"s20-artifacts/hxl1-research/stock-boot-v2-audit.json")
    args = ap.parse_args()
    output = args.output.expanduser().resolve()
    try:
        report = analyze(args.artifacts.expanduser().resolve())
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2)+"\n")
        output.with_suffix(".md").write_text(markdown(report))
    except (AuditError, OSError, struct.error) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[PASS] Original HXL1 boot.img SHA256")
    for name, status in report["separateArtifactAvailability"].items():
        print("[artifact]", name, status)
    for k, v in report["bootHeader"]["declaredAddressFields"].items():
        print("[header]", k, f"0x{v:x}")
    for k, v in report["payloadComparisons"].items():
        print("[payload]", k, "embedded_pin_match=", v["embeddedRegionMatchesPinnedSha256"],
              "matches_optional_file=", v["referenceEqualsImageRegion"])
    print("[report]", output)
    print("[report]", output.with_suffix(".md"))
    print("[LIMIT] Header addresses are NOT verified runtime kernel addresses")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
