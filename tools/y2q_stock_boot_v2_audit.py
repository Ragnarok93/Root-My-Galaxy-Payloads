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
    artifacts = {name: pinned(root/name, digest) for name, digest in PINS.items()}
    boot = artifacts["boot.img"]
    if len(boot) != 67108864:
        raise AuditError("original HXL1 boot.img size changed")
    h = boot_header(boot)
    checks = {}
    for component, filename in (("kernel", "kernel.bin"), ("ramdisk", "ramdisk.img"),
                                ("dtb", "dtb.img")):
        segment = h["regions"][component]
        data = boot[segment["offset"]:segment["offset"]+segment["size"]]
        checks[component] = {
            "referenceArtifact": filename,
            "referenceSize": len(artifacts[filename]),
            "headerDeclaredSize": len(data),
            "referenceEqualsImageRegion": data == artifacts[filename],
            "imageRegionSha256": sha(data),
        }
    return {
        "firmware": "G986U1UESCHXL1",
        "originalFileHashesVerified": True,
        "bootHeader": h,
        "payloadComparisons": checks,
        "runtimeKernelPhysicalAddressVerified": False,
        "originalBootloaderHandoffRegistersVerified": False,
        "deviceModified": False,
        "warning": "These addresses are original boot.img header declarations only; "
                   "ABL relocation and actual booted memory remain unverified.",
    }

def markdown(r: dict) -> str:
    h = r["bootHeader"]
    lines = ["# HXL1 original Android boot image v2", "",
             "**Original artifacts hash-verified; no actual boot handoff measured.**",
             "", f"- Header: v{h['headerVersion']}",
             f"- Page size: {h['pageSize']} bytes",
             f"- Board name: {h['boardName']}",
             "", "## Original header declared addresses", "",
             "| Field | Value |", "|---|---|"]
    for name, value in h["declaredAddressFields"].items():
        lines.append(f"| {name} | 0x{value:x} |")
    lines += ["", "## Packing and original component agreement", "",
              "| Region | Offset | Bytes | Matches pinned extraction |",
              "|---|---|---:|---|"]
    for key in ("kernel", "ramdisk", "second", "dtb"):
        region = h["regions"][key]
        check = r["payloadComparisons"].get(key)
        lines.append(f"| {key} | 0x{region['offset']:x} | {region['size']} | "
                     f"{check['referenceEqualsImageRegion'] if check else 'n/a'} |")
    lines += ["", "Header-provided addresses do not establish the true "
              "runtime physical kernel base or Qualcomm ABL handoff.", ""]
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
    print("[PASS] Original boot.img/kernel.bin/ramdisk.img/dtb.img hashes")
    for k, v in report["bootHeader"]["declaredAddressFields"].items():
        print("[header]", k, f"0x{v:x}")
    for k, v in report["payloadComparisons"].items():
        print("[payload]", k, "identical_to_reference=",v["referenceEqualsImageRegion"])
    print("[report]", output)
    print("[report]", output.with_suffix(".md"))
    print("[LIMIT] Header addresses are NOT verified runtime kernel addresses")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
