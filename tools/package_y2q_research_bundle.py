#!/usr/bin/env python3
"""Package firmware-locked y2q identity probe + research evidence (not root).

The archive is diagnostic-only. It has no privilege-escalation code,
boot image, kernel module, installation script, autostart or network access.
"""
import argparse
import hashlib
import json
import os
import struct
import zipfile
from pathlib import Path

from assess_y2q_root_candidate import MODEL, DEVICE, RELEASE, BUILD, FIRMWARE


def hash_data(data):
    return hashlib.sha256(data).hexdigest()


def check_arm64_executable(blob):
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise ValueError("identity probe must be a real ELF binary")
    if blob[4:6] != b"\x02\x01":
        raise ValueError("identity probe must be ELF64 little-endian")
    if struct.unpack_from("<H", blob, 18)[0] != 183:
        raise ValueError("identity probe is not an AArch64 binary")
    kind = struct.unpack_from("<H", blob, 16)[0]
    if kind not in (2, 3):
        raise ValueError("identity probe must be an ARM64 executable or PIE")
    return {"ELF64": True, "littleEndian": True, "machine": "AARCH64",
            "elfType": "ET_EXEC" if kind == 2 else "ET_DYN"}


def check_candidate(candidate):
    expected = {
        "model": MODEL, "codename": DEVICE, "firmware": FIRMWARE,
        "kernelRelease": RELEASE, "fingerprint": BUILD,
    }
    if candidate.get("device") != expected:
        raise ValueError("candidate does not match exact y2q firmware identity")
    if candidate.get("cve") != "CVE-2026-43499":
        raise ValueError("candidate CVE mismatch")
    if candidate.get("format") != "root-my-galaxy-offline-research-candidate":
        raise ValueError("incorrect candidate format")
    payload = candidate.get("candidatePayload")
    required = {
        "kind": "metadata-only-non-executable", "executable": False,
        "rootGranted": False, "readyToInstall": False,
        "deviceTested": False, "allowRegistrationInSupportFeed": False,
        "deploymentBlocked": True,
    }
    if not isinstance(payload, dict) or any(payload.get(k) != v
                                            for k, v in required.items()):
        raise ValueError("candidate is not demonstrably nondeployable")
    if payload.get("privilegeEscalationPayload") is not None:
        raise ValueError("archive cannot contain a privilege-escalation payload")
    if payload.get("kernelSuArtifact") is not None:
        raise ValueError("archive cannot contain a kernel module")
    if not candidate.get("unmetGates"):
        raise ValueError("candidate must retain unresolved verification gates")


def write_archive(out, report, probe):
    readme = (
        "SAMSUNG S20+ HXL1 -- RESEARCH DIAGNOSTICS ONLY\n"
        "Model SM-G986U1; firmware G986U1UESCHXL1; kernel 4.19.113-27095354.\n"
        "The ELF program included is ONLY the pre-existing firmware ID probe.\n"
        "No rooting, exploit, persistence, kernel writes, KernelSU install, or\n"
        "bootloader unlocking functionality is included. Nothing runs on open.\n"
        "No support-feed registration or firmware modifications.\n"
    ).encode("utf-8")
    report_content = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    binary = probe.read_bytes()
    validate = check_arm64_executable(binary)
    entries = {
        "README.txt": readme,
        "candidate.json": report_content,
        "y2q-identity-probe": binary,
    }
    manifest = {
        "schema": 1,
        "purpose": "offline-research-bundle",
        "firmware": FIRMWARE,
        "executableRootPayload": False,
        "kernelSuIncluded": False,
        "probeELF": validate,
        "files": {name: {"size": len(data), "sha256": hash_data(data)}
                  for name, data in entries.items()},
    }
    entries["bundle-manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True)
                                       + "\n").encode("utf-8")
    with zipfile.ZipFile(out, "x", compression=zipfile.ZIP_STORED) as dest:
        for name in sorted(entries):
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zi.external_attr = (0o100755 if name == "y2q-identity-probe"
                                else 0o100644) << 16
            dest.writestr(zi, entries[name])
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--identity-probe", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        source = args.candidate.expanduser().resolve()
        probe = args.identity_probe.expanduser().resolve()
        out = args.out.expanduser().absolute()
        if not source.is_file() or not probe.is_file():
            raise ValueError("candidate JSON and identity ELF must exist")
        if source.is_symlink() or probe.is_symlink():
            raise ValueError("cannot package symlink inputs")
        if out.exists() or out.is_symlink():
            raise ValueError("refusing to overwrite existing research bundle")
        if not out.parent.is_dir() or out.parent.is_symlink():
            raise ValueError("output parent must exist and be an ordinary directory")
        report = json.loads(source.read_text(encoding="utf-8"))
        check_candidate(report)
        manifest = write_archive(out, report, probe)
        print("Diagnostic-only bundle:", out)
        print("Identity executable:", manifest["probeELF"]["machine"])
        print("Root payload included: NO")
        print("KernelSU module included: NO")
        print("SHA-256:", hash_data(out.read_bytes()))
    except (OSError, ValueError, KeyError, struct.error, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
