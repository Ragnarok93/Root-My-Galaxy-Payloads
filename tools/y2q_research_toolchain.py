#!/usr/bin/env python3
"""Reproducible HXL1 Root-My-Galaxy research pipeline (never enables root).

Commands:
  scan        Verify HXL1 evidence, audited Samsung source and optional images.
  build-probe Compile an inert Android ARM64 .so that ONLY checks device identity.
  bundle      Package the report and read-only .so with checksums for local review.
  references  Print device constraints and relevant GhostLock reference ports.

Neither a scan classification nor a built ELF grants root, and no generated
file is eligible for the Root-My-Galaxy support feed. No direct ADB operations,
device writes, exploit execution, module loading or firmware modifications.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from assess_y2q_root_candidate import (
    FIRMWARE, MODEL, DEVICE, RELEASE, BUILD, inspect_configuration,
    inspect_source, inspect_boot_file, make_report,
)
from prepare_samsung_vdso_compat import source_gate

ROOT = Path(__file__).resolve().parents[1]
PROBE_SOURCE = ROOT / "research/y2q-G986U1UESCHXL1/diagnostic_payload.c"
DEFAULT_EVIDENCE = ROOT / "research/y2q-G986U1UESCHXL1/evidence.json"
PROFILE = "y2q-G986U1UESCHXL1"
SHARED_LIBRARY = PROFILE + "-identity-diagnostic.so"
RESEARCH_KIND = "RMG_HXL1_READ_ONLY_IDENTITY_NOT_ROOT"
REFERENCES = (
    {
        "repository": "NebuSec/CyberMeowfia",
        "path": "IonStack/CVE-2026-43499",
        "role": "Original public disclosure/reference; not a Samsung y2q port",
        "targetMatch": False,
    },
    {
        "repository": "ccp-p/ghostlock-cve-2026-43499-4.19-k40",
        "path": "README.md",
        "role": "Qualcomm Linux 4.19.157 example, different vendor device",
        "targetMatch": False,
    },
    {
        "repository": "XiaoBaiLovesStirring/ghostlock-k419-adapter",
        "path": "README_K419.md",
        "role": "4.19.152-perf+ adapter, no Samsung HXL1 verification",
        "targetMatch": False,
    },
    {
        "repository": "wxxsfxyzm/GhostLock-Galaxy",
        "path": "README.md",
        "role": "Shizuku/ADB shell launcher pattern, Galaxy Z Fold6 6.1",
        "targetMatch": False,
    },
    {
        "repository": "Meowkis/ghostlock-samsung-research",
        "path": "README.md",
        "role": "Samsung per-firmware provenance practice, S23 Ultra",
        "targetMatch": False,
    },
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_input(path, label):
    path = Path(path).expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise ValueError(label + " must be an existing ordinary file")
    return path


def output_path(path, sources=()):
    path = Path(path).expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to overwrite output: " + str(path))
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("output parent must already exist and be a regular directory")
    for original in sources:
        source = Path(original).expanduser().resolve()
        if path == source or source in path.parents:
            raise ValueError("cannot write inside an original evidence/source tree")
    return path


def identity_ok(profile):
    expected = {
        "model": MODEL,
        "codename": DEVICE,
        "firmware": FIRMWARE,
        "kernelRelease": RELEASE,
        "fingerprint": BUILD,
    }
    if not isinstance(profile, dict):
        raise ValueError("missing research device profile")
    if any(profile.get(field) != value for field, value in expected.items()):
        raise ValueError("exact firmware, model, fingerprint or uname identity mismatch")


def load_candidate(path):
    data = json.loads(valid_input(path, "scan report").read_text(encoding="utf-8"))
    identity_ok(data.get("device"))
    candidate = data.get("candidatePayload", {})
    if (data.get("format") != "root-my-galaxy-offline-research-candidate"
            or data.get("cve") != "CVE-2026-43499"
            or candidate.get("executable") is not False
            or candidate.get("rootGranted") is not False
            or candidate.get("deploymentBlocked") is not True
            or candidate.get("allowRegistrationInSupportFeed") is not False
            or not data.get("unmetGates")):
        raise ValueError("unsafe or invalid research candidate; no payload build permitted")
    return data


def command_scan(args):
    evidence_file = valid_input(args.evidence, "evidence")
    audit_file = valid_input(args.audit_json, "stock-source audit")
    stock = Path(args.stock_source).expanduser().resolve()
    if not stock.is_dir() or stock.is_symlink():
        raise ValueError("stock source must be an existing real directory")
    output = output_path(args.output, sources=(stock,))
    evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    checked = inspect_configuration(evidence)
    audit = source_gate(stock, audit_file)
    report_source = inspect_source(stock)
    report_source["sourceAudit"] = {
        "firmware": FIRMWARE,
        "originalKernelMakefile": audit["makefileVersion"]["matchesExpected"],
        "verifiedOverlayFiles": audit["overlayVerification"]["verified"],
        "deviceConfigHashesVerified": all(
            item["matchesOfficialAudit"] for item in audit["deviceConfigs"].values()
        ),
    }
    image_checks = {}
    for key, path in (("boot.img", args.boot_img), ("kernel.bin", args.kernel_bin)):
        if path:
            digest = checked["sourceArtifactHashes"].get(key)
            if not digest:
                raise ValueError("no expected firmware digest for " + key)
            image_checks[key] = inspect_boot_file(Path(path), digest, key)
    research = make_report(evidence, report_source, image_checks)
    research["referenceComparison"] = list(REFERENCES)
    research["sourceEvidenceSha256"] = sha256(evidence_file)
    research["pipelineKind"] = RESEARCH_KIND
    with output.open("x", encoding="utf-8") as target:
        json.dump(research, target, indent=2)
        target.write("\n")
    print("RESEARCH SCAN COMPLETE:", output)
    print("Source heuristic:", report_source["classification"])
    print("Deployable: NO; not an exploit or root validation.")


def verify_elf_shared_aarch64(path):
    with path.open("rb") as library:
        header = library.read(20)
    if (len(header) != 20 or header[:4] != b"\x7fELF"
            or header[4:6] != bytes((2, 1))
            or header[16:18] != bytes((3, 0))
            or header[18:20] != bytes((183, 0))):
        raise ValueError("expected ARM64 little-endian ELF64 ET_DYN shared library")


def validate_ndk(ndk):
    ndk = Path(ndk).expanduser().resolve()
    if not ndk.is_dir():
        raise ValueError("Android NDK directory not found")
    cc = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
    if not cc.is_file() or not os.access(cc, os.X_OK):
        raise ValueError("Android NDK API33 ARM64 Clang missing: " + str(cc))
    return cc


def command_build_probe(args):
    scan = load_candidate(args.scan_report)
    scan_path = valid_input(args.scan_report, "scan report")
    output = output_path(args.output, sources=(ROOT / "research",))
    manifest_file = output_path(args.manifest, sources=(ROOT / "research",))
    if output == manifest_file:
        raise ValueError("ELF output and manifest paths must be different")
    clang = validate_ndk(args.ndk)
    source = valid_input(PROBE_SOURCE, "inert probe source")
    flags = [
        str(clang), "-std=c11", "-O2", "-g0", "-fPIC", "-shared",
        "-fvisibility=hidden", "-fstack-protector-strong",
        "-Wall", "-Wextra", "-Werror", "-Wl,--no-undefined",
        str(source),
    ]
    # Compile to a temporary, auto-deleted object before publishing anything.
    with tempfile.TemporaryDirectory(prefix="rmg-y2q-diagnostic-") as folder:
        compiled = Path(folder) / SHARED_LIBRARY
        proc = subprocess.run(
            flags + ["-o", str(compiled)], capture_output=True,
            text=True, timeout=90, check=False,
        )
        if proc.returncode != 0 or not compiled.is_file():
            raise ValueError("read-only NDK diagnostic compilation failed: " +
                             (proc.stdout + proc.stderr)[-1200:])
        verify_elf_shared_aarch64(compiled)
        binary = compiled.read_bytes()
    info = {
        "schemaVersion": 1,
        "kind": RESEARCH_KIND,
        "device": scan["device"],
        "payload": {
            "file": output.name,
            "sha256": hashlib.sha256(binary).hexdigest(),
            "sizeBytes": len(binary),
            "arch": "aarch64",
            "elf": "ELF64 ET_DYN",
            "function": "rmg_y2q_probe_status",
            "purpose": "read-only firmware identity only",
        },
        "originalSourceSha256": sha256(source),
        "scanReportSha256": sha256(scan_path),
        "compilation": {
            "compiler": "Android NDK Clang for API33 ARM64",
            "flags": flags[1:],
        },
        "executableExploit": False,
        "rootVerified": False,
        "kernelWriteCapability": False,
        "moduleLoadCapability": False,
        "publishInSupportFeed": False,
        "deploymentBlocked": True,
    }
    # Exclusive writes. The files live only in caller-chosen WSL output paths.
    with output.open("xb") as destination:
        destination.write(binary)
    with manifest_file.open("x", encoding="utf-8") as destination:
        json.dump(info, destination, indent=2)
        destination.write("\n")
    print("ARM64 diagnostic .so CREATED:", output)
    print("SHA-256:", info["payload"]["sha256"])
    print("Manifest:", manifest_file)
    print("NOT ROOT; NO EXPLOIT; NOT INCLUDED IN APP PAYLOAD FEED.")


def command_bundle(args):
    scan_path = valid_input(args.scan_report, "scan report")
    manifest_path = valid_input(args.manifest, "payload manifest")
    library_path = valid_input(args.library, "ARM64 diagnostic library")
    scan = load_candidate(scan_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    identity_ok(manifest.get("device"))
    if (manifest["device"] != scan["device"]
            or manifest.get("kind") != RESEARCH_KIND
            or manifest.get("deploymentBlocked") is not True
            or manifest.get("publishInSupportFeed") is not False
            or manifest.get("executableExploit") is not False
            or manifest.get("rootVerified") is not False
            or manifest.get("kernelWriteCapability") is not False
            or manifest.get("moduleLoadCapability") is not False
            or manifest.get("scanReportSha256") != sha256(scan_path)
            or manifest.get("payload", {}).get("file") != SHARED_LIBRARY
            or manifest["payload"]["sha256"] != sha256(library_path)
            or manifest["payload"]["sizeBytes"] != library_path.stat().st_size):
        raise ValueError("manifest has wrong exact firmware / hash / deployability state")
    verify_elf_shared_aarch64(library_path)
    output = output_path(args.output, sources=(ROOT / "research",))
    readme = (
        "Root-My-Galaxy / Galaxy S20+ SM-G986U1 HXL1\\n"
        "RESEARCH-ONLY DEVICE IDENTITY DIAGNOSTIC\\n"
        "This package contains no root exploit, kernel writes or KernelSU.\\n"
        "DO NOT register in support/targets-v3.json or execute as an exploit.\\n"
    ).replace("\\n", "\n").encode("utf-8")
    files = {
        "README.txt": readme,
        "candidate.json": scan_path.read_bytes(),
        "diagnostic-manifest.json": manifest_path.read_bytes(),
        SHARED_LIBRARY: library_path.read_bytes(),
    }
    with output.open("xb") as destination:
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as package:
            for name in sorted(files):
                entry = zipfile.ZipInfo(name, (2026, 10, 9, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o644 << 16
                package.writestr(entry, files[name])
    print("RESEARCH-ONLY BUNDLE:", output)
    print("SHA-256:", sha256(output))
    print("All files exact-HXL1; no root exploit included.")


def command_references(args):
    data = {
        "device": {
            "model": MODEL, "codename": DEVICE, "firmware": FIRMWARE,
            "kernelRelease": RELEASE, "fingerprint": BUILD,
        },
        "references": list(REFERENCES),
        "crossDeviceValuesReusable": False,
        "actualFirmwareVulnerabilityProven": False,
        "supportedExploitAvailable": False,
        "caution": "Do not run foreign prebuilt GhostLock binaries, import offsets or publish HXL1 in production feed.",
    }
    print(json.dumps(data, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="audited source + exact firmware identity and CVE heuristic")
    scan.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    scan.add_argument("--audit-json", type=Path, required=True)
    scan.add_argument("--stock-source", type=Path, required=True)
    scan.add_argument("--boot-img", type=Path)
    scan.add_argument("--kernel-bin", type=Path)
    scan.add_argument("--output", type=Path, required=True)
    scan.set_defaults(action=command_scan)
    build = sub.add_parser("build-probe", help="compile inert identity-only ARM64 shared library")
    build.add_argument("--scan-report", type=Path, required=True)
    build.add_argument("--ndk", type=Path, default=os.environ.get("ANDROID_NDK_HOME", ""))
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--manifest", type=Path, required=True)
    build.set_defaults(action=command_build_probe)
    bundle = sub.add_parser("bundle", help="package inert probe with locked firmware research metadata")
    bundle.add_argument("--scan-report", type=Path, required=True)
    bundle.add_argument("--library", type=Path, required=True)
    bundle.add_argument("--manifest", type=Path, required=True)
    bundle.add_argument("--output", type=Path, required=True)
    bundle.set_defaults(action=command_bundle)
    reference = sub.add_parser("references", help="offline version-scoped GhostLock reference matrix")
    reference.set_defaults(action=command_references)
    args = parser.parse_args()
    try:
        args.action(args)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
