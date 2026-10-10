#!/usr/bin/env python3
"""Read-only stock HXL1 GhostLock symbol and image provenance cross-check.

Checks only pinned original image bytes, independently recovered kallsyms,
and an isolated upstream *static* analysis report. Not an exploit, an offset
harvester, a physical mapping oracle, or a KernelSU readiness gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

KERNEL_SHA256 = "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
KERNEL_BYTES = 51957772
EXPECTED_TEXT = 0xFFFFFF8008080000
EXPECTED_RELATIVE = 0xC7DB4
SAMPLE_LEN = 64
SAMPLE_SHA256 = "4428228c0bd3bb7bb6d742b9f43b28f0ff2316fc458fcd36a1aab59991b124c4"
RELEASE = "4.19.113-27095354"
DEFAULT_ROOT = Path.home() / "s20-artifacts"
NM_LINE = re.compile(r"^([0-9a-fA-F]{8,16})\s+(\S)\s+(\S+)(?:\s+.*)?$")


class AuditError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_symbols(nm_text: str) -> dict[str, int]:
    wanted = {"_text", "remove_waiter"}
    found: dict[str, set[int]] = {name: set() for name in wanted}
    for line in nm_text.splitlines():
        match = NM_LINE.fullmatch(line.strip())
        if not match:
            continue
        address, kind, name = match.groups()
        if name in wanted:
            if not kind.isalpha():
                raise AuditError(f"Invalid symbol kind for {name}")
            found[name].add(int(address, 16))
    for name in sorted(wanted):
        if len(found[name]) != 1:
            raise AuditError(f"{name}: missing/ambiguous original symbol ({len(found[name])})")
    return {name: next(iter(values)) for name, values in found.items()}


def parse_upstream_analysis(text: str, diagnostics: str, *,
                            expected_relative: int = EXPECTED_RELATIVE) -> dict[str, str]:
    if "== GhostLock kernel analysis ==" not in text:
        raise AuditError("Missing upstream static analysis heading")
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        m = re.fullmatch(r"(\S(?:.*?\S)?)\s{2,}(.+)", line)
        if not m:
            continue
        name, value = m.groups()
        if name in pairs:
            raise AuditError(f"Ambiguous upstream analysis field: {name}")
        pairs[name] = value.strip()
    required = {
        "release": RELEASE,
        "kernel_major": "4.19",
        "kernel_family": "unverified (no family layout will be emitted)",
        "rt_mutex_waiter": "(no rt_mutex_waiter type in BTF)",
        "mm_struct size": "(unavailable)",
        "pselect chain": "not attempted (no embedded BTF)",
        "suggested route": "none (low)",
    }
    for name, expected in required.items():
        if pairs.get(name) != expected:
            raise AuditError(f"Unexpected {name!r}: {pairs.get(name)!r}")
    if not pairs.get("kernel_phys_load", "").startswith("unset ("):
        raise AuditError("STOP: kernel_phys_load not unset; host/device physical evidence contaminated")
    if "iomem source" in diagnostics.lower() or "kernel_phys_load=" in diagnostics.lower():
        raise AuditError("STOP: diagnostics show physical-load inference")
    primitive = pairs.get("primitive", "")
    match = re.fullmatch(r"remove_waiter@0x([0-9a-fA-F]+) unpatched", primitive)
    if not match:
        raise AuditError(f"Unexpected static primitive classification: {primitive!r}")
    if int(match.group(1), 16) != expected_relative:
        raise AuditError("GhostLock relative function offset differs from pinned expected value")
    if "missing" not in pairs.get("path tcp_zerocopy", ""):
        raise AuditError("Unexpected TCP path analysis")
    return pairs


def audit(kernel: Path, nm: Path, analysis: Path, diagnostics: Path,
          *, expected_kernel_sha: str = KERNEL_SHA256,
          expected_kernel_bytes: int = KERNEL_BYTES,
          expected_text: int = EXPECTED_TEXT,
          expected_relative: int = EXPECTED_RELATIVE,
          expected_sample_sha: str = SAMPLE_SHA256) -> dict:
    binary = kernel.read_bytes()
    if len(binary) != expected_kernel_bytes or sha256(binary) != expected_kernel_sha:
        raise AuditError("STOP: original HXL1 kernel image size/hash mismatch")
    if len(binary) < 64 or binary[0x38:0x3C] != b"ARM\x64":
        raise AuditError("STOP: original kernel image ARM64 header invalid")
    symbols = extract_symbols(nm.read_text(encoding="utf-8", errors="replace"))
    if symbols["_text"] != expected_text:
        raise AuditError("STOP: recovered _text does not match stock kernel")
    relative = symbols["remove_waiter"] - symbols["_text"]
    if relative != expected_relative or relative % 4 or relative < 0:
        raise AuditError("STOP: recovered remove_waiter offset mismatch")
    if relative + SAMPLE_LEN > len(binary):
        raise AuditError("STOP: symbol sample exceeds original kernel image")
    sample_hash = sha256(binary[relative:relative + SAMPLE_LEN])
    if sample_hash != expected_sample_sha:
        raise AuditError("STOP: pinned original function bytes mismatch")
    analysis_text = analysis.read_text(encoding="utf-8")
    diagnostics_text = diagnostics.read_text(encoding="utf-8")
    fields = parse_upstream_analysis(analysis_text, diagnostics_text,
                                      expected_relative=expected_relative)
    if fields["primitive"] != f"remove_waiter@0x{relative:x} unpatched":
        raise AuditError("STOP: upstream analyzer and stock NM offset disagree")
    return {
        "firmware": "G986U1UESCHXL1",
        "kernelRelease": RELEASE,
        "classification": "PASS_STATIC_SYMBOL_AND_IMAGE_CORRELATION_ONLY",
        "inputKernelSha256": sha256(binary),
        "inputKernelSize": len(binary),
        "stockTextVirtualSymbol": f"0x{symbols['_text']:016x}",
        "stockRemoveWaiterVirtualSymbol": f"0x{symbols['remove_waiter']:016x}",
        "relativeImageOffset": f"0x{relative:x}",
        "imageSampleBytes": SAMPLE_LEN,
        "imageSampleSha256": sample_hash,
        "upstreamStaticPattern": fields["primitive"],
        "hostPhysicalAddressContamination": False,
        "physicalKernelLoadVerified": False,
        "runtimeVulnerabilityVerified": False,
        "executableGhostlockProfileVerified": False,
        "kernelSuVerified": False,
        "phoneModified": False,
        "warning": "Image-relative symbol agreement does not establish runtime physical loading, CVE reachability, kernel object layout, root, or KernelSU.",
    }


def markdown(result: dict) -> str:
    lines = [
        "# HXL1 — GhostLock static symbol corroboration", "",
        "**PASS: original stock image, NM symbol delta, function bytes, and isolated static report agree.**", "",
        f"- Kernel SHA256: {result['inputKernelSha256']}",
        f"- _text (reconstructed virtual symbol): {result['stockTextVirtualSymbol']}",
        f"- remove_waiter (reconstructed virtual symbol): {result['stockRemoveWaiterVirtualSymbol']}",
        f"- Verified image-relative delta: {result['relativeImageOffset']}",
        f"- Original 64-byte sample SHA256: {result['imageSampleSha256']}",
        "- Upstream analysis classification: static pattern only",
        "- Physical Linux load: **UNVERIFIED** (clean report says unset)",
        "- Factory ABI / runtime CVE / GhostLock / KernelSU: **UNVERIFIED**", "",
        "This tool does not interact with the device, determine a physical address, or produce an executable exploit profile.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-bin", type=Path, default=DEFAULT_ROOT / "kernel.bin")
    parser.add_argument("--nm", type=Path, default=DEFAULT_ROOT / "hxl1-research/vmlinux-stock.nm")
    parser.add_argument("--analysis", type=Path, default=DEFAULT_ROOT / "hxl1-research/ghostlock-upstream-analysis-isolated.txt")
    parser.add_argument("--diagnostics", type=Path, default=DEFAULT_ROOT / "hxl1-research/ghostlock-upstream-diagnostics-isolated.txt")
    parser.add_argument("--output", type=Path, default=DEFAULT_ROOT / "hxl1-research/ghostlock-symbol-crosscheck.json")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    inputs = [getattr(args, name).expanduser().resolve() for name in ("kernel_bin", "nm", "analysis", "diagnostics")]
    if output.suffix != ".json" or output in inputs:
        parser.error("Output must be a separate .json report, never a source input")
    try:
        result = audit(*inputs)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        output.with_suffix(".md").write_text(markdown(result))
    except (AuditError, OSError, UnicodeError) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2
    print("[PASS] Exact original stock Image SHA256 + 64-byte sample verified")
    print("[PASS] GhostLock image-relative symbol matches recovered stock NM")
    print("[PASS] Isolated upstream report carries no physical-load inference")
    print("[report]", output)
    print("[LIMIT] No physical kernel handoff, factory layout, GhostLock root or KernelSU")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
