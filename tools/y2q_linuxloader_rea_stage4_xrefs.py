#!/usr/bin/env python3
"""Audit precisely three REA/Ghidra xrefs on verified HXL1 LinuxLoader strings.

All addresses are static Ghidra analysis coordinates. Xrefs reveal code/data
references, not runtime kernel physical placement or actual boot execution.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LOADER_SHA256 = "5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"
REFS = (
    ("kernel-load-print", "kernel", "0xbc48c", "Kernel Load Address: 0x%x"),
    ("kernel-dt-boundary", "kernel", "0xbce52", "KERNEL SIZE :"),
    ("best-dtb-match", "dtb", "0xbd674", "Best match DTB tags"),
)
ADDR = re.compile(r"^(?:0x[0-9a-f]+|[A-Za-z0-9._~-]+:0x[0-9a-f]+)$")
MAX_REFERENCES = 10000


class AuditError(ValueError):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validate_seed(directory: Path, item: tuple[str, str, str, str]) -> str:
    _, group, coordinate, expected_text = item
    report = json.loads((directory / "rea-stage4-seed-audit.json").read_text())
    if report.get("originalLoaderSha256") != LOADER_SHA256:
        raise AuditError("REA seed report does not match exact original HXL1 loader")
    candidates = [q for q in report.get("queries", [])
                  if q.get("query") == group and q.get("status") == "VERIFIED_STATIC_SEARCH"]
    if len(candidates) != 1:
        raise AuditError("Missing authenticated REA search group: " + group)
    hits = [h for h in candidates[0].get("hits", [])
            if h.get("address") == coordinate
            and expected_text in h.get("value", "")]
    if len(hits) != 1:
        raise AuditError("Original Ghidra seed text/address not verified: " + coordinate)
    return candidates[0]["evidenceId"]


def parse_xrefs(path: Path, coordinate: str) -> dict:
    if not path.is_file() or path.is_symlink():
        raise AuditError("Missing regular, non-symlinked REA xrefs file")
    result = json.loads(path.read_text())
    if not isinstance(result, dict) or "error" in result:
        raise AuditError("REA returned failure, not a Ghidra xrefs observation")
    if result.get("operation") != "xrefs":
        raise AuditError("Expected REA xrefs operation")
    if not isinstance(result.get("provider"), dict) or result["provider"].get("id") != "ghidra":
        raise AuditError("Expected direct Ghidra provider")
    subject = result.get("subject")
    if (not isinstance(subject, dict) or
            not isinstance(subject.get("digest"), dict) or
            subject["digest"].get("sha256") != LOADER_SHA256 or
            subject.get("architecture") != "arm64"):
        raise AuditError("REA xrefs provenance does not match pinned AArch64 PE")
    if not isinstance(result.get("parameters"), dict) or result["parameters"].get("address") != coordinate:
        raise AuditError("REA xrefs request coordinate mismatch")
    if not isinstance(result.get("evidence_id"), str):
        raise AuditError("REA xrefs evidence ID absent")
    edges = result.get("normalized_result")
    if not isinstance(edges, list) or len(edges) > MAX_REFERENCES:
        raise AuditError("Expected bounded array of reference addresses")
    for address in edges:
        if not isinstance(address, str) or not ADDR.fullmatch(address):
            raise AuditError("Invalid reference analysis coordinate: " + repr(address))
    return {
        "status": "VERIFIED_GHIDRA_XREFS",
        "sourceEvidenceId": result["evidence_id"],
        "crossReferenceCount": len(edges),
        "sourceAddresses": list(dict.fromkeys(edges)),
    }


def assess(directory: Path) -> dict:
    loader = directory / "LinuxLoader-HXL1.efi"
    if not loader.is_file() or loader.is_symlink() or digest(loader) != LOADER_SHA256:
        raise AuditError("Original HXL1 LinuxLoader SHA256 no longer matches")
    records = []
    for item in REFS:
        label, group, address, text = item
        seed_id = validate_seed(directory, item)
        f = directory / ("rea-stage4-xrefs-" + label + ".json")
        try:
            verified = parse_xrefs(f, address)
        except (OSError, AuditError, ValueError) as exc:
            verified = {"status": "XREFS_NOT_YET_VERIFIED", "error": str(exc),
                        "crossReferenceCount": None, "sourceAddresses": []}
        records.append({"label": label, "stringGroup": group,
                        "seed": {"analysisAddress": address,
                                 "text": text, "searchEvidenceId": seed_id},
                        "referenceFile": str(f), **verified})
    return {
        "classification": "STATIC_GHIDRA_XREFS_NOT_RUNTIME_HANDOFF",
        "originalLoaderSha256": LOADER_SHA256,
        "references": records,
        "physicalKernelLoadVerified": False,
        "kernelHandoffVerified": False,
        "runtimeDtbSelectionVerified": False,
        "deviceModified": False,
    }


def markdown(report: dict) -> str:
    lines = ["# HXL1 LinuxLoader: targeted Ghidra xrefs", "",
             "Original loader SHA256: " + report["originalLoaderSha256"], "",
             "Addresses are Ghidra static coordinates, not RAM-load or Linux handoff addresses.", ""]
    for r in report["references"]:
        lines += ["## " + r["label"], "",
                  "String at " + r["seed"]["analysisAddress"] + ": " + r["seed"]["text"], "",
                  "Status: " + r["status"], ""]
        if r["status"] != "VERIFIED_GHIDRA_XREFS":
            lines += ["Gap: " + r["error"], ""]
            continue
        lines += ["Search evidence ID: " + r["seed"]["searchEvidenceId"],
                  "Xrefs evidence ID: " + r["sourceEvidenceId"],
                  "Reference count: " + str(r["crossReferenceCount"]), ""]
        if not r["sourceAddresses"]:
            lines += ["No Ghidra references at this coordinate; this does not exclude",
                      "references to nearby string interiors/pointers or different image-loader code.", ""]
        for address in r["sourceAddresses"]:
            lines.append("- " + address)
        lines.append("")
    lines += ["## Next action", "",
              "Resolve containing procedures for observed reference *source* addresses;",
              "then use REA function/decompile/trace-native-values with verified function",
              "entrypoints. No physical address is inferred from these xrefs.", ""]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/abl-linuxloader")
    p.add_argument("--verify-single", choices=[x[0] for x in REFS])
    opts = p.parse_args()
    try:
        if opts.verify_single:
            selected = next(x for x in REFS if x[0] == opts.verify_single)
            validate_seed(opts.out, selected)
            parse_xrefs(opts.out / ("rea-stage4-xrefs-" + selected[0] + ".json"), selected[2])
            print("[CACHE VERIFIED]", selected[0])
            return 0
        report = assess(opts.out)
        (opts.out / "rea-stage4-xrefs-audit.json").write_text(
            json.dumps(report, indent=2) + "\n")
        (opts.out / "rea-stage4-xrefs-audit.md").write_text(markdown(report))
    except (OSError, ValueError, KeyError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for item in report["references"]:
        print("[" + item["status"] + "]", item["label"],
              "references=", item["crossReferenceCount"])
        for address in item["sourceAddresses"][:20]:
            print(" ", address)
    print("[REPORT]", opts.out / "rea-stage4-xrefs-audit.md")
    print("[LIMIT] No kernel physical load or handoff identified from xrefs alone")
    return 0 if all(r["status"] == "VERIFIED_GHIDRA_XREFS"
                    for r in report["references"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
