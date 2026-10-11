#!/usr/bin/env python3
"""Offline, hash-verified hotspot inventory from an EXISTING HXL1 scan/export.

No new firmware extraction or G9860 download; no device operations. These
are binary string FILE OFFSETS only, not Ghidra addresses or exploit evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_bootloader_unlock_audit import (
    HXL1_BL_SHA256, KEYWORDS, PRINTABLE_ASCII, PRINTABLE_UTF16,
    TARGET_IMAGES, TriageError,
)

# Broader discovery terms intentionally separate from validated policy semantics.
PATTERNS = {
    **KEYWORDS,
    "broad_unlock_mentions": re.compile(r"unlock|oem.?lock|oem.?unlock|flash.?lock", re.I),
    "trust_boundaries": re.compile(
        r"trustzone|trusted.?app|secure.?world|scm.?call|"
        r"smc.?call|vault.?keeper|rpmb|sec.?storage", re.I),
    "download_protocol": re.compile(
        r"download|odin|heimdall|sahara|firehose|qualcomm.?flash", re.I),
}
WEIGHTS = {
    "unlock_state": 9, "broad_unlock_mentions": 6,
    "security_services": 5, "flashing_interface": 5,
    "trust_boundaries": 3, "verified_boot": 2, "download_protocol": 1,
}
MAX_PER_CATEGORY = 8
MAX_MODULE_BYTES = 128 * 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_terms(data: bytes) -> dict:
    counts = {category: 0 for category in PATTERNS}
    samples = {category: [] for category in PATTERNS}
    for pattern, encoding in ((PRINTABLE_ASCII, "ascii"),
                              (PRINTABLE_UTF16, "utf16le")):
        for match in pattern.finditer(data):
            string = match.group().decode(
                "ascii" if encoding == "ascii" else "utf-16-le", "replace")
            for category, regex in PATTERNS.items():
                if regex.search(string):
                    counts[category] += 1
                    if len(samples[category]) < MAX_PER_CATEGORY:
                        samples[category].append({
                            "fileOffset": match.start(),
                            "encoding": encoding,
                            "text": string[:160],
                        })
    return {"counts": counts, "samples": samples,
            "score": sum(WEIGHTS[k] * min(v, 10) for k, v in counts.items())}


def require_verified(path: Path, expected_sha: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise TriageError(f"missing or symlinked analysis copy: {path}")
    if path.stat().st_size > MAX_MODULE_BYTES:
        raise TriageError(f"analysis copy exceeds {MAX_MODULE_BYTES} bytes: {path}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise TriageError(f"original scan SHA256 does not match analysis copy: {path}")
    return data


def analyze_saved(input_dir: Path) -> dict:
    """Trust no local exports without matching original scan's hashes."""
    root = input_dir.expanduser().resolve()
    metadata = root / "bootloader-unlock-candidates.json"
    if not metadata.is_file() or metadata.is_symlink():
        raise TriageError(f"missing original HXL1 scan JSON: {metadata}")
    report = json.loads(metadata.read_text())
    if (report.get("schemaVersion") != 1
            or report.get("hxl1", {}).get("archiveSha256") != HXL1_BL_SHA256
            or report.get("target") != "SM-G986U1 G986U1UESCHXL1"
            or not isinstance(report.get("hxl1Images"), dict)):
        raise TriageError("original HXL1 scan metadata identity mismatch")
    records = []
    skipped = []
    for name in TARGET_IMAGES:
        image = report["hxl1Images"].get(name)
        if not image:
            skipped.append({"name": name, "reason": "NOT_IN_ORIGINAL_SCAN"})
            continue
        path = root / "comparison-inputs" / "HXL1" / name
        data = require_verified(path, image["sha256"])
        records.append({
            "source": name, "kind": "outer-image", "fileName": name,
            "sha256": image["sha256"], "size": len(data),
            "hints": scan_terms(data),
        })
        if name not in ("abl.elf", "xbl.elf"):
            continue
        nested = image.get("nestedUefi", {})
        if nested.get("peModuleListTruncated"):
            raise TriageError(f"nested module inventory truncated for {name}")
        if nested.get("status") != "SCAN_COMPLETED":
            skipped.append({"name": name, "reason": "NESTED_SCAN_NOT_COMPLETE"})
        for index, module in enumerate(nested.get("peModules", [])):
            sha, guid = module["sha256"], module["fileGuid"]
            # Filenames are created by the pinned exporter; match exact naming.
            expected_name = f"{index:03d}-{guid}-{sha[:16]}.efi"
            path = root / "comparison-inputs" / "HXL1" / "uefi-modules" / name / expected_name
            raw = require_verified(path, sha)
            records.append({
                "source": name, "kind": "nested-uefi-pe", "fileName": expected_name,
                "fileGuid": guid, "ui": module["ui"], "sha256": sha,
                "size": len(raw), "hints": scan_terms(raw),
            })
    records.sort(key=lambda x: (-x["hints"]["score"], x["source"], x["fileName"]))
    return {
        "schemaVersion": 1, "target": "SM-G986U1 G986U1UESCHXL1",
        "archiveSha256FromPinnedOriginalScan": HXL1_BL_SHA256,
        "sourceVerified": True,
        "moduleCount": len(records), "skipped": skipped, "modules": records,
        "securityDecisionEstablished": False, "unlockMethodEstablished": False,
        "phoneModified": False,
        "limitations": [
            "The archive identity is carried from an existing verified original scan; no archive was re-read.",
            "Every analyzed extracted file is independently SHA256 matched to the saved scan.",
            "String offsets are file offsets, NOT rebased PE/Ghidra addresses.",
            "Printed strings may be dead/unreachable; zero matches are NOT proof of absence.",
            "This parser recognizes only supported bounded UEFI formats and executable architectures.",
        ],
    }


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 bootloader — hash-pinned extracted-component security hotspots", "",
        "**Research candidates only. No unlock state change or flashing performed.**",
        "",
        f"- Original pinned HXL1 archive: `{report['archiveSha256FromPinnedOriginalScan']}`",
        f"- Verified analysis copies: **{report['moduleCount']}**",
        "- Ranking is a deterministic keyword triage score, not likelihood of exploitation.",
        "",
        "| Component / module | Origin | Score | Unlock | Boot verify | Security services | Download |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for item in report["modules"]:
        n = item["ui"] if item["kind"] == "nested-uefi-pe" and item["ui"] else item["fileName"]
        n = n.replace("|", "/").replace("\n", " ")[:72]
        c = item["hints"]["counts"]
        lines.append(
            f"| {n} | {item['source']} | {item['hints']['score']} | "
            f"{c['broad_unlock_mentions']} | {c['verified_boot']} | "
            f"{c['security_services']} | {c['download_protocol']} |")
    lines += ["", "## First observed candidate strings (file offsets; NOT runtime addresses)", ""]
    count = 0
    for item in report["modules"]:
        if item["hints"]["score"] == 0:
            continue
        count += 1
        if count > 12:
            break
        label = (item.get("ui") or item["fileName"]).replace("\n", " ")[:100]
        lines += [
            f"### {label} — {item['source']}",
            f"- Kind: {item['kind']}",
            f"- SHA256: `{item['sha256']}`",
        ]
        for category in ("unlock_state", "broad_unlock_mentions", "security_services",
                         "trust_boundaries", "flashing_interface", "verified_boot",
                         "download_protocol"):
            hits = item["hints"]["samples"][category]
            if not hits:
                continue
            lines.append(f"- **{category}:** {item['hints']['counts'][category]} candidates")
            for hit in hits[:4]:
                txt = hit["text"].replace("|", "/").replace("\n", " ")
                lines.append(
                    f"  - file+0x{hit['fileOffset']:x} ({hit['encoding']}): `{txt}`")
        lines.append("")
    if report["skipped"]:
        lines += ["## Not fully inspected", ""]
        for skip in report["skipped"]:
            lines.append(f"- {skip['name']}: {skip['reason']}")
        lines.append("")
    lines += ["## Evidence limits", ""]
    lines.extend(f"- {x}" for x in report["limitations"])
    lines += [
        "",
        "**Next:** In REA/Ghidra, open the exact hash-named exported PE and",
        "confirm whether interesting strings have *executed-code xrefs*,",
        "then trace the producer of any OEM lock state or flashing authorization.",
        "Prioritize proven string xrefs and called secure interfaces over raw counts.",
        "Do not flash cross-model or modified bootloader images.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path,
                        default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    args = parser.parse_args()
    out = args.input_dir.expanduser().resolve()
    try:
        summary = analyze_saved(out)
        (out / "hxl1-bootloader-hotspots.json").write_text(json.dumps(summary, indent=2) + "\n")
        (out / "hxl1-bootloader-hotspots.md").write_text(markdown(summary))
    except (TriageError, OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2
    print("[PASS] All analyzed HXL1 copies SHA256 match saved original scan")
    print("[MODULES]", summary["moduleCount"])
    print("[REPORT]", out / "hxl1-bootloader-hotspots.md")
    print("[LIMIT] Candidate strings only; no unlock / executable xrefs established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
