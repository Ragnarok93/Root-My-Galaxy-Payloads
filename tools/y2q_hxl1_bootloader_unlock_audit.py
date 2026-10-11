#!/usr/bin/env python3
"""Read-only, evidence-pinned G986U1 HXL1 / G9860 bootloader triage.

Only summarizes binary formats, hashes and candidate strings. A string match
is NOT a verified unlock branch, bypass, trusted certificate or executable path.
No phone, firmware modification, flashing or external network access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_stock_bl_elf_audit import AuditError, parse_elf
from tools.y2q_abl_linuxloader_extract import ExtractError, Walker

HXL1_BL_SHA256 = "f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b"
HXL1_BL_BYTES = 92600434
TARGET_IMAGES = (
    "abl.elf", "xbl.elf", "xbl_config.elf", "tz.mbn",
    "vaultkeeper.mbn", "uefi_sec.mbn", "storsec.mbn",
    "sec.elf", "vbmeta.img",
)
MAX_IMAGE_BYTES = 128 * 1024 * 1024
PRINTABLE_ASCII = re.compile(rb"[\x20-\x7e]{5,160}")
PRINTABLE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,160}")
KEYWORDS = {
    "unlock_state": re.compile(
        r"oem.{0,12}unlock|unlock.{0,16}boot|bootloader.{0,16}lock|"
        r"flash.{0,12}lock|device.{0,12}unlock|isdeviceunlocked", re.I),
    "verified_boot": re.compile(
        r"\bavb\b|vbmeta|dm.verity|verified?.{0,12}boot|"
        r"secure.{0,12}boot|anti.?rollback|rollback", re.I),
    "security_services": re.compile(
        r"vault.?keeper|knox.?guard|\bRMM\b|\bKG.{0,8}state\b", re.I),
    "flashing_interface": re.compile(
        r"download.{0,8}mode|\bodin\b|\bsahara\b|\bfirehose\b|"
        r"flash.{0,12}(?:auth|denied|reject|fail)", re.I),
}


class TriageError(ValueError):
    pass


def digest_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def classify(data: bytes) -> dict:
    if data.startswith(b"\x7fELF"):
        try:
            parsed = parse_elf(data)
            return {
                "format": "ELF",
                "elfClass": parsed["elfClass"],
                "machine": parsed["machine"],
                "programHeaderCount": parsed["programHeaderCount"],
                "entryPoint": parsed["entryPoint"],
            }
        except AuditError as exc:
            return {"format": "ELF_UNPARSED", "reason": str(exc)}
    if data.startswith(b"AVB0"):
        return {"format": "ANDROID_VBMETA_HEADER_UNVERIFIED"}
    if data.startswith(b"MZ"):
        return {"format": "MZ_HEADER_UNVERIFIED"}
    return {"format": "MBN_OR_OTHER_UNCLASSIFIED"}


def string_hints(data: bytes) -> dict:
    counts = {key: 0 for key in KEYWORDS}
    samples = {key: [] for key in KEYWORDS}
    # Both string encodings are scanned. These are candidates, not xrefs.
    for pattern, encoding in ((PRINTABLE_ASCII, "ascii"),
                              (PRINTABLE_UTF16, "utf16le")):
        for match in pattern.finditer(data):
            string = match.group().decode(
                "ascii" if encoding == "ascii" else "utf-16-le", "replace")
            for category, expression in KEYWORDS.items():
                if expression.search(string):
                    counts[category] += 1
                    if len(samples[category]) < 20:
                        samples[category].append({
                            "offset": match.start(),
                            "encoding": encoding,
                            "text": string[:160],
                        })
    return {"categoryCounts": counts, "samples": samples}


def load_archive(path: Path, *, expected_digest: str | None = None,
                 expected_bytes: int | None = None) -> tuple[dict, dict[str, bytes]]:
    if path.is_symlink() or not path.is_file():
        raise TriageError(f"not a regular firmware archive: {path}")
    size = path.stat().st_size
    sha256 = digest_path(path)
    if expected_bytes is not None and size != expected_bytes:
        raise TriageError("HXL1 BL archive size mismatch; refusing substituted firmware")
    if expected_digest is not None and sha256.lower() != expected_digest.lower():
        raise TriageError("HXL1 BL SHA256 mismatch; refusing substituted firmware")
    try:
        import lz4.frame
    except ImportError as exc:
        raise TriageError("Install python3-lz4 for bounded .lz4 inspection") from exc

    archive_members = []
    binaries = {}
    with tarfile.open(path, "r:") as tar:
        members = {}
        for item in tar.getmembers():
            archive_members.append({"name": item.name, "compressedBytes": item.size,
                                    "regularFile": item.isfile()})
            if item.name in {name + ".lz4" for name in TARGET_IMAGES}:
                if item.name in members or not item.isfile():
                    raise TriageError(f"duplicate or nonregular target entry: {item.name}")
                members[item.name] = item
        for name in TARGET_IMAGES:
            item = members.get(name + ".lz4")
            if item is None:
                continue
            source = tar.extractfile(item)
            if source is None:
                raise TriageError(f"cannot read archive entry {item.name}")
            try:
                with source, lz4.frame.open(source, mode="rb") as stream:
                    data = stream.read(MAX_IMAGE_BYTES + 1)
            except (OSError, RuntimeError, EOFError, ValueError) as exc:
                raise TriageError(f"bad LZ4 stream for {item.name}: {exc}") from exc
            if len(data) > MAX_IMAGE_BYTES:
                raise TriageError(f"oversize decompressed entry: {item.name}")
            binaries[name] = data

    if not binaries:
        raise TriageError("no expected BL images were found")
    return {
        "archiveName": path.name,
        "archiveSha256": sha256,
        "archiveBytes": size,
        "members": archive_members,
        "selectedImageCount": len(binaries),
    }, binaries


def nested_uefi_modules(data: bytes) -> dict:
    """Inventory discovered PE/FFS GUIDs, not an authenticated unlock policy."""
    walker = Walker()
    status = "SCAN_COMPLETED"
    try:
        walker.search_fv(data, ["original-bl-image"], 0)
    except (ExtractError, ValueError, OverflowError) as exc:
        status = "PARTIAL_SCAN_ERROR: " + str(exc)[:200]
    entries = [
        {
            "fileGuid": item["fileGuid"],
            "ui": item["ui"],
            "sha256": item["info"]["sha256"],
            "bytes": item["info"]["fileBytes"],
            "coffMachine": item["info"]["coffMachine"],
            "trace": item["trace"],
        }
        for item in walker.identified
    ]
    return {
        "status": status,
        "firmwareVolumes": len(walker.fv_headers),
        "ffsEntries": len(walker.ffs_files),
        "qualifiedPeCount": len(entries),
        "peModules": entries[:128],
        "peModuleListTruncated": len(entries) > 128,
        "otherExecutableSections": len(walker.unrecognized_executable_sections),
        "unlockImplementationAuthenticated": False,
    }


def describe(binaries: dict[str, bytes]) -> dict:
    return {
        name: {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            **classify(data),
            "stringHints": string_hints(data),
            **({"nestedUefi": nested_uefi_modules(data)}
               if name in ("abl.elf", "xbl.elf") else {}),
        }
        for name, data in binaries.items()
    }


def compare_nested_uefi(primary: dict, other: dict) -> dict:
    def groups(record: dict) -> dict:
        modules = record.get("nestedUefi", {}).get("peModules", [])
        grouped = {}
        for module in modules:
            grouped.setdefault(module["fileGuid"].lower(), []).append(module)
        return grouped

    a, b = groups(primary), groups(other)
    matched = []
    for guid in sorted(a.keys() & b.keys()):
        matched.append({
            "fileGuid": guid,
            "hxl1": [{"ui": x["ui"], "sha256": x["sha256"]} for x in a[guid]],
            "g9860": [{"ui": x["ui"], "sha256": x["sha256"]} for x in b[guid]],
            "sameSetOfExecutableHashes":
                sorted(x["sha256"] for x in a[guid]) ==
                sorted(x["sha256"] for x in b[guid]),
        })
    return {
        "matchedFileGuids": matched,
        "hxl1OnlyGuids": sorted(a.keys() - b.keys()),
        "g9860OnlyGuids": sorted(b.keys() - a.keys()),
        "caveat": "FFS GUID overlap identifies candidates for disassembly, not interchangeable firmware or matching authorization.",
    }


def compare(primary: dict, other: dict) -> dict:
    result = {}
    for name in TARGET_IMAGES:
        a, b = primary.get(name), other.get(name)
        if not a or not b:
            result[name] = {"status": "MISSING_SIDE",
                            "presentHxl1": a is not None,
                            "presentG9860": b is not None}
            continue
        result[name] = {
            "status": "IDENTICAL" if a["sha256"] == b["sha256"] else "DIFFERENT",
            "hxl1Sha256": a["sha256"], "g9860Sha256": b["sha256"],
            "hxl1Bytes": a["bytes"], "g9860Bytes": b["bytes"],
            "hxl1Format": a["format"], "g9860Format": b["format"],
            "candidateCounts": {
                category: {"hxl1": a["stringHints"]["categoryCounts"][category],
                           "g9860": b["stringHints"]["categoryCounts"][category]}
                for category in KEYWORDS
            },
            **({"uefiModuleComparison": compare_nested_uefi(a, b)}
               if name in ("abl.elf", "xbl.elf") else {}),
        }
    return result


def report_markdown(report: dict) -> str:
    lines = [
        "# HXL1 versus G9860 — offline bootloader candidate audit", "",
        "**No bootloader unlock, custom flash, signature bypass, or device action is proved.**",
        "", f"- HXL1 SHA256: `{report['hxl1']['archiveSha256']}`",
        f"- Comparator: {report['comparatorState']}",
    ]
    if report.get("g9860"):
        lines += [f"- G9860 archive: `{report['g9860']['archiveName']}`",
                  f"- G9860 SHA256: `{report['g9860']['archiveSha256']}`"]
    lines += ["", "| Image | HXL1 format | Unlock strings | AVB strings | G9860 comparison |",
              "|---|---|---:|---:|---|"]
    for name in TARGET_IMAGES:
        one = report["hxl1Images"].get(name)
        two = report["comparisons"].get(name, {})
        if not one:
            lines.append(f"| {name} | absent | — | — | {two.get('status', 'not checked')} |")
        else:
            ct = one["stringHints"]["categoryCounts"]
            lines.append(f"| {name} | {one['format']} | {ct['unlock_state']} | "
                         f"{ct['verified_boot']} | {two.get('status', 'not checked')} |")
    lines += ["", "## Nested UEFI executable modules (inside ABL/XBL)", "",
              "These are PE files discovered by the bounded FV/FFS walker. Outer-ELF",
              "string counts above do not represent semantic analysis of these modules.",
              "Matching GUIDs alone do not establish an unlock function.", "",
              "| Parent | FV scan | FFS entries | PE count | Other executable sections |",
              "|---|---|---:|---:|---:|"]
    for parent in ("abl.elf", "xbl.elf"):
        img = report["hxl1Images"].get(parent, {})
        nested = img.get("nestedUefi", {})
        lines.append(
            f"| {parent} | {nested.get('status', 'not scanned')} | "
            f"{nested.get('ffsEntries', '—')} | {nested.get('qualifiedPeCount', '—')} | "
            f"{nested.get('otherExecutableSections', '—')} |")
    lines += ["", "| Parent | FFS GUID | Module UI name | SHA256 prefix | PE bytes |",
              "|---|---|---|---|---:|"]
    for parent in ("abl.elf", "xbl.elf"):
        nested = report["hxl1Images"].get(parent, {}).get("nestedUefi", {})
        for item in nested.get("peModules", []):
            ui = item["ui"].replace("|", "/").replace(chr(10), " ")[:90] or "(unnamed)"
            lines.append(
                f"| {parent} | `{item['fileGuid']}` | {ui} | "
                f"`{item['sha256'][:16]}` | {item['bytes']} |")
        if nested.get("peModuleListTruncated"):
            lines.append(f"| {parent} | **TRUNCATED** | Some modules omitted | — | — |")
    lines += ["", "Review `comparison-inputs/HXL1/uefi-modules/` after"
              " using `--export-binaries`. Binary-specific security strings"
              " require separate analysis of those exported PEs.", ""]
    lines += ["", "## Interpretation limits", "",
              "- A print-string hit is only a lead for disassembly/xref review, not proof of a policy branch.",
              "- Matching nested UEFI module GUIDs guide semantic analysis; they never authorize cross-flashing.",
              "- Cross-model binary differences may reflect build age, region, chipset configuration or certificates.",
              "- Comparator filename/model is **not independently authenticated** by this offline scanner.",
              "- ELF header metadata does not establish the secure chain or the Android kernel entry.",
              "- Static findings do not establish an unlock service, an acceptable programmer, or authorization.",
              "- Originals are read-only; optional exported binaries and nested UEFI PEs are research copies only.", "",
              "## Suggested REA/Ghidra review order", "",
              "1. Inspect ABL unlock-state string references and their callers.",
              "2. Trace verified-boot decisions and TrustZone/VaultKeeper service boundaries.",
              "3. Compare matching functions across device models, with full provenance.",
              "4. Separately investigate Download Mode authorization; do not flash the G9860 image to G986U1.",
              ""]
    return "\n".join(lines)


def export_binaries(directory: Path, label: str, binaries: dict[str, bytes]) -> None:
    dest = directory / label
    dest.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise TriageError("export directory cannot be a symlink")
    for name, data in binaries.items():
        file = dest / name
        if file.is_symlink() or (file.exists() and file.read_bytes() != data):
            raise TriageError(f"refusing to replace existing different image: {file}")
        if not file.exists():
            file.write_bytes(data)
        if name not in ("abl.elf", "xbl.elf"):
            continue
        walker = Walker()
        try:
            walker.search_fv(data, [name], 0)
        except (ExtractError, ValueError, OverflowError) as exc:
            # The JSON report records partial scans; never promote them to
            # complete or silently manufacture output executables.
            raise TriageError(f"cannot export partially parsed UEFI {name}: {exc}") from exc
        if len(walker.identified) > 128:
            raise TriageError(f"too many nested PE candidates in {name}")
        nested_dir = dest / "uefi-modules" / name
        if walker.identified:
            nested_dir.mkdir(parents=True, exist_ok=True)
            if nested_dir.is_symlink():
                raise TriageError(f"symlinked nested output: {nested_dir}")
        for idx, module in enumerate(walker.identified):
            payload = module["image"]
            if len(payload) > 64 * 1024 * 1024:
                raise TriageError("nested PE exceeds export size limit")
            sha = hashlib.sha256(payload).hexdigest()
            guid = module["fileGuid"]
            nested = nested_dir / f"{idx:03d}-{guid}-{sha[:16]}.efi"
            if nested.is_symlink() or (nested.exists() and nested.read_bytes() != payload):
                raise TriageError(f"refusing to overwrite a different nested PE: {nested}")
            if not nested.exists():
                nested.write_bytes(payload)


def run(hxl1_path: Path, comparator_path: Path | None, output: Path, *,
        pin_hash: str = HXL1_BL_SHA256,
        pin_bytes: int = HXL1_BL_BYTES,
        export: bool = False) -> dict:
    if comparator_path and hxl1_path.resolve() == comparator_path.resolve():
        raise TriageError("HXL1 and comparator must not be the same archive")
    sources = [hxl1_path] + ([comparator_path] if comparator_path else [])
    if comparator_path and not comparator_path.name.startswith("BL_G9860"):
        raise TriageError("comparator BL filename must begin BL_G9860")
    for source in sources:
        if not source:
            continue
        resolved, target = source.resolve(), output.resolve()
        if target == resolved.parent or resolved.parent in target.parents:
            raise TriageError("reports must be outside input firmware archive directories")
    hxl1, hxl1_data = load_archive(
        hxl1_path, expected_digest=pin_hash, expected_bytes=pin_bytes)
    comp, comp_data = (load_archive(comparator_path)
                       if comparator_path else (None, {}))
    primary = describe(hxl1_data)
    secondary = describe(comp_data)
    report = {
        "schemaVersion": 1,
        "target": "SM-G986U1 G986U1UESCHXL1",
        "comparisonModelClaim": "SM-G9860" if comp else None,
        "comparatorState": ("UNVERIFIED_COMPARATOR_PROVENANCE" if comp
                            else "COMPARATOR_NOT_PROVIDED"),
        "hxl1": hxl1, "g9860": comp,
        "hxl1Images": primary, "g9860Images": secondary,
        "comparisons": compare(primary, secondary) if comp else {},
        "runtimeSecurityDecisionEstablished": False,
        "unlockMethodEstablished": False,
        "phoneModified": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise TriageError("output directory cannot be a symlink")
    (output / "bootloader-unlock-candidates.json").write_text(
        json.dumps(report, indent=2) + "\n")
    (output / "bootloader-unlock-candidates.md").write_text(report_markdown(report))
    if export:
        export_binaries(output / "comparison-inputs", "HXL1", hxl1_data)
        if comp:
            export_binaries(output / "comparison-inputs", "G9860", comp_data)
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hxl1-bl", type=Path, required=True,
                   help="Original BL_G986U1UESCHXL1_*.tar.md5; exact SHA256 enforced")
    p.add_argument("--g9860-bl", type=Path,
                   help="Optional separately obtained BL_G9860*.tar.md5")
    p.add_argument("--output-dir", type=Path,
                   default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--export-binaries", action="store_true",
                   help="Save decompressed BL components and discovered nested UEFI PE modules under output-dir only")
    args = p.parse_args()
    try:
        report = run(args.hxl1_bl, args.g9860_bl, args.output_dir,
                     export=args.export_binaries)
    except (TriageError, OSError, tarfile.TarError) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2
    print("[PASS] pinned HXL1 archive and offline bootloader inventory")
    print("[COMPARATOR]", report["comparatorState"])
    print("[REPORT]", args.output_dir / "bootloader-unlock-candidates.md")
    print("[LIMIT] No unlock/security decision verified; phone untouched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
