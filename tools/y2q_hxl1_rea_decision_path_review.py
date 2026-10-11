#!/usr/bin/env python3
"""Reconstruct five proven HXL1 Odin/LinuxLoader security-reference dossiers.

Offline analysis of SAVED original REA/Ghidra Evidence. No REA commands,
firmware execution, device calls, flashing or vulnerability claims.

Each supplied HXL1 seed is authenticated across:
  original binary SHA256 -> REA search -> literal Ghidra address ->
  REA xrefs -> exact observed source -> owning Ghidra body/pseudocode.

The original REA Evidence is never edited. Function pseudocode is provided as
a small selected-context excerpt; this is NOT comprehensive path analysis.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    EXPECTED, choose_targets, evidence, function_record, reference_sources,
    search_hits, safe_segment,
)

MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SNIPPET_LINES = 80
# All values here come from the FIRST owner-executed original-HXL1 Ghidra run.
# Future firmware builds / different Ghidra analysis coordinates are NOT accepted
# under this exact owner-evidence reference manifest.
SEEDS = (
    ("Odin", "oem-state", "Oem unlock value", "0x83aa4",
     "0x1ecc8", "0x1ec00", "oem_lock_state_consumer"),
    ("Odin", "custom-deny", "Blocked By OEM Lock", "0x8297d",
     "0x1b3d4", "0x1b6a8", "custom_image_lock_rejection"),
    ("LinuxLoader", "unlocked-skip", "Skipping boot verification", "0xb2fa7",
     "0x40f0", "0x3f54", "unlocked_boot_verify_skip"),
    ("LinuxLoader", "unlocked-callback", "read_is_device_unlocked", "0xb3662",
     "0x59d4", "0x5950", "avb_unlock_callback_reference"),
    ("LinuxLoader", "unlock-count", "device unlocked", "0xb2dc4",
     "0x3f34", "0x2274", "device_unlock_counter_log"),
)
KEYWORDS = re.compile(
    r"oem|unlock|lock|avb|vbmeta|verify|secure|auth|deny|reject|"
    r"flash|rpmb|qsee|scm|rollback|signed|read_is_device_unlocked",
    re.I,
)


def load_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise TriageError(f"Missing, unsafe or oversized saved REA evidence: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise TriageError(f"Invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TriageError(f"Expected JSON Evidence object at {path}")
    return value


def candidate_context(code: str) -> dict:
    """Capture bounded pseudocode with line numbers; no code is executed."""
    lines = code.splitlines()
    matches = [i for i, line in enumerate(lines) if KEYWORDS.search(line)]
    chosen: set[int] = set()
    for i in matches[:24]:
        chosen.update(range(max(0, i - 3), min(len(lines), i + 5)))
    # Even no-literal functions get their prologue to permit visual review.
    if not chosen:
        chosen.update(range(min(12, len(lines))))
    selected = sorted(chosen)[:MAX_SNIPPET_LINES]
    return {
        "lineCount": len(lines), "matchingLineCount": len(matches),
        "matchingLineNumbers": [i + 1 for i in matches[:24]],
        "matchingLinesTruncated": len(matches) > 24,
        "excerptTruncated": len(selected) < len(chosen),
        "selectedLines": [
            {"number": i + 1, "text": lines[i][:300]}
            for i in selected
        ],
    }


def follow_seed(out: Path, target, seed: tuple) -> dict:
    module, label, term, string_addr, source, entry, hypothesis = seed
    subdir = out / module
    search_file = subdir / f"search-{label}.json"
    search_ev = evidence(search_file, sha=target.sha256,
                         operation="search_strings", parameter="pattern", value=term)
    hits = search_hits(search_ev, term)
    if not any(hit["address"] == string_addr for hit in hits):
        raise TriageError(f"Missing exact Ghidra seed string: {module}/{label} {string_addr}")
    xref_file = subdir / f"xrefs-{label}-{safe_segment(string_addr)}.json"
    xref_ev = evidence(xref_file, sha=target.sha256,
                        operation="xrefs", parameter="address", value=string_addr)
    sources = reference_sources(xref_ev)
    if source not in sources:
        raise TriageError(f"Exact observed xref missing from original evidence: {module}/{label} {source}")
    fn_file = subdir / f"function-{safe_segment(source)}.json"
    fn_ev = evidence(fn_file, sha=target.sha256,
                     operation="analyze_function", parameter="procedure", value=source)
    verified = function_record(fn_ev, source)
    if verified["entry"] != entry:
        raise TriageError(
            f"Original Ghidra entry differs for {module}/{label}: {verified['entry']} != {entry}")
    pseudo = fn_ev["normalized_result"]["pseudocode"]
    return {
        "hypothesis": hypothesis, "module": module, "originalSha256": target.sha256,
        "literalSearch": term, "stringAddress": string_addr,
        "xrefSource": source, "ghidraFunctionEntry": entry,
        "disjointBodyPossible": int(source, 16) < int(entry, 16),
        "searchEvidenceId": search_ev["evidence_id"],
        "xrefsEvidenceId": xref_ev["evidence_id"],
        "functionEvidenceId": fn_ev["evidence_id"],
        "verifiedGhidraFunctionBody": True,
        "pcodeAvailable": verified["pcodeAvailable"],
        "codeContext": candidate_context(pseudo),
        "findingLevel": "AUTHENTICATED_STATIC_REFERENCE_ONLY",
        "vulnerabilityProven": False,
        "unlockMechanismProven": False,
        "sourceEvidenceFiles": [str(search_file), str(xref_file), str(fn_file)],
    }


def audit(root: Path) -> dict:
    hotspots = root / "hxl1-bootloader-hotspots.json"
    if load_json(hotspots).get("archiveSha256FromPinnedOriginalScan") != HXL1_BL_SHA256:
        raise TriageError("Original stock archive identity mismatch")
    targets = {x.name: x for x in choose_targets(root, include_secure=False)}
    output = root / "rea-security-audit"
    summary_file = output / "security-paths.json"
    aggregate = load_json(summary_file)
    if (aggregate.get("mode") != "EXECUTE_STATIC_GHIDRA"
            or aggregate.get("originalArchiveSha256") != HXL1_BL_SHA256
            or aggregate.get("sourceAttested") is not True):
        raise TriageError("First-pass summary is not a successful original-HXL1 execution")
    if aggregate.get("bootloaderUnlockDemonstrated") is not False:
        raise TriageError("Unexpected unverified unlock claim in input report")
    records, failures = [], []
    for seed in SEEDS:
        try:
            records.append(follow_seed(output, targets[seed[0]], seed))
        except (TriageError, OSError, KeyError, TypeError, ValueError) as exc:
            failures.append({
                "module": seed[0], "hypothesis": seed[-1], "reason": str(exc),
            })
    return {
        "schemaVersion": 1,
        "target": "SM-G986U1 G986U1UESCHXL1",
        "originalArchiveSha256": HXL1_BL_SHA256,
        "qualifiedFunctionReferences": len(records),
        "expectedFunctionReferences": len(SEEDS),
        "allFiveReferencesVerified": len(records) == len(SEEDS) and not failures,
        "references": records, "unresolved": failures,
        "secureWorldDecisionVerified": False, "deviceUnlockDemonstrated": False,
        "vulnerabilityDemonstrated": False, "deviceModified": False,
    }


def to_markdown(result: dict) -> str:
    lines = [
        "# HXL1 OEM unlock and verified-boot — original Ghidra code dossier",
        "", "**Verified references only; no exploit or unlock demonstrated.**",
        "", f"- Original BL SHA256: \`{result['originalArchiveSha256']}\`",
        f"- Independently linked search → xrefs → function dossiers: "
        f"**{result['qualifiedFunctionReferences']} / {result['expectedFunctionReferences']}**",
        "- Function entries and string locations are STATIC Ghidra addresses.",
        "- Pseudocode is reverse-engineered, potentially incomplete and not a runtime trace.", "",
    ]
    for item in result["references"]:
        lines += [
            f"## {item['module']}: {item['hypothesis']}", "",
            f"- Binary: \`{item['originalSha256']}\`",
            f"- String address: \`{item['stringAddress']}\` / xref source: "
            f"\`{item['xrefSource']}\`",
            f"- Owning function: **\`{item['ghidraFunctionEntry']}\`**",
            f"- Ghidra evidence IDs: search \`{item['searchEvidenceId']}\`, "
            f"xrefs \`{item['xrefsEvidenceId']}\`, "
            f"function \`{item['functionEvidenceId']}\`",
            f"- HighFunction p-code available: {item['pcodeAvailable']}",
            f"- Code lines matching security topics: "
            f"{item['codeContext']['matchingLineCount']}",
            "- Selected pseudocode context (line numbers shown):", "",
            "~~~c",
        ]
        for line in item["codeContext"]["selectedLines"]:
            lines.append(f"{line['number']:5d} | {line['text']}")
        lines += ["~~~", ""]
        if item["disjointBodyPossible"]:
            lines += ["**Review:** this xref lies numerically before the function "
                      "entry. Ghidra's verified body ranges include it, but "
                      "ownership should be independently confirmed in the "
                      "disassembler before treating the flow as a contiguous function.", ""]
        if item["codeContext"]["excerptTruncated"] or item["codeContext"]["matchingLinesTruncated"]:
            lines += ["**Truncated context:** consult original saved "
                      "function Evidence for the full pseudocode.", ""]
    if result["unresolved"]:
        lines += ["## Unresolved identity / evidence checks", ""]
        for gap in result["unresolved"]:
            lines.append(f"- {gap['module']}/{gap['hypothesis']}: {gap['reason']}")
        lines.append("")
    lines += [
        "## Next semantic validation gates", "",
        "1. Identify actual dataflow into Odin OEM-state tests, including "
        "persistent state and secure-service return codes.",
        "2. Prove which code decides to accept/reject a custom image and "
        "whether that decision is in Odin, ABL, or secure world.",
        "3. Trace LinuxLoader read_is_device_unlocked callback implementation "
        "and the AVB image-authentication path.",
        "4. Review return-value checks, bounds validation and reachable "
        "protocol inputs; do not convert lexical hints into vulnerability verdicts.",
        "5. Compare against authenticated G9860 binaries when available, "
        "without cross-model flashing.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path,
                   default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    opts = p.parse_args()
    try:
        root = opts.input_dir.expanduser().resolve()
        result = audit(root)
        out = root / "rea-security-audit"
        (out / "decision-path-review.json").write_text(json.dumps(result, indent=2) + "\n")
        (out / "decision-path-review.md").write_text(to_markdown(result))
    except (TriageError, OSError, KeyError, ValueError, TypeError) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2
    print(f"[VERIFIED] Qualified saved Ghidra function chains: "
          f"{result['qualifiedFunctionReferences']}/{result['expectedFunctionReferences']}")
    for x in result["references"]:
        print(f"  {x['module']} {x['hypothesis']} => {x['ghidraFunctionEntry']}, "
              f"matched code lines={x['codeContext']['matchingLineCount']}")
    for x in result["unresolved"]:
        print(f"[UNRESOLVED] {x['module']}/{x['hypothesis']}: {x['reason']}")
    print("[REPORT]", out / "decision-path-review.md")
    print("[LIMIT] Semantic unlock policy and vulnerability status unverified")
    return 0 if result["allFiveReferencesVerified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
