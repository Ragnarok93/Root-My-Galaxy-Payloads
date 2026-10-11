#!/usr/bin/env python3
"""HXL1 original 0x351055 candidate writer provenance, static Ghidra only.

The owner's pinned original-LinuxLoader Ghidra xref inspection found two
candidate STRB sites in separate owning functions. Query ONLY their original
function decompilations and complete native instruction lists, preserving
exact source hashes, existing Evidence and unknown memory aliasing.

Default PLAN ONLY. --execute runs at most four bounded read-only Ghidra
queries. Never patches firmware or communicates with a device.
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

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, function_record, safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_writers import (
    REMAINING_REFS, audit as verify_prior_writers, parse_instructions,
)

CANDIDATES = (
    ("0x33c88", "0x33d08", "strb", "w19,[x8,#0xd]", "variable-byte-store"),
    ("0x33da8", "0x33ee0", "strb", "wzr,[x19,#0xd]", "zero-byte-store"),
)
SOURCE_GLOBAL = "0x351055"
MAX_PSEUDOCODE = 240000
MAX_INSTRUCTIONS = 1600
PSEUDO_MARKER = re.compile(
    r"0x3510|00351055|351055|FUN_000|LAB_000|DAT_|"
    r"\+ 0xd\b|\[0xd\]|\bif\s*\(|\breturn\b", re.I,
)


def verified_xref_candidates(previous: dict) -> list[dict]:
    if previous.get("originalSourcesVerified") is not True:
        raise TriageError("Original HXL1 byte xrefs not source authenticated")
    selected = previous.get("remainingSites")
    if not isinstance(selected, list) or len(selected) != len(REMAINING_REFS):
        raise TriageError("Original HXL1 8-site xref review missing")
    original = {}
    for entry in selected:
        if not isinstance(entry, dict) or entry.get("status") != "SOURCE_ATTESTED":
            raise TriageError("Original site instruction still unresolved")
        site = entry.get("address")
        obs = entry.get("observation")
        if site in original or site not in REMAINING_REFS or not isinstance(obs, dict):
            raise TriageError("Duplicated/missing source-attested xref observation")
        if not isinstance(obs.get("evidenceId"), str):
            raise TriageError("Ghidra source Evidence ID missing")
        original[site] = obs
    if set(original) != set(REMAINING_REFS):
        raise TriageError("Original xref source inventory differs")
    candidates = []
    expected = {site: (entry, opcode, operands, label)
                for entry, site, opcode, operands, label in CANDIDATES}
    for site, obs in original.items():
        is_candidate = site in expected
        if obs.get("instructionKind") != (
            "store-instruction" if is_candidate else "load-instruction"
        ):
            raise TriageError("Original instruction kind changed")
        if not is_candidate:
            continue
        parent, opcode, operands, label = expected[site]
        raw = obs.get("nativeInstruction")
        normalized = re.sub(r"\s+", "", raw.lower()) if isinstance(raw, str) else ""
        if (obs.get("owningProcedure") != parent
                or not normalized.startswith(opcode + operands)):
            raise TriageError(f"Original HXL1 candidate store mismatched at {site}")
        candidates.append({
            "ownerEntry": parent, "site": site, "opcode": opcode,
            "operands": operands, "label": label,
            "xrefInstructionEvidenceId": obs["evidenceId"],
            "actualMemoryWriteProven": False,
            "effectiveAddressVerified": False,
            "sourceValueVerified": False,
        })
    if len(candidates) != 2:
        raise TriageError("Original HXL1 expected exactly two candidate STRB references")
    return sorted(candidates, key=lambda x: int(x["site"], 16))


def function_context(ev: dict, *, entry: str, site: str) -> dict:
    record = function_record(ev, site)
    if record.get("entry") != entry:
        raise TriageError("Original candidate writer owning function differs")
    pseudo = ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo, str) or not pseudo.strip() or len(pseudo) > MAX_PSEUDOCODE:
        raise TriageError("Original candidate writer Ghidra pseudocode missing/oversized")
    lines = pseudo.splitlines()
    if len(lines) > 5000:
        raise TriageError("Candidate writer original Ghidra lines exceed bound")
    matching = [i for i, line in enumerate(lines) if PSEUDO_MARKER.search(line)]
    relevant = set(range(min(22, len(lines))))
    for i in matching[:45]:
        relevant.update(range(max(0, i-4), min(len(lines), i+6)))
    indices = sorted(relevant)[:160]
    return {
        "entry": entry, "evidenceId": ev["evidence_id"],
        "lines": len(lines), "pcodeAvailable": record["pcodeAvailable"],
        "pseudocodeSha256": hashlib.sha256(pseudo.encode()).hexdigest(),
        "selectedCode": [
            {"line": i+1, "code": lines[i][:680]} for i in indices
        ],
        "excerptTruncated": len(relevant) > len(indices) or len(matching) > 45,
        "producerOrAliasVerified": False,
    }


def native_context(ev: dict, *, entry: str, site: str,
                   opcode: str, operands: str) -> dict:
    decoded = parse_instructions(ev, entry)
    if len(decoded) > MAX_INSTRUCTIONS:
        raise TriageError("Native writer function exceeds bounded instruction budget")
    expected = (opcode, operands)
    if decoded.get(site) != expected:
        raise TriageError("Original candidate STRB instruction differs in owner listing")
    addresses = sorted(decoded, key=lambda x: int(x, 16))
    where = addresses.index(site)
    window = addresses[max(0, where-30):min(len(addresses), where+14)]
    return {
        "entry": entry, "site": site, "evidenceId": ev["evidence_id"],
        "instructionCount": len(decoded),
        "nativeStoreOpcodeVerified": True,
        "nativeStoreAddressAliasVerified": False,
        "nativeValueProvenanceVerified": False,
        "instructionWindow": [
            {"address": address, "mnemonic": decoded[address][0],
             "operands": decoded[address][1]}
            for address in window
        ],
        "windowStartsBeforeSite": window[0] != addresses[0],
        "windowEndsBeforeFunctionEnd": window[-1] != addresses[-1],
    }


def audit(root: Path, *, execute: bool=False,
          rea: Path|None=None, node: str="node", timeout: int=240,
          recover_partials: bool=False) -> dict:
    previous = verify_prior_writers(root)
    if previous.get("byteReturnPath", {}).get("returnedByteAddress") != SOURCE_GLOBAL:
        raise TriageError("Pinned original returned byte global mismatch")
    candidates = verified_xref_candidates(previous)
    target = {t.name: t for t in choose_targets(root)}["LinuxLoader"]
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA entrypoint missing/unsafe")
    folder = root/"rea-security-audit"/"LinuxLoader"
    runner = Runner(root/"rea-security-audit",
                    rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    results = []
    for c in candidates:
        entry, site = c["ownerEntry"], c["site"]
        function = runner.obtain(
            target, ["function", str(target.path), entry],
            folder/("function-"+safe_segment(entry)+".json"),
            operation="analyze_function", parameter="procedure", value=entry,
        )
        instructions = runner.obtain(
            target, ["instructions", str(target.path), entry],
            folder/("instructions-"+safe_segment(entry)+".json"),
            operation="read_function_instructions", parameter="procedure", value=entry,
        )
        results.append({
            **c,
            "functionDossier": function_context(function, entry=entry, site=site)
                        if function is not None else None,
            "nativeDossier": native_context(
                instructions, entry=entry, site=site,
                opcode=c["opcode"], operands=c["operands"],
            ) if instructions is not None else None,
        })
    return {
        "schemaVersion": 1, "archiveSha256": HXL1_BL_SHA256,
        "mode": "STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "queryCount": len(runner.planned),
        "originalGlobal": SOURCE_GLOBAL,
        "sourceAttested": True,
        "storeCandidates": results,
        "actualWriterIdentified": False,
        "trustedBootStateSourceIdentified": False,
        "firmwareFlashAuthorizationBypass": False,
        "deviceModified": False,
    }


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 original IsUnlocked global — candidate producer provenance",
        "",
        "**Original pinned LinuxLoader static Ghidra Evidence. No device actions.**",
        "", "BL SHA256: "+report["archiveSha256"],
        "Global read by AVB status callback: "+report["originalGlobal"],
        "New Ghidra queries: "+str(report["queryCount"]),
        "",
        "## Original source-attested candidate stores",
        "",
    ]
    for candidate in report["storeCandidates"]:
        entry, site = candidate["ownerEntry"], candidate["site"]
        lines += [
            "### "+entry+" store "+site,
            "",
            "- Hypothesis: "+candidate["label"],
            "- Original STRB xref Evidence: "+candidate["xrefInstructionEvidenceId"],
            "- Store operand: "+candidate["opcode"]+" "+candidate["operands"],
            "- Actual store to 0x351055 proven: False (address alias unresolved)",
            "",
        ]
        pseudo = candidate["functionDossier"]
        if pseudo is None:
            lines += ["Original Ghidra function dossier not yet collected.", ""]
        else:
            lines += [
                "- Original function Evidence: "+pseudo["evidenceId"],
                "- Ghidra decompilation lines: "+str(pseudo["lines"]),
                "- Native p-code availability: "+str(pseudo["pcodeAvailable"]),
                "", "#### Function code with numbered lines", "", "~~~c",
            ]
            for line in pseudo["selectedCode"]:
                lines.append(f"{line['line']:5d} | {line['code']}")
            lines += ["~~~", ""]
            if pseudo["excerptTruncated"]:
                lines += ["Bounded excerpt only; full original Evidence JSON retained.", ""]
        instructions = candidate["nativeDossier"]
        if instructions is None:
            lines += ["Native instruction listing not yet collected.", ""]
        else:
            lines += [
                "- Original native instruction Evidence: "+instructions["evidenceId"],
                "- Native instructions in owning function: "+str(instructions["instructionCount"]),
                "", "#### Native address/value provenance window", "", "~~~asm",
            ]
            for n in instructions["instructionWindow"]:
                lines.append(n["address"]+": "+n["mnemonic"]+" "+n["operands"])
            lines += ["~~~", "",
                      "Note: the instruction window is static, not a verified",
                      "control-flow path. W19 origin / X8 or X19 alias may remain unresolved.",
                      ""]
    lines += [
        "## Outstanding gates", "",
        "1. Trace the register base to the exact target byte using actual",
        "   address-formation instructions, including any branch, register",
        "   alias, object pointer, or indirect call dependencies.",
        "2. Trace stored byte W19 to its local computation or caller-supplied",
        "   input, and determine reachable conditions for both stores.",
        "3. Resolve the producer of the value and whether it is protected",
        "   by secure-world policy. A diagnostic AVB flag may be a derived",
        "   copy rather than the enforceable OEM unlock authorization.",
        "4. No patch, flash, or bootloader unlock is demonstrated.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path, default=Path.home()/
                    "s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea", type=Path, default=Path.home()/"src/rea/scripts/rea.mjs")
    ap.add_argument("--node", default="node")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--recover-partials", action="store_true")
    ap.add_argument("--timeout", type=int, default=240)
    a = ap.parse_args()
    if not 30 <= a.timeout <= 1200:
        ap.error("Ghidra timeout out of bounded range")
    try:
        root = a.input_dir.expanduser().resolve()
        report = audit(root, execute=a.execute, rea=a.rea,
                       node=a.node, timeout=a.timeout,
                       recover_partials=a.recover_partials)
        out = root/"rea-security-audit"
        (out/"avb-byte-producers.json").write_text(json.dumps(report, indent=2)+"\n")
        (out/"avb-byte-producers.md").write_text(markdown(report))
    except (TriageError, OSError, KeyError, TypeError, ValueError) as e:
        print("[STOP]", str(e), file=sys.stderr)
        return 2
    for result in report["storeCandidates"]:
        print("[CANDIDATE]", result["site"], result["label"],
              "function", result["functionDossier"]["entry"] if result["functionDossier"] else "PENDING",
              "native", "VERIFIED" if result["nativeDossier"] else "PENDING")
    print("[REPORT]", out/"avb-byte-producers.md")
    print("[LIMIT] Memory alias, secure-state authority and unlock unproved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
