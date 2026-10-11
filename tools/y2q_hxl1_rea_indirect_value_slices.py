#!/usr/bin/env python3
"""Host-only original-HXL1 register/indirect-pointer p-code backward slices.

Works entirely with previously SHA256-validated REA/Ghidra Evidence. Never
calls REA, Ghidra, Odin, ADB, Fastboot or the phone. All results are static
decompiler-derived review candidates; no callback callee/unlock is inferred.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import choose_targets, evidence, function_record
from tools.y2q_hxl1_rea_callsite_attribution import (
    SITES, STORE_PROVIDER, audit as validate_callsite_evidence,
)
from tools.y2q_hxl1_rea_indirect_pages import inspect_pages
from tools.y2q_hxl1_rea_trace_evidence import validated_trace

MAX_DEPTH = 7
MAX_SLICE_NODES = 72
MAX_DISPLAY_LINES = 110
ENTRY_LABELS = {"Odin": "0x1ec00", "LinuxLoader": "0x5950"}
ALLOWED_DEPENDENCIES = {"def-use", "parameter-use", "return-binding"}


def graph_for(root: Path, module: str, entry: str, sha: str) -> tuple[dict, dict]:
    directory = root / "rea-security-audit" / module
    first = validated_trace(directory / ("trace-" + entry + ".json"),
                            sha=sha, entry=entry)
    offset = first["normalized_result"].get("next_offset")
    second = None
    if offset is not None:
        if module != "LinuxLoader" or offset != 1000:
            raise TriageError("Unexpected original HXL1 graph pagination address")
        second = validated_trace(
            directory / f"trace-{entry}-offset{offset}-limit1000.json",
            sha=sha, entry=entry, offset=offset, limit=1000)
    pages = inspect_pages(first, second, entry=entry)
    if pages["coveredNodes"] != pages["totalNodes"] or pages["nextOffset"] is not None:
        raise TriageError("Cannot slice missing original HXL1 retained graph page")
    graphs = [first["normalized_result"]]
    if second:
        graphs.append(second["normalized_result"])
    nodes = [n for g in graphs for n in g["nodes"]]
    edges = [e for g in graphs for e in g["edges"]]
    identities = [n["id"] for n in nodes]
    if (len(identities) != len(set(identities))
            or len(nodes) != first["normalized_result"]["total_nodes"]
            or len(edges) != first["normalized_result"]["total_edges"]):
        raise TriageError("REA complete retained nodes/edges mismatch")
    return {
        "nodes": nodes, "edges": edges,
        "unknowns": first["normalized_result"]["unknowns"],
        "truncated": first["normalized_result"]["truncated"],
        "totalNodes": len(nodes), "totalEdges": len(edges),
        "decompilations": first["normalized_result"]["decompilations"],
    }, pages


def varnode(v: object) -> dict | None:
    if v is None:
        return None
    if not isinstance(v, dict):
        raise TriageError("Invalid original p-code varnode")
    return {
        "kind": v.get("kind"),
        "location": v.get("location"),
        "constantHex": v.get("constant_hex"),
        "sizeBytes": v.get("size_bytes"),
    }


def compact_node(node: dict, depth: int) -> dict:
    op = node.get("operation")
    if node.get("kind") == "parameter":
        return {
            "node": node["id"], "distance": depth, "kind": "parameter",
            "parameter": node.get("parameter"),
        }
    if not isinstance(op, dict):
        raise TriageError("Original REA operation missing for active graph node")
    ins = op.get("inputs")
    if not isinstance(ins, list) or len(ins) > 64:
        raise TriageError("Original REA p-code inputs missing or oversized")
    return {
        "node": node["id"], "distance": depth, "kind": "operation",
        "address": op.get("address"), "opcode": op.get("opcode"),
        "sequence": op.get("sequence"),
        "blockMembership": op.get("block_membership"),
        "inputs": [varnode(x) for x in ins[:6]],
        "moreInputs": len(ins) > 6, "output": varnode(op.get("output")),
    }


def backward_slice(graph: dict, *, entry: str, site: str,
                   max_depth: int = MAX_DEPTH, max_nodes: int = MAX_SLICE_NODES) -> dict:
    """Follow only Ghidra-derived operation def-use edges toward CALLIND input[0].

    Input zero is the computed callee of a CALLIND p-code operation. Following
    producer operations does NOT resolve memory aliasing or callback origin.
    """
    nodes = graph["nodes"]
    index = {}
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise TriageError("Malformed saved graph node")
        if node["id"] in index:
            raise TriageError("Duplicate saved graph node")
        index[node["id"]] = node
    exact = [
        n for n in nodes if n.get("procedure") == entry
        and isinstance(n.get("operation"), dict)
        and n["operation"].get("address") == site
        and n["operation"].get("opcode") == "CALLIND"
    ]
    if len(exact) != 1:
        raise TriageError(f"Expected exactly one owned Ghidra CALLIND at {entry}:{site}")
    root = exact[0]
    if root["operation"].get("block_membership") != "member":
        raise TriageError("Original indirect call not part of live Ghidra block")
    inputs = root["operation"].get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise TriageError("Missing original CALLIND target operand")
    incoming = defaultdict(list)
    for edge in graph["edges"]:
        if not isinstance(edge, dict):
            raise TriageError("Malformed REA dependency edge")
        if edge.get("kind") in ALLOWED_DEPENDENCIES:
            incoming[edge.get("target")].append(edge)
    selected = [compact_node(root, 0)]
    traversed = []
    queue = [(root["id"], 0, True)]
    visited = {root["id"]}
    missing = []
    while queue and len(selected) < max_nodes:
        current, depth, first = queue.pop(0)
        if depth >= max_depth:
            continue
        for edge in incoming.get(current, []):
            if first and edge.get("input_index") != 0:
                continue
            src = edge.get("source")
            if not isinstance(src, str):
                raise TriageError("Malformed REA dependency source")
            if len(traversed) < 400:
                traversed.append({
                    "from": src, "to": current, "kind": edge["kind"],
                    "inputIndex": edge.get("input_index"),
                    "status": edge.get("status"),
                })
            pred = index.get(src)
            if pred is None:
                missing.append(src)
                continue
            if src in visited:
                continue
            visited.add(src)
            selected.append(compact_node(pred, depth + 1))
            queue.append((src, depth + 1, False))
            if len(selected) >= max_nodes:
                break
    return {
        "entry": entry, "callsite": site, "callNode": root["id"],
        "targetOperand": varnode(inputs[0]),
        "matchedDependencyEdges": len(traversed),
        "chain": selected,
        "chainNodeCount": len(selected),
        "unseenSourceReferences": sorted(set(missing))[:24],
        "limitedByDepthOrSize": bool(queue) or any(
            x["distance"] == max_depth for x in selected),
        "loadRequiresAliasResolution": any(
            n.get("opcode") == "LOAD" for n in selected),
        "indirectTargetResolved": False,
        "securityStateSourceEstablished": False,
    }


def code_window(pseudo: str, patterns: tuple[str, ...], *,
                window: int = 6, max_lines: int = MAX_DISPLAY_LINES) -> dict:
    lines = pseudo.splitlines()
    matches = [
        i for i, line in enumerate(lines)
        if any(re.search(p, line, re.I) for p in patterns)
    ]
    keep = set()
    for i in matches[:30]:
        keep.update(range(max(0, i-window), min(len(lines), i+window+1)))
    chosen = sorted(keep)[:max_lines]
    return {
        "totalLines": len(lines), "matchedLineNumbers": [i+1 for i in matches],
        "truncated": len(matches) > 30 or len(keep) > len(chosen),
        "selected": [{"line": i+1, "code": lines[i][:550]} for i in chosen],
    }


def original_dossiers(root: Path, targets: dict) -> dict:
    out = root / "rea-security-audit"
    module, entry = STORE_PROVIDER
    odin_ev = evidence(
        out / module / ("function-" + entry + ".json"),
        sha=targets[module].sha256, operation="analyze_function",
        parameter="procedure", value=entry)
    verified = function_record(odin_ev, entry)
    if verified["entry"] != entry:
        raise TriageError("Original Odin storage provider owning function mismatched")
    original = odin_ev["normalized_result"]["pseudocode"]
    if not isinstance(original, str):
        raise TriageError("Missing original Odin function pseudocode")
    # All 58 lines of the owner's original Ghidra 0x10e58 dossier, not the
    # single lexical match displayed in the earlier report.
    if len(original.splitlines()) > 200:
        raise TriageError("Odin original provider function exceeds bounded full display")
    avb = evidence(
        out / "LinuxLoader" / "function-0x3f34.json",
        sha=targets["LinuxLoader"].sha256,
        operation="analyze_function", parameter="procedure", value="0x3f34")
    avb_check = function_record(avb, "0x3f34")
    if avb_check["entry"] != "0x2274":
        raise TriageError("Original AVB caller seed owning entry unexpected")
    pseudo_avb = avb["normalized_result"]["pseudocode"]
    callback = evidence(
        out / "LinuxLoader" / "function-0x59d4.json",
        sha=targets["LinuxLoader"].sha256,
        operation="analyze_function", parameter="procedure", value="0x59d4")
    cb_check = function_record(callback, "0x59d4")
    if cb_check["entry"] != "0x5950":
        raise TriageError("Original AVB callback user owning entry unexpected")
    return {
        "odinStorageLookup": {
            "entry": entry, "evidenceId": odin_ev["evidence_id"],
            "fullLines": [{"line": i+1, "code": line[:550]}
                          for i, line in enumerate(original.splitlines())],
        },
        "linuxLoaderAvbImage": {
            "entry": "0x2274", "evidenceId": avb["evidence_id"],
            "candidateCallAndInitializerContext": code_window(
                pseudo_avb,
                (r"FUN_00005950", r"read_is_device_unlocked",
                 r"(?<![0-9a-f])0x5950\b", r"\+ 0x40\b"),
                window=7, max_lines=105),
        },
        "linuxLoaderUnlockCallbackUser": {
            "entry": "0x5950", "evidenceId": callback["evidence_id"],
            "callContext": code_window(
                callback["normalized_result"]["pseudocode"],
                (r"\(param_1 \+ 0x40\)", r"androidboot\.vbmeta\.device_state"),
                window=9, max_lines=85),
        },
    }


def audit(root: Path) -> dict:
    # Verifies exact owner-identified CALLIND addresses, full retained pages,
    # original binary hashes, native decoding and original Ghidra provenance.
    root_review = validate_callsite_evidence(root)
    if not root_review["allCallsiteFactsObserved"]:
        raise TriageError("Unverified original Ghidra instruction/call-target Evidence")
    targets = {x.name: x for x in choose_targets(root)}
    graphs = {}
    for module, entry in ENTRY_LABELS.items():
        graphs[module], _ = graph_for(root, module, entry, targets[module].sha256)
    findings = []
    for module, entry, site, purpose in SITES:
        detail = next((x for x in root_review["selectedCalls"]
                       if x["module"] == module and x["callsite"] == site), None)
        if detail is None or detail.get("observed") is None:
            raise TriageError("Original call site provider evidence incomplete")
        record = backward_slice(graphs[module], entry=entry, site=site)
        findings.append({
            "module": module, "purpose": purpose,
            "nativeInstruction": detail["observed"]["rawDisassembly"],
            "GhidraResolution": detail["observed"]["providerResolutionStatus"],
            "instructionEvidenceId": detail["observed"]["instructionEvidenceId"],
            "resolverEvidenceId": detail["observed"]["resolverEvidenceId"],
            **record,
        })
    return {
        "schemaVersion": 1, "originalArchiveSha256": HXL1_BL_SHA256,
        "HXL1OriginalSourcesAuthenticated": True, "mode": "SAVED_ONLY_NO_NEW_REA",
        "traces": [
            {"module": n, "entry": ENTRY_LABELS[n], "nodes": graphs[n]["totalNodes"],
             "edges": graphs[n]["totalEdges"],
             "truncated": graphs[n]["truncated"],
             "decompilations": graphs[n]["decompilations"]}
            for n in ENTRY_LABELS
        ],
        "callSlices": findings, "originalDossiers": original_dossiers(root, targets),
        "callbackInitializerVerified": False,
        "oemAuthorizationAuthorityVerified": False,
        "vulnerabilityDemonstrated": False, "phoneModified": False,
    }


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 original Ghidra — indirect call target backward slices",
        "",
        "**Strictly offline review of original, saved, SHA256-attested HXL1 Evidence.**",
        "No indirect callee, protected state authority, security bypass or unlock proven.",
        "",
        "Original archive: " + report["originalArchiveSha256"],
        "New REA commands: zero", "",
    ]
    for block in report["callSlices"]:
        lines += [
            "## " + block["module"] + " " + block["callsite"], "",
            "- Purpose: " + block["purpose"],
            "- Native instruction: " + block["nativeInstruction"],
            "- Ghidra resolution: " + block["GhidraResolution"],
            "- CALLIND target input[0]: " + str(block["targetOperand"]),
            "- Backward dependency operations: " + str(block["chainNodeCount"]),
            "- Dependency edges retained: " + str(block["matchedDependencyEdges"]),
            "- LOAD alias follow-up required: " + str(block["loadRequiresAliasResolution"]),
            "- Slice budget limit reached: " + str(block["limitedByDepthOrSize"]),
            "", "### Static Ghidra producers (root first)", "",
        ]
        for n in block["chain"]:
            if n["kind"] == "parameter":
                lines.append("- depth " + str(n["distance"]) + " parameter " +
                             n["node"] + " " + str(n["parameter"]))
            else:
                lines.append("- depth " + str(n["distance"]) + " " +
                             str(n["address"]) + " " + str(n["opcode"]) +
                             " " + n["node"] + " inputs=" + str(n["inputs"][:3]))
        if block["unseenSourceReferences"]:
            lines += ["", "Missing graph sources: " +
                      str(block["unseenSourceReferences"])]
        lines.append("")
    dossiers = report["originalDossiers"]
    lines += ["## Odin 0x10e58 — full original 58-line partition-lookup function", "",
              "~~~c"]
    for line in dossiers["odinStorageLookup"]["fullLines"]:
        lines.append(f"{line['line']:5d} | {line['code']}")
    lines += ["~~~", "",
              "## LinuxLoader 0x2274 — potential AVB callback initializer/caller references", ""]
    avb = dossiers["linuxLoaderAvbImage"]["candidateCallAndInitializerContext"]
    lines.append("Original pseudocode matching lines: " +
                 str(avb["matchedLineNumbers"]))
    lines.append("~~~c")
    for line in avb["selected"]:
        lines.append(f"{line['line']:5d} | {line['code']}")
    lines += ["~~~", "", "## LinuxLoader 0x5950 — callback invocation context", "",
              "~~~c"]
    for line in dossiers["linuxLoaderUnlockCallbackUser"]["callContext"]["selected"]:
        lines.append(f"{line['line']:5d} | {line['code']}")
    lines += ["~~~", "", "## Coverage and interpretation", "",
              "- A CALLIND target loaded from memory is not resolved solely by",
              "  Ghidra p-code SSA edges; object aliasing and interface assignment",
              "  require separate static evidence.",
              "- No matching LinuxLoader initializer in the saved 0x2274 dossier",
              "  would NOT establish that the initializer does not exist.",
              "- Both original REA graphs reached decompilation budgets;",
              "  all retained pages have been recovered but call coverage is partial.",
              "- The one-byte persistent-storage observation alone does not",
              "  establish authenticity, authority, exploitability or unlock.", ""]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    args = p.parse_args()
    try:
        root = args.input_dir.expanduser().resolve()
        result = audit(root)
        out = root / "rea-security-audit"
        (out / "indirect-value-slices.json").write_text(json.dumps(result, indent=2) + "\n")
        (out / "indirect-value-slices.md").write_text(markdown(result))
    except (TriageError, OSError, KeyError, TypeError, ValueError) as exc:
        print("[STOP]", str(exc), file=sys.stderr)
        return 2
    for site in result["callSlices"]:
        print("[SLICE]", site["module"], site["callsite"],
              "nodes", site["chainNodeCount"],
              "load_alias", site["loadRequiresAliasResolution"])
    print("[REPORT]", out / "indirect-value-slices.md")
    print("[LIMIT] No static callee assignment, unlock authority or exploit proven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
