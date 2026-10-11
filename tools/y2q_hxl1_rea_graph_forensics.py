#!/usr/bin/env python3
"""Offline, bounded REA p-code graph inventory for original HXL1 OEM/AVB traces.

Uses authenticated REA workflow JSON, never launches Ghidra or accesses a phone.
Outputs static review candidates, not verified vulnerabilities or unlocks.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import choose_targets
from tools.y2q_hxl1_rea_decision_path_review import audit as validate_dossiers
from tools.y2q_hxl1_rea_trace_evidence import validated_trace

ROOTS = (("Odin", "0x1ec00"), ("LinuxLoader", "0x5950"))
INTERESTING = {"CALLIND", "CALL", "RETURN", "CBRANCH", "LOAD", "STORE"}
HEXADDR = re.compile(r"^0x[0-9a-f]+$", re.I)


def varnode_summary(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TriageError("Malformed high-p-code varnode")
    kind = value.get("kind")
    if kind not in ("constant", "address", "register", "unique", "other"):
        raise TriageError("Unknown high-p-code varnode kind")
    location, const = value.get("location"), value.get("constant_hex")
    if location is not None and not isinstance(location, str):
        raise TriageError("Invalid p-code varnode location")
    if const is not None and (not isinstance(const, str) or
                              re.fullmatch(r"[0-9a-f]+", const) is None):
        raise TriageError("Invalid p-code constant representation")
    return {"kind": kind, "location": location, "constantHex": const}


def summarize(ev: dict, name: str, entry: str) -> dict:
    graph = ev["normalized_result"]
    nodes, edges, unknowns = (graph.get(x) for x in ("nodes", "edges", "unknowns"))
    if (not isinstance(nodes, list) or len(nodes) > 5000
            or not isinstance(edges, list) or len(edges) > 40000
            or not isinstance(unknowns, list) or len(unknowns) > 10000):
        raise TriageError("Invalid or oversized original REA graph page")
    total_nodes = graph.get("total_nodes")
    total_edges = graph.get("total_edges")
    next_offset = graph.get("next_offset")
    if (type(total_nodes) is not int or type(total_edges) is not int
            or total_nodes < len(nodes) or total_edges < 0
            or (next_offset is not None and
                (type(next_offset) is not int or next_offset <= 0))):
        raise TriageError("Inconsistent REA graph pagination")
    ids = set()
    op_counts = Counter()
    focal = []
    for node in nodes:
        if not isinstance(node, dict):
            raise TriageError("Malformed high-p-code node")
        ident, procedure = node.get("id"), node.get("procedure")
        if not isinstance(ident, str) or not isinstance(procedure, str) or ident in ids:
            raise TriageError("Invalid or duplicate high-p-code node ID")
        ids.add(ident)
        if procedure != entry or node.get("kind") != "operation":
            continue
        op = node.get("operation")
        if not isinstance(op, dict) or not isinstance(op.get("opcode"), str):
            raise TriageError("Malformed original root high-p-code operation")
        opcode = op["opcode"]
        op_counts[opcode] += 1
        if opcode not in INTERESTING:
            continue
        address = op.get("address")
        inputs = op.get("inputs")
        if (not isinstance(address, str) or not HEXADDR.fullmatch(address)
                or not isinstance(inputs, list) or len(inputs) > 64):
            raise TriageError("Invalid p-code address/operand list")
        focal.append({
            "nodeId": ident, "address": address, "opcode": opcode,
            "sequence": op.get("sequence"),
            "blockMembership": op.get("block_membership"),
            "inputs": [varnode_summary(v) for v in inputs[:4]],
            "inputsTruncated": len(inputs) > 4,
            "output": varnode_summary(op.get("output")),
        })
    focal.sort(key=lambda x: (int(x["address"], 16), x["nodeId"]))
    calls = [x for x in focal if x["opcode"] in ("CALL", "CALLIND")]
    edge_counts = Counter()
    calls_related = []
    for edge in edges:
        if not isinstance(edge, dict) or not isinstance(edge.get("kind"), str):
            raise TriageError("Malformed REA dependency edge")
        edge_counts[edge["kind"]] += 1
        src, dst = edge.get("source"), edge.get("target")
        if not isinstance(src, str) or not isinstance(dst, str):
            raise TriageError("Missing REA dependency edge endpoint")
        if (edge["kind"] in ("call", "argument-binding", "return-binding")
                and (src.startswith(entry + "/") or dst.startswith(entry + "/"))):
            calls_related.append({
                "source": src, "target": dst, "kind": edge["kind"],
                "status": edge.get("status"), "inputIndex": edge.get("input_index"),
                "targetPresentOnPage": dst in ids,
            })
    unknown_reasons = Counter()
    for item in unknowns:
        if not isinstance(item, dict) or not isinstance(item.get("reason"), str):
            raise TriageError("Malformed REA unresolved observation")
        unknown_reasons[item["reason"]] += 1
    return {
        "module": name, "entry": entry, "traceEvidenceId": ev["evidence_id"],
        "nodesOnPage": len(nodes), "edgesOnPage": len(edges),
        "totalNodes": total_nodes, "totalEdges": total_edges,
        "nextOffset": next_offset, "truncatedOrPaged": graph["truncated"],
        "decompilations": graph["decompilations"],
        "procedures": [{"address": p.get("address"), "depth": p.get("depth")}
                       for p in graph["procedures"][:32]],
        "rootOpcodeCounts": dict(sorted(op_counts.items())),
        "rootFocalOperations": len(focal), "rootCalls": len(calls),
        "rootCallSample": calls[:48],
        "edgeTypeCounts": dict(sorted(edge_counts.items())),
        "rootCallEdgeCount": len(calls_related),
        "rootCallEdgeSample": calls_related[:48],
        "unresolvedCount": len(unknowns),
        "unresolvedReasons": [{"reason": k, "count": v}
                              for k, v in unknown_reasons.most_common(18)],
        "originalSecureStateProven": False,
        "indirectCallbackImplementationProven": False,
        "vulnerabilityProven": False,
    }


def audit(root: Path) -> dict:
    dossier = validate_dossiers(root)
    if not dossier.get("allFiveReferencesVerified"):
        raise TriageError("Original HXL1 search/xref/function proof chain incomplete")
    targets = {t.name: t for t in choose_targets(root)}
    results = []
    for module, entry in ROOTS:
        path = root / "rea-security-audit" / module / ("trace-" + entry + ".json")
        original = validated_trace(path, sha=targets[module].sha256, entry=entry)
        results.append(summarize(original, module, entry))
    return {
        "schemaVersion": 1, "originalArchiveSha256": HXL1_BL_SHA256,
        "sourcesVerified": True, "results": results,
        "trustedUnlockStateOriginVerified": False,
        "deviceModified": False, "workingUnlockDemonstrated": False,
    }


def markdown(report: dict) -> str:
    lines = [
        "# Original HXL1 REA graphs — dataflow and coverage review", "",
        "Authenticated saved REA/Ghidra data; NOT a runtime or vulnerability finding.",
        "", "Archive SHA256: " + report["originalArchiveSha256"], "",
    ]
    for item in report["results"]:
        lines += [
            "## " + item["module"] + " " + item["entry"], "",
            "REA Evidence ID: " + item["traceEvidenceId"],
            "Nodes page / total: " + str(item["nodesOnPage"]) + " / " + str(item["totalNodes"]),
            "Edges page / total: " + str(item["edgesOnPage"]) + " / " + str(item["totalEdges"]),
            "Next page offset: " + str(item["nextOffset"]),
            "Truncated or paged: " + str(item["truncatedOrPaged"]),
            "Decompiled procedures: " + str(item["decompilations"]),
            "Root p-code opcode counts: " + str(item["rootOpcodeCounts"]),
            "Root CALL and CALLIND opcodes on this page: " + str(item["rootCalls"]),
            "", "### Original root call sites", "",
        ]
        for call in item["rootCallSample"]:
            parts = [
                operand["kind"] + ":" + str(operand["location"] or operand["constantHex"])
                for operand in call["inputs"][:3]
            ]
            lines.append("- " + call["address"] + " " + call["opcode"] +
                         " [" + call["nodeId"] + "] " + ", ".join(parts))
        if not item["rootCallSample"]:
            lines.append("- No calls on current page; this is not an absence proof.")
        lines += ["", "### Root call relationships", ""]
        for edge in item["rootCallEdgeSample"]:
            lines.append("- " + edge["kind"] + " (" + str(edge["status"]) + "): " +
                         edge["source"] + " => " + edge["target"] +
                         ("" if edge["targetPresentOnPage"] else " [target not on page]"))
        if not item["rootCallEdgeSample"]:
            lines.append("- No root call edges on the returned page.")
        lines += ["", "### Unresolved trace observations", "",
                  "Total: " + str(item["unresolvedCount"])]
        for row in item["unresolvedReasons"]:
            lines.append("- " + str(row["count"]) + "x " + row["reason"])
        if item["nextOffset"] is not None:
            lines += ["", "COVERAGE WARNING: REA returned a graph page. Some",
                      "operations are outside this page; no absence conclusions."]
        lines.append("")
    lines += [
        "## Next investigation gates", "",
        "1. Odin: inspect the provider behind the persistent storage lookup,",
        "   the indirect storage read, and the final one-byte extraction.",
        "2. LinuxLoader: identify who assigns the indirect function pointer",
        "   at param_1 + 0x40 and the trusted source of the returned state.",
        "3. Investigate individual Ghidra CALLIND sites using exact",
        "   function/instruction evidence; do not infer unresolved targets.",
        "4. Distinguish the separate Odin OEM authorization result producer",
        "   from diagnostic messages in the error-reporting function.",
        "5. A paginated/static graph does not prove exploitability,",
        "   firmware signature bypass, or bootloader unlock.", "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", type=Path,
                    default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    args = ap.parse_args()
    try:
        root = args.input_dir.expanduser().resolve()
        result = audit(root)
        out = root / "rea-security-audit"
        (out / "graph-forensics.json").write_text(json.dumps(result, indent=2) + "\n")
        (out / "graph-forensics.md").write_text(markdown(result))
    except (TriageError, OSError, ValueError, TypeError, KeyError) as err:
        print("[STOP]", err, file=sys.stderr)
        return 2
    for row in result["results"]:
        print("[VERIFIED]", row["module"], row["entry"],
              "nodes", row["nodesOnPage"], "/", row["totalNodes"],
              "root calls", row["rootCalls"],
              "unknowns", row["unresolvedCount"],
              "nextOffset", row["nextOffset"])
    print("[REPORT]", out / "graph-forensics.md")
    print("[LIMIT] No protected state origin or bypass demonstrated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
