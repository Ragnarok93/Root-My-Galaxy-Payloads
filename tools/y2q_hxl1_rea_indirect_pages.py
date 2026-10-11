#!/usr/bin/env python3
"""Read-only HXL1 REA graph pagination and complete root indirect-call inventory.

The owner-executed Odin trace covers all retained 947 nodes but is marked
truncated because the provider hit a decompilation budget. The LinuxLoader
trace returned only 1000/1630 nodes and advertises next_offset=1000.

Default mode inspects saved traces and PLANS a bounded second-page request.
Only --execute launches the preconfigured local REA/Ghidra CLI. The script
reuses original validated results, never overwrites Evidence or touches a phone.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import Runner, choose_targets
from tools.y2q_hxl1_rea_decision_path_review import audit as verify_five
from tools.y2q_hxl1_rea_trace_evidence import validated_trace

TARGETS = (("Odin", "0x1ec00"), ("LinuxLoader", "0x5950"))
PAGE_LIMIT = 1000


def extract_indirect(graph: dict, entry: str) -> list[dict]:
    """Inventory every CALLIND on a returned graph page, never infer its target."""
    sites = []
    seen = set()
    for node in graph["nodes"]:
        if not isinstance(node, dict) or node.get("procedure") != entry:
            continue
        op = node.get("operation")
        if not isinstance(op, dict) or op.get("opcode") != "CALLIND":
            continue
        identity, address = node.get("id"), op.get("address")
        if (not isinstance(identity, str) or identity in seen
                or not isinstance(address, str)):
            raise TriageError("Invalid or duplicated root Ghidra CALLIND operation")
        seen.add(identity)
        sites.append({
            "node": identity,
            "address": address,
            "blockMembership": op.get("block_membership"),
            "operandKinds": [i.get("kind") for i in op.get("inputs", [])[:4]],
            "resolvedDestination": None,
            "origin": "GHIDRA_PCODE_ONLY",
        })
    sites.sort(key=lambda x: (x["address"], x["node"]))
    return sites


def inspect_pages(first: dict, second: dict | None, *,
                  entry: str, expected_limit: int = PAGE_LIMIT) -> dict:
    base = first["normalized_result"]
    initial = base["nodes"]
    total = base["total_nodes"]
    offset = base.get("next_offset")
    if not isinstance(total, int) or not isinstance(initial, list) or total < len(initial):
        raise TriageError("Original REA first-page total invalid")
    if offset is not None and offset != len(initial):
        raise TriageError("Unexpected non-contiguous first REA graph page")
    if second is not None and offset is None:
        raise TriageError("Extra REA graph page where original trace declared none")
    final_nodes = list(initial)
    combined_pages = 1
    paged = None
    if second is not None:
        page = second["normalized_result"]
        if (page.get("seed") != entry or page.get("target_sha256") != base.get("target_sha256")
                or page.get("total_nodes") != total
                or page.get("total_edges") != base.get("total_edges")
                or page.get("decompilations") != base.get("decompilations")
                or page.get("procedures") != base.get("procedures")
                or page.get("unknowns") != base.get("unknowns")):
            raise TriageError("REA pagination regenerated inconsistent dependency graph")
        if len(page["nodes"]) != min(expected_limit, total - offset):
            raise TriageError("REA page length is inconsistent with original offset")
        first_ids = {n.get("id") for n in initial}
        if len(first_ids) != len(initial) or len({n.get("id") for n in page["nodes"]}) != len(page["nodes"]):
            raise TriageError("Duplicate high-p-code identity within a page")
        if any(n.get("id") in first_ids for n in page["nodes"]):
            raise TriageError("Overlapping REA graph page node identities")
        combined_pages = 2
        paged = {
            "offset": offset, "returnedNodes": len(page["nodes"]),
            "evidenceId": second["evidence_id"],
            "nextOffset": page.get("next_offset"),
        }
        final_nodes.extend(page["nodes"])
    unknowns = base["unknowns"]
    reasons = Counter(x["reason"] for x in unknowns)
    combined = {"nodes": final_nodes}
    return {
        "entry": entry, "originalEvidenceId": first["evidence_id"],
        "baselineReturned": len(initial), "totalNodes": total,
        "coveredNodes": len(final_nodes),
        "nextOffset": None if second is not None and paged["nextOffset"] is None else (
            paged["nextOffset"] if paged is not None else offset),
        "pages": combined_pages, "secondPage": paged,
        "rootIndirectCallsObserved": extract_indirect(combined, entry),
        "truncatedDespiteAllNodes": (len(final_nodes) == total and
                                     base["truncated"] is True),
        "decompilationBudgetReached": reasons.get("decompilation budget reached", 0) > 0,
        "decompilations": base["decompilations"],
        "unresolvedCount": len(unknowns),
        "unresolvedReasons": [{"reason": k, "count": count}
                              for k, count in reasons.most_common(16)],
        "trustedOriginProven": False, "indirectCallTargetProven": False,
    }


def review(root: Path, *, execute: bool = False, rea: Path | None = None,
           node: str = "node", timeout: int = 240,
           recover_partials: bool = False) -> dict:
    verified = verify_five(root)
    if not verified["allFiveReferencesVerified"]:
        raise TriageError("Five original HXL1 function Evidence chains are incomplete")
    targets = {t.name: t for t in choose_targets(root)}
    out = root / "rea-security-audit"
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA Node script is not an installed regular file")
    runner = Runner(out, rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    results = []
    for name, entry in TARGETS:
        target = targets[name]
        first_path = out / name / ("trace-" + entry + ".json")
        first = validated_trace(first_path, sha=target.sha256, entry=entry)
        base = first["normalized_result"]
        second = None
        offset = base.get("next_offset")
        if name == "LinuxLoader" and offset is not None:
            if type(offset) is not int or not 1 <= offset <= 5000:
                raise TriageError("Unexpected original HXL1 REA graph offset")
            if offset != len(base["nodes"]):
                raise TriageError("Original LinuxLoader graph has invalid first-page offset")
            suffix = f"-offset{offset}-limit{PAGE_LIMIT}.json"
            page_file = out / name / ("trace-" + entry + suffix)
            second = runner.obtain(
                target,
                ["trace-native-values", str(target.path), entry,
                 "--offset", str(offset), "--limit", str(PAGE_LIMIT)],
                page_file,
                operation="trace_native_values", parameter="procedure", value=entry,
                trace_offset=offset, trace_limit=PAGE_LIMIT,
            )
        results.append({
            "module": name,
            **inspect_pages(first, second, entry=entry),
            "pendingSecondPage": name == "LinuxLoader" and offset is not None and second is None,
        })
    return {
        "schemaVersion": 1, "originalArchiveSha256": HXL1_BL_SHA256,
        "mode": "STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "sourcesAttested": True, "roots": results,
        "newCommands": len(runner.planned),
        "phoneModified": False,
        "authorizationBypassEstablished": False,
    }


def markdown(report: dict) -> str:
    lines = [
        "# Original HXL1 REA high-p-code page and CALLIND audit", "",
        "Original HXL1 binary and REA provenance validated; no device or unlock testing.",
        "", f"- Source BL SHA256: {report['originalArchiveSha256']}",
        f"- Execution mode: {report['mode']}",
        f"- New Ghidra operations: {report['newCommands']}", "",
    ]
    for row in report["roots"]:
        lines += [
            f"## {row['module']} {row['entry']}", "",
            f"- Combined graph nodes: {row['coveredNodes']} / {row['totalNodes']}",
            f"- Baseline Evidence: {row['originalEvidenceId']}",
            f"- Second-page Evidence: {row['secondPage']['evidenceId'] if row['secondPage'] else 'none'}",
            f"- Remaining page offset: {row['nextOffset']}",
            f"- REA decompilations: {row['decompilations']}",
            f"- Decompilation budget reached: {row['decompilationBudgetReached']}",
            f"- Graph truncation flag with all retained nodes: {row['truncatedDespiteAllNodes']}",
            f"- Unresolved observations: {row['unresolvedCount']}", "",
            "### Original root indirect calls (CALLIND)", "",
        ]
        for call in row["rootIndirectCallsObserved"]:
            lines.append(
                f"- {call['address']} ({call['node']}), block={call['blockMembership']}; "
                + "destination remains unverified"
            )
        if not row["rootIndirectCallsObserved"]:
            lines.append("None in returned pages; not proof of absence in the binary.")
        lines += ["", "### Most common unresolved observations", ""]
        for unknown in row["unresolvedReasons"]:
            lines.append(f"- {unknown['count']}x {unknown['reason']}")
        lines.append("")
        if row["pendingSecondPage"]:
            lines += [
                "PAGING GAP: run the explicit static page collector to review the",
                "remaining LinuxLoader Ghidra nodes. No missing-call conclusion yet.", "",
            ]
        elif row["nextOffset"] is not None:
            lines += ["PAGING GAP: additional pages remain beyond this bounded run.", ""]
    lines += [
        "## Next HXL1 static validation gates", "",
        "1. Odin: check CALLIND 0x1ec84 implementation and the provider function",
        "   0x10e58 for the persistent partition; neither is proven a trust anchor.",
        "2. LinuxLoader: locate the exact CALLIND implementing the AVB lock-state",
        "   callback and search for the function-pointer initializer.",
        "3. REA's per-run decompilation budgets can truncate a graph even when",
        "   every retained node is returned. Increase coverage only when needed.",
        "4. These are decompiler-derived static dependencies, not signed-image",
        "   acceptance, a security vulnerability, or a working unlock.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea", type=Path, default=Path.home() /
                   "src/rea/scripts/rea.mjs")
    p.add_argument("--node", default="node")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--recover-partials", action="store_true")
    p.add_argument("--timeout", type=int, default=240)
    a = p.parse_args()
    if not 30 <= a.timeout <= 1200:
        p.error("Invalid bounded Ghidra timeout")
    try:
        root = a.input_dir.expanduser().resolve()
        result = review(root, execute=a.execute, rea=a.rea,
                        node=a.node, timeout=a.timeout,
                        recover_partials=a.recover_partials)
        dest = root / "rea-security-audit"
        (dest / "indirect-call-pages.json").write_text(json.dumps(result, indent=2) + "\n")
        (dest / "indirect-call-pages.md").write_text(markdown(result))
    except (TriageError, OSError, ValueError, KeyError, TypeError) as exc:
        print("[STOP]", str(exc), file=sys.stderr)
        return 2
    for item in result["roots"]:
        print("[ROOT]", item["module"], item["entry"],
              "nodes", item["coveredNodes"], "/", item["totalNodes"],
              "indirect_calls", len(item["rootIndirectCallsObserved"]),
              "pending_page", item["pendingSecondPage"])
    print("[REPORT]", dest / "indirect-call-pages.md")
    print("[LIMIT] No OEM lock bypass, secure-state source or exploitable issue established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
