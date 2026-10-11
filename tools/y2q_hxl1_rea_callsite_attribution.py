#!/usr/bin/env python3
"""Exactly bounded original-HXL1 indirect-call provider resolution.

Proven original HXL1 Odin/LinuxLoader SHA, original five xref/function links,
and both owner-saved paged HighFunction graphs are admission prerequisites.

Default is PLAN ONLY. With --execute, request direct Ghidra instruction facts
and static provider target resolution for exactly four original CALLIND sites,
plus a function dossier for Odin's observed persistent-provider lookup.

Static outputs are review queues. There is NO firmware/device execution, no
flash action, no forged target inference, and no unlock claimed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, function_record, safe_segment,
)
from tools.y2q_hxl1_rea_indirect_pages import (
    review as verify_graph_pages,
)

SITES = (
    ("Odin", "0x1ec00", "0x1ec84", "persistent storage read"),
    ("LinuxLoader", "0x5950", "0x5dc4", "AVB indirect call A"),
    ("LinuxLoader", "0x5950", "0x5ea4", "AVB indirect call B"),
    ("LinuxLoader", "0x5950", "0x6020", "AVB indirect call C"),
)
STORE_PROVIDER = ("Odin", "0x10e58")


def callsite_observation(insn: dict, resolver: dict, *,
                         parent: str, address: str) -> dict:
    """Never infer a concrete callee unless the provider reports one."""
    decoded = insn.get("normalized_result")
    resolved = resolver.get("normalized_result")
    if not isinstance(decoded, dict) or not isinstance(resolved, dict):
        raise TriageError("Missing decoded instruction or call-target result")
    if (decoded.get("address") != address
            or decoded.get("procedure") != parent
            or resolved.get("call_site") != address
            or resolved.get("procedure") != parent):
        raise TriageError("Instruction/call-target function ownership mismatch")
    status, flow = decoded.get("status"), decoded.get("flow")
    if status != "decoded" or not isinstance(flow, dict):
        raise TriageError("Ghidra has not decoded exact indirect call instruction")
    if flow.get("kind") != "call" or flow.get("computed") is not True:
        raise TriageError("Ghidra decoded non-indirect-call at original CALLIND address")
    resolution = resolved.get("status")
    if resolution not in ("direct", "resolved-indirect", "ambiguous",
                          "unresolved", "not-call", "unavailable"):
        raise TriageError("Unexpected REA native call target status")
    targets = resolved.get("targets")
    if not isinstance(targets, list) or len(targets) > 64:
        raise TriageError("Invalid bounded native target resolution")
    out = []
    for target in targets:
        if (not isinstance(target, dict)
                or target.get("status") not in
                ("direct", "resolved-indirect", "candidate")
                or target.get("basis") != "provider-reference"
                or not isinstance(target.get("address"), str)):
            raise TriageError("Invalid original Ghidra native target")
        out.append({
            "address": target["address"],
            "procedure": target.get("procedure"),
            "status": target["status"], "basis": target["basis"],
        })
    return {
        "instructionEvidenceId": insn["evidence_id"],
        "resolverEvidenceId": resolver["evidence_id"],
        "mnemonic": decoded.get("mnemonic"),
        "rawDisassembly": decoded.get("raw_disassembly"),
        "flowKind": flow.get("kind"),
        "computedFlow": flow.get("computed"),
        "providerResolutionStatus": resolution,
        "mechanism": resolved.get("mechanism"),
        "targets": out, "limitations": resolved.get("limitations", []),
        "resolvedByProvider": resolution in ("direct", "resolved-indirect")
                              and any(x["status"] != "candidate" for x in out),
        "callbackSemanticIdentityEstablished": False,
        "runtimeReachabilityEstablished": False,
    }


def provider_dossier(ev: dict, *, entry: str) -> dict:
    """Attest the read-only Ghidra function; don't assign semantics by strings."""
    data = ev.get("normalized_result")
    if not isinstance(data, dict) or not isinstance(data.get("procedure"), dict):
        raise TriageError("Missing storage-provider function dossier")
    proc = data["procedure"]
    if proc.get("address") != entry:
        raise TriageError("Unexpected Ghidra provider function entry")
    verified = function_record(ev, entry)
    pseudo = data["pseudocode"]
    interesting = ("persistent", "blockio", "diskio", "partition", "locateprotocol")
    lines = pseudo.splitlines()
    matches = [i for i, line in enumerate(lines) if
               any(term in line.casefold() for term in interesting)]
    ranges = set()
    for index in matches[:24]:
        ranges.update(range(max(0, index-5), min(len(lines), index+8)))
    if not ranges:
        ranges.update(range(min(18, len(lines))))
    selected = sorted(ranges)[:90]
    return {
        "entry": entry, "evidenceId": ev["evidence_id"],
        "pcodeAvailable": verified["pcodeAvailable"],
        "fullPseudocodeLines": len(lines),
        "selected": [{"line": i+1, "code": lines[i][:450]} for i in selected],
        "truncated": len(matches)>24 or len(selected)<len(ranges),
        "storageDeviceSelectedAndAuthenticated": False,
        "OEMPolicyDecisionConfirmed": False,
    }


def audit(root: Path, *, execute: bool = False,
          rea: Path | None = None, node: str = "node",
          timeout: int = 240, recover_partials: bool = False) -> dict:
    pages = verify_graph_pages(root)
    by_module = {p["module"]: p for p in pages["roots"]}
    targets = {x.name: x for x in choose_targets(root)}
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA script unavailable/unsafe for exact static audit")
    expected_sites = {(module, address) for module, _, address, _ in SITES}
    graph_sites = {(p["module"], x["address"]) for p in pages["roots"]
                   for x in p["rootIndirectCallsObserved"]}
    if graph_sites != expected_sites:
        raise TriageError(f"Original HXL1 CALLIND evidence differs from owner run: {graph_sites}")
    if any(p["coveredNodes"] != p["totalNodes"] or p["nextOffset"] is not None
           for p in pages["roots"]):
        raise TriageError("Original REA graph pages remain incomplete")
    out = root / "rea-security-audit"
    runner = Runner(out, rea or Path("/not-installed/rea.mjs"),
                    node=node, run_commands=execute, deadline=timeout,
                    recover_partials=recover_partials)
    results = []
    for module, parent, address, label in SITES:
        target = targets[module]
        directory = out / module
        arg = safe_segment(address)
        inst = runner.obtain(
            target,
            ["inspect-native-instruction", str(target.path), address],
            directory / f"instruction-{arg}.json",
            operation="inspect_native_instruction", parameter="address", value=address)
        resolver = runner.obtain(
            target,
            ["resolve-native-call-targets", str(target.path), address],
            directory / f"resolve-call-{arg}.json",
            operation="resolve_native_call_targets", parameter="address", value=address)
        record = {
            "module": module, "parent": parent, "callsite": address,
            "hypothesis": label, "originalBinarySha256": target.sha256,
            "verifiedPcodeCALLIND": True,
            "status": "PLANNED",
            "observed": None,
        }
        if inst is not None and resolver is not None:
            record["observed"] = callsite_observation(
                inst, resolver, parent=parent, address=address)
            record["status"] = "PROVIDER_FACTS_VALIDATED"
        results.append(record)
    module, entry = STORE_PROVIDER
    target = targets[module]
    fn = runner.obtain(
        target, ["function", str(target.path), entry],
        out / module / f"function-{safe_segment(entry)}.json",
        operation="analyze_function", parameter="procedure", value=entry)
    store = {
        "module": module, "entry": entry,
        "status": "PLANNED", "dossier": None,
    }
    if fn is not None:
        store["status"] = "VERIFIED_GHIDRA_DOSSIER"
        store["dossier"] = provider_dossier(fn, entry=entry)
    return {
        "schemaVersion": 1, "originalArchiveSha256": HXL1_BL_SHA256,
        "mode": "STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "newCommands": len(runner.planned),
        "selectedCalls": results, "odinStorageProvider": store,
        "allCallsiteFactsObserved": all(x["status"] == "PROVIDER_FACTS_VALIDATED" for x in results),
        "callbackImplementationProven": False,
        "OEMUnlockAuthorizationProven": False,
        "vulnerabilityConfirmed": False,
        "deviceModified": False,
    }


def markdown(report: dict) -> str:
    lines = [
        "# HXL1 original firmware — exact indirect-call and storage-provider review",
        "", "Source-attested, read-only REA/Ghidra observations. No unlock proven.", "",
        f"- Pinned BL SHA256: {report['originalArchiveSha256']}",
        f"- Mode: {report['mode']}",
        f"- New REA operations: {report['newCommands']}", "",
    ]
    for call in report["selectedCalls"]:
        lines += [
            f"## {call['module']} original call {call['callsite']}", "",
            f"- Parent function: {call['parent']}",
            f"- Investigation label: {call['hypothesis']}",
            f"- Saved status: {call['status']}",
        ]
        r = call["observed"]
        if r is not None:
            lines += [
                f"- Instruction: {r['mnemonic']} — {r['rawDisassembly']}",
                f"- Flow: {r['flowKind']}, computed={r['computedFlow']}",
                f"- Provider target status: {r['providerResolutionStatus']}",
                f"- Mechanism: {r['mechanism']}",
                f"- Target candidates: {r['targets']}",
                f"- Instruction Evidence: {r['instructionEvidenceId']}",
                f"- Resolution Evidence: {r['resolverEvidenceId']}",
                f"- Target semantic identity verified: {r['callbackSemanticIdentityEstablished']}",
            ]
        lines.append("")
    store = report["odinStorageProvider"]
    lines += [f"## Odin storage-provider helper {store['entry']}", "",
              f"- Status: {store['status']}", ""]
    dossier = store["dossier"]
    if dossier is not None:
        lines += [
            f"- Original Ghidra Evidence: {dossier['evidenceId']}",
            f"- Total pseudocode lines: {dossier['fullPseudocodeLines']}",
            "- Security/storage-related context:", "", "~~~c",
        ]
        for ln in dossier["selected"]:
            lines.append(f"{ln['line']:5} | {ln['code']}")
        lines += ["~~~", ""]
        if dossier["truncated"]:
            lines += ["Full original Ghidra pseudocode must be inspected; excerpt truncated.", ""]
    lines += [
        "## Interpretation gates", "",
        "- A resolved indirect target is a static code reference, not proof",
        "  it receives the OEM lock state, makes an authorization decision,",
        "  or is reachable under a particular device configuration.",
        "- A provider answer of unresolved or ambiguous is retained as",
        "  uncertainty; it is never converted to a trusted implementation.",
        "- Map the LinuxLoader callback's param_1+0x40 load to one specific",
        "  native instruction and identify its initializer independently.",
        "- Identify authorization policy and state integrity separately",
        "  from observable boot-property reporting and Odin error logging.",
        "- Neither the device nor original firmware is modified.", "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea", type=Path,
                   default=Path.home() / "src/rea/scripts/rea.mjs")
    p.add_argument("--node", default="node")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--recover-partials", action="store_true")
    p.add_argument("--timeout", type=int, default=240)
    a = p.parse_args()
    if not 30 <= a.timeout <= 1200:
        p.error("Timeout outside supported bounds")
    try:
        root = a.input_dir.expanduser().resolve()
        report = audit(root, execute=a.execute, rea=a.rea, node=a.node,
                       timeout=a.timeout, recover_partials=a.recover_partials)
        out = root / "rea-security-audit"
        (out / "callsite-attribution.json").write_text(json.dumps(report, indent=2) + "\n")
        (out / "callsite-attribution.md").write_text(markdown(report))
    except (TriageError, OSError, ValueError, KeyError, TypeError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for site in report["selectedCalls"]:
        obs = site["observed"]
        print("[SITE]", site["module"], site["callsite"], site["status"],
              "resolution", obs["providerResolutionStatus"] if obs else "unverified")
    print("[STORAGE]", report["odinStorageProvider"]["entry"],
          report["odinStorageProvider"]["status"])
    print("[REPORT]", out / "callsite-attribution.md")
    print("[LIMIT] No verified callback initializer, unlock or vulnerability")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
