#!/usr/bin/env python3
"""Audit existing REA/Ghidra string-search Evidence for original HXL1 LinuxLoader.

No Ghidra calls, firmware unpacking or runtime actions. Analysis addresses
reported here are not physical Linux kernel load/entry addresses.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LOADER_SHA256 = "5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"
QUERIES = ("bootimg", "kernel", "dtb")
ADDRESS = re.compile(r"^(?:0x[0-9a-f]+|[a-zA-Z0-9._~-]+:0x[0-9a-f]+)$")
MAX_HITS = 10000

class EvidenceError(ValueError):
    pass

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()

def parse_saved(path: Path, query: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("Missing or symlinked REA result")
    ev = json.loads(path.read_text())
    if not isinstance(ev, dict) or "error" in ev:
        raise EvidenceError("REA returned error or unexpected top-level value")
    if ev.get("operation") != "search_strings":
        raise EvidenceError("REA result is not a search_strings observation")
    if ev.get("provider", {}).get("id") != "ghidra":
        raise EvidenceError("REA result was not obtained using Ghidra")
    subject = ev.get("subject")
    if not isinstance(subject, dict) or subject.get("digest", {}).get("sha256") != LOADER_SHA256:
        raise EvidenceError("REA evidence subject does not match pinned original LinuxLoader")
    if subject.get("architecture") != "arm64":
        raise EvidenceError("REA evidence subject architecture is not ARM64")
    if ev.get("parameters", {}).get("pattern", "").lower() != query:
        raise EvidenceError("REA actual search pattern does not match requested query")
    observations = ev.get("normalized_result")
    if not isinstance(observations, list) or len(observations) > MAX_HITS:
        raise EvidenceError("REA result is not a bounded search hit list")
    if not isinstance(ev.get("evidence_id"), str):
        raise EvidenceError("Missing REA evidence identifier")
    hits = []
    for item in observations:
        if not isinstance(item, dict):
            raise EvidenceError("Non-object REA search hit")
        a, v = item.get("address"), item.get("value")
        if not isinstance(a, str) or not ADDRESS.fullmatch(a) or not isinstance(v, str):
            raise EvidenceError("Invalid address or text in REA search hit")
        hits.append({"address": a, "value": v})
    return {
        "query": query, "status": "VERIFIED_STATIC_SEARCH",
        "evidenceId": ev["evidence_id"], "inputFile": str(path),
        "hitCount": len(hits), "hits": hits,
    }

def analyze(directory: Path) -> dict:
    loader = directory / "LinuxLoader-HXL1.efi"
    if loader.is_symlink() or not loader.is_file() or digest(loader) != LOADER_SHA256:
        raise EvidenceError("Original HXL1 LinuxLoader hash mismatch")
    observations = []
    for q in QUERIES:
        path = directory / ("rea-ghidra-search-" + q + ".json")
        try:
            observations.append(parse_saved(path, q))
        except (EvidenceError, OSError, ValueError) as exc:
            observations.append({"query": q, "status": "UNVERIFIED_EVIDENCE",
                                 "inputFile": str(path), "reason": str(exc),
                                 "hitCount": None, "hits": []})
    return {
        "classification": "REA_GHIDRA_STATIC_SEARCH_EVIDENCE_ONLY",
        "originalLoaderSha256": LOADER_SHA256,
        "queries": observations,
        "physicalKernelLoadVerified": False,
        "actualHandoffVerified": False,
        "actualDtbSelectionVerified": False,
        "deviceModified": False,
    }

def markdown(report: dict) -> str:
    rows = ["# HXL1 LinuxLoader — saved REA/Ghidra string evidence", "",
            "Source binary SHA256: " + report["originalLoaderSha256"], "",
            "These are Ghidra static analysis addresses, NOT physical Linux load/entry addresses.", ""]
    for rec in report["queries"]:
        rows += ["## Search: " + rec["query"], "",
                 "Status: " + rec["status"], ""]
        if rec["status"] != "VERIFIED_STATIC_SEARCH":
            rows += ["Failure: " + rec["reason"], ""]
            continue
        rows += ["REA evidence ID: " + rec["evidenceId"],
                 "Total matched string entries: " + str(rec["hitCount"]), ""]
        if not rec["hits"]:
            rows += ["No analyzed matching strings. This does not prove there is no loader code.", ""]
        for hit in rec["hits"]:
            value = hit["value"].replace("\n", " ").replace("\r", " ")
            rows.append("- " + hit["address"] + " — " + value[:300] +
                        (" [truncated for markdown]" if len(value) > 300 else ""))
        rows.append("")
    rows += ["## Limits", "",
             "The full REA JSON retains all string bytes and provenance. Use targeted REA",
             "xrefs, trace, function and p-code value flow to investigate discovered",
             "addresses; do not infer a kernel physical address from a PE RVA or a string.", ""]
    return "\n".join(rows)

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/abl-linuxloader")
    opts = p.parse_args()
    try:
        report = analyze(opts.out)
        (opts.out / "rea-stage4-seed-audit.json").write_text(
            json.dumps(report, indent=2) + "\n")
        (opts.out / "rea-stage4-seed-audit.md").write_text(markdown(report))
    except (OSError, EvidenceError, ValueError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for r in report["queries"]:
        print("[" + r["status"] + "] " + r["query"] +
              ": " + str(r["hitCount"]) + " hits")
        for item in r["hits"][:10]:
            print("  " + item["address"] + " " + repr(item["value"][:120]))
        if len(r["hits"]) > 10:
            print("  ... remaining entries retained in report")
    print("[REPORT]", opts.out / "rea-stage4-seed-audit.md")
    print("[LIMIT] No kernel physical handoff proven")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
