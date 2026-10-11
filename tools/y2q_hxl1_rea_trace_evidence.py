#!/usr/bin/env python3
"""Validate REA *workflow* value traces against source + upstream Ghidra origin.

REA trace_native_values is provider='rea-workflow', unlike the direct
'ghidra' search/xrefs/function primitives. The trace includes the underlying
Ghidra profile and a source-bound target_sha256. No firmware is executed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from tools.y2q_hxl1_bootloader_unlock_audit import TriageError

MAX_TRACE_BYTES = 32 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COORD = re.compile(r"^0x[0-9a-f]+$", re.I)


def _dict(obj: object) -> dict:
    return obj if isinstance(obj, dict) else {}


def _profile_check(ev: dict) -> str:
    profile = _dict(ev.get("analysis_profile"))
    if _dict(profile.get("provider")).get("id") != "rea-workflow":
        raise TriageError("REA value trace missing outer workflow analysis profile")
    upstream = _dict(_dict(profile.get("parameters")).get("upstream_analysis_profile"))
    if _dict(upstream.get("provider")).get("id") != "ghidra":
        raise TriageError("REA value trace missing original upstream Ghidra profile")
    profile_digest = upstream.get("digest")
    if not isinstance(profile_digest, str) or not HEX64.fullmatch(profile_digest):
        raise TriageError("REA value trace missing upstream Ghidra profile digest")
    return profile_digest


def validated_trace(path: Path, *, sha: str, entry: str) -> dict:
    """Strictly read saved workflow JSON; never infer proof from absent fields."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TRACE_BYTES:
        raise TriageError(f"Missing, symlinked or oversized REA workflow trace: {path}")
    try:
        ev = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise TriageError(f"Incomplete or malformed saved REA trace: {path}: {exc}") from exc
    if not isinstance(ev, dict) or "error" in ev:
        raise TriageError("REA trace contains a top-level failure or non-object result")
    subject = _dict(ev.get("subject"))
    if (ev.get("operation") != "trace_native_values"
            or _dict(ev.get("provider")).get("id") != "rea-workflow"
            or _dict(subject.get("digest")).get("sha256") != sha
            or subject.get("architecture") != "arm64"
            or _dict(ev.get("parameters")).get("procedure") != entry
            or not isinstance(ev.get("evidence_id"), str)
            or not ev["evidence_id"]):
        detail = {
            "operation": ev.get("operation"),
            "provider": _dict(ev.get("provider")).get("id"),
            "subjectSha256": _dict(subject.get("digest")).get("sha256"),
            "architecture": subject.get("architecture"),
            "procedure": _dict(ev.get("parameters")).get("procedure"),
            "hasEvidenceId": bool(ev.get("evidence_id")),
        }
        raise TriageError(f"REA value-trace top-level identity mismatch: {detail}")
    upstream_digest = _profile_check(ev)
    graph = _dict(ev.get("normalized_result"))
    if (graph.get("seed") != entry or graph.get("target_sha256") != sha
            or not isinstance(graph.get("nodes"), list)
            or not isinstance(graph.get("edges"), list)
            or not isinstance(graph.get("procedures"), list)
            or not isinstance(graph.get("unknowns"), list)
            or not isinstance(graph.get("truncated"), bool)
            or not isinstance(graph.get("limitations"), list)
            or not isinstance(graph.get("decompilations"), int)):
        raise TriageError("REA value trace graph / seed / binary SHA256 mismatch")
    if graph["decompilations"] < 1 or len(graph["procedures"]) < 1:
        raise TriageError("REA value trace cannot attest original seed function")
    addresses = set()
    for proc in graph["procedures"]:
        if (not isinstance(proc, dict)
                or proc.get("provider") != "ghidra"
                or proc.get("analysis_profile_digest") != upstream_digest
                or not isinstance(proc.get("address"), str)
                or not COORD.fullmatch(proc["address"])):
            raise TriageError("REA trace has a procedure without original Ghidra profile")
        addresses.add(proc["address"].lower())
    if entry.lower() not in addresses:
        raise TriageError("REA trace has no exact original Ghidra seed procedure")
    return ev


def recover_partial_trace(final: Path, *, sha: str, entry: str) -> dict | None:
    """Recover complete SHA-attested .partial via atomic no-clobber hard link.

    Keep the original staging evidence unchanged even if recovery succeeds.
    This is only called after the old REA execution has terminated.
    """
    partial = final.with_suffix(final.suffix + ".partial")
    if final.exists() or final.is_symlink():
        return None
    if not partial.exists() and not partial.is_symlink():
        return None
    ev = validated_trace(partial, sha=sha, entry=entry)
    try:
        os.link(partial, final, follow_symlinks=False)
    except FileExistsError as exc:
        raise TriageError(f"Refusing to replace existing original REA trace {final}") from exc
    except OSError as exc:
        raise TriageError(f"Cannot promote verified original REA trace {partial}: {exc}") from exc
    validated_trace(final, sha=sha, entry=entry)
    return ev
