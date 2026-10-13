#!/usr/bin/env python3
"""Read-only HXL1 Samsung-source DWARF vs. existing Stage 3 hypothesis audit.

Compiles nothing, executes no exploit, and never promotes an OEM factory ABI
member from Clang18 DWARF or static Ghidra matches. Operates on retained
AArch64 objects and optionally rechecks an existing REA/Ghidra live report.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

EXPECTED_KERNEL_SHA = "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
EXPECTED_SOURCE_SHA = "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9"
DEFAULT_BASE = Path.home() / "s20-artifacts"
DEFAULT_REPO = Path.home() / "src/Root-My-Galaxy-Payloads"
DEFAULT_SOURCE = Path.home() / "src/samsung-y2q-hxl1-stock"

class AuditError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AuditError(message)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def file_ok(path: Path, limit: int) -> None:
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            "Missing, symlinked or oversized input: " + str(path))


def read_comparison_registry(repo: Path) -> dict[str, dict[str, str]]:
    """Extract the canonical 13-member registry as data, without importing code."""
    path = repo / "tools/y2q_hxl1_rtmutex_displacement_attest.py"
    file_ok(path, 300_000)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fields = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "FIELDS" for t in node.targets)]
    require(len(fields) == 1, "Canonical Stage 3 FIELDS registry unavailable")
    data = ast.literal_eval(fields[0])
    require(isinstance(data, dict) and set(data) ==
            {"rt_mutex", "rt_mutex_waiter", "task_struct"}, "Wrong candidate type registry")
    require(sum(len(v) for v in data.values()) == 13, "Expected 13 candidate paths")
    for typ, members in data.items():
        require(isinstance(members, dict), "Invalid registry structure")
        for path, offset in members.items():
            require(isinstance(path, str) and re.fullmatch(r"[a-z_][a-z0-9_.]*", path)
                    and isinstance(offset, str) and re.fullmatch(r"0x[0-9a-f]+", offset),
                    "Invalid offset candidate: " + typ)
    return data


def parse_layout(text: str, expected_type: str) -> dict[str, dict]:
    require(re.search(r"\bstruct\s+" + re.escape(expected_type) + r"\s*\{", text) is not None,
            "Missing pahole structure declaration: " + expected_type)
    parsed = {}
    rx = re.compile(r"^\s*(.+?)\s+([A-Za-z_]\w*)(?:\s+__attribute__\(\(.*?\)\))?\s*;\s*/\*\s*(\d+)\s+(\d+)\s*\*/\s*$", re.M)
    for match in rx.finditer(text):
        type_decl, name, start, size = match.groups()
        require(name not in parsed, "Ambiguous duplicate member: " + expected_type + "." + name)
        parsed[name] = {"type": type_decl.strip(), "offset": int(start), "size": int(size)}
    require(parsed, "No direct member entries in pahole: " + expected_type)
    return parsed


def get_layout(object_path: Path, typename: str) -> tuple[dict, str]:
    file_ok(object_path, 60 * 1024 * 1024)
    result = subprocess.run(["pahole", "-C", typename, str(object_path)],
                            text=True, capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and result.stdout.strip(),
            "pahole " + typename + " failed: " + result.stderr[-500:])
    return parse_layout(result.stdout, typename), result.stdout


def resolve_nested(layouts: dict, root: str, path: str) -> dict:
    current = root
    offset = 0
    fields = path.split(".")
    steps = []
    for index, field in enumerate(fields):
        require(current in layouts and field in layouts[current],
                "Structure member missing: " + current + "." + field)
        member = layouts[current][field]
        offset += member["offset"]
        steps.append({"struct": current, "member": field,
                      "memberOffset": hex(member["offset"]), "memberSize": member["size"]})
        if index < len(fields) - 1:
            match = re.search(r"\bstruct\s+(rb_root_cached|rb_root)\b", member["type"])
            require(match is not None and "*" not in member["type"],
                    "Nested member is not a value-type rb_root: " + current + "." + field)
            current = match.group(1)
    return {"offset": hex(offset), "size": member["size"], "steps": steps}


def config_options(path: Path) -> dict[str, str]:
    file_ok(path, 2 * 1024 * 1024)
    result = {}
    for line in path.read_text().splitlines():
        m = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.*)", line)
        if m:
            result[m[1]] = m[2]
        m = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if m:
            result[m[1]] = "n"
    return result


def validate_configuration(original: Path, rebuilt: Path) -> dict:
    stock = config_options(original)
    model = config_options(rebuilt)
    for field, value in {"CONFIG_ARM64_VA_BITS": "39", "CONFIG_DEBUG_INFO": "y",
                         "CONFIG_RT_GROUP_SCHED": "y", "CONFIG_SCHED_DEBUG": "y"}.items():
        require(stock.get(field) == model.get(field) == value,
                "Critical original/Clang18 config mismatch: " + field)
    changed = {key: {"stock": stock.get(key), "rebuilt": model.get(key)}
               for key in stock.keys() | model.keys() if stock.get(key) != model.get(key)}
    semantic_changes = {k: v for k, v in changed.items()
                        if k != "CONFIG_CLANG_VERSION"
                        and not (v["stock"] == "n" and v["rebuilt"] is None)}
    return {"originalSha256": sha256(original), "rebuiltSha256": sha256(rebuilt),
            "compilerVersionStock": stock.get("CONFIG_CLANG_VERSION"),
            "compilerVersionRebuilt": model.get("CONFIG_CLANG_VERSION"),
            "changedConfigOptions": changed,
            "unexpectedSemanticChanges": semantic_changes,
            "essentialLayoutOptionsPreserved": True}


def saved_rea_review(repo: Path, report: Path | None) -> dict:
    if report is None:
        return {"state": "NO_SAVED_LIVE_REPORT", "factoryMemberOffsetsCertified": 0}
    file_ok(report, 8 * 1024 * 1024)
    verifier = repo / "tools/y2q_hxl1_stage3_rea_live_review.py"
    file_ok(verifier, 300_000)
    proc = subprocess.run([sys.executable, str(verifier), "--recheck-saved-live", str(report)],
                          capture_output=True, text=True, timeout=60, check=False, cwd=str(repo))
    require(proc.returncode == 0, "Saved REA verifier rejected evidence: " + proc.stderr[-700:])
    data = json.loads(proc.stdout)
    coverage = data["analysisCoverage"]
    require(coverage.get("factoryMemberIdentityPromoted") is False
            and data.get("factoryMemberOffsetsVerified") == 0,
            "Saved provider report unexpectedly claims certified OEM members")
    # Keep original immutable live-run analysis separate from later code.
    # A saved-live recheck may use an expanded set of candidate chains.
    original = json.loads(report.read_text(encoding="utf-8"))
    require(original.get("target") == "SM-G986U1/G986U1UESCHXL1"
            and original.get("mode") == "EXECUTE_FRESH_REA_GHIDRA"
            and original.get("factoryMemberOffsetsVerified") == 0,
            "Original live-run report identity/gate mismatch")
    saved_candidates = original.get("memberCandidateRegisterFlow", {}).get("candidates", [])
    original_statuses = {}
    for entry in saved_candidates:
        key = (entry["type"], entry["member"])
        require(key not in original_statuses, "Duplicate original live-run member")
        original_statuses[key] = (
            "MATCHED_STATIC_CHAIN" if entry.get("staticGhidraChainMatched") is True
            else "NOT_PRESENT_IN_ORIGINAL_CHAIN_REPORT")
    statuses = {(x["type"], x["member"]): x["status"]
                for x in coverage["memberComparisons"]}
    require(len(statuses) == len(original_statuses) == 13
            and set(statuses) == set(original_statuses),
            "Original/rechecked 13-member registry mismatch")
    require(sum(x == "MATCHED_STATIC_CHAIN" for x in original_statuses.values())
            == original["memberCandidateRegisterFlow"]["matchedStaticChains"],
            "Original live-run static chain count mismatch")
    return {"state": "SAVED_LIVE_RECORDS_RECHECKED_NOT_FACTORY_REAUTHENTICATED",
            "savedReportSha256": sha256(report),
            "coverage": coverage,
            "memberStatus": statuses,
            "originalMemberStatus": original_statuses,
            "originalMatchedStaticChains": sum(
                x == "MATCHED_STATIC_CHAIN" for x in original_statuses.values()),
            "retrospectiveMatchedStaticChains": sum(
                x == "MATCHED_STATIC_CHAIN" for x in statuses.values()),
            "factoryMemberOffsetsCertified": 0}


def audit(repo: Path, source: Path, base: Path, build: Path, report: Path | None = None) -> dict:
    registry = read_comparison_registry(repo)
    config = validate_configuration(base / "ghostlock-419/config-analysis/stock.config",
                                    build / ".config")
    kernel = base / "kernel.bin"
    file_ok(kernel, 100 * 1024 * 1024)
    require(sha256(kernel) == EXPECTED_KERNEL_SHA, "Original HXL1 factory Image SHA mismatch")
    src = source / "kernel/locking/rtmutex.c"
    file_ok(src, 2 * 1024 * 1024)
    require(sha256(src) == EXPECTED_SOURCE_SHA, "Samsung rtmutex source SHA mismatch")
    objs = {"task_struct": build / "kernel/fork.o",
            "rt_mutex": build / "kernel/locking/rtmutex.o",
            "rt_mutex_waiter": build / "kernel/locking/rtmutex.o",
            "rb_root_cached": build / "kernel/locking/rtmutex.o",
            "rb_root": build / "kernel/locking/rtmutex.o"}
    layouts = {}
    for name, obj in objs.items():
        try:
            layouts[name], _ = get_layout(obj, name)
        except AuditError:
            if name not in ("rb_root_cached", "rb_root"):
                raise
            layouts[name], _ = get_layout(objs["task_struct"], name)
    live = saved_rea_review(repo, report)
    rows = []
    for typ, fields in registry.items():
        for path, expected in fields.items():
            derived = resolve_nested(layouts, typ, path)
            status = live.get("memberStatus", {}).get((typ, path), "NO_LIVE_REVIEW")
            original_status = live.get("originalMemberStatus", {}).get(
                (typ, path), "NO_ORIGINAL_LIVE_REVIEW")
            rows.append({"type": typ, "memberPath": path,
                         "existingClang10Candidate": expected,
                         "clang18SourceDerived": derived["offset"],
                         "crossCompilerOffsetAgreement": int(expected, 16) == int(derived["offset"], 16),
                         "nestedDerivation": derived["steps"],
                         "savedOriginalRegisterChainStatus": original_status,
                         "retrospectiveRecheckRegisterChainStatus": status,
                         "factoryCMemberIdentityCertified": False})
    objects = {str(obj.relative_to(build)): sha256(obj) for obj in set(objs.values())}
    return {"schemaVersion": 1, "target": "SM-G986U1/G986U1UESCHXL1",
            "purpose": "READ_ONLY_CLANG18_TO_EXISTING_CLANG10_CANDIDATE_PARITY",
            "factoryImageSha256": EXPECTED_KERNEL_SHA, "sourceRtmutexSha256": EXPECTED_SOURCE_SHA,
            "configReview": config, "objectSha256": objects,
            "members": rows, "matchedOffsets": sum(r["crossCompilerOffsetAgreement"] for r in rows),
            "candidateCount": len(rows), "reaStatus": {k: v for k, v in live.items()
                          if k not in ("memberStatus", "originalMemberStatus")},
            "originalOEMFactoryCompiledABIAuthenticated": False,
            "factoryMemberOffsetsCertified": 0, "stage3Complete": False,
            "runtimeGhostlockOrRootVerified": False, "deviceModified": False}


def markdown(result: dict) -> str:
    lines = ["# HXL1 Stage 3 — Clang18/Clang10 candidate parity",
             "", "**Stage 3: PARTIAL. Factory-certified members: 0.**", "",
             "This report compares Clang18 Samsung-source DWARF with existing Clang10",
             "candidate offsets; it is not OEM factory DWARF or field-specific proof.", "",
             "| Member | Clang10 candidate | Clang18 DWARF | Parity | Original REA chain | Later recheck chain |",
             "| --- | ---: | ---: | --- | --- | --- |"]
    for item in result["members"]:
        lines.append("| `{type}.{memberPath}` | `{existingClang10Candidate}` | "
                     "`{clang18SourceDerived}` | {parity} | {savedOriginalRegisterChainStatus} | {retrospectiveRecheckRegisterChainStatus} |".format(
                         **item, parity="MATCH" if item["crossCompilerOffsetAgreement"] else "MISMATCH"))
    lines.extend(["", f"**Candidate matches:** {result['matchedOffsets']}/{result['candidateCount']}",
                  "", "The original saved live-run chain status is immutable; later",
                  "rechecks use the current registry and must be interpreted separately.",
                  "", "Any discrepancy must be investigated before using a source-derived",
                  "offset. A matching displacement does not establish OEM member identity.",
                  "No exploit, flashing, ABI gate promotion, or device access occurred.", ""])
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    p.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    p.add_argument("--artifacts", type=Path, default=DEFAULT_BASE)
    p.add_argument("--build", type=Path, default=DEFAULT_BASE / "ghostlock-419/stock-abi-build/toolchain-fixed")
    p.add_argument("--saved-live-report", type=Path)
    p.add_argument("--output-dir", type=Path)
    args = p.parse_args()
    repo, source, base, build = [p.expanduser().absolute() for p in
                                  (args.repo, args.source, args.artifacts, args.build)]
    report = args.saved_live_report.expanduser().absolute() if args.saved_live_report else None
    if report is None:
        available = sorted((base / "hxl1-research").glob("stage3-rea-live-*/live-stage3-rea-review.json"))
        report = available[-1] if available else None
    output = (args.output_dir or
              (base / "hxl1-research" / ("stage3-abi-parity-" +
                datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))).expanduser().absolute()
    try:
        require(not output.exists() and not output.is_symlink(), "Use a new output directory")
        for protected in (repo, source, build):
            require(output != protected and protected not in output.parents
                    and output not in protected.parents,
                    "Output must not overlap source, repository or build roots")
        require(output != base and output not in base.parents,
                "Output cannot replace the artifact root")
        result = audit(repo, source, base, build, report)
        output.mkdir(parents=True, exist_ok=False)
        (output / "abi-parity.json").write_text(json.dumps(result, indent=2) + "\n")
        (output / "abi-parity.md").write_text(markdown(result))
        print(f"[CLANG18-CLANG10 CANDIDATE PARITY] {result['matchedOffsets']}/{result['candidateCount']}")
        print("[OEM FACTORY MEMBER OFFSETS CERTIFIED] 0")
        print("[STAGE 3] PARTIAL")
        print("[SAVED REA]", result["reaStatus"]["state"])
        print("[REPORT]", output / "abi-parity.md")
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print("[STOP]", error, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
