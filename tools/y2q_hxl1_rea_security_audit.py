#!/usr/bin/env python3
"""Bounded, offline REA/Ghidra security-path investigation of ORIGINAL HXL1 BL modules.

Defaults to PLAN ONLY. --execute explicitly runs static Ghidra analysis against
SHA256-attested exported firmware copies. Never executes firmware or talks to
a phone, Odin, EDL, Firehose, ADB, or fastboot. Findings are manual-review
leads, not proof of a bootloader unlock or exploitable vulnerability.

This workflow uses REA's supported native CLI operations:
  search --kind strings; xrefs; function; optional trace-native-values.
It validates operation, provider, architecture, artifact digest, parameters,
and Evidence ID before trusting each saved response. String FILE offsets
in the hotspot JSON are NOT submitted as Ghidra virtual addresses.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from typing import Any

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError

EXPECTED = {
    "Odin": "09da14205be3e773f8b6ca9651fc9a1faabe871950b713ea79fc626e3c36de42",
    "LinuxLoader": "5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003",
    "vaultkeeper.mbn": "614795b445c776859bdacdfe12ccc42bfe4cc47330b7b657adbb1730ce714183",
    "xbl.elf": "78d1bff9ef5c2aa626652390c112f0bf81869bb1f9a05fcd8a8e3dfff8f8b357",
    "tz.mbn": "f79b81a62a362b9ce00af346759e7351aa90138327a53037967032b96b6a83a5",
}
# Each term is an exact literal REA search string. A search hit only qualifies
# when its returned value contains the searched phrase (case-insensitive).
SEEDS = {
    "Odin": (
        ("oem-state", "Oem unlock value"),
        ("oem-lock", "OEMLOCK"),
        ("custom-deny", "Blocked By OEM Lock"),
        ("unlock-failed", "flash unlock Failed"),
        ("secureboot", "QUALCOMM SECUREBOOT"),
        ("rpmb", "ProvisionRpmb"),
    ),
    "LinuxLoader": (
        ("unlocked-skip", "Skipping boot verification"),
        ("unlocked-callback", "read_is_device_unlocked"),
        ("unlock-count", "device unlocked"),
        ("vaultkeeper", "vaultkeeperappid"),
        ("rollback-scm", "Rollback Version syscall"),
        ("flash-block", "DOWNLOAD IS BLOCKED"),
    ),
    "vaultkeeper.mbn": (
        ("vk-processing", "VaultKeeper Processing"),
        ("vk-daemon", "vaultkeeperd"),
    ),
    "xbl.elf": (
        ("retail-unlock", "RETAIL_UNLOCK"),
        ("rpmb-rollback", "ROLLBACK"),
    ),
    "tz.mbn": (
        ("anti-rollback", "anti_rollback"),
        ("rpmb-policy", "OEM_allow_rpmb_key_provision"),
    ),
}
# Pattern matches are REVIEW QUEUES, not findings of insecure behavior.
VULN_REVIEW_MARKERS = {
    "unsafe-copy-api": re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove)\s*\(", re.I),
    "untrusted-input": re.compile(r"\b(?:rx.?buffer|cmd.?length|command.?length|packet.?size|user.?buffer)\b", re.I),
    "auth-state-branch": re.compile(r"(?:oem|flash|device).{0,24}unlock|verified.?boot|avbslotverify|isdeviceunlocked", re.I),
    "secure-service": re.compile(r"qseecom|scmcall|trustzone|vaultkeeper|rpmb|smc", re.I),
    "bounds-check": re.compile(r"\b(?:length|len|size|count)\b.{0,24}(?:>|<|==|!=)", re.I),
}
COORD = re.compile(r"^(?:0x[0-9a-fA-F]+|[a-zA-Z0-9._~-]+:0x[0-9a-fA-F]+)$")
MAX_JSON = 32 * 1024 * 1024
MAX_HITS = 10000
MAX_REFS = 10000


@dataclass(frozen=True)
class Target:
    name: str
    path: Path
    sha256: str
    module: dict[str, Any]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validated_source(path: Path, sha: str) -> Path:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 128 * 1024 * 1024:
        raise TriageError(f"Missing, symlinked, or oversized original copy: {path}")
    if digest(path) != sha:
        raise TriageError(f"SHA256 mismatch for HXL1 source: {path}")
    return path.resolve()


def choose_targets(root: Path, *, include_secure: bool = False) -> list[Target]:
    report_path = root / "hxl1-bootloader-hotspots.json"
    if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > MAX_JSON:
        raise TriageError("Saved HXL1 hotspot inventory missing/unsafe; run hotspot analyzer first")
    report = json.loads(report_path.read_text())
    if (report.get("schemaVersion") != 1
            or report.get("archiveSha256FromPinnedOriginalScan") != HXL1_BL_SHA256
            or report.get("target") != "SM-G986U1 G986U1UESCHXL1"
            or report.get("sourceVerified") is not True):
        raise TriageError("Hotspot report does not identify authenticated original HXL1")
    modules = report.get("modules")
    if not isinstance(modules, list):
        raise TriageError("Expected bounded HXL1 component records")
    choices = ("Odin", "LinuxLoader") + (
        ("vaultkeeper.mbn", "xbl.elf", "tz.mbn") if include_secure else ())
    selected = []
    for name in choices:
        found = [m for m in modules
                 if (m.get("ui") if name in ("Odin", "LinuxLoader") else
                     m.get("fileName")) == name and
                 m.get("sha256") == EXPECTED[name] and
                 m.get("kind") == ("nested-uefi-pe" if name in ("Odin", "LinuxLoader")
                                   else "outer-image")]
        if len(found) != 1:
            raise TriageError(f"Expected one pinned HXL1 {name} in saved hotspot report")
        item = found[0]
        if name in ("Odin", "LinuxLoader"):
            parent = item.get("source")
            if parent != "abl.elf" or not isinstance(item.get("fileName"), str):
                raise TriageError("Nested Odin/LinuxLoader must originate from HXL1 ABL")
            expected_prefix = root / "comparison-inputs" / "HXL1" / "uefi-modules" / parent
            file = expected_prefix / item["fileName"]
            # Filenames must be generated by original exporter, not arbitrary JSON paths.
            pattern = re.compile(r"^\d{3}-[0-9a-f-]{36}-" +
                                 EXPECTED[name][:16] + r"\.efi$")
            if not pattern.fullmatch(item["fileName"]):
                raise TriageError(f"Invalid original UEFI export name for {name}")
        else:
            if item.get("source") != name:
                raise TriageError("Outer component source mismatch")
            file = root / "comparison-inputs" / "HXL1" / name
        validated_source(file, EXPECTED[name])
        selected.append(Target(name, file, EXPECTED[name], item))
    return selected


def evidence(path: Path, *, sha: str, operation: str,
             parameter: str, value: str, architecture: str = "arm64") -> dict:
    """Strict provenance: an invalid cached result is NEVER silently reused."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise TriageError(f"Missing/unsafe Ghidra evidence {path}")
    try:
        ev = json.loads(path.read_text())
    except (UnicodeError, ValueError) as exc:
        raise TriageError(f"Malformed Ghidra JSON {path}: {exc}") from exc
    if (not isinstance(ev, dict) or "error" in ev or ev.get("operation") != operation
            or ev.get("provider", {}).get("id") != "ghidra"
            or ev.get("subject", {}).get("digest", {}).get("sha256") != sha
            or ev.get("subject", {}).get("architecture") != architecture
            or ev.get("parameters", {}).get(parameter) != value
            or not isinstance(ev.get("evidence_id"), str)
            or not ev["evidence_id"]):
        raise TriageError(f"Ghidra provider / source / query provenance mismatch: {path}")
    return ev


def search_hits(ev: dict, term: str) -> list[dict]:
    hits = ev.get("normalized_result")
    if not isinstance(hits, list) or len(hits) > MAX_HITS:
        raise TriageError("Unbounded/invalid Ghidra string search result")
    out = []
    for hit in hits:
        if not isinstance(hit, dict):
            raise TriageError("Invalid search hit record")
        address, value = hit.get("address"), hit.get("value")
        if not isinstance(address, str) or not COORD.fullmatch(address) or not isinstance(value, str):
            raise TriageError("Invalid search hit address/text")
        if term.casefold() in value.casefold():
            out.append({"address": address, "text": value})
    return out


def reference_sources(ev: dict) -> list[str]:
    refs = ev.get("normalized_result")
    if not isinstance(refs, list) or len(refs) > MAX_REFS:
        raise TriageError("Invalid/unbounded Ghidra xrefs result")
    if any(not isinstance(ref, str) or not COORD.fullmatch(ref) for ref in refs):
        raise TriageError("Invalid Ghidra xrefs source coordinate")
    return list(dict.fromkeys(refs))


def function_record(ev: dict, xref: str) -> dict:
    data = ev.get("normalized_result")
    if not isinstance(data, dict):
        raise TriageError("Missing Ghidra function result")
    proc = data.get("procedure")
    if not isinstance(proc, dict):
        raise TriageError("Missing containing procedure identity")
    entry, body = proc.get("address"), proc.get("body")
    if not isinstance(entry, str) or not COORD.fullmatch(entry):
        raise TriageError("No original procedure entry")
    if not isinstance(body, dict) or body.get("available") is not True or not isinstance(body.get("ranges"), list):
        raise TriageError("Ghidra has no authenticated function body")
    def contained(coordinate: str) -> bool:
        try:
            addr = int(coordinate, 16)
            return any(int(r["start"], 16) <= addr <= int(r["end"], 16)
                       for r in body["ranges"] if isinstance(r, dict)
                       and isinstance(r.get("start"), str) and
                       isinstance(r.get("end"), str))
        except ValueError:
            return False
    if not contained(xref) or not contained(entry):
        raise TriageError("Ghidra function does not own xref and entry")
    pseudo = data.get("pseudocode")
    if not isinstance(pseudo, str):
        raise TriageError("Missing Ghidra pseudocode; review function evidence")
    review = {
        key: sorted({m.group(0)[:80] for m in pat.finditer(pseudo)})[:16]
        for key, pat in VULN_REVIEW_MARKERS.items()
    }
    flow = data.get("native_value_flow")
    if not isinstance(flow, dict):
        flow = {}
    return {
        "entry": entry, "name": proc.get("name"), "pcodeAvailable":
            flow.get("available") is True,
        "pseudocodePresent": bool(pseudo.strip()), "pseudocodeCharacters": len(pseudo),
        "reviewMarkers": review, "reviewRequired": any(review.values()),
        "pseudocodeExcerpt": pseudo[:8000],
        "evidenceId": ev["evidence_id"],
        "vulnerabilityConfirmed": False, "unlockAuthorizationVerified": False,
    }


def safe_segment(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", value)[:100]


class Runner:
    def __init__(self, out: Path, script: Path, *, node: str = "node",
                 run_commands: bool = False, deadline: int = 240,
                 max_functions: int = 10, max_xrefs_per_seed: int = 2,
                 max_traces: int = 0, seed_limit: int = 3):
        self.out = out
        self.script = script
        self.node = node
        self.run_commands = run_commands
        self.deadline = deadline
        self.max_functions = max_functions
        self.max_xrefs_per_seed = max_xrefs_per_seed
        self.max_traces = max_traces
        self.seed_limit = seed_limit
        self.function_uses = 0
        self.trace_uses = 0
        self.planned: list[list[str]] = []

    def obtain(self, target: Target, args: list[str], dest: Path, *,
               operation: str, parameter: str, value: str) -> dict | None:
        # Never treat a partial prior query as valid complete Evidence.
        tmp = dest.with_suffix(dest.suffix + ".partial")
        err = dest.with_suffix(dest.suffix + ".stderr.txt")
        if dest.is_file():
            return evidence(dest, sha=target.sha256, operation=operation,
                            parameter=parameter, value=value)
        if dest.is_symlink() or tmp.exists() or err.exists():
            raise TriageError(f"Existing unsafe or incomplete REA evidence: {dest}")
        cmd = [self.node, str(self.script), *args, "--provider", "ghidra", "--json"]
        self.planned.append(cmd)
        if not self.run_commands:
            return None
        # Always write to a new file, no overwrite and no firmware execution.
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with tmp.open("x") as stdout, err.open("x") as stderr:
                proc = subprocess.Popen(
                    cmd, stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    status = proc.wait(timeout=self.deadline)
                except subprocess.TimeoutExpired as exc:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    raise TriageError(
                        f"REA timeout {self.deadline}s; partial Evidence retained: {tmp}"
                    ) from exc
            if status != 0:
                raise TriageError(f"REA returned {status}; inspect partial {tmp} and {err}")
            if tmp.stat().st_size > MAX_JSON:
                raise TriageError(f"REA Evidence too large; partial retained at {tmp}")
            obj = evidence(tmp, sha=target.sha256, operation=operation,
                           parameter=parameter, value=value)
            tmp.rename(dest)  # no existing dest allowed on entry
            return obj
        except (OSError, ValueError) as exc:
            if isinstance(exc, TriageError):
                raise
            raise TriageError(f"Cannot run REA: {exc}") from exc

    def run_target(self, target: Target) -> dict:
        result = {
            "component": target.name, "originalSha256": target.sha256,
            "file": str(target.path),
            "fileSize": target.path.stat().st_size,
            "searches": [], "candidateFunctions": [], "traces": [],
            "manualVulnerabilityReview": True, "exploitableBugProven": False,
            "bootloaderUnlocked": False, "errors": [],
        }
        work = self.out / safe_segment(target.name)
        visited = set()
        for label, term in SEEDS[target.name][:self.seed_limit]:
            saved = work / f"search-{label}.json"
            try:
                ev = self.obtain(
                    target, ["search", str(target.path), term, "--kind", "strings"],
                    saved, operation="search_strings", parameter="pattern", value=term)
                if ev is None:
                    result["searches"].append({"term": term, "status": "PLANNED"})
                    continue
                hits = search_hits(ev, term)
                item = {"term": term, "evidenceId": ev["evidence_id"],
                        "hits": hits[:32], "hitCount": len(hits),
                        "status": "VERIFIED_GHIDRA_SEARCH"}
                if len(hits) > 32:
                    item["limitedDisplay"] = True
                result["searches"].append(item)
                for idx, hit in enumerate(hits[:self.max_xrefs_per_seed]):
                    coord = hit["address"]
                    refs_file = work / f"xrefs-{label}-{safe_segment(coord)}.json"
                    refs_ev = self.obtain(
                        target, ["xrefs", str(target.path), coord],
                        refs_file, operation="xrefs", parameter="address", value=coord)
                    if refs_ev is None:
                        continue
                    sources = reference_sources(refs_ev)
                    item.setdefault("xrefs", []).append({
                        "address": coord, "evidenceId": refs_ev["evidence_id"],
                        "sourceAddresses": sources[:24],
                        "sourceCount": len(sources), "reviewIfZero": len(sources) == 0,
                    })
                    for source in sources[:2]:
                        if source in visited or self.function_uses >= self.max_functions:
                            continue
                        visited.add(source)
                        fn_file = work / f"function-{safe_segment(source)}.json"
                        fn_ev = self.obtain(
                            target, ["function", str(target.path), source],
                            fn_file, operation="analyze_function",
                            parameter="procedure", value=source)
                        if fn_ev is None:
                            continue
                        try:
                            function = function_record(fn_ev, source)
                        except TriageError as exc:
                            result["errors"].append({
                                "stage": "resolve-containing-procedure",
                                "source": source, "note": str(exc),
                            })
                            continue
                        self.function_uses += 1
                        function.update({"xrefSource": source, "seed": label})
                        result["candidateFunctions"].append(function)
                        entry = function["entry"]
                        if self.trace_uses < self.max_traces and function["pcodeAvailable"]:
                            trace_file = work / f"trace-{safe_segment(entry)}.json"
                            # trace-native-values may be resource-intensive; never
                            # assume complete p-code or resolved secure-world calls.
                            trace_ev = self.obtain(
                                target, ["trace-native-values", str(target.path), entry],
                                trace_file, operation="trace_native_values",
                                parameter="procedure", value=entry)
                            if trace_ev is not None:
                                result["traces"].append({
                                    "entry": entry, "evidenceId": trace_ev["evidence_id"],
                                    "coverageUnknown": True, "traceFile": str(trace_file),
                                })
                                self.trace_uses += 1
            except TriageError as exc:
                result["errors"].append({"stage": "search-or-xref", "seed": label,
                                         "reason": str(exc)})
                if self.run_commands:
                    # Keep other independent seeds runnable, but no failed seed
                    # is promoted as verified evidence.
                    continue
        return result


def summary_markdown(report: dict) -> str:
    lines = [
        "# HXL1 OEM unlock / flashing-authorization static audit", "",
        "**Read-only REA/Ghidra observations. No vulnerability or bootloader unlock proven.**",
        "", f"- Mode: {report['mode']}",
        f"- Original BL archive SHA256: {report['originalArchiveSha256']}",
        f"- REA calls planned/executed newly: {report['commandCount']}",
        f"- New Ghidra function dossiers: {report['functionCount']}",
        f"- Source files independently SHA256 verified: {report['sourceAttested']}",
        "", "| Target | Verified searches | Owned code functions | Unresolved errors |",
        "|---|---:|---:|---:|",
    ]
    for target in report["targets"]:
        good = sum(x["status"] == "VERIFIED_GHIDRA_SEARCH" for x in target["searches"])
        lines.append(
            f"| {target['component']} | {good} | "
            f"{len(target['candidateFunctions'])} | {len(target['errors'])} |")
    for target in report["targets"]:
        lines += ["", f"## {target['component']}", "",
                  f"- SHA256: {target['originalSha256']}", ""]
        for search in target["searches"]:
            lines.append(f"- {search['term']}: {search['status']}"
                         + (f", {search['hitCount']} string hits" if "hitCount" in search else ""))
            for xref in search.get("xrefs", [])[:4]:
                lines.append(f"  - string {xref['address']} → {xref['sourceCount']} source references")
        for fn in target["candidateFunctions"]:
            markers = [k for k, v in fn["reviewMarkers"].items() if v]
            lines.append(
                f"- REVIEW function {fn['entry']} ({fn['name']}), xref {fn['xrefSource']}: "
                + (", ".join(markers) if markers else "no lexical markers"))
        for error in target["errors"]:
            lines.append("- UNRESOLVED: " + str(error)[:350])
    lines += [
        "", "## Static vulnerability review rubric", "",
        "1. Validate each Ghidra string hit belongs to this SHA256-pinned component.",
        "2. Read the full Ghidra function Evidence, not merely the bounded excerpt.",
        "3. Identify the actual incoming user/USB/flash-protocol data source.",
        "4. Trace lengths, allocations, bounds, integer conversions and copies.",
        "5. Inspect whether lock state and signatures are checked by a trusted authority.",
        "6. Trace all success and failure branches, including caller return checks.",
        "7. Record which decisions occur in secure world versus normal-world UEFI.",
        "8. Treat any suspected flaw as unverified until independently reproduced",
        "   in an isolated host harness; do not flash altered firmware to the phone.",
        "", "## Limitations", "",
        "- This is candidate discovery and code-path analysis, NOT executable fuzzing.",
        "- Lexical markers cannot prove missing validation, a bypass or reachability.",
        "- Firmware and secure-world components may be packed or unsupported by Ghidra.",
        "- No phone, kernel, bootloader, partition, RSA key, RPMB, or fuse is modified.",
        "- A valid REA JSON response may still contain partial/unknown coverage.",
        "",
    ]
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict:
    root = args.input_dir.expanduser().resolve()
    out = args.out.expanduser().resolve()
    if out == root or root in out.parents:
        # Output may be under current research area, but never inside originals.
        originals = root / "comparison-inputs"
        if out == originals or originals in out.parents:
            raise TriageError("Refusing output inside original exported firmware copies")
    targets = choose_targets(root, include_secure=args.include_secure)
    if args.execute and (not args.rea.is_file() or args.rea.is_symlink()):
        raise TriageError(f"REA script not present as regular file: {args.rea}")
    if args.execute and not (args.out.parent.exists() or args.out.exists()):
        raise TriageError("Output parent must exist for REA execution")
    runner = Runner(
        out, args.rea, node=args.node, run_commands=args.execute,
        deadline=args.timeout, max_functions=args.max_functions,
        max_xrefs_per_seed=args.max_xrefs_per_seed,
        max_traces=args.max_traces, seed_limit=args.seed_limit)
    # Execution of uploaded firmware is never permitted; subprocess runs
    # ONLY the user's existing REA Node/Ghidra CLI on verified local copies.
    results = [runner.run_target(target) for target in targets]
    record = {
        "schemaVersion": 1, "mode": "EXECUTE_STATIC_GHIDRA" if args.execute else "PLAN_ONLY",
        "originalArchiveSha256": HXL1_BL_SHA256, "sourceAttested": True,
        "tool": str(args.rea), "commandCount": len(runner.planned),
        "functionCount": runner.function_uses,
        "commands": runner.planned if not args.execute else [],
        "targets": results, "bootloaderUnlockDemonstrated": False,
        "vulnerabilityDemonstrated": False, "phoneModified": False,
    }
    # Output is a new research directory, independent of verified binaries.
    out.mkdir(parents=True, exist_ok=True)
    (out / "security-paths.json").write_text(json.dumps(record, indent=2) + "\n")
    (out / "security-paths.md").write_text(summary_markdown(record))
    return record


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", type=Path,
                   default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--out", type=Path,
                   default=Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit")
    p.add_argument("--rea", type=Path, default=Path.home() / "src/rea/scripts/rea.mjs")
    p.add_argument("--node", default="node", help="Node executable used ONLY for REA CLI")
    p.add_argument("--execute", action="store_true",
                   help="Run static Ghidra reads; default only validates inputs/plans")
    p.add_argument("--include-secure", action="store_true",
                   help="Also investigate VaultKeeper, XBL and TZ (Ghidra admission unverified)")
    p.add_argument("--max-functions", type=int, default=10)
    p.add_argument("--seed-limit", type=int, default=3,
                   help="Literal queries per module; increase to 6 after initial run")
    p.add_argument("--max-xrefs-per-seed", type=int, default=2)
    p.add_argument("--max-traces", type=int, default=0)
    p.add_argument("--timeout", type=int, default=240)
    a = p.parse_args()
    if (not 1 <= a.seed_limit <= 6 or not 1 <= a.max_functions <= 64 or not 1 <= a.max_xrefs_per_seed <= 5
            or not 0 <= a.max_traces <= 8 or not 30 <= a.timeout <= 1200):
        p.error("budgets out of supported bounds")
    try:
        report = run(a)
    except (TriageError, OSError, ValueError, KeyError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[RESULT]", report["mode"], "targets=", len(report["targets"]))
    print("[REPORT]", a.out / "security-paths.md")
    print("[LIMIT] Static reverse engineering only; no unlock or vulnerability verified")
    return 0 if not any(t["errors"] for t in report["targets"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
