#!/usr/bin/env python3
"""Read-only DWARF *type presence* audit in partial HXL1 Samsung objects.

Do not infer type presence from pahole's return code alone; some pahole
builds return zero when -C reports 'type not found'. Require a complete
struct declaration in stdout and classify diagnostic failures separately.
This script derives no member offsets and never touches a phone.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

EXPECTED_CONFIG_SHA = "97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09"
DEFAULT_BUILD = Path.home() / "src/samsung-y2q-hxl1-config-clang18"
DEFAULT_OUTPUT = Path.home() / "s20-artifacts/hxl1-research/rtmutex-dwarf-presence.json"
STRUCTS = ("rt_mutex_waiter", "rt_mutex")


def sha256(path: Path) -> str:
    d = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            d.update(chunk)
    return d.hexdigest()


def classify(output: str, error: str, code: int, type_name: str) -> str:
    """Mark PRESENT only on an exact complete declaration with closing brace."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", type_name):
        raise ValueError("Invalid struct identifier")
    # A message claiming 'not found' takes priority over a zero exit status.
    if re.search(r"(?i)\b(?:type|class)\b[^\n]*\bnot found\b", output + "\n" + error):
        return "NOT_FOUND"
    start = re.search(r"(?m)^\s*struct\s+" + re.escape(type_name) + r"\s*\{", output)
    if start and re.search(r"(?m)^\s*}\s*;", output[start.end():]):
        return "PRESENT" if code == 0 else "INCONSISTENT_TOOL_STATUS"
    if code != 0:
        return "TOOL_ERROR"
    return "NO_COMPLETE_DEFINITION"


def arch_object(path: Path) -> bool:
    with path.open("rb") as f:
        header = f.read(20)
    return (len(header) == 20 and header[:4] == b"\x7fELF"
            and header[4] == 2 and header[5] == 1
            and header[16:20] == bytes([1, 0, 183, 0]))


def probe(path: Path, type_name: str) -> dict:
    try:
        result = subprocess.run(
            ["pahole", "-C", type_name, str(path)],
            capture_output=True, text=True, timeout=12, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "TOOL_ERROR", "detail": type(exc).__name__}
    outcome = classify(result.stdout, result.stderr, result.returncode, type_name)
    return {
        "status": outcome,
        "returnCode": result.returncode,
        "printedDefinitionHeader": bool(re.search(
            r"(?m)^\s*struct\s+" + re.escape(type_name) + r"\s*\{",
            result.stdout)),
        "diagnosticExcerpt": result.stderr.strip()[:180],
    }


def run(build: Path) -> dict:
    config = build / ".config"
    if not config.is_file() or sha256(config) != EXPECTED_CONFIG_SHA:
        raise ValueError("STOP: generated Samsung Clang18 .config hash mismatch")
    files = sorted(p for p in build.rglob("*.o")
                   if p.is_file() and not p.is_symlink() and arch_object(p))
    if not files:
        raise ValueError("STOP: no ARM64 relocatable object inputs found")
    checks = {name: [] for name in STRUCTS}
    for obj in files:
        name = obj.relative_to(build).as_posix()
        for type_name in STRUCTS:
            observation = probe(obj, type_name)
            if observation["status"] != "NOT_FOUND":
                # Preserve only actionable/ambiguous findings; still report
                # the number inspected and actual confirmed matches.
                checks[type_name].append({"object": name, **observation})
    stats = {}
    for type_name, observations in checks.items():
        present = [x["object"] for x in observations if x["status"] == "PRESENT"]
        uncertain = [x for x in observations
                     if x["status"] not in ("PRESENT", "NOT_FOUND")]
        stats[type_name] = {
            "objectsChecked": len(files),
            "completeDefinitionsFound": len(present),
            "presentIn": present,
            "ambiguousOrToolError": uncertain,
            "allNonlistedObjects": "NOT_FOUND (pahole text-checked)",
        }
    return {
        "schemaVersion": 1,
        "target": "Samsung SM-G986U1 G986U1UESCHXL1",
        "input": "partial source-derived Samsung Clang18 ARM64 .o objects",
        "verifiedConfigSha256": EXPECTED_CONFIG_SHA,
        "aarch64ObjectsInspected": len(files),
        "types": stats,
        "zeroExitDoesNotProveTypePresence": True,
        "stockFirmwareLayoutVerified": False,
        "runtimeKernelCodeExecuted": False,
        "rootVerified": False,
        "note": "Only complete DWARF type availability; not field offsets. "
                "This incomplete Clang18 build differs from OEM Clang10.",
    }


def to_md(report: dict) -> str:
    lines = [
        "# HXL1 Samsung partial-build RT-mutex DWARF type presence", "",
        "Type presence requires a complete printed definition; not pahole exit code.",
        "",
        "| Type | ARM64 objects inspected | Complete definitions |",
        "|---|---:|---:|",
    ]
    for name, entry in report["types"].items():
        lines.append(
            f"| {name} | {entry['objectsChecked']} | {entry['completeDefinitionsFound']} |"
        )
        for found in entry["presentIn"]:
            lines.append(f"- {name}: {found}")
        for uncertain in entry["ambiguousOrToolError"]:
            lines.append(
                f"- CHECK {name} in {uncertain['object']}: {uncertain['status']}"
            )
    lines.extend([
        "", "**These are incomplete modern-compiler source-build objects.**",
        "A found type does not establish a factory Samsung Clang10 layout,",
        "stock-kernel parity, CVE reachability, or root.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, default=DEFAULT_BUILD)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = p.parse_args()
    build = args.build.expanduser().resolve()
    out = args.output.expanduser().resolve()
    if out.suffix != ".json" or out == build or build in out.parents:
        p.error("JSON report must be outside the experimental kernel build")
    try:
        data = run(build)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2) + "\n")
        out.with_suffix(".md").write_text(to_md(data))
    except (OSError, ValueError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for name, item in data["types"].items():
        print(f"[{name}] verified complete definitions: "
              f"{item['completeDefinitionsFound']}/{item['objectsChecked']} "
              f"ambiguous: {len(item['ambiguousOrToolError'])}")
        for path in item["presentIn"]:
            print("  VERIFIED TYPE PRESENT:", path)
    print("[reports]", out, out.with_suffix(".md"))
    print("[LIMIT] Presence only; no numeric offsets, factory ABI, or root")
    return 0


if __name__ == "__main__":
    sys.exit(main())
