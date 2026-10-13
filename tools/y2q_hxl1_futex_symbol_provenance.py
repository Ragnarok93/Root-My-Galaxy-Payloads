#!/usr/bin/env python3
"""Reconcile a missing HXL1 kernel symbol against exact Samsung source/config.

Read-only, non-exploit evidence inventory. A missing name in recovered nm
does not prove removal or inlining; source function presence does not
prove a function was emitted in the factory kernel. No ADB or code execution.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import y2q_hxl1_ghostlock_stack_gate as gate

STOCK_FUTEX_SHA = "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5"
STOCK_CONFIG_SHA = "1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd"
FUNCTION_NAME = "futex_wait_requeue_pi"
SOURCE_PATH = "kernel/futex.c"
FLAGS = (
    "CONFIG_FUTEX",
    "CONFIG_FUTEX_PI",
    "CONFIG_LTO",
    "CONFIG_LTO_CLANG",
    "CONFIG_LTO_CLANG_THIN",
    "CONFIG_KALLSYMS",
    "CONFIG_KALLSYMS_ALL",
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise EvidenceError(explanation)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def check_source(raw: bytes) -> dict:
    require(sha256(raw) == STOCK_FUTEX_SHA, "Samsung kernel/futex.c SHA256 mismatch")
    text = raw.decode("utf-8")
    # Match source declarations, not prose mentions or invocations.
    name = re.escape(FUNCTION_NAME)
    pattern = re.compile(
        r"(?m)^[ \t]*(?P<declaration>(?:(?:static|inline|noinline|__always_inline|"
        r"__visible|int|long|unsigned|signed|void|__sched|__maybe_unused|"
        r"__cold|asmlinkage|__init|__weak)[ \t]+)+)"
        + name + r"[ \t]*\(")
    declarations = []
    for match in pattern.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        qualifiers = match.group("declaration").split()
        declarations.append({
            "line": line,
            "qualifiers": qualifiers,
            "declaredStatic": "static" in qualifiers,
            "sourceOnly": True,
        })
    return {
        "sourceSha256Verified": True,
        "declaredFunctionName": FUNCTION_NAME,
        "sourceDeclarations": declarations,
        "sourceDeclarationCount": len(declarations),
        "factoryCodeEmissionProven": False,
    }


def config_value(text: str, flag: str) -> str:
    matches = []
    for row in text.splitlines():
        if row.startswith(flag + "="):
            matches.append(row.split("=", 1)[1].strip())
        elif row == "# " + flag + " is not set":
            matches.append("n")
    require(len(matches) <= 1, "Ambiguous kernel config: " + flag)
    return matches[0] if matches else "NOT_RECORDED"


def check_config(raw: bytes) -> dict:
    require(sha256(raw) == STOCK_CONFIG_SHA, "Samsung original config.gz SHA256 mismatch")
    text = gzip.decompress(raw).decode("utf-8")
    return {"configSha256Verified": True,
            "values": {flag: config_value(text, flag) for flag in FLAGS}}


def name_inventory(text: str) -> dict:
    parsed = gate.parse_nm(text)
    variants = sorted((
        {"name": name, "vaFromRecoveredImage": hex(va), "nmType": typ}
        for name, (va, typ) in parsed.items()
        if FUNCTION_NAME in name
    ), key=lambda row: (row["name"], row["vaFromRecoveredImage"]))
    related = sorted((
        {"name": name, "nmType": typ}
        for name, (_, typ) in parsed.items()
        if ("requeue" in name or "futex_wait" in name)
        and FUNCTION_NAME not in name
    ), key=lambda row: row["name"])[:40]
    return {
        "exactNamedTextSymbolPresent": FUNCTION_NAME in parsed,
        "nameContainingVariants": variants[:40],
        "relatedTextSymbolNamesSample": related,
        "relatedNameSampleTruncated": len(related) >= 40,
        "recoveredNmNotAFactoryCompileTrace": True,
    }


def evaluate(source: dict, config: dict, names: dict) -> dict:
    named = names["exactNamedTextSymbolPresent"]
    declared = source["sourceDeclarationCount"] > 0
    if named:
        status = "SOURCE_AND_RECOVERED_SYMBOL_PRESENT" if declared else "RECOVERED_SYMBOL_PRESENT_SOURCE_NOT_FOUND"
    elif declared:
        status = "PINNED_SOURCE_DECLARATION_PRESENT_RECOVERED_NAME_ABSENT"
    else:
        status = "SOURCE_DECLARATION_AND_RECOVERED_NAME_ABSENT"
    return {
        "status": status,
        "source": source,
        "config": config,
        "recoveredSymbols": names,
        "compiledFunctionAbsenceProven": False,
        "inliningOrOptimizationProven": False,
        "usableExploitPathProven": False,
        "workingRootProven": False,
        "sourceVsBinaryInterpretation": (
            "A source declaration and recovered symbol-name coverage are distinct evidence. "
            "Do not assign an address, inferred stack location, or cause of symbol omission "
            "from this report; missing recovered symbols can reflect compilation, "
            "optimization, naming, configuration or symbol recovery."
        ),
    }


def markdown(report: dict) -> str:
    rows = [
        "# HXL1 original futex source vs recovered text-symbol evidence", "",
        "**Diagnostic only; no compilation, device access or exploit execution.**", "",
        "- Status: " + report["status"],
        "- Original Samsung kernel/futex.c SHA256: verified",
        "- Original Samsung config.gz SHA256: verified",
        "- Factory function emission: unverified",
        "- Compiler inlining/removal: unverified",
        "- Working root: unverified",
        "",
        "## Original source declarations",
        "",
    ]
    declarations = report["source"]["sourceDeclarations"]
    if declarations:
        for item in declarations:
            rows.append("- Line {}: {}".format(
                item["line"], " ".join(item["qualifiers"]) + " " + FUNCTION_NAME))
    else:
        rows.append("- No matching function declaration found by bounded parser")
    rows.extend(["", "## Original kernel configuration", ""])
    for key, value in report["config"]["values"].items():
        rows.append("- {}: {}".format(key, value))
    rows.extend(["", "## Recovered symbol-name inventory", ""])
    names = report["recoveredSymbols"]
    rows.append("- Exact text-symbol name: " +
                ("PRESENT" if names["exactNamedTextSymbolPresent"] else "ABSENT"))
    for variant in names["nameContainingVariants"]:
        rows.append("- Related variant {} [{}]".format(
            variant["name"], variant["nmType"]))
    if not names["nameContainingVariants"]:
        rows.append("- No exact-name-containing variants in parsed text symbols")
    rows.append("- Related symbol name sample: " + ", ".join(
        item["name"] for item in names["relatedTextSymbolNamesSample"]))
    rows.extend(["", report["sourceVsBinaryInterpretation"], ""])
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path.home() / "src/samsung-y2q-hxl1-stock/kernel/futex.c")
    parser.add_argument("--config", type=Path,
                        default=Path.home() / "s20-artifacts/config.gz")
    parser.add_argument("--nm", type=Path,
                        default=Path.home() / "s20-artifacts/hxl1-research/vmlinux-stock.nm")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        for path in (args.source, args.config, args.nm):
            require(path.is_file() and not path.is_symlink(),
                    "Original evidence missing/unsafe: " + str(path))
        require(args.nm.stat().st_size <= gate.MAX_NM_BYTES,
                "Recovered symbol table exceeds bounded input")
        result = evaluate(
            check_source(args.source.read_bytes()),
            check_config(args.config.read_bytes()),
            name_inventory(args.nm.read_text(encoding="utf-8")),
        )
        output = args.output_dir or (
            Path.home() / "s20-artifacts/hxl1-research" / "futex-symbol-provenance")
        require(not output.exists() and not output.is_symlink(),
                "Choose a new output directory; do not overwrite prior findings")
        output.mkdir(parents=True, exist_ok=False)
        (output / "futex-symbol-provenance.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (output / "futex-symbol-provenance.md").write_text(
            markdown(result), encoding="utf-8")
        print("[SYMBOL DIAGNOSIS]", result["status"])
        print("[STOCK SOURCE HASH] PASS")
        print("[STOCK CONFIG HASH] PASS")
        print("[ROOT OR STACK GEOMETRY VERIFIED] NO")
        print("[REPORT]", output / "futex-symbol-provenance.md")
        return 0
    except (OSError, ValueError, gzip.BadGzipFile) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
