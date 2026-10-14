#!/usr/bin/env python3
"""Read-only Samsung HXL1 select-stack header provenance.

Verifies exact retained source files, follows SELECT_STACK_ALLOC definitions in
the same source checkout, and records what source proves vs what OEM machine
code does not. Never runs a kernel, loads a module, or guesses object offsets.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE_PINS = {
    "kernel/futex.c": "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5",
    "fs/select.c": "8b73f69f3f1929a39d7d7549f96cf6fa670420e140b9d67cae8177d1fe4642f3",
}
HEADER = "include/linux/poll.h"
MAX_BYTES = 300_000
DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Z][A-Z0-9_]*)[ \t]+([^\r\n]+)", re.M)
IDENT = re.compile(r"[A-Z][A-Z0-9_]*\Z")
NUMBER = re.compile(r"(?:0x[0-9a-fA-F]+|[0-9]+)\Z")


class SourceError(ValueError):
    pass


def insist(condition: bool, reason: str) -> None:
    if not condition:
        raise SourceError(reason)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_file(root: Path, relative: str) -> bytes:
    file = root / relative
    insist(file.is_file() and not file.is_symlink(),
           "Missing/unsafe HXL1 source: " + relative)
    insist(file.stat().st_size <= MAX_BYTES, "Oversized HXL1 source: " + relative)
    return file.read_bytes()


def definitions(header: str) -> dict[str, str]:
    """Accept only unique, simple object-like macro definitions."""
    found: dict[str, str] = {}
    for match in DEFINE.finditer(header):
        name, value = match.groups()
        if name in found:
            raise SourceError("Ambiguous repeated macro definition: " + name)
        value = value.split("//", 1)[0].split("/*", 1)[0].strip()
        insist(value and "\\" not in value, "Unsupported macro syntax: " + name)
        found[name] = value
    return found


def unparen(raw: str) -> str:
    token = raw.strip()
    while token.startswith("(") and token.endswith(")"):
        inner = token[1:-1].strip()
        if not inner or inner.count("(") != inner.count(")"):
            break
        token = inner
    return token


def resolve(defs: dict[str, str], name: str) -> tuple[int, list[str]]:
    used: set[str] = set()
    chain = []
    for _ in range(12):
        insist(name not in used, "Macro alias cycle: " + name)
        used.add(name)
        insist(name in defs, "Macro missing from exact HXL1 header: " + name)
        expression = unparen(defs[name])
        chain.append(name + "=" + expression)
        if NUMBER.fullmatch(expression):
            value = int(expression, 0)
            insist(64 <= value <= 4096 and value % 8 == 0,
                   "Unexpected or unbounded stack constant")
            return value, chain
        insist(IDENT.fullmatch(expression) is not None,
               "Complex macro not evaluable without original preprocessor: " + name)
        name = expression
    raise SourceError("Macro alias chain too deep")


def audit(root: Path) -> dict:
    root = root.expanduser().resolve(strict=True)
    checked = {}
    for name, digest in SOURCE_PINS.items():
        content = load_file(root, name)
        insist(sha256(content) == digest,
               "Required stock source pin mismatch: " + name)
        checked[name] = digest
    select_source = load_file(root, "fs/select.c").decode("utf-8")
    insist(re.search(r"(?m)^#include\s+<linux/poll\.h>\s*$", select_source) is not None,
           "Verified select.c does not include exact poll header")
    insist("long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];" in select_source,
           "Source select stack declaration changed")
    header_bytes = load_file(root, HEADER)
    header_text = header_bytes.decode("utf-8")
    value, chain = resolve(definitions(header_text), "SELECT_STACK_ALLOC")
    return {
        "target": "SM-G986U1/G986U1UESCHXL1",
        "check": "READ_ONLY_SAME_SOURCE_TREE_MACRO_RECONCILIATION",
        "checkedStockSourceHashes": checked,
        "headerPath": HEADER,
        "headerSha256": sha256(header_bytes),
        "selectStackAllocationSourceBytes": value,
        "macroAliasChain": chain,
        "sourceHeaderAndPinnedSourceAgree": True,
        "headerFactoryCompilerInputIndependentlyProven": False,
        "oemCompiledStackLocalOffsetProven": False,
        "runtimeStackReuseOrPrivilegeProven": False,
        "deviceAccessed": False,
        "limits": (
            "This is an unpreprocessed header declaration in a checkout whose "
            "futex.c/select.c hashes agree with earlier evidence. OEM compiler "
            "flags, conditional macro selection, machine-code local-variable "
            "attribution and live stack addresses are not verified."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path.home() / "src/samsung-y2q-hxl1-stock")
    parser.add_argument("--output", type=Path,
                        default=None, help="New JSON report path")
    args = parser.parse_args()
    try:
        result = audit(args.source)
        if args.output is not None:
            insist(not args.output.exists() and not args.output.is_symlink(),
                   "Refusing to overwrite an existing report")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print("[PINNED SOURCE FILES]", len(result["checkedStockSourceHashes"]), "MATCH")
        print("[POLL HEADER SHA256]", result["headerSha256"])
        print("[SELECT STACK SOURCE CONSTANT]", result["selectStackAllocationSourceBytes"], "bytes")
        print("[MACRO CHAIN]", " -> ".join(result["macroAliasChain"]))
        print("[OEM LOCAL-VARIABLE STACK POSITIONS CERTIFIED] NO")
        print("[ROOT/KERNELSU CERTIFIED] NO")
        if args.output is not None:
            print("[REPORT]", args.output)
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
