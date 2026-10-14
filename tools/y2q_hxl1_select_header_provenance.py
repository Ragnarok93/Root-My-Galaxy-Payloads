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
import tarfile

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


def definitions(header: str) -> dict[str, list[str]]:
    """Record all definitions; reject ambiguity only in the followed chain."""
    found: dict[str, list[str]] = {}
    for match in DEFINE.finditer(header):
        name, value = match.groups()
        value = value.split("//", 1)[0].split("/*", 1)[0].strip()
        insist(value and "\\" not in value, "Unsupported macro syntax: " + name)
        found.setdefault(name, []).append(value)
    return found


def unparen(raw: str) -> str:
    token = raw.strip()
    while token.startswith("(") and token.endswith(")"):
        inner = token[1:-1].strip()
        if not inner or inner.count("(") != inner.count(")"):
            break
        token = inner
    return token


def resolve(defs: dict[str, list[str]], name: str) -> tuple[int, list[str]]:
    used: set[str] = set()
    chain = []
    for _ in range(12):
        insist(name not in used, "Macro alias cycle: " + name)
        used.add(name)
        insist(name in defs, "Macro missing from exact HXL1 header: " + name)
        insist(len(defs[name]) == 1, "Ambiguous conditional definitions: " + name)
        expression = unparen(defs[name][0])
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



def numeric_select_crosswalk(disassembly: str, stack_bytes: int) -> dict:
    """Prove the native select boundary arithmetic, not C local stack offsets.

    The saved ARM64 control flow tests rounded FD count in 64-descriptor
    units and allocates six 8-byte bitmaps per unit on the dynamic path.
    Require one ordered, contiguous sequence; unrelated CMPs are not enough.
    """
    word_bytes, bitmaps, bits_per_word = 8, 6, 64
    insist(stack_bytes % word_bytes == 0,
           "Select stack bytes cannot hold whole native longs")
    words_per_bitmap = stack_bytes // (bitmaps * word_bytes)
    insist(words_per_bitmap > 0, "Select stack bitmap capacity is zero")
    maximum_nfds = words_per_bitmap * bits_per_word
    expected_rounded_limit = maximum_nfds + bits_per_word

    pattern = re.compile(
        r"(?m)^([0-9a-f]{16}):\s+[0-9a-f]{8}\s+([a-z0-9.]+)(?:\s+([^\n]*))?$",
        re.I)
    decoded = []
    for match in pattern.finditer(disassembly):
        decoded.append((int(match.group(1), 16), match.group(2).lower(),
                        (match.group(3) or "").split("//")[0].strip()))
    sequence = [
        ("sxtw", "x8, w22"),
        ("add", "x8, x8, #0x3f"),
        ("lsr", "x27, x8, #6"),
        ("cmp", "x8, #0x" + format(expected_rounded_limit, "x")),
    ]
    matches = [i for i in range(len(decoded) - 4)
               if [(op, args) for _, op, args in decoded[i:i+4]]
               == sequence
               and all(decoded[i+j][0] == decoded[i][0] + 4*j
                       for j in range(5))
               and decoded[i+4][1] == "b.cc"]
    insist(len(matches) == 1,
           "Original native select rounded-count comparison disagrees "
           "with source stack bytes or is ambiguous")
    i = matches[0]
    branch_address = decoded[i+4][2]
    insist(re.fullmatch(r"0x[0-9a-f]+", branch_address) is not None,
           "Original select stack decision branch has no direct target")
    stack_target = int(branch_address, 16)
    insist(sum(1 for va, op, args in decoded
               if va == stack_target and op == "add"
               and args == "x19, sp, #0x50") == 1,
           "Branch no longer targets original stack-backed path")

    # Dynamic path: 3 * units << 4 => 48 * ceil(n / 64) bytes.
    dynamic = [
        ("add", "x8, x27, x27, lsl #1"),
        ("lsl", "x0, x8, #4")
    ]
    pos = [next((j for j in range(i+5, len(decoded))
                 if (decoded[j][1], decoded[j][2]) == item), None)
           for item in dynamic]
    insist(None not in pos and i < pos[0] < pos[1]
           and decoded[pos[1]][0] < stack_target,
           "Native select dynamic allocation sizing path changed")
    return {
        "sourceSelectStackBytes": stack_bytes,
        "nativeLongBytes": word_bytes,
        "bitmapCount": bitmaps,
        "wordsPerBitmapFittingStack": words_per_bitmap,
        "maximumNfdsUsingStack": maximum_nfds,
        "firstNfdsRequiringDynamicAllocation": maximum_nfds + 1,
        "dynamicAllocationBytesPer64Descriptors": bitmaps * word_bytes,
        "roundedCountComparisonOperand": expected_rounded_limit,
        "compiledArithmeticMatchesSourceCapacity": True,
        "smallestSourceArrayBytesWithThisCompiledCutoff":
            words_per_bitmap * bitmaps * word_bytes,
        "largestSourceArrayBytesWithThisCompiledCutoff":
            (words_per_bitmap + 1) * bitmaps * word_bytes - 1,
        "compiledCutoffUniquelyAuthenticatesExactSourceBytes": False,
        "sourceObjectPhysicalLocationCertified": False,
        "crossSyscallReuseOrRootCertified": False,
    }


def check_saved_disassembly(path: Path, source_stack_bytes: int | None = None) -> dict:
    """Confirm recorded native select source structure against saved code.

    Rechecks the existing archive's own HXL1 manifest and disassembly SHA;
    a match is not original compiler DWARF or local-object attribution.
    """
    from tools import y2q_hxl1_dispatch_archive_audit as archive_audit

    evidence = archive_audit.audit(path)
    with tarfile.open(path, "r:gz") as bundle:
        manifest = json.loads(bundle.extractfile("stack-gate.json").read())
        select_entry = next(
            (record for record in manifest["functions"]
             if record["symbol"] == "core_sys_select"), None)
        insist(select_entry is not None, "Missing native select manifest")
        text = bundle.extractfile("core_sys_select.disasm.txt").read()
        insist(sha256(text) == select_entry["disassembly"]["textSha256"],
               "Native select disassembly hash mismatch")
        # Distinct SP-relative buffer choice and dynamic-allocation branch.
        has_stack = re.search(
            r"(?m)^[0-9a-f]{16}:\s+[0-9a-f]{8}\s+add\s+x19,\s*sp,\s*#0x50\b",
            text.decode("utf-8")) is not None
        has_choice = re.search(
            r"(?m)^[0-9a-f]{16}:\s+[0-9a-f]{8}\s+cmp\s+x8,\s*#0x180\b",
            text.decode("utf-8")) is not None
        insist(has_stack and has_choice,
               "Original select buffer/allocation branch evidence changed")
        numeric = (numeric_select_crosswalk(text.decode("utf-8"), source_stack_bytes)
                   if source_stack_bytes is not None else None)
        return {
            "savedArchiveSha256": sha256(path.read_bytes()),
            "savedDisassemblyTextHashesChecked":
                evidence["matchedArchivedDisassemblySha256"],
            "nativeSelectStackPathRecognized": True,
            "nativeSelectDynamicChoiceRecognized": True,
            "sourceMacroToExactMachineObjectCertified": False,
            "numericSelectAllocationCrosswalk": numeric,
            "originalKernelImageRehashedIndependently": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path.home() / "src/samsung-y2q-hxl1-stock")
    parser.add_argument("--output", type=Path,
                        default=None, help="New JSON report path")
    parser.add_argument("--disassembly-archive", type=Path, default=None,
                        help="Optional previously collected disassembly review archive")
    args = parser.parse_args()
    try:
        result = audit(args.source)
        if args.disassembly_archive is not None:
            result["savedMachineCodeEvidence"] = check_saved_disassembly(
                args.disassembly_archive, result["selectStackAllocationSourceBytes"])
        if args.output is not None:
            insist(not args.output.exists() and not args.output.is_symlink(),
                   "Refusing to overwrite an existing report")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print("[PINNED SOURCE FILES]", len(result["checkedStockSourceHashes"]), "MATCH")
        print("[POLL HEADER SHA256]", result["headerSha256"])
        print("[SELECT STACK SOURCE CONSTANT]", result["selectStackAllocationSourceBytes"], "bytes")
        print("[MACRO CHAIN]", " -> ".join(result["macroAliasChain"]))
        if "savedMachineCodeEvidence" in result:
            print("[ARCHIVED NATIVE SELECT DISASSEMBLY] MATCH")
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
