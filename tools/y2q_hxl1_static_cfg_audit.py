#!/usr/bin/env python3
"""Read-only HXL1 original ARM64 disassembly control-flow audit.

Verifies saved text digests and computes conservative direct-branch reachability.
It cannot prove source object identity, live runtime paths, root or KernelSU.
"""
from __future__ import annotations
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

NAMES = ("core_sys_select", "do_select", "futex_requeue", "do_futex", "futex_lock_pi")
TARGET = "SM-G986U1/G986U1UESCHXL1"
LINE = re.compile(r"^([0-9a-f]{16}):\s+([0-9a-f]{8})\s+(\S+)(?:\s+(.*?))?\s*$", re.I)
CONDITIONAL = {"cbz", "cbnz", "tbz", "tbnz"}
STOP = {"ret", "eret", "brk", "hlt"}

class AuditError(ValueError):
    pass

def check(ok, msg):
    if not ok:
        raise AuditError(msg)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def parse_disassembly(raw, begin, count):
    rows = {}
    for line in raw.decode("utf-8").splitlines():
        m = LINE.match(line)
        if m:
            address = int(m.group(1), 16)
            check(address not in rows, "Duplicate instruction address")
            rows[address] = (m.group(3).lower(),
                             (m.group(4) or "").split("//")[0].strip())
    check(count > 0 and count % 4 == 0 and len(rows) == count // 4,
          "Manifest instruction count mismatch")
    check(all((begin + i) in rows for i in range(0, count, 4)),
          "Instruction addresses are not contiguous")
    return rows

def read_archive(path):
    check(path.is_file() and not path.is_symlink()
          and 0 < path.stat().st_size < 4_000_000,
          "Missing or oversized archive")
    with tarfile.open(path, "r:gz") as tar:
        members = tar.getmembers()
        expected = {"stack-gate.json"} | {x + ".disasm.txt" for x in NAMES}
        check(len(members) == len(expected)
              and {item.name for item in members} == expected
              and all(item.isfile() and 0 < item.size < 750_000 for item in members),
              "Unexpected or unsafe archive members")
        manifest = json.loads(tar.extractfile("stack-gate.json").read())
        check(manifest.get("target") == TARGET
              and manifest.get("originalKernelSha256Verified") is True
              and manifest.get("originalFunctionsWithBoundedCode") == 5,
              "Unexpected device or evidence type")
        items = manifest["functions"]
        check(len(items) == 6
              and {x["symbol"] for x in items} == set(NAMES) | {"futex_wait_requeue_pi"},
              "Incomplete function inventory")
        symbols = {x["symbol"]: x for x in items}
        check(symbols["futex_wait_requeue_pi"].get("status") ==
              "NOT_FOUND_IN_RECOVERED_NM", "Original symbol status changed")
        result = {}
        for name in NAMES:
            item = symbols[name]
            body = tar.extractfile(name + ".disasm.txt").read()
            check(digest(body) == item["disassembly"]["textSha256"],
                  "Archived disassembly hash mismatch: " + name)
            begin = int(item["recoveredFileRelativeImageVA"], 16)
            result[name] = {"start": begin,
                            "instructions": parse_disassembly(body, begin,
                                                             item["byteCount"])}
        return result

def edges_for(instructions):
    edges = {}
    outside, unresolved = 0, 0
    direct = 0
    for address, (operation, operands) in instructions.items():
        next_address = address + 4
        conditional = operation.startswith("b.") or operation in CONDITIONAL
        unconditional = operation == "b"
        successors = []
        if conditional or unconditional:
            direct += 1
            raw = operands.rsplit(",", 1)[-1].strip()
            if not re.fullmatch("0x[0-9a-fA-F]+", raw):
                unresolved += 1
            else:
                value = int(raw, 16)
                if value in instructions:
                    successors.append(value)
                else:
                    outside += 1
            if conditional and next_address in instructions:
                successors.append(next_address)
        elif operation in ("br", "blr"):
            unresolved += 1
            if operation == "blr" and next_address in instructions:
                successors.append(next_address)
        elif operation not in STOP and next_address in instructions:
            successors.append(next_address)  # Calls may return
        edges[address] = successors
    return edges, direct, outside, unresolved

def reachable(edges, entry):
    pending = deque([entry]) if entry in edges else deque()
    seen = set()
    while pending:
        value = pending.pop()
        if value not in seen:
            seen.add(value)
            pending.extend(x for x in edges[value] if x not in seen)
    return seen

def analyze(windows):
    details, graphs = {}, {}
    for name in NAMES:
        entry = windows[name]["start"]
        code = windows[name]["instructions"]
        graph, direct, outside, unknown = edges_for(code)
        graphs[name] = graph
        path = reachable(graph, entry)
        returns = {a for a, (op, _) in code.items() if op == "ret"}
        details[name] = {"instructions": len(code), "directBranches": direct,
                         "targetsOutsideWindow": outside, "unresolvedIndirect": unknown,
                         "entryMayReach": len(path),
                         "notReachableInDirectGraph": len(code) - len(path),
                         "entryMayReachReturn": bool(path & returns),
                         "runtimeFeasibilityEstablished": False}
    name = "do_futex"
    base = windows[name]["start"]
    code = windows[name]["instructions"]
    check(code.get(base + 0xb14) == ("cmp", "w8, #0xb"),
          "Original operation-11 comparison missing")
    operation, raw = code.get(base + 0xb18, ("", ""))
    check(operation == "b.eq" and re.fullmatch("0x[0-9a-fA-F]+", raw),
          "Original operation-11 branch missing")
    target = int(raw, 16)
    check(target in code, "Original branch target missing")
    from_entry = reachable(graphs[name], base)
    from_branch = reachable(graphs[name], target)
    returns = {a for a,(op, _) in code.items() if op == "ret"}
    return {"target": TARGET, "schemaVersion": 1,
            "functions": details,
            "instructionsChecked": sum(x["instructions"] for x in details.values()),
            "operation11Branch": {
                "canReachBranchFromEntry": target in from_entry,
                "branchMayReachDispatcherReturn": bool(from_branch & returns),
                "possibleInstructionNodes": len(from_branch)},
            "sourceHelperInliningProven": False,
            "sourceLocalObjectPositionsProven": False,
            "crossSyscallStackReuseProven": False,
            "liveRuntimeOrRootVerified": False,
            "deviceModified": False,
            "limit": ("Graph overapproximates both sides of conditional branches "
                      "and treats calls as potentially returning; a graph path is "
                      "not proof of a feasible runtime execution path.")}

def markdown(report):
    lines = ["# HXL1 original ARM64 static control-flow evidence", "",
             "Hash-checked archived disassembly, not a live kernel trace.", "",
             "| Function | Instructions | Direct branches | Out-of-window | "
             "Indirect unknowns | Entry-reachable |",
             "|---|---:|---:|---:|---:|---:|"]
    for name, row in report["functions"].items():
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            name, row["instructions"], row["directBranches"],
            row["targetsOutsideWindow"], row["unresolvedIndirect"],
            row["entryMayReach"]))
    test = report["operation11Branch"]
    lines += ["", "Operation 11: may reach block from entry = " +
              str(test["canReachBranchFromEntry"]),
              "Operation 11: may reach common return = " +
              str(test["branchMayReachDispatcherReturn"]),
              "", "Source-to-C-object mapping: NOT VERIFIED",
              "Cross-syscall stack reuse: NOT VERIFIED",
              "Live root/KernelSU: NOT VERIFIED", "",
              report["limit"], ""]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    ap.add_argument("--output-dir", type=Path)
    args = ap.parse_args()
    try:
        report = analyze(read_archive(args.archive))
        if args.output_dir:
            check(not args.output_dir.exists(), "Refuse to overwrite evidence")
            args.output_dir.mkdir(parents=True, exist_ok=False)
            (args.output_dir / "static-cfg-audit.json").write_text(
                json.dumps(report, indent=2) + "\n")
            (args.output_dir / "static-cfg-audit.md").write_text(markdown(report))
        print("[ORIGINAL INSTRUCTION SLOTS]", report["instructionsChecked"])
        print("[OP11 REACHABILITY]", report["operation11Branch"])
        print("[ROOT / STACK REUSE PROVEN] NO")
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
