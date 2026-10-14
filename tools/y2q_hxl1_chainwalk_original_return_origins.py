#!/usr/bin/env python3
"""Single missing HXL1 original-function audit: PI-chain error-result origins.

Read-only. Pin existing stock ELF and recovered NM. No futex execution, device
connection, payload construction, source patching or repeated Stage-3 scans.
The output is a conservative static instruction inventory, NOT a feasible
error-interleaving or stale-reference proof.
"""
from __future__ import annotations

import argparse
import bisect
from collections import deque
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_task_blocks_original_compiled_gap as pinned
from tools import y2q_hxl1_ghostlock_call_target_crosswalk as syms
from tools import y2q_hxl1_static_cfg_audit as cfg

FUNC = "rt_mutex_adjust_prio_chain"
ENTRY = 0xffffff8008146ca4
MAX_BYTES = 0x8000
IMM32 = re.compile(r"^#(0x[0-9a-fA-F]+|\d+)$")
W0_OPERANDS = {"w0", "x0"}
STORES = {"str", "stur", "stp", "stnp", "stxr", "stlxr", "stlr", "sttr"}
CALLS = {"bl", "blr"}

def bounds(nm: bytes):
    names, addrs = syms.read_symbols(nm)
    pinned.need(FUNC in names.get(ENTRY, []),
                "Expected original chain-walk entry missing from recovered NM")
    p = bisect.bisect_right(addrs, ENTRY)
    pinned.need(p < len(addrs), "No recovered end boundary for chainwalk")
    end = addrs[p]
    pinned.need(32 <= end-ENTRY <= MAX_BYTES and
                (end-ENTRY) % 4 == 0, "Unexpected chainwalk size or alignment")
    return end, names, addrs

def original_rows(elf: Path, end: int, objdump: str):
    result = subprocess.run([
        objdump, "-d", "--start-address="+hex(ENTRY),
        "--stop-address="+hex(end), str(elf)],
        text=True, capture_output=True, errors="replace", timeout=35)
    pinned.need(result.returncode == 0 and len(result.stdout) < 2_000_000,
                "Original chainwalk objdump failed")
    rows = {}
    for line in result.stdout.splitlines():
        m = pinned.PC_LINE.match(line)
        if not m: continue
        va = int(m.group(1), 16)
        if not ENTRY <= va < end: continue
        pinned.need(va not in rows, "Duplicate chainwalk instruction VA")
        op = m.group(3).lower()
        raw = (m.group(4) or "").split("//", 1)[0].split(" <", 1)[0].strip()
        rows[va] = {
            "relative":hex(va-ENTRY), "word":m.group(2).lower(),
            "op":op, "args":pinned.normalize_objdump_control_target(op, raw)
        }
    pinned.need(len(rows) == (end-ENTRY)//4 and all(
                    ENTRY + 4*n in rows for n in range(len(rows))),
                "Original function instructions missing or noncontiguous")
    return rows

def writes_return_reg(row):
    op, args = row["op"], row["args"]
    if op in CALLS: return True
    if op in STORES or op in ("cmp", "cmn", "tst", "prfm", "b",
                               "cbz", "cbnz", "tbz", "tbnz", "ret"):
        return False
    if op.startswith("b."): return False
    operands = [x.strip() for x in args.split(",")]
    return bool(operands and operands[0] in W0_OPERANDS or
                op in ("ldp", "ldnp") and len(operands)>1 and
                operands[1] in W0_OPERANDS)

def immediate_result(row):
    """A syntactic 32-bit return constant, not proof its CFG path is feasible."""
    op, parts = row["op"], [x.strip() for x in row["args"].split(",")]
    if len(parts) != 2 or parts[0] != "w0" or op not in ("mov", "movz", "movn"):
        return None
    m = IMM32.fullmatch(parts[1])
    if not m: return None
    raw = int(m.group(1), 0)
    if op == "movn": raw = (~raw) & 0xffffffff
    else: raw &= 0xffffffff
    signed = raw if raw < 0x80000000 else raw - 0x100000000
    return signed

def no_clobber_path(rows, edges, start, end):
    """Existential CFG witness; interior calls and w0 writes invalidate it."""
    if start not in rows or end not in rows: return None
    q = deque([(start, [start])])
    seen = set()
    while q:
        pc, path = q.popleft()
        if pc in seen: continue
        seen.add(pc)
        if pc == end: return [hex(a-ENTRY) for a in path]
        if writes_return_reg(rows[pc]): continue
        for nxt in edges.get(pc, ()):
            if nxt not in seen and nxt in rows:
                q.append((nxt, path+[nxt]))
    return None

def inspect(rows, names, addrs):
    edges, branches, outside, unresolved = cfg.edges_for(
        {p:(r["op"],r["args"]) for p,r in rows.items()})
    returns = sorted(p for p,r in rows.items() if r["op"] == "ret")
    pinned.need(bool(returns), "No original chainwalk return")
    writes = []
    for pc, row in sorted(rows.items()):
        if not writes_return_reg(row) or row["op"] in CALLS:
            continue
        val = immediate_result(row)
        witnesses = []
        for ret in returns:
            path = no_clobber_path(rows,edges,pc+4,ret)
            if path:
                witnesses.append({"returnRelativeVA":hex(ret-ENTRY),
                                  "candidateUnclobberedPath":path,
                                  "runtimePredicatesFeasible":False})
        writes.append({
            "relativeVA":row["relative"],
            "word":row["word"],
            "asm":row["op"]+" "+row["args"],
            "immediateSigned32":val,
            "possibleUnclobberedReturnPaths":witnesses,
            "returnValueOriginProven":False,
        })
    exact_calls = []
    for pc,r in sorted(rows.items()):
        if r["op"] != "bl":continue
        label = syms.symbol_match(r["args"],names,addrs)
        exact_calls.append({
            "relativeVA":r["relative"],
            "target":r["args"],
            "symbolMatch":label,
            "calleeSideEffectsProven":False
        })
    return {
        "schemaVersion":1,
        "target":"SM-G986U1/G986U1UESCHXL1",
        "scope":"ORIGINAL_RT_MUTEX_ADJUST_PRIO_CHAIN_RETURN_ORIGIN_ONLY",
        "sourceOriginalStockElfSha256":pinned.ELF_SHA,
        "sourceRecoveredNmSha256":syms.ORIGINAL_NM_SHA,
        "functionName":FUNC, "originalEntryVA":hex(ENTRY),
        "instructionCount":len(rows),
        "branchInstructions":branches,
        "outOfWindowBranches":outside,
        "unresolvedBranchDestinations":unresolved,
        "returnSites":[hex(pc-ENTRY) for pc in returns],
        "returnRegisterWriteCandidates":writes,
        "syntacticNegativeImmediateReturnCandidates":[
            x for x in writes if x["immediateSigned32"] is not None and
                                  x["immediateSigned32"] < 0],
        "calledFunctions":exact_calls,
        "interproceduralErrorCausesComplete":False,
        "negativeErrorFromPublishedWaiterPathFeasibleVerified":False,
        "rollbackOwnerGuardSimultaneouslySatisfiedVerified":False,
        "postReturnDanglingReferenceVerified":False,
        "rootOrKernelSuVerified":False,
        "deviceModified":False,
        "interpretation":"Only original machine-code return origins and conservative paths. "
                         "Call side effects, runtime input constraints, task identity, "
                         "full return-value dataflow and cross-task stale references "
                         "are outside this report. No exploitability inference.",
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--elf",type=Path,required=True)
    p.add_argument("--nm",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a = p.parse_args()
    try:
        destination = a.output.expanduser().resolve()
        pinned.need(not a.output.expanduser().is_symlink() and not destination.exists()
                    and "/src/" not in str(destination),
                    "Output must be new and outside source checkout")
        pinned.pin(a.elf.expanduser(),pinned.ELF_SHA,256_000_000)
        nm = pinned.pin(a.nm.expanduser(),syms.ORIGINAL_NM_SHA,20_000_000)
        end,names,addrs = bounds(nm)
        tool = shutil.which("aarch64-linux-gnu-objdump")
        pinned.need(bool(tool),"Requires installed aarch64-linux-gnu-objdump")
        result = inspect(original_rows(a.elf.expanduser(),end,tool),names,addrs)
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open("x",encoding="utf-8") as out:
            json.dump(result,out,indent=2);out.write("\n")
        print("[NEW COMPILED FUNCTION]",FUNC)
        print("[RETURN SITES]",result["returnSites"])
        print("[RETURN REGISTER WRITES]",len(result["returnRegisterWriteCandidates"]))
        print("[POTENTIAL NEGATIVE IMMEDIATE WRITES]",
              len(result["syntacticNegativeImmediateReturnCandidates"]))
        print("[LATE ERROR FEASIBILITY / STALE REFERENCE / ROOT] UNVERIFIED")
        print("[REPORT]",destination)
        return 0
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        print("[STOP]",exc,file=sys.stderr);return 2

if __name__ == "__main__":
    raise SystemExit(main())
