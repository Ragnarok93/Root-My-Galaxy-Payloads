#!/usr/bin/env python3
"""HXL1 offline AVB IsUnlocked state-persistence read/write provenance.

Reuses SHA256-validated owner Ghidra Evidence through the 0x33c88 and
0x33da8 native writer dossiers. Verifies distinct save/initialize paths
and a local address proof at 0x33d08. Conservatively attempts to recover
X19's static base at 0x33ee0: if a unique reaching ADRP+ADD producer cannot
be established, leaves the address UNRESOLVED.

With --execute, makes only four additional host-only Ghidra queries:
 xrefs to 0x33c88 / 0x33da8; function and instructions at 0x2ae38.
Default PLAN ONLY. No device access, firmware writes or unlock operation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, function_record, reference_sources,
    safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_producers import audit as verify_byte_producers
from tools.y2q_hxl1_rea_avb_byte_writers import (
    parse_instructions, exact_instruction,
)

SOURCE_GLOBAL = "0x351055"
SOURCE_OBJECT = "0x351048"
OBJECT_SIZE = 0x9A0
STORE_FN = "0x33c88"
INIT_FN = "0x33da8"
STORAGE_FN = "0x2ae38"
CALLER_TARGETS = (STORE_FN, INIT_FN)
MAX_LISTING = 8000
MAX_PSEUDO = 350000
# Exact original Ghidra statements: string/whitespace-neutral but
# do NOT equate a decompiler assignment to native SSA proof.
PSEUDO_STORE = (
    r"\bDAT_00351055\s*=\s*param_1\s*;",
    r"\bFUN_0002ae38\s*\(\s*1\s*,\s*&DAT_00351048\s*,\s*0x9a0\s*\)",
)
PSEUDO_INIT = (
    r"\bFUN_0002ae38\s*\(\s*0\s*,\s*&DAT_00351048\s*,\s*0x9a0\s*\)",
    r'\bFUN_0000f7e4\s*\(\s*&DAT_00351048\s*,\s*"SAMANDR-BOOT!"\s*,\s*0xd\s*\)',
    r"\bDAT_00351055\s*=\s*0\s*;",
    r"\bFUN_0002ae38\s*\(\s*1\s*,\s*&DAT_00351048\s*,\s*0x9a0\s*\)",
)


def validate_pseudocode(ev: dict, owner: str, patterns: tuple[str, ...]) -> dict:
    info = function_record(ev, owner)
    if info["entry"] != owner:
        raise TriageError(f"Original writer {owner} Ghidra owning entry changed")
    pseudo = ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>MAX_PSEUDO:
        raise TriageError("Missing/oversized original HXL1 writer pseudocode")
    lines=pseudo.splitlines()
    if len(lines)>MAX_LISTING:
        raise TriageError("Excessive original source pseudo lines")
    exact = {}
    for expression in patterns:
        m = list(re.finditer(expression, pseudo))
        if len(m) != 1:
            raise TriageError(
                f"Original {owner} required write/storage sequence missing/ambiguous: {expression}")
        line_no=pseudo[:m[0].start()].count("\n")+1
        exact[expression]={"line":line_no,"code":lines[line_no-1].strip()}
    return {
        "entry":owner,"evidenceId":ev["evidence_id"],
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "totalLines":len(lines),
        "observedStatements":list(exact.values()),
        "nativeMemoryAliasOrPersistentIntegrityProven":False,
    }


def exact_33c88_local_store(ev: dict) -> dict:
    ops=parse_instructions(ev,STORE_FN)
    # Pin the original conditional write path and the local address.
    required = [
        ("0x33c94","mov","w19,w0"),
        ("0x33ce0","adrp","x8,0x351000"),
        ("0x33ce4","add","x8,x8,#0x48"),
        ("0x33ce8","ldrb","w9,[x8,#0xd]"),
        ("0x33cec","cmp","w9,w19,uxtb"),
        ("0x33cf0","b.ne","0x00033cfc"),
        ("0x33cf4","mov","x19,xzr"),
        ("0x33cf8","b","0x00033d7c"),
        ("0x33cfc","ldr","w9,[x8,#0x998]"),
        ("0x33d00","tst","w19,#0xff"),
        ("0x33d04","and","w10,w19,#0xff"),
        ("0x33d08","strb","w19,[x8,#0xd]"),
    ]
    for address, mnemonic, operands in required:
        exact_instruction(ops,address,mnemonic,operands)
    # No X8-defining instruction may intervene on the supported
    # compare-and-store branch. This does not prove broader CFG
    # reachability or whether earlier byte input is authorized.
    addresses = sorted(
        (x for x in ops if 0x33CE4<int(x,16)<0x33D08),
        key=lambda x:int(x,16))
    for a in addresses:
        m,o=ops[a]
        first=o.split(",",1)[0]
        if first in ("x8","w8") and m not in ("str","strb","cmp","tst"):
            raise TriageError(f"X8 redefined between pinned ADRP and STRB at {a}")
    result=0x351000+0x48+0xD
    if result!=int(SOURCE_GLOBAL,16):
        raise TriageError("Computed variable-byte store address mismatch")
    return {
        "owner":STORE_FN, "site":"0x33d08",
        "evidenceId":ev["evidence_id"],
        "addressCalculation":"0x351000 + 0x48 + 0x0d",
        "effectiveByteAddress":SOURCE_GLOBAL,
        "nativeStoreTargetVerifiedOnSourceAddressPath":True,
        "w19FromParameterW0ObservedAt":"0x33c94",
        "conditionalByteMismatchBranch":"0x33cf0",
        "sourceCallerAuthorizationVerified":False,
        "persistentWriteViaStorageHelperVerified":False,
    }


def x19_33da8_provenance(ev: dict) -> dict:
    ops=parse_instructions(ev,INIT_FN)
    exact_instruction(ops,"0x33ee0","strb","wzr,[x19,#0xd]")
    earlier=sorted(
        (a for a in ops if int(a,16)<0x33EE0),key=lambda a:int(a,16))
    assignments=[]
    for a in earlier:
        mnemonic, operands = ops[a]
        dest=operands.split(",",1)[0]
        if dest in ("x19","w19") and mnemonic in (
            "mov","movz","movk","adr","adrp","add","sub","ldr","ldrb","orr","and"):
            assignments.append({"address":a,"mnemonic":mnemonic,"operands":operands})
    # A conservative lexical nearest-writer check. If another
    # unrecognized instruction or control-flow path may assign x19,
    # do not claim an absolute effective memory alias.
    last=assignments[-1] if assignments else None
    match=None
    if last is not None and last["mnemonic"]=="add" and last["operands"]=="x19,x19,#0x48":
        i=earlier.index(last["address"])
        if i>0 and ops[earlier[i-1]]==("adrp","x19,0x351000"):
            match=(earlier[i-1],last["address"])
    context=earlier[:24]
    verified=match is not None
    return {
        "owner":INIT_FN,"site":"0x33ee0","evidenceId":ev["evidence_id"],
        "nativeZeroByteStoreOpcodeVerified":True,
        "x19AssignmentCandidates":assignments[:35],
        "entryInstructionExcerpt":[
            {"address":a,"mnemonic":ops[a][0],"operands":ops[a][1]}
            for a in context
        ],
        "staticAddressBasePair":list(match) if match else [],
        "staticAddressCandidate":SOURCE_GLOBAL if verified else None,
        "effectiveAddressProvedOnAllControlFlowPaths":False,
        "initializeOrResetSemanticHypothesis":True,
        "writerAuthorizationVerified":False,
    }


def storage_helper_dossier(ev: dict) -> dict:
    rec=function_record(ev,STORAGE_FN)
    if rec["entry"]!=STORAGE_FN:
        raise TriageError("Original read/write helper owner does not match source")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>MAX_PSEUDO:
        raise TriageError("Missing/oversized Ghidra read/write helper pseudocode")
    lines=pseudo.splitlines()
    if len(lines)>MAX_LISTING:
        raise TriageError("Original persistence helper exceeds line budget")
    refs={}
    for i,line in enumerate(lines):
        for name in re.findall(r"\bFUN_([0-9a-fA-F]{8})\s*\(",line):
            refs.setdefault("0x"+name.lstrip("0").lower(),[]).append(i+1)
    if len(refs)>400:
        raise TriageError("Excessive original persistence helper direct-call refs")
    return {
        "entry":STORAGE_FN,"evidenceId":ev["evidence_id"],
        "lines":len(lines),
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "directLexicalCallees":[{"address":name,"lines":indices[:15]}
                                for name,indices in refs.items()],
        "fullPseudocode":[
            {"line":i+1,"code":line[:800]}
            for i,line in enumerate(lines[:240])
        ],
        "excerptTruncated":len(lines)>240,
        "partitionOrSecureStorageOriginVerified":False,
        "readWriteFlagSemanticsProven":False,
    }


def storage_helper_instructions(ev: dict) -> dict:
    ops=parse_instructions(ev,STORAGE_FN)
    if len(ops)>MAX_LISTING:
        raise TriageError("Persistence helper instruction list exceeds bound")
    lines=sorted(ops,key=lambda a:int(a,16))
    return {
        "evidenceId":ev["evidence_id"],
        "instructionCount":len(ops),
        "excerptTruncated":len(lines)>100,
        "excerpt":[{"address":a,"mnemonic":ops[a][0],"operands":ops[a][1]}
                   for a in lines[:100]],
        "actualBackendVerified":False,
    }


def audit(root: Path, *, execute:bool=False, rea:Path|None=None,
          node:str="node", timeout:int=240, recover_partials:bool=False) -> dict:
    prior=verify_byte_producers(root)
    if prior.get("sourceAttested") is not True:
        raise TriageError("Original source-attested HXL1 byte producer Evidence missing")
    expected={(x["ownerEntry"],x["site"]) for x in prior.get("storeCandidates",[])}
    if expected!={(STORE_FN,"0x33d08"),(INIT_FN,"0x33ee0")}:
        raise TriageError("Original writer owner identities changed")
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    source={}
    for entry,patterns in ((STORE_FN,PSEUDO_STORE),(INIT_FN,PSEUDO_INIT)):
        f=evidence(folder/("function-"+safe_segment(entry)+".json"),
                   sha=target.sha256, operation="analyze_function",
                   parameter="procedure", value=entry)
        source[entry]=validate_pseudocode(f,entry,patterns)
    first=evidence(folder/"instructions-0x33c88.json",
                   sha=target.sha256,operation="read_function_instructions",
                   parameter="procedure",value=STORE_FN)
    second=evidence(folder/"instructions-0x33da8.json",
                    sha=target.sha256,operation="read_function_instructions",
                    parameter="procedure",value=INIT_FN)
    native_variable=exact_33c88_local_store(first)
    native_clear=x19_33da8_provenance(second)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing/unsafe")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    callers=[]
    for entry in CALLER_TARGETS:
        response=runner.obtain(
            target,["xrefs",str(target.path),entry],
            folder/("xrefs-function-"+safe_segment(entry)+".json"),
            operation="xrefs",parameter="address",value=entry)
        hits=reference_sources(response) if response is not None else []
        callers.append({
            "function":entry,"evidenceId":response["evidence_id"] if response else None,
            "count":len(hits),
            "sites":hits[:100],
            "truncated":len(hits)>100,
            "callerOwnershipVerified":False,
            "allCallersKnown":False,
        })
    helper_fn=runner.obtain(
        target,["function",str(target.path),STORAGE_FN],
        folder/("function-"+safe_segment(STORAGE_FN)+".json"),
        operation="analyze_function",parameter="procedure",value=STORAGE_FN)
    helper_native=runner.obtain(
        target,["instructions",str(target.path),STORAGE_FN],
        folder/("instructions-"+safe_segment(STORAGE_FN)+".json"),
        operation="read_function_instructions",parameter="procedure",value=STORAGE_FN)
    return {
        "schemaVersion":1,"mode":"STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "archiveSha256":HXL1_BL_SHA256,"sourceAttested":True,
        "newQueries":len(runner.planned),
        "globalAddress":SOURCE_GLOBAL,"objectBase":SOURCE_OBJECT,
        "objectBytes":OBJECT_SIZE,
        "originalPseudocode":source,
        "variableStoreNative":native_variable,
        "resetStoreNative":native_clear,
        "functionXrefs":callers,
        "storageHelperPseudocode":storage_helper_dossier(helper_fn) if helper_fn else None,
        "storageHelperNative":storage_helper_instructions(helper_native) if helper_native else None,
        "trustedUnlockAuthorizationProven":False,
        "onDiskIntegrityOrCryptoProven":False,
        "unlockBypassProven":False,"deviceModified":False,
    }


def markdown(r:dict)->str:
    lines=[
        "# HXL1 IsUnlocked byte — original state persistence and call provenance",
        "",
        "**Original source-attested Ghidra analysis only. No unlock, flash or device changes.**",
        "", "Source BL SHA256: "+r["archiveSha256"],
        "State global: "+r["globalAddress"],
        "Structure base: "+r["objectBase"],
        "Structure bytes: "+str(r["objectBytes"]),
        "New read-only Ghidra queries: "+str(r["newQueries"]),
        "",
        "## Original writer functions and persistence calls","",
    ]
    for owner in (STORE_FN, INIT_FN):
        obs=r["originalPseudocode"][owner]
        lines += [
            "### "+owner,"","- Original Ghidra Evidence: "+obs["evidenceId"],
            "- Pseudocode lines: "+str(obs["totalLines"]),
            "- Exact source statements:","", "~~~c",
        ]
        for item in obs["observedStatements"]:
            lines.append(f"{item['line']:5d} | {item['code']}")
        lines += ["~~~",""]
    n=r["variableStoreNative"]
    lines += [
        "## 0x33c88 — native variable-value assignment","",
        "- Native Evidence: "+n["evidenceId"],
        "- Input W0 copied to W19 at "+n["w19FromParameterW0ObservedAt"],
        "- ADRP/ADD + STRB at 0x33ce0/0x33ce4/0x33d08",
        "- Effective byte address on pinned source path: "+n["effectiveByteAddress"],
        "- Assignment gated by byte comparison at "+n["conditionalByteMismatchBranch"],
        "- External authorization of W0 input: UNKNOWN",
        "",
        "## 0x33da8 — reset/initialization store","",
    ]
    c=r["resetStoreNative"]
    lines += [
        "- Native Evidence: "+c["evidenceId"],
        "- Instruction 0x33ee0: STRB WZR,[X19,#0xd]",
        "- X19 static base pair: "+str(c["staticAddressBasePair"]),
        "- X19 possible store address: "+str(c["staticAddressCandidate"]),
        "- All-path register alias / state authority: UNPROVEN",
        "",
        "### Original function-entry native context","", "~~~asm",
    ]
    for i in c["entryInstructionExcerpt"]:
        lines.append(i["address"]+": "+i["mnemonic"]+" "+i["operands"])
    lines += ["~~~","","## Who calls these writers?",""]
    for x in r["functionXrefs"]:
        lines += [
            "### "+x["function"],"",
            "- Source Evidence: "+str(x["evidenceId"]),
            "- Xref count: "+str(x["count"]),
            "- Caller-site coordinates: "+str(x["sites"]),
            "- Xref types/owning callers still require confirmation.","",
        ]
    lines += ["## FUN_0002ae38 — state-object persistence interface",""]
    f=r["storageHelperPseudocode"]
    if f is None:
        lines += ["Ghidra helper source planned but not yet collected.",""]
    else:
        lines += [
            "- Original Ghidra Evidence: "+f["evidenceId"],
            "- Decompilation lines: "+str(f["lines"]),
            "- Lexical callees: "+str(f["directLexicalCallees"]),"",
            "### Original decompiled helper","", "~~~c",
        ]
        for item in f["fullPseudocode"]:
            lines.append(f"{item['line']:5d} | {item['code']}")
        lines += ["~~~",""]
    native=r["storageHelperNative"]
    if native is not None:
        lines += ["### Original native helper instruction excerpt","", "~~~asm"]
        for row in native["excerpt"]:
            lines.append(row["address"]+": "+row["mnemonic"]+" "+row["operands"])
        lines += ["~~~",""]
    lines += [
        "## Open security-authority questions","",
        "1. Confirm the storage backend and whether the structure is",
        "   authenticated or only a cached local representation.",
        "2. Classify xrefs to 0x33c88 as true callers, not just addresses;",
        "   prove how W0 is derived and which privilege boundary applies.",
        "3. Establish whether bootloader/Odin image authorization uses",
        "   this same value or a separately protected security decision.",
        "4. A persisted 'IsUnlocked' diagnostic is NOT a working unlock.",
        "",
    ]
    return "\n".join(lines)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir",type=Path,
                    default=Path.home()/"s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    ap.add_argument("--node",default="node")
    ap.add_argument("--execute",action="store_true")
    ap.add_argument("--recover-partials",action="store_true")
    ap.add_argument("--timeout",type=int,default=240)
    opts=ap.parse_args()
    if not 30<=opts.timeout<=1200:
        ap.error("Timeout outside bounded range")
    try:
        root=opts.input_dir.expanduser().resolve()
        report=audit(root,execute=opts.execute,rea=opts.rea,
                     node=opts.node,timeout=opts.timeout,
                     recover_partials=opts.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-state-persistence.json").write_text(json.dumps(report,indent=2)+"\n")
        (out/"avb-state-persistence.md").write_text(markdown(report))
    except (TriageError,OSError,KeyError,ValueError,TypeError) as exc:
        print("[STOP]",str(exc),file=sys.stderr)
        return 2
    print("[STORE]",STORE_FN,"native byte at",report["variableStoreNative"]["effectiveByteAddress"])
    print("[INIT]",INIT_FN,"X19 candidate",report["resetStoreNative"]["staticAddressCandidate"])
    for x in report["functionXrefs"]:
        print("[XREF]",x["function"],x["count"])
    print("[HELPER]",STORAGE_FN,
          "VERIFIED" if report["storageHelperPseudocode"] else "PENDING")
    print("[REPORT]",out/"avb-state-persistence.md")
    print("[LIMIT] Secure authority, flash authorization and unlock remain UNKNOWN")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
