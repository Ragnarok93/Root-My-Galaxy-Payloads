#!/usr/bin/env python3
"""Read-only original HXL1 unlock-choice bitmask writer / boot UI flag audit.

Reattest source-SHA-pinned Ghidra native body of 0x67dd8 (18 instructions),
which returns !!([0x3651ec] & W0); stock LinuxLoader calls it with mask 4
after 0x68f18, choosing direct unlock or relock. Separately 0x182d0
uses 0x60bd8 in the interactive Odin-mode confirmation path.

After strict saved-evidence validation, allow only six new host Ghidra
queries: xrefs of 0x3651ec and 0x68f18; function and instructions of
0x68f18 (potential producer) and 0x60bd8 (UI-context predicate).
Record actual original code without deciding that these software state
bits authorize signed images or an OEM bootloader unlock.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256,TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner,choose_targets,evidence,function_record,reference_sources,safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions,exact_instruction
from tools.y2q_hxl1_rea_avb_oem_persistent_boundary import (
    audit as verify_boundary,DECISION,MAIN,BOOT_DISPATCH
)

BITMASK_GLOBAL="0x3651ec"
BITMASK_MASK=4
PRODUCER="0x68f18"
INTERACTIVE_FLAG="0x60bd8"
SITES=(
    ("0x3651ec","unlock-request-bitmask-global"),
    ("0x68f18","pre-dispatch-helper-calls"),
)
FUNCTIONS=(
    ("0x68f18","pre-selector-state-producer"),
    ("0x60bd8","Odin-interactive-mode-condition"),
)
DECISION_PINS=(
    ("0x67de4","adrp","x9,0x365000"),
    ("0x67df8","ldr","w8,[x9,#0x1ec]"),
    ("0x67e00","tst","w8,w0"),
    ("0x67e04","cset","w0,ne"),
    ("0x67e08","cmp","x10,x9"),
    ("0x67e0c","b.ne","0x00067e1c"),
    ("0x67e10","ldr","x30,[sp,#0x10]"),
    ("0x67e14","add","sp,sp,#0x20"),
    ("0x67e18","ret",""),
)
ENTRY_PINS=(
    ("0x1b34","bl","0x00068f18"),
    ("0x1b38","mov","w0,#0x4"),
    ("0x1b3c","bl","0x00067dd8"),
    ("0x1b40","tst","w0,#0xff"),
    ("0x1b44","b.eq","0x00001db0"),
    ("0x1b48","bl","0x00034238"),
    ("0x1db0","bl","0x00034370"),
)
MAX_HELPER_SOURCE_LINES=3200
MAX_HELPER_INSTRUCTIONS=3500


def assert_prior(prior:dict)->dict:
    if prior.get("sourceAttested") is not True:
        raise TriageError("HXL1 boundary source attribution missing")
    main=prior.get("mainUnlockSelection") or {}
    if not (main.get("entry")==MAIN
            and main.get("selectorFunction")==DECISION
            and main.get("nativeSelectorBranchVerified") is True
            and main.get("inputToSelector")=="0x4"
            and main.get("nonzeroResultDirectTarget")=="0x34238"
            and main.get("zeroResultDirectTarget")=="0x34370"):
        raise TriageError("Original HXL1 main unlock/relock selector changed")
    others={row.get("entry"):row for row in prior.get("boundaryHelpers",[])}
    for entry in (DECISION,"0x1e5f0",BOOT_DISPATCH):
        if (entry not in others or not isinstance(others[entry].get("native"),dict)
                or not isinstance(others[entry].get("function"),dict)):
            raise TriageError("Original HXL1 source-boundary helper evidence incomplete")
    if len(others)!=3:
        raise TriageError("Original HXL1 boundary helper inventory changed")
    return others


def bitmask_native(ev:dict,prior:dict)->dict:
    if ev["evidence_id"]!=prior["native"]["nativeEvidenceId"]:
        raise TriageError("Original 0x67dd8 native Evidence ID changed")
    ops=parse_instructions(ev,DECISION)
    if len(ops)!=18:
        raise TriageError("Original selector native 18-instruction body changed")
    for a,m,o in DECISION_PINS:
        exact_instruction(ops,a,m,o)
    calc=int("0x365000",16)+int("0x1ec",16)
    if hex(calc)!=BITMASK_GLOBAL:
        raise TriageError("Original selector ADRP + LDR effective address differs")
    interval=("0x67df8","0x67dfc","0x67e00","0x67e04")
    observed=sorted((a for a in ops if int(interval[0],16)<=int(a,16)<=int(interval[-1],16)),
                    key=lambda x:int(x,16))
    if observed!=list(interval):
        raise TriageError("Original bitmask load/test/cset interrupted")
    return {
        "sourceEvidenceId":ev["evidence_id"],
        "globalAddress":BITMASK_GLOBAL,
        "globalWidthBits":32,
        "nativeInputRegister":"w0",
        "nativeReturnRegister":"w0",
        "transformation":"(uint32_at_0x3651ec & incoming_w0) != 0",
        "normalReturnFlowVerified":True,
        "callerInputMask":BITMASK_MASK,
        "specificResult":"(uint32_at_0x3651ec & 4) != 0",
        "meaningOfBit2Proven":False,
        "originOfGlobalBitsProven":False,
        "secureStatePolicyProven":False,
    }


def verify_entry_native(ev:dict,prior:dict)->dict:
    if ev["evidence_id"]!=prior["mainUnlockSelection"]["nativeEvidenceId"]:
        raise TriageError("Main entry 0x17d8 native Evidence changed")
    ops=parse_instructions(ev,MAIN)
    if len(ops)!=569:
        raise TriageError("Original main entry instruction count changed")
    for a,m,o in ENTRY_PINS:
        exact_instruction(ops,a,m,o)
    return {
        "sourceEvidenceId":ev["evidence_id"],
        "preSelectionFunction":PRODUCER,
        "preSelectionCallSite":"0x1b34",
        "selectorCallSite":"0x1b3c",
        "maskValue":4,
        "zeroBranch":"0x1db0",
        "nonzeroBranch":"0x1b48",
        "preSelectionWriterOfGlobalVerified":False,
        "entryAuthorizationVerified":False,
    }


def verify_interactive_link(ev:dict,prior:dict)->dict:
    if ev["evidence_id"]!=prior["function"]["sourceEvidenceId"]:
        raise TriageError("Boot-mode Ghidra source Evidence changed")
    fun=function_record(ev,BOOT_DISPATCH)
    if fun["entry"]!=BOOT_DISPATCH:
        raise TriageError("Boot-mode helper original function changed")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or len(pseudo)>260000:
        raise TriageError("Original boot-mode source unavailable")
    required=(r"\bFUN_00060bd8\s*\(\s*\)",r"\bFUN_000674d8\s*\(\s*\)",
              r"\bFUN_0002cae8\s*\(")
    for q in required:
        if re.search(q,pseudo) is None:
            raise TriageError("Original boot-mode interactive source marker missing: "+q)
    return {
        "evidenceId":ev["evidence_id"],
        "bootModeUsesInteractiveFlagFunction":INTERACTIVE_FLAG,
        "bootModeCallsUnlockConfirmation":"0x674d8",
        "interactiveEntryPermissionEstablished":False,
    }


def helper_function(ev:dict,entry:str,kind:str)->dict:
    rec=function_record(ev,entry)
    if rec["entry"]!=entry:
        raise TriageError("Original extra helper source owner changed")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>260000:
        raise TriageError("Original extra helper decompilation missing/too large")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=MAX_HELPER_SOURCE_LINES:
        raise TriageError("Original helper Ghidra source budget exceeded")
    return {
        "entry":entry,"kind":kind,
        "evidenceId":ev["evidence_id"],
        "pseudoSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "lineCount":len(lines),
        "source":[{"line":i+1,"code":s[:800]} for i,s in enumerate(lines[:180])],
        "sourceTruncated":len(lines)>180,
        "directFunctionCandidates":sorted(set(re.findall(r"\bFUN_[0-9a-fA-F]{8}\b",pseudo)))[:100],
        "globalCandidates":sorted(set(re.findall(r"\bDAT_[0-9a-fA-F]{8}\b",pseudo)))[:100],
        "controlsBitmaskOrSecurityAuthoritativelyProven":False,
    }


def helper_instructions(ev:dict,entry:str)->dict:
    ops=parse_instructions(ev,entry)
    if not 6<=len(ops)<=MAX_HELPER_INSTRUCTIONS:
        raise TriageError("Original helper native listing unavailable/bounds exceeded")
    addresses=sorted(ops,key=lambda s:int(s,16))
    text=[a+": "+ops[a][0]+(" "+ops[a][1] if ops[a][1] else "")
          for a in addresses[:190]]
    return {
        "entry":entry,"evidenceId":ev["evidence_id"],
        "nativeInstructionCount":len(ops),
        "sourceInstructions":text,"truncated":len(addresses)>190,
        "writesTo0x3651ecVerified":False,
        "secureAuthorizationVerified":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_boundary(root)
    known=assert_prior(prior)
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    original_selector=evidence(
        folder/"instructions-state-boundary-0x67dd8.json",
        sha=target.sha256,operation="read_function_instructions",
        parameter="procedure",value=DECISION)
    original_main=evidence(
        folder/"instructions-route-owner-0x17d8.json",
        sha=target.sha256,operation="read_function_instructions",
        parameter="procedure",value=MAIN)
    original_boot=evidence(
        folder/"function-state-boundary-0x182d0.json",
        sha=target.sha256,operation="analyze_function",
        parameter="procedure",value=BOOT_DISPATCH)
    selector=bitmask_native(original_selector,known[DECISION])
    entry=verify_entry_native(original_main,prior)
    boot=verify_interactive_link(original_boot,known[BOOT_DISPATCH])
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing/symlinked")
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    xrefs=[]
    for addr,kind in SITES:
        ev=runner.obtain(
            target,["xrefs",str(target.path),addr],
            folder/("xrefs-selector-root-"+safe_segment(addr)+".json"),
            operation="xrefs",parameter="address",value=addr)
        sites=reference_sources(ev) if ev is not None else []
        xrefs.append({
            "address":addr,"kind":kind,"originalEvidenceId":ev["evidence_id"] if ev else None,
            "xrefCount":len(sites),"sites":sites[:200],"displayTruncated":len(sites)>200,
            "nativeStoresOrCallersProven":False,
        })
    helpers=[]
    for addr,kind in FUNCTIONS:
        f=runner.obtain(
            target,["function",str(target.path),addr],
            folder/("function-selector-root-"+safe_segment(addr)+".json"),
            operation="analyze_function",parameter="procedure",value=addr)
        ins=runner.obtain(
            target,["instructions",str(target.path),addr],
            folder/("instructions-selector-root-"+safe_segment(addr)+".json"),
            operation="read_function_instructions",parameter="procedure",value=addr)
        helpers.append({
            "entry":addr,"kind":kind,
            "function":helper_function(f,addr,kind) if f else None,
            "native":helper_instructions(ins,addr) if ins else None,
        })
    return {
        "schemaVersion":1,"originalBlArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"READ_ONLY_ORIGINAL_GHIDRA" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),
        "nativeBitmaskSelector":selector,
        "originalEntryRoute":entry,
        "originalInteractiveBootPath":boot,
        "sourceXrefs":xrefs,"investigationHelpers":helpers,
        "bit2SecurityAuthorizationVerified":False,
        "trustedBootOrOdinSignatureAcceptanceVerified":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    sel=r["nativeBitmaskSelector"]
    lines=[
        "# HXL1 — original bit-2 unlock request flag and its producer boundary",
        "",
        "**Original HXL1 stock LinuxLoader SHA-attested read-only Ghidra. No unlock.**",
        "", "- Firmware BL archive SHA256: "+r["originalBlArchiveSha256"],
        "- New static original Ghidra queries: "+str(r["newQueries"]),
        "",
        "## Native 0x67dd8 returns Boolean from 0x3651ec & W0","",
        "- Original native Evidence: "+sel["sourceEvidenceId"],
        "- Global: "+sel["globalAddress"]+" (32-bit)",
        "- Native return expression: "+sel["transformation"],
        "- Main caller mask: "+str(sel["callerInputMask"]),
        "- Exact main call result: "+sel["specificResult"],
        "- Ghidra decompiled function is VOID; the native W0 CSET",
        "  followed by an unchanged normal RET establishes Boolean W0.",
        "- This is a **bitmask reader**, not by itself an authorization gate.",
        "","~~~asm",
        "0x67de4: adrp x9,0x365000",
        "0x67df8: ldr  w8,[x9,#0x1ec]",
        "0x67e00: tst  w8,w0",
        "0x67e04: cset w0,ne",
        "0x67e18: ret",
        "~~~","",
        "## Original entry selection and interactive Odin pathway","",
        "- 0x17d8: 0x1b34 BL 0x68f18, then 0x67dd8(4).",
        "- Bit-2 zero: 0x1db0 BL 0x34370 (relock request).",
        "- Bit-2 nonzero: 0x1b48 BL 0x34238 (unlock request).",
        "- Boot selector 0x182d0 separately uses 0x60bd8 and",
        "  interactive confirmation handler 0x674d8.",
        "- Whether the producer, key state, or stored OEM permission",
        "  is trusted or restricts execution: NOT PROVEN.","",
        "## Original Ghidra references (unclassified)", "",
    ]
    for row in r["sourceXrefs"]:
        lines += [
            "### "+row["address"]+" — "+row["kind"],"",
            "- Evidence: "+str(row["originalEvidenceId"]),
            "- Count: "+str(row["xrefCount"]),
            "- Source coordinates: "+str(row["sites"]),
            "- Read/write/call ownership and address alias not yet proven.","",
        ]
    lines += ["## Bounded original native/source helper analyses",""]
    for row in r["investigationHelpers"]:
        lines += ["### "+row["entry"]+" — "+row["kind"],""]
        f=row["function"]
        if f is not None:
            lines += [
                "- Ghidra function Evidence: "+f["evidenceId"],
                "- Pseudocode line count: "+str(f["lineCount"]),
                "- Candidate calls: "+str(f["directFunctionCandidates"]),
                "- Candidate globals: "+str(f["globalCandidates"]),
                "","~~~c",
            ]
            for x in f["source"]:
                lines.append(f"{x['line']:5d} | {x['code']}")
            lines += ["~~~",""]
        else:
            lines += ["- Function source query pending.",""]
        n=row["native"]
        if n is not None:
            lines += [
                "- Native Evidence: "+n["evidenceId"],
                "- Original native instruction count: "+str(n["nativeInstructionCount"]),
                "","~~~asm",*n["sourceInstructions"],"~~~","",
            ]
    lines += [
        "## Outstanding trust gates","",
        "1. Determine which original native instructions write or",
        "   initialize 0x3651ec; prove their register/address alias.",
        "2. Trace 0x68f18 state acquisition and 0x60bd8 UI conditions",
        "   independently of OEM partition byte and FRP state.",
        "3. Classify the bit-2 meaning using real caller/producer paths;",
        "   never equate a bit set with securely unlocked bootloader.",
        "4. Secure-boot signature policy, Odin acceptance, device unlock",
        "   and any firmware-state modification remain UNPROVEN.","",
    ]
    return "\n".join(lines)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path,default=Path.home()/
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    p.add_argument("--node",default="node")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--recover-partials",action="store_true")
    p.add_argument("--timeout",type=int,default=240)
    x=p.parse_args()
    if not 30<=x.timeout<=1200:
        p.error("timeout out of bounds")
    try:
        root=x.input_dir.expanduser().resolve()
        report=audit(root,execute=x.execute,rea=x.rea,node=x.node,
                     timeout=x.timeout,recover_partials=x.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-unlock-bitmask-producers.json").write_text(json.dumps(report,indent=2)+"\n")
        (out/"avb-unlock-bitmask-producers.md").write_text(markdown(report))
    except (TriageError,OSError,TypeError,ValueError,KeyError) as err:
        print("[STOP]",err,file=sys.stderr)
        return 2
    print("[BITMASK] 0x67dd8(4) => (uint32_at_0x3651ec & 4) != 0")
    for row in report["investigationHelpers"]:
        print("[HELPER]",row["entry"],row["kind"],
              "ORIGINAL_VERIFIED" if row["native"] and row["function"] else "PLAN_ONLY")
    print("[REPORT]",out/"avb-unlock-bitmask-producers.md")
    print("[LIMIT] Secure state / image signature policy / unlock remain UNPROVEN")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
