#!/usr/bin/env python3
"""Original HXL1 IsUnlocked setter mode/byte provenance from native ARM64.

The user's SHA-pinned original LinuxLoader Ghidra output places both
0x33c88 setter calls in one parent at 0x33928. This auditor verifies
the two distinct native W0 argument paths, the separately persisted
IsUnlockCritical byte (+0xe), and collects ONE new original Ghidra
xref inventory for the parent. It does not claim complete CFG,
secure authorization, a bootloader bypass, or runtime execution.
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
from tools.y2q_hxl1_rea_avb_setter_callers import audit as verify_setter_callers
from tools.y2q_hxl1_rea_avb_byte_writers import (
    parse_instructions, exact_instruction,
)

PARENT = "0x33928"
SETTER = "0x33c88"
CALLS = ("0x33a08", "0x33b20")
NATIVE_EVIDENCE = "instructions-caller-owner-0x33928.json"
NORMAL_BYTE = "0x351055"
CRITICAL_BYTE = "0x351056"
PSEUDO_REQUIRED = (
    r"\bFUN_00033c88\s*\(\s*param_2\s*\)",
    r"\bFUN_00033c88\s*\(\s*bVar1\s*\)",
    r"\bIsUnlockCritical\b",
    r"\bDAT_00351056\b",
    r"\bFUN_0002ae38\s*\(\s*1\s*,\s*&DAT_00351048\s*,\s*0x9a0\s*\)",
    r"recovery\\n--wipe_data",
)
REQUIRED_NATIVE = (
    ("0x33948","mov","w21,w1"),
    ("0x3394c","mov","w20,w0"),
    ("0x33964","cbz","w0,0x00033a04"),
    ("0x33a04","mov","w0,w21"),
    ("0x33a08","bl","0x00033c88"),
    ("0x33a14","bl","0x0002b600"),
    ("0x33a18","cbz","x0,0x00033ad4"),
    ("0x33a1c","tst","w21,#0xff"),
    ("0x33a20","mov","x19,x0"),
    ("0x33a24","cset","w21,eq"),
    ("0x33a28","cbz","w20,0x00033b1c"),
    ("0x33b1c","mov","w0,w21"),
    ("0x33b20","bl","0x00033c88"),
    ("0x339c8","strb","w21,[x1,#0xe]"),
    ("0x33a84","strb","w21,[x1,#0xe]"),
)
MAX_ROWS = 350


def verified_parent_function(ev: dict, site: str) -> dict:
    owner = function_record(ev, site)
    if owner["entry"] != PARENT:
        raise TriageError("Original HXL1 setter caller is not function 0x33928")
    pseudo = ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo, str) or not pseudo.strip() or len(pseudo)>90000:
        raise TriageError("Original HXL1 setter parent pseudocode missing or oversized")
    lines = pseudo.splitlines()
    if not 35 <= len(lines) <= 300:
        raise TriageError("Unexpected original 0x33928 decompilation length")
    observations = []
    for pat in PSEUDO_REQUIRED:
        matches = list(re.finditer(pat, pseudo))
        if not matches:
            raise TriageError("Original 0x33928 setter, critical byte or wipe string changed: "+pat)
        observations.append({
            "pattern": pat,
            "lineNumbers": [pseudo[:m.start()].count("\n")+1 for m in matches[:12]],
        })
    if not re.search(r"\bFUN_00033928\s*\(\s*int\s+param_1\s*,\s*uint\s+param_2\s*\)",pseudo):
        raise TriageError("Original parent argument interpretation changed")
    return {
        "entry": PARENT, "site": site, "evidenceId": ev["evidence_id"],
        "pseudocodeSha256": hashlib.sha256(pseudo.encode()).hexdigest(),
        "pseudocodeLines": len(lines),
        "observations": observations,
        "completeNativeCFGVerified": False, "authorizationVerified": False,
    }


def verify_two_setter_paths(ev: dict) -> dict:
    ops = parse_instructions(ev, PARENT)
    if not 50 <= len(ops) <= MAX_ROWS:
        raise TriageError("Original setter-parent native instruction budget changed")
    for a,m,o in REQUIRED_NATIVE:
        exact_instruction(ops,a,m,o)
    # First call is preceded immediately by W0<-W21, on a branch
    # from 0x33964 conditioned on entry W0. The second call is
    # preceded immediately by W0<-W21 after a CSET modifying W21.
    for pair in (("0x33a04","0x33a08"),("0x33b1c","0x33b20"),
                 ("0x33a1c","0x33a20"),("0x33a20","0x33a24"),
                 ("0x33a24","0x33a28")):
        start,end=map(lambda x:int(x,16),pair)
        if [int(a,16) for a in ops if start<int(a,16)<end]:
            raise TriageError("Unverified native instructions inserted into byte-argument local chain")
    return {
        "entry": PARENT, "originalEvidenceId": ev["evidence_id"],
        "nativeInstructionCount": len(ops),
        "firstCallSite": CALLS[0],
        "firstArgumentPreparation": "0x33a04 mov w0,w21",
        "entryArgumentSavedToW21At": "0x33948",
        "modeSavedToW20At": "0x3394c",
        "modeZeroBranchAt": "0x33964",
        "firstPath": "mode-zero dispatch passes saved W21 into W0 at 0x33a04",
        "secondCallSite": CALLS[1],
        "secondArgumentPreparation": "0x33b1c mov w0,w21",
        "derivedByteSequence": [
            "0x33a1c tst w21,#0xff", "0x33a24 cset w21,eq",
            "0x33a28 cbz w20,0x00033b1c",
        ],
        "secondPath": "conditional CSET converts current W21 low byte equality-to-zero into a boolean",
        "secondPathGate": "0x33a14 call 0x2b600; 0x33a18 branch on zero; 0x33a28 checks saved mode",
        "criticalByteStores": ["0x339c8","0x33a84"],
        "criticalByte": CRITICAL_BYTE,
        "normalByte": NORMAL_BYTE,
        "callerSuppliedW1InputObserved": True,
        "localRegisterTransfersVerified": True,
        "allPathValueProvenanceVerified": False,
        "interproceduralX21PreservationVerified": False,
        "upstreamCommandAuthorizationVerified": False,
    }


def audit(root: Path, *, execute:bool=False, rea:Path|None=None,
          node:str="node", timeout:int=240, recover_partials:bool=False)->dict:
    prior=verify_setter_callers(root)
    if prior.get("sourceAttested") is not True:
        raise TriageError("Original HXL1 callsite evidence not authenticated")
    entries=[r for r in prior.get("directNativeSites",[]) if r.get("site") in CALLS]
    if len(entries)!=2 or {r["site"] for r in entries}!=set(CALLS):
        raise TriageError("Original two setter callsites unavailable")
    for row in entries:
        facts=row.get("native") or {}
        caller=row.get("callerFunction") or {}
        native=row.get("callerNative") or {}
        if not (facts.get("directBranchToTarget") is True
                and facts.get("directBranchMnemonic")=="bl"
                and caller.get("entry")==PARENT
                and native.get("owner")==PARENT
                and native.get("exactSetterBranchVerified") is True):
            raise TriageError("Native direct setter branch or parent ownership missing")
    target={x.name:x for x in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    functions=[]
    for site in CALLS:
        ev=evidence(folder/("function-caller-"+safe_segment(site)+".json"),
                    sha=target.sha256,operation="analyze_function",
                    parameter="procedure",value=site)
        functions.append(verified_parent_function(ev,site))
    if functions[0]["pseudocodeSha256"]!=functions[1]["pseudocodeSha256"]:
        raise TriageError("Two source-attested callers disagree about their original parent pseudocode")
    ev=evidence(folder/NATIVE_EVIDENCE,
                sha=target.sha256, operation="read_function_instructions",
                parameter="procedure",value=PARENT)
    native=verify_two_setter_paths(ev)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA script missing/symlinked on owner host")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    xrefs=runner.obtain(
        target,["xrefs",str(target.path),PARENT],
        folder/("xrefs-parent-"+safe_segment(PARENT)+".json"),
        operation="xrefs",parameter="address",value=PARENT)
    sources=reference_sources(xrefs) if xrefs is not None else []
    return {
        "schemaVersion":1,"originalArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "newQueries":len(runner.planned),
        "originalPseudocode":functions,
        "originalNativeArgumentPaths":native,
        "parentXrefEvidenceId":xrefs["evidence_id"] if xrefs else None,
        "parentXrefSites":sources[:200],
        "parentXrefCount":len(sources),
        "parentXrefsTruncated":len(sources)>200,
        "callerOwnersAndSourceArgumentsVerified":False,
        "wipeTriggerConditionsFullyProven":False,
        "criticalUnlockAuthorizationProven":False,
        "bootloaderUnlockDemonstrated":False,"deviceModified":False,
    }


def markdown(r:dict)->str:
    n=r["originalNativeArgumentPaths"]
    lines=[
        "# HXL1 IsUnlocked setter mode and parent-caller provenance",
        "","**Original pinned LinuxLoader Ghidra source. No bootloader unlock.**",
        "","Archive SHA256: "+r["originalArchiveSha256"],
        "New original host Ghidra queries: "+str(r["newQueries"]),
        "Owner function: "+PARENT+" (both setter callsites)",
        "Original native owner Evidence: "+n["originalEvidenceId"],"",
        "## Native setter argument paths","",
        "- On the 0x33964 mode-zero branch: original W1 is saved",
        "  in W21 at 0x33948, then copied into W0 at 0x33a04",
        "  immediately before BL 0x33c88 at 0x33a08.",
        "- The second setter call at 0x33b20 is immediately",
        "  preceded by 0x33b1c MOV W0,W21. The 0x33a1c TST",
        "  and 0x33a24 CSET W21,EQ compute a conditional boolean",
        "  from the current low byte of W21 before 0x33a28",
        "  CBZ W20 dispatches to 0x33b1c.",
        "- Ghidra source describes inputs as mode param_1 and value param_2.",
        "- Critical unlock state is a **different byte** at 0x351056;",
        "  original native stores occur at 0x339c8 and 0x33a84.",
        "- Interprocedural W21 preservation, whole-function reachability,",
        "  wipe authorization and secure-boot policy are NOT proven.","",
        "## Original parent Ghidra observations","",
    ]
    for x in r["originalPseudocode"]:
        lines.extend([
            "- At setter site "+x["site"]+": Evidence "+x["evidenceId"],
            "  original pseudocode "+str(x["pseudocodeLines"])+" lines",
            "  SHA256 "+x["pseudocodeSha256"],
        ])
    lines += [
        "","## Upstream references to 0x33928","",
        "- Ghidra xref Evidence: "+str(r["parentXrefEvidenceId"]),
        "- Source coordinate count: "+str(r["parentXrefCount"]),
        "- Unclassified sites: "+str(r["parentXrefSites"]),
        "- These are xrefs, not verified calling instructions or",
        "  authorized commands; inspect exact native instructions next.","",
        "## Remaining validation gates","",
        "1. Confirm native BL sites and containing functions for",
        "   upstream calls into 0x33928 (mode/value input).",
        "2. Determine the purpose and authorization of the value source,",
        "   mode selector, and userdata-wipe/critical-unlock branches.",
        "3. Resolve the VB protocol storage method protection separately",
        "   from Odin/AVB image-signature enforcement.",
        "4. Static evidence never demonstrates successful unlocking.","",
    ]
    return "\n".join(lines)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir",type=Path,default=Path.home()/
                    "s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    ap.add_argument("--node",default="node")
    ap.add_argument("--execute",action="store_true")
    ap.add_argument("--recover-partials",action="store_true")
    ap.add_argument("--timeout",type=int,default=240)
    a=ap.parse_args()
    if not 30<=a.timeout<=1200:
        ap.error("timeout out of bounds")
    try:
        root=a.input_dir.expanduser().resolve()
        r=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-setter-mode-provenance.json").write_text(json.dumps(r,indent=2)+"\n")
        (out/"avb-setter-mode-provenance.md").write_text(markdown(r))
    except (TriageError,OSError,KeyError,ValueError,TypeError) as err:
        print("[STOP]",err,file=sys.stderr)
        return 2
    print("[PARENT]",PARENT,"setter calls",",".join(CALLS))
    print("[ARGUMENTS] W21 saves W1; second path CSET derives boolean")
    print("[PARENT-XREF]",r["parentXrefCount"],"sites")
    print("[REPORT]",out/"avb-setter-mode-provenance.md")
    print("[LIMIT] Upstream authorization, VB backend and bootloader unlock unproved")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
