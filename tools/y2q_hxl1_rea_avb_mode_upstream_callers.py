#!/usr/bin/env python3
"""Original HXL1 native caller provenance for unlock-mode dispatcher 0x33928.

The owner verified precisely five original Ghidra xrefs to 0x33928.
Revalidate the upstream source-attested setter-mode dossier and the
exact xref set before obtaining native instruction at each coordinate.
Only native BL branches to 0x33928 qualify for new containing-function
and full-native-owner Ghidra queries. Those artifacts provide bounded
W0/W1 input investigation; no authorization or control-flow
reachability claim can be made from lexical predecessors alone.

Host static only: no firmware modification, handset, unlock, bypass,
or network requests. --execute enables at most 15 bounded Ghidra queries.
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
from tools.y2q_hxl1_rea_avb_setter_modes import audit as verify_setter_modes
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions

TARGET = "0x33928"
ORIGINAL_XREF_SITES = (
    "0x2f604", "0x342e0", "0x343dc", "0x675a0", "0x67640",
)
NATIVE_BRANCH = re.compile(r"^\s*bl\s+0x([0-9a-f]+)\s*$", re.I)
CONTEXT_TERMS = re.compile(
    r"\bFUN_00033928\b|unlock|critical|oem|device|command|"
    r"secure|permission|allow|deny|error|return|if\s*\(|"
    r"FUN_|DAT_|reboot|recovery", re.I,
)
MAX_PSEUDOCODE = 280000
MAX_NATIVE_ROWS = 4000


def verify_original_inventory(prior: dict) -> dict:
    if prior.get("sourceAttested") is not True:
        raise TriageError("Parent 0x33928 original evidence not attested")
    if prior.get("originalNativeArgumentPaths",{}).get("entry") != TARGET:
        raise TriageError("Original parent 0x33928 native mode/byte paths absent")
    raw = prior.get("parentXrefSites")
    if (not isinstance(raw,list) or len(raw) != len(ORIGINAL_XREF_SITES)
            or set(raw) != set(ORIGINAL_XREF_SITES)
            or prior.get("parentXrefCount") != len(ORIGINAL_XREF_SITES)
            or prior.get("parentXrefsTruncated") is not False
            or not isinstance(prior.get("parentXrefEvidenceId"),str)):
        raise TriageError("Original HXL1 0x33928 xref inventory inconsistent")
    return {
        "parent": TARGET,
        "sites": list(ORIGINAL_XREF_SITES),
        "sourceEvidenceId": prior["parentXrefEvidenceId"],
        "sitesCount": len(raw),
        "originalXrefsVerified": True,
    }


def verify_native_reference(ev: dict, site: str) -> dict:
    result = ev.get("normalized_result")
    if not isinstance(result,dict) or result.get("address") != site:
        raise TriageError("Original upstream Ghidra xref coordinate mismatch")
    status = result.get("status")
    if status not in ("decoded","data","not-instruction-boundary",
                      "undecodable","outside-memory"):
        raise TriageError("Unexpected original Ghidra native instruction status")
    raw = result.get("raw_disassembly")
    mnemonic = result.get("mnemonic")
    if status == "decoded" and (not isinstance(raw,str) or not isinstance(mnemonic,str)):
        raise TriageError("Decoded original callsite missing native opcode")
    match = NATIVE_BRANCH.fullmatch(raw) if status=="decoded" else None
    dest = hex(int(match.group(1),16)) if match else None
    if match and mnemonic.lower() != "bl":
        raise TriageError("Ghidra native BL mnemonic inconsistent")
    return {
        "xrefSite": site,
        "evidenceId": ev["evidence_id"],
        "decodedStatus":status,
        "nativeInstruction":raw,
        "owningProcedureHint":result.get("procedure"),
        "directBLToParent":bool(match and dest == TARGET),
        "observedBranchDestination":dest,
        "nativeInputsVerified":False,
        "upstreamAuthorityProven":False,
    }


def analyze_owner_source(ev:dict, site:str)->dict:
    rec=function_record(ev,site)
    pseudo=ev["normalized_result"].get("pseudocode")
    if (not isinstance(pseudo,str) or not pseudo.strip()
            or len(pseudo) > MAX_PSEUDOCODE):
        raise TriageError("Original 0x33928 upstream caller pseudocode invalid")
    lines=pseudo.splitlines()
    if not 3 <= len(lines) <= 5000:
        raise TriageError("Original upstream caller pseudocode line budget exceeded")
    call_lines=[i for i,x in enumerate(lines)
                if re.search(r"\bFUN_00033928\s*\(",x)
                and not re.search(r"^\s*\w+\s+FUN_00033928\s*\(",x)]
    matches=[i for i,x in enumerate(lines) if CONTEXT_TERMS.search(x)]
    chosen=set(range(min(len(lines),20)))
    for i in matches[:70]:
        chosen.update(range(max(0,i-4),min(len(lines),i+6)))
    selected=sorted(chosen)[:250]
    return {
        "xrefSite":site,"containingFunction":rec["entry"],
        "originalEvidenceId":ev["evidence_id"],
        "fullPseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "totalLines":len(lines),"nativePcodeAvailable":rec["pcodeAvailable"],
        "possibleParentCalls":[i+1 for i in call_lines[:30]],
        "selectedPseudocode":[
            {"line":i+1,"code":lines[i][:720]} for i in selected],
        "excerptTruncated":len(chosen)>len(selected) or len(matches)>70,
        "sourceInputTrustVerified":False,
        "nativeArgumentDefinitionsVerified":False,
    }


def native_argument_window(ev: dict, site: str, owner: str) -> dict:
    insns = parse_instructions(ev,owner)
    if not 3 <= len(insns) <= MAX_NATIVE_ROWS:
        raise TriageError("Original 0x33928 calling function native size out of bounds")
    if insns.get(site) != ("bl","0x00033928"):
        raise TriageError("Original upstream native full function does not contain exact BL")
    addresses=sorted(insns,key=lambda a:int(a,16))
    index=addresses.index(site)
    before=addresses[max(0,index-75):index]
    window=addresses[max(0,index-48):min(len(addresses),index+10)]
    # These are lexical sites only. A call may clobber W0/W1 and
    # conditional branches may skip nearby instructions altogether.
    defs={"w0":[],"w1":[]}
    for addr in before:
        mnemonic,operands=insns[addr]
        dest=operands.split(",",1)[0]
        if dest in ("w0","x0"):
            defs["w0"].append({"address":addr,"mnemonic":mnemonic,"operands":operands})
        if dest in ("w1","x1"):
            defs["w1"].append({"address":addr,"mnemonic":mnemonic,"operands":operands})
        if mnemonic in ("bl","blr"):
            defs["w0"].append({
                "address":addr,"mnemonic":mnemonic,"operands":operands,
                "note":"call may redefine W0; requires actual ABI/CFG review",
            })
    return {
        "xrefSite":site,"owner":owner,"evidenceId":ev["evidence_id"],
        "originalInstructionCount":len(insns),
        "nativeBLVerified":True,
        "nativeContext":[{"address":a,"mnemonic":insns[a][0],
                          "operands":insns[a][1]} for a in window],
        "potentialW0Writes":defs["w0"][-24:],
        "potentialW1Writes":defs["w1"][-24:],
        "snippetTruncatedBefore":index>75,
        "noControlFlowPathOrInterproceduralClobberProof":True,
        "nativeModeValueReachingDefinitionsProven":False,
        "authoritativeOemUnlockAuthorizationProven":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_setter_modes(root)
    pinned=verify_original_inventory(prior)
    target={x.name:x for x in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    # Independently verify the cached exact original inventory even
    # if the previous renderer happened to be patched or misreported.
    inventory=evidence(folder/"xrefs-parent-0x33928.json",
                       sha=target.sha256,operation="xrefs",
                       parameter="address",value=TARGET)
    sites=reference_sources(inventory)
    if len(sites)!=len(ORIGINAL_XREF_SITES) or set(sites)!=set(ORIGINAL_XREF_SITES):
        raise TriageError("Original saved Ghidra parent-xref evidence differs")
    if pinned["sourceEvidenceId"]!=inventory["evidence_id"]:
        raise TriageError("Original parent xref evidence ID differs")
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Host REA script missing/unsafe")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    results=[]
    for site in ORIGINAL_XREF_SITES:
        record=runner.obtain(
            target,["inspect-native-instruction",str(target.path),site],
            folder/("instruction-upstream-"+safe_segment(site)+".json"),
            operation="inspect_native_instruction",
            parameter="address",value=site)
        classified=verify_native_reference(record,site) if record else None
        entry={"site":site,"native":classified,"containingFunction":None,
               "ownerNative":None,"directBLToParent":
               bool(classified and classified["directBLToParent"])}
        if entry["directBLToParent"]:
            function=runner.obtain(
                target,["function",str(target.path),site],
                folder/("function-upstream-"+safe_segment(site)+".json"),
                operation="analyze_function",parameter="procedure",value=site)
            if function is not None:
                parent=analyze_owner_source(function,site)
                entry["containingFunction"]=parent
                source=runner.obtain(
                    target,["instructions",str(target.path),parent["containingFunction"]],
                    folder/("instructions-upstream-owner-"+
                            safe_segment(parent["containingFunction"])+".json"),
                    operation="read_function_instructions",
                    parameter="procedure",value=parent["containingFunction"])
                if source is not None:
                    entry["ownerNative"]=native_argument_window(
                        source,site,parent["containingFunction"])
        results.append(entry)
    return {
        "schemaVersion":1,"originalHxl1BlSha256":HXL1_BL_SHA256,
        "mode":"ORIGINAL_STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "sourceAttested":True,"queriesRequested":len(runner.planned),
        "parentFunction":TARGET,"parentEvidenceId":inventory["evidence_id"],
        "originalXrefCount":len(sites),"sites":results,
        "upstreamCommandEntryIdentified":False,
        "allCallersReachableProven":False,
        "modeAndValueTrustedSourcesProven":False,
        "oemUnlockAuthorityProven":False,
        "signatureOrOdinPolicyBypassProven":False,
        "deviceModified":False,
    }


def markdown(report:dict)->str:
    lines=[
        "# HXL1 original state-setter dispatcher 0x33928 — upstream caller attribution",
        "",
        "**Original firmware static SHA-bound Ghidra. No unlock or device action.**",
        "", "- Original BL archive SHA256: "+report["originalHxl1BlSha256"],
        "- Original xrefs Evidence: "+report["parentEvidenceId"],
        "- New Ghidra queries: "+str(report["queriesRequested"]),
        "- Xref count pinned: "+str(report["originalXrefCount"]), "",
    ]
    for item in report["sites"]:
        lines += ["## Source xref "+item["site"],""]
        n=item["native"]
        if n is None:
            lines += ["- Native instruction: pending original source review", ""]
        else:
            lines += [
                "- Original instruction Evidence: "+n["evidenceId"],
                "- Native: "+str(n["nativeInstruction"]),
                "- Ghidra owner hint: "+str(n["owningProcedureHint"]),
                "- Direct BL to 0x33928: "+str(n["directBLToParent"]),
                "- Security authorization established: False","",
            ]
        f=item["containingFunction"]
        if f is not None:
            lines += [
                "### Original containing function "+f["containingFunction"],"",
                "- Evidence: "+f["originalEvidenceId"],
                "- Original pseudo line count: "+str(f["totalLines"]),
                "- Parent invocation line candidates: "+str(f["possibleParentCalls"]),
                "", "~~~c",
            ]
            for row in f["selectedPseudocode"]:
                lines.append(f"{row['line']:5d} | {row['code']}")
            lines += ["~~~",""]
        w=item["ownerNative"]
        if w is not None:
            lines += [
                "### Native W0/W1 input context","",
                "- Original owner native Evidence: "+w["evidenceId"],
                "- Source-attested native BL: True",
                "- Lexical W0 candidates: "+str(w["potentialW0Writes"]),
                "- Lexical W1 candidates: "+str(w["potentialW1Writes"]),
                "- **Neither lexical list proves reaching definitions,",
                "  trusted command authority, or executable path.**","",
                "~~~asm",
            ]
            for row in w["nativeContext"]:
                lines.append(row["address"]+": "+row["mnemonic"]+" "+row["operands"])
            lines += ["~~~",""]
    lines += [
        "## Remaining proof gates","",
        "1. Determine which source-attested call sites are real BL calls",
        "   and map their owning dispatcher/command entry points.",
        "2. Trace both incoming mode and value (W0/W1) with native",
        "   control-flow constraints; identify any authorization checks.",
        "3. Keep ordinary IsUnlocked 0x351055 distinct from critical",
        "   IsUnlockCritical 0x351056 and the userdata-wipe workflow.",
        "4. AVB boot-property output and VB persistence are not",
        "   equivalent to signature or Odin flash authorization.",
        "5. No firmware/handset modification or unlock demonstrated.", "",
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
        ap.error("Timeout outside bounded range")
    try:
        root=a.input_dir.expanduser().resolve()
        report=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                     timeout=a.timeout,recover_partials=a.recover_partials)
        output=root/"rea-security-audit"
        (output/"avb-mode-upstream-callers.json").write_text(
            json.dumps(report,indent=2)+"\n")
        (output/"avb-mode-upstream-callers.md").write_text(markdown(report))
    except (TriageError,OSError,ValueError,KeyError,TypeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for item in report["sites"]:
        n=item["native"]
        print("[XREF]",item["site"],n["nativeInstruction"] if n else "PENDING",
              "direct-BL" if item["directBLToParent"] else "UNRESOLVED",
              "owner",item["containingFunction"]["containingFunction"]
              if item["containingFunction"] else "UNKNOWN")
    print("[REPORT]",output/"avb-mode-upstream-callers.md")
    print("[LIMIT] W0/W1 upstream authority, secure policy and unlock not proven")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
