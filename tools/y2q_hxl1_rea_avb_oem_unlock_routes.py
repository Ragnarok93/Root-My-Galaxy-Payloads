#!/usr/bin/env python3
"""Original HXL1 OEM_UNLOCK predicate and direct flash unlock caller audit.

Purely original stock SHA-pinned LinuxLoader Ghidra static evidence.
The 0x34238 direct (0,1) path MUST NOT be presumed reachable from
untrusted inputs; nor is a persisted status byte a trusted boot unlock.

New read-only REA queries: xrefs of four owner functions, function,
instructions and xrefs of the 0x608c8 OEM flag predicate. Max seven.
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
    Runner,choose_targets,evidence,function_record,reference_sources,safe_segment
)
from tools.y2q_hxl1_rea_avb_mode_upstream_callers import audit as verify_upstream
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions,exact_instruction

OWNER_BY_SITE={
    "0x2f604":"0x2f538","0x342e0":"0x34238","0x343dc":"0x34370",
    "0x675a0":"0x674d8","0x67640":"0x674d8",
}
OWNERS=("0x2f538","0x34238","0x34370","0x674d8")
PREDICATE="0x608c8"
NATIVE_PINS={
    "0x2f538":(
        ("0x2f5f0","adrp","x8,0xc0000"),
        ("0x2f5f4","add","x8,x8,#0x8a0"),
        ("0x2f5f8","add","x8,x8,x21,lsl#0x4"),
        ("0x2f5fc","ldr","w0,[x8]"),
        ("0x2f600","ldrb","w1,[x8,#0x8]"),
        ("0x2f604","bl","0x00033928"),
    ),
    "0x34238":(
        ("0x34294","ldrb","w8,[x8,#0xd]"),
        ("0x34298","cbz","w8,0x000342d8"),
        ("0x342d8","mov","w1,#0x1"),
        ("0x342dc","mov","w0,wzr"),
        ("0x342e0","bl","0x00033928"),
    ),
    "0x34370":(
        ("0x343cc","ldrb","w8,[x8,#0xd]"),
        ("0x343d0","cbz","w8,0x00034418"),
        ("0x343d4","mov","w0,wzr"),
        ("0x343d8","mov","w1,wzr"),
        ("0x343dc","bl","0x00033928"),
    ),
    "0x674d8":(
        ("0x67528","bl","0x00033770"),
        ("0x67598","mov","w0,wzr"),
        ("0x6759c","mov","w1,wzr"),
        ("0x675a0","bl","0x00033928"),
        ("0x67630","bl","0x000608c8"),
        ("0x67634","cbz","w0,0x000676f4"),
        ("0x67638","mov","w1,#0x1"),
        ("0x6763c","mov","w0,wzr"),
        ("0x67640","bl","0x00033928"),
    )
}
MARKERS={
    "0x2f538":(r"FUN_00033928",r"DAT_000c08a0",r"FUN_0002ae38"),
    "0x34238":(r"FUN_00033928\s*\(\s*0\s*,\s*1\s*\)",r"flash unlock Success"),
    "0x34370":(r"FUN_00033928\s*\(\s*0\s*,\s*0\s*\)",r"flash lock"),
    "0x674d8":(r"FUN_000608c8\s*\(\s*\)",r"OEM_UNLOCK flag is NOT set",
              r"FUN_00033928\s*\(\s*0\s*,\s*1\s*\)",
              r"FUN_00033928\s*\(\s*0\s*,\s*0\s*\)"),
}


def attested_owner_inventory(prior:dict)->dict:
    items=prior.get("sites")
    if prior.get("sourceAttested") is not True or not isinstance(items,list) or len(items)!=5:
        raise TriageError("Original five site owner evidence missing")
    found={}
    for row in items:
        site=row.get("site")
        if site not in OWNER_BY_SITE or site in found or row.get("directBLToParent") is not True:
            raise TriageError("Unexpected original mode-dispatcher caller")
        source=row.get("containingFunction") or {}
        native=row.get("ownerNative") or {}
        ref=row.get("native") or {}
        owner=OWNER_BY_SITE[site]
        if not (source.get("containingFunction")==owner
                and native.get("owner")==owner and native.get("nativeBLVerified") is True
                and ref.get("nativeInstruction")=="bl 0x00033928"):
            raise TriageError("Original 0x33928 native caller/owner not verified")
        found[site]={"functionEvidence":source.get("originalEvidenceId"),
                     "nativeEvidence":native.get("evidenceId")}
    if set(found)!=set(OWNER_BY_SITE):
        raise TriageError("Original five caller site set changed")
    return found


def verify_cached_routes(prior:dict,folder:Path,sha:str)->list[dict]:
    verified=attested_owner_inventory(prior)
    results=[]
    for owner in OWNERS:
        related=[site for site,o in OWNER_BY_SITE.items() if o==owner]
        funcs=[]
        for site in related:
            ev=evidence(folder/("function-upstream-"+safe_segment(site)+".json"),
                        sha=sha,operation="analyze_function",parameter="procedure",value=site)
            rec=function_record(ev,site)
            if rec["entry"]!=owner or ev["evidence_id"]!=verified[site]["functionEvidence"]:
                raise TriageError("Original HXL1 caller source function Evidence mismatch")
            pseudo=ev["normalized_result"].get("pseudocode")
            if not isinstance(pseudo,str) or not 10<=len(pseudo.splitlines())<=5000:
                raise TriageError("Original HXL1 route source decompilation invalid")
            for marker in MARKERS[owner]:
                if not re.search(marker,pseudo,re.I):
                    raise TriageError(f"Original {owner} function marker absent: {marker}")
            funcs.append({"site":site,"evidenceId":ev["evidence_id"],
                          "sha256":hashlib.sha256(pseudo.encode()).hexdigest()})
        if len({x["sha256"] for x in funcs})!=1:
            raise TriageError("Original shared owner pseudocode changed between callers")
        ev=evidence(folder/("instructions-upstream-owner-"+safe_segment(owner)+".json"),
                    sha=sha,operation="read_function_instructions",
                    parameter="procedure",value=owner)
        if any(verified[site]["nativeEvidence"]!=ev["evidence_id"] for site in related):
            raise TriageError("Original owner native instruction Evidence mismatch")
        ins=parse_instructions(ev,owner)
        for addr,mnem,operands in NATIVE_PINS[owner]:
            exact_instruction(ins,addr,mnem,operands)
        # Local contiguous source-of-argument native sequence, not global CFG.
        seq=(NATIVE_PINS[owner][-3:] if owner in ("0x34238","0x34370")
             else NATIVE_PINS[owner] if owner=="0x2f538"
             else NATIVE_PINS[owner][-5:])
        keys=[addr for addr,_,_ in seq]
        within=sorted((addr for addr in ins if int(keys[0],16)<=int(addr,16)<=int(keys[-1],16)),
                      key=lambda a:int(a,16))
        if within!=keys:
            raise TriageError("Unknown instruction inserted into original argument preparation")
        results.append({"owner":owner,"sites":related,"sourceFunctions":funcs,
                        "originalNativeEvidence":ev["evidence_id"],
                        "nativePins":[addr+": "+ins[addr][0]+" "+ins[addr][1]
                                      for addr,_,_ in NATIVE_PINS[owner]],
                        "callerAuthorizationEstablished":False,
                        "allPathDominanceEstablished":False})
    return results


def original_oem_predicate(ev:dict)->dict:
    rec=function_record(ev,PREDICATE)
    if rec["entry"]!=PREDICATE:
        raise TriageError("Original OEM_UNLOCK predicate function owner mismatch")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>190000:
        raise TriageError("Original OEM predicate pseudocode invalid")
    lines=pseudo.splitlines()
    if len(lines)>2400:
        raise TriageError("Original OEM predicate Ghidra line budget exceeded")
    return {"entry":PREDICATE,"evidenceId":ev["evidence_id"],
            "pseudoSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
            "lineCount":len(lines),
            "pseudo":[{"line":i+1,"code":line[:780]} for i,line in enumerate(lines[:160])],
            "truncated":len(lines)>160,
            "functionRefs":sorted(set(re.findall(r"\bFUN_[0-9a-fA-F]{8}\b",pseudo))),
            "globalRefs":sorted(set(re.findall(r"\bDAT_[0-9a-fA-F]{8}\b",pseudo))),
            "secureAuthorityProven":False}


def original_oem_native(ev:dict)->dict:
    ins=parse_instructions(ev,PREDICATE)
    if not 3<=len(ins)<=3000:
        raise TriageError("Original OEM helper native list missing/excessive")
    ordered=sorted(ins,key=lambda a:int(a,16))
    return {"evidenceId":ev["evidence_id"],"count":len(ordered),
            "native":[a+": "+ins[a][0]+" "+ins[a][1] for a in ordered[:130]],
            "truncated":len(ordered)>130,"trustedPredicateSemanticsProven":False}


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,node:str="node",
          timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_upstream(root)
    if prior.get("sourceAttested") is not True or prior.get("originalXrefCount")!=5:
        raise TriageError("Original upstream source not authenticated")
    target={x.name:x for x in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    owners=verify_cached_routes(prior,folder,target.sha256)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA entrypoint unavailable/symlinked")
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    callers=[]
    for owner in OWNERS:
        ev=runner.obtain(target,["xrefs",str(target.path),owner],
                         folder/("xrefs-route-"+safe_segment(owner)+".json"),
                         operation="xrefs",parameter="address",value=owner)
        refs=reference_sources(ev) if ev else []
        callers.append({"function":owner,"evidenceId":ev["evidence_id"] if ev else None,
                        "total":len(refs),"referenceSites":refs[:160],
                        "truncated":len(refs)>160,"callersVerified":False})
    helper=runner.obtain(target,["function",str(target.path),PREDICATE],
                         folder/("function-oem-flag-"+safe_segment(PREDICATE)+".json"),
                         operation="analyze_function",parameter="procedure",value=PREDICATE)
    native=runner.obtain(target,["instructions",str(target.path),PREDICATE],
                         folder/("instructions-oem-flag-"+safe_segment(PREDICATE)+".json"),
                         operation="read_function_instructions",parameter="procedure",value=PREDICATE)
    refs=runner.obtain(target,["xrefs",str(target.path),PREDICATE],
                       folder/("xrefs-oem-flag-"+safe_segment(PREDICATE)+".json"),
                       operation="xrefs",parameter="address",value=PREDICATE)
    return {"schemaVersion":1,"archiveSha256":HXL1_BL_SHA256,
            "sourceAttested":True,
            "mode":"STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
            "newQueries":len(runner.planned),"verifiedRoutes":owners,
            "routeCallerXrefs":callers,
            "oemPredicate":original_oem_predicate(helper) if helper else None,
            "oemNative":original_oem_native(native) if native else None,
            "oemXrefsEvidence":refs["evidence_id"] if refs else None,
            "oemXrefSites":reference_sources(refs)[:160] if refs else [],
            "unrestrictedDirectUnlockReachableProven":False,
            "protectedOemAuthorizationProven":False,
            "secureBootOrFlashPolicyBypassProven":False,
            "deviceModified":False}


def markdown(report:dict)->str:
    lines=[
        "# HXL1 original flash unlock entrypoints and OEM_UNLOCK predicate",
        "",
        "**Original SHA-pinned stock LinuxLoader static only. No device unlock.**",
        "","BL archive SHA256: "+report["archiveSha256"],
        "New read-only Ghidra queries: "+str(report["newQueries"]),
        "","## Native source-proven four dispatcher routes","",
    ]
    for item in report["verifiedRoutes"]:
        lines.extend(["### "+item["owner"],"",
                      "- Original native Evidence: "+item["originalNativeEvidence"],
                      "- Decompilation Evidence: "+
                        ", ".join(f["evidenceId"] for f in item["sourceFunctions"]),
                      "","~~~asm",*item["nativePins"],"~~~",
                      "","Authorization of caller and all-path reachability: UNKNOWN",""])
    lines += ["## Source references to those entrypoints",""]
    for item in report["routeCallerXrefs"]:
        lines.extend(["### "+item["function"],"",
                      "- Xref Evidence: "+str(item["evidenceId"]),
                      "- Original xref count: "+str(item["total"]),
                      "- Coordinates: "+str(item["referenceSites"]),
                      "- References are not yet classified as real BL callers.",""])
    lines += [
        "## 0x608c8 — OEM_UNLOCK eligibility predicate candidate","",
        "In 0x674d8, original native 0x67630 BL 0x608c8",
        "followed by CBZ W0,0x676f4; successful branch continuation",
        "sets W1=1,W0=0 before BL 0x33928.",
        "The separate 0x34238 direct (0,1) call has no",
        "0x608c8 invocation inside its own function.",
        "**This does not prove the direct route can bypass permission.**","",
    ]
    f=report["oemPredicate"]
    if f is not None:
        lines.extend(["- Original predicate Evidence: "+f["evidenceId"],
                      "- Function references: "+str(f["functionRefs"]),
                      "- Global references: "+str(f["globalRefs"]),
                      "","~~~c"])
        for x in f["pseudo"]:
            lines.append(f"{x['line']:5d} | {x['code']}")
        lines.extend(["~~~",""])
    n=report["oemNative"]
    if n is not None:
        lines.extend(["- Native Evidence: "+n["evidenceId"],
                      "- Native instruction rows: "+str(n["count"]),
                      "","~~~asm",*n["native"],"~~~",""])
    lines.extend(["- Predicate other xref sites: "+str(report["oemXrefSites"]),
                  "- Predicate xref Evidence: "+str(report["oemXrefsEvidence"]),
                  "","## Outstanding proof gates","",
                  "1. Determine who calls direct 0x34238 and 0x34370;",
                  "   verify caller-native policy checks before assuming a bypass.",
                  "2. Trace 0x608c8's actual state provenance and return logic.",
                  "3. Identify table entries and index bounds for 0x2f538.",
                  "4. Distinguish status byte reporting from signed-image",
                  "   acceptance and Odin flashing authorization.",
                  "5. No firmware/handset operation or unlock was attempted.",""])
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
        p.error("Timeout outside bounded range")
    try:
        root=x.input_dir.expanduser().resolve()
        result=audit(root,execute=x.execute,rea=x.rea,node=x.node,
                     timeout=x.timeout,recover_partials=x.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-oem-unlock-routes.json").write_text(json.dumps(result,indent=2)+"\n")
        (out/"avb-oem-unlock-routes.md").write_text(markdown(result))
    except (TriageError,OSError,ValueError,TypeError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for x in result["routeCallerXrefs"]:
        print("[ROUTE]",x["function"],"refs",x["total"])
    print("[OEM] 0x608c8", "FUNCTION_VERIFIED" if result["oemPredicate"] else "PLAN_ONLY")
    print("[REPORT]",out/"avb-oem-unlock-routes.md")
    print("[LIMIT] Caller authorization / OEM trust / actual unlock not proven")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
