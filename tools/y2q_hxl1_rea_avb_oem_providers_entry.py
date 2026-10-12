#!/usr/bin/env python3
"""Original HXL1 OEM/FRP provider and LinuxLoaderEntry dispatch source audit.

Reattests the original SHA-pinned 0x608c8 W0 return, OEM initializer
0x60af8, exact direct unlock/relock callsites 0x1b48 and 0x1db0 and
identical original 0x17d8 Ghidra decompilations.

Only five additional read-only original Ghidra queries:
  instructions at 0x17d8
  function/instructions for OEM value provider 0x60790
  function/instructions for FRP-related provider 0x60918

This forensic audit does not patch firmware or attempt to modify
secure boot, OEM flags, the phone, or signed-image policy.
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
    Runner,choose_targets,evidence,function_record,safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_writers import (
    parse_instructions,exact_instruction,INSTRUCTION_PATTERN,
)
from tools.y2q_hxl1_rea_avb_oem_state_entry import audit as verify_oem_state

MAIN="0x17d8"
OEM_INIT="0x60af8"
PROVIDERS=(("0x60790","OEM-value"),("0x60918","FRP-related"))
DIRECT_SITES=(("0x1b48","0x34238"),("0x1db0","0x34370"))
MAX_MAIN_NATIVE=10000
INIT_PINS=(
    ("0x60b10","bl","0x00060918"),
    ("0x60b14","adrp","x20,0x35c000"),
    ("0x60b18","str","w0,[x20,#0xb14]"),
    ("0x60b1c","bl","0x00060790"),
    ("0x60b20","ldr","w21,[x20,#0xb14]"),
    ("0x60b24","adrp","x20,0x35c000"),
    ("0x60b28","mov","w19,w0"),
    ("0x60b2c","str","w0,[x20,#0xb18]"),
    ("0x60b34","orr","w8,wzr,#0x10001"),
    ("0x60b38","cmp","w19,w8"),
    ("0x60b3c","b.eq","0x00060b80"),
    ("0x60b40","cmp","w21,w8"),
    ("0x60b44","b.eq","0x00060b80"),
    ("0x60b70","adrp","x8,0x35c000"),
    ("0x60b74","mov","w9,#0x1"),
    ("0x60b78","str","w9,[x8,#0xb1c]"),
    ("0x60ba8","str","wzr,[x20,#0xb18]"),
)
INIT_PSEUDO=(
    r"DAT_0035cb14\s*=\s*FUN_00060918\s*\(\s*\)",
    r"iVar4\s*=\s*FUN_00060790\s*\(\s*\)",
    r"DAT_0035cb18\s*=\s*iVar4",
    r"iVar4\s*==\s*0x10001",
    r"iVar2\s*==\s*0x10001",
    r"DAT_0035cb18\s*=\s*0",
    r"DAT_0035cb1c\s*=\s*1",
)
PROVIDER_LIMIT=4000
MAIN_CODE_PATTERN=re.compile(
    r"FUN_00034238|FUN_00034370|unlock|lock|download|fastboot|"
    r"permission|secure|if\s*\(|FUN_000608c8|OEM",re.I,
)


def validate_prior(prior:dict)->dict:
    if (prior.get("sourceAttested") is not True
        or prior.get("predicateNative",{}).get("normalReturnW0ReadFrom")!="0x35cb18"
        or prior.get("predicateNative",{}).get("initializationGuardReadFrom")!="0x35cb1c"):
        raise TriageError("Original OEM state predicate evidence missing")
    names={x.get("site"):x for x in prior.get("routeEntries",[])}
    if len(names)!=4 or len(prior.get("routeEntries",[]))!=4:
        raise TriageError("Original four LinuxLoader route references missing")
    for site,target in DIRECT_SITES:
        entry=names.get(site) or {}
        facts=entry.get("native") or {}
        caller=entry.get("caller") or {}
        if not (entry.get("target")==target
                and facts.get("directBLToTarget") is True
                and facts.get("instruction")==f"bl 0x{int(target,16):08x}"
                and caller.get("owner")==MAIN
                and isinstance(caller.get("sourceEvidence"),str)):
            raise TriageError(f"Original direct route {site} parent/branch evidence unavailable")
    if not (prior.get("initializerFunction",{}).get("entry")==OEM_INIT
            and prior.get("initializerNative",{}).get("nativeCount")==55):
        raise TriageError("Original OEM flag initializer source/native evidence incomplete")
    return names


def verify_native_initializer(ev:dict,prior:dict)->dict:
    ops=parse_instructions(ev,OEM_INIT)
    if len(ops)!=55:
        raise TriageError("Original OEM init native function instruction count changed")
    for a,m,o in INIT_PINS:
        exact_instruction(ops,a,m,o)
    if ev["evidence_id"]!=prior["initializerNative"]["evidenceId"]:
        raise TriageError("Original OEM init native Ghidra evidence identity changed")
    return {
        "evidenceId":ev["evidence_id"],
        "frpSourceCall":"0x60b10",
        "frpSource":"0x60918",
        "oemSourceCall":"0x60b1c",
        "oemSource":"0x60790",
        "frpStore":"0x60b18","oemStore":"0x60b2c",
        "errorSentinel":"0x10001",
        "oemClearOnError":"0x60ba8",
        "initSuccessfulFlagStore":"0x60b78",
        "originalNativeAssignmentsVerified":True,
        "secureSourceTrustVerified":False,
        "errorPathDominanceVerified":False,
    }


def verify_source_initializer(ev:dict,prior:dict)->dict:
    rec=function_record(ev,OEM_INIT)
    if rec["entry"]!=OEM_INIT:
        raise TriageError("Original OEM initializer function owner changed")
    if ev["evidence_id"]!=prior["initializerFunction"]["evidenceId"]:
        raise TriageError("Original OEM initializer function evidence ID differs")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or len(pseudo)>180000:
        raise TriageError("Original OEM initializer source pseudocode unavailable/oversized")
    for pattern in INIT_PSEUDO:
        if not re.search(pattern,pseudo):
            raise TriageError("Original OEM initialization source statement changed: "+pattern)
    return {
        "entry":OEM_INIT,"evidenceId":ev["evidence_id"],
        "sourceSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "sourceStatementCount":len(INIT_PSEUDO),
        "actualPersistentSecureWorldAuthorizationVerified":False,
    }


def verify_main_pseudocode(evs:dict[str,dict],prior:dict)->dict:
    records={}
    expected={x["site"]:x for x in prior["routeEntries"]}
    for site,_ in DIRECT_SITES:
        ev=evs[site]
        rec=function_record(ev,site)
        if rec["entry"]!=MAIN or ev["evidence_id"]!=expected[site]["caller"]["sourceEvidence"]:
            raise TriageError("Original 0x17d8 owner Ghidra function evidence mismatch")
        pseudo=ev["normalized_result"].get("pseudocode")
        if not isinstance(pseudo,str) or not 50<=len(pseudo.splitlines())<=4500:
            raise TriageError("Original LinuxLoaderEntry pseudocode incomplete/oversized")
        records[site]=pseudo
    shas={hashlib.sha256(s.encode()).hexdigest() for s in records.values()}
    if len(shas)!=1:
        raise TriageError("Original main owner source disagrees between unlock/relock sites")
    lines=next(iter(records.values())).splitlines()
    found={}
    for site,fn in DIRECT_SITES:
        pattern=r"\bFUN_"+fn[2:].zfill(8)+r"\s*\("
        hits=[i for i,line in enumerate(lines) if re.search(pattern,line)]
        if len(hits)!=1:
            raise TriageError("Original main source direct unlock/relock call count differs")
        i=hits[0]
        found[site]={
            "sourceLine":i+1,"target":fn,
            "context":[{"line":j+1,"source":lines[j][:850]}
                       for j in range(max(0,i-30),min(len(lines),i+22))],
            "nativeBranchDominanceVerified":False,
        }
    return {
        "entry":MAIN,"sourceEvidence":[evs[x]["evidence_id"] for x,_ in DIRECT_SITES],
        "pseudocodeSha256":next(iter(shas)),
        "totalLines":len(lines),"directCalls":found,
        "branchAuthorizationVerified":False,
    }


def parse_large_main_instructions(ev:dict)->dict[str,tuple[str,str]]:
    data=ev.get("normalized_result")
    rows=data if isinstance(data,list) else data.get("instructions") if isinstance(data,dict) else None
    if not isinstance(rows,list) or not 10<=len(rows)<=MAX_MAIN_NATIVE:
        raise TriageError("Original 0x17d8 native instruction listing missing/oversized")
    ins={}
    for row in rows:
        if isinstance(row,str):
            m=INSTRUCTION_PATTERN.fullmatch(row)
            if m is None:
                raise TriageError("Original 0x17d8 contains unrecognized native instruction")
            addr,mnemonic,operand=m.groups()
        elif isinstance(row,dict):
            addr,mnemonic,operand=(row.get("address"),row.get("mnemonic"),row.get("operands"))
            if not all(isinstance(v,str) for v in (addr,mnemonic,operand)):
                raise TriageError("Original main native record malformed")
        else:
            raise TriageError("Original main native record type invalid")
        address=hex(int(addr,16))
        if address in ins:
            raise TriageError("Duplicate original 0x17d8 native address")
        ins[address]=(mnemonic.lower(),re.sub(r"\s+","",operand.lower()))
    return ins


def main_native_context(ev:dict)->dict:
    ops=parse_large_main_instructions(ev)
    addresses=sorted(ops,key=lambda a:int(a,16))
    windows={}
    for site,target in DIRECT_SITES:
        exact_instruction(ops,site,"bl",f"0x{int(target,16):08x}")
        i=addresses.index(site)
        span=addresses[max(0,i-55):min(len(addresses),i+20)]
        windows[site]={
            "target":target,
            "instructions":[site_addr+": "+ops[site_addr][0]+" "+ops[site_addr][1]
                            for site_addr in span],
            "nearbyNativeBranchHints":[
                site_addr+": "+ops[site_addr][0]+" "+ops[site_addr][1]
                for site_addr in span if ops[site_addr][0].startswith(("b.","cb","tb","b"))
            ],
            "nativeBLVerified":True,
            "controlFlowDominanceVerified":False,
        }
    return {"evidenceId":ev["evidence_id"],"originalInstructionCount":len(ops),
            "entry":MAIN,"callWindows":windows,
            "wholeProgramEntryPermissionProven":False}


def provider_source(ev:dict,entry:str,kind:str)->dict:
    rec=function_record(ev,entry)
    if rec["entry"]!=entry:
        raise TriageError("Original OEM/FRP provider function owner mismatch")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>270000:
        raise TriageError("Original OEM/FRP helper pseudocode invalid")
    lines=pseudo.splitlines()
    if len(lines)>PROVIDER_LIMIT:
        raise TriageError("Original OEM/FRP helper source lines unbounded")
    return {
        "entry":entry,"kind":kind,"evidenceId":ev["evidence_id"],
        "lineCount":len(lines),
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "pseudocode":[{"line":i+1,"source":line[:850]} for i,line in enumerate(lines[:170])],
        "excerptTruncated":len(lines)>170,
        "functionRefs":sorted(set(re.findall(r"\bFUN_[0-9a-fA-F]{8}\b",pseudo))),
        "globalRefs":sorted(set(re.findall(r"\bDAT_[0-9a-fA-F]{8}\b",pseudo))),
        "returnRegisterVerified":False,
        "trustedSecureStorageVerified":False,
    }


def provider_native(ev:dict,entry:str)->dict:
    ins=parse_instructions(ev,entry)
    if len(ins)>PROVIDER_LIMIT:
        raise TriageError("Original OEM/FRP native function too large")
    items=sorted(ins,key=lambda a:int(a,16))
    return {
        "evidenceId":ev["evidence_id"],"instructionCount":len(ins),
        "nativeInstructions":[x+": "+ins[x][0]+" "+ins[x][1] for x in items[:190]],
        "excerptTruncated":len(items)>190,
        "returnRegisterSourceProven":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_oem_state(root)
    validate_prior(prior)
    target={x.name:x for x in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    init_fn=evidence(folder/"function-oem-initializer-0x60af8.json",
                     sha=target.sha256,operation="analyze_function",
                     parameter="procedure",value=OEM_INIT)
    init_ins=evidence(folder/"instructions-oem-initializer-0x60af8.json",
                      sha=target.sha256,operation="read_function_instructions",
                      parameter="procedure",value=OEM_INIT)
    source_init=verify_source_initializer(init_fn,prior)
    native_init=verify_native_initializer(init_ins,prior)
    saved={}
    for site,_ in DIRECT_SITES:
        saved[site]=evidence(folder/("function-route-entry-"+safe_segment(site)+".json"),
                             sha=target.sha256,operation="analyze_function",
                             parameter="procedure",value=site)
    main_src=verify_main_pseudocode(saved,prior)
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing/unsafe")
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    main_ins=runner.obtain(target,["instructions",str(target.path),MAIN],
                           folder/("instructions-route-owner-"+safe_segment(MAIN)+".json"),
                           operation="read_function_instructions",parameter="procedure",value=MAIN)
    provider_rows=[]
    for entry,kind in PROVIDERS:
        f=runner.obtain(target,["function",str(target.path),entry],
                        folder/("function-oem-provider-"+safe_segment(entry)+".json"),
                        operation="analyze_function",parameter="procedure",value=entry)
        n=runner.obtain(target,["instructions",str(target.path),entry],
                        folder/("instructions-oem-provider-"+safe_segment(entry)+".json"),
                        operation="read_function_instructions",parameter="procedure",value=entry)
        provider_rows.append({
            "entry":entry,"kind":kind,
            "function":provider_source(f,entry,kind) if f else None,
            "native":provider_native(n,entry) if n else None,
        })
    return {
        "schemaVersion":1,"originalArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"ORIGINAL_STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "newQueries":len(runner.planned),
        "initializerSource":source_init,"initializerNative":native_init,
        "mainFunctionSource":main_src,
        "mainNative":main_native_context(main_ins) if main_ins else None,
        "stateProviders":provider_rows,
        "directUnlockEntryAuthorizedProven":False,
        "oemFrpProtectedSourceProven":False,
        "secureBootAcceptanceOrOdinBypassProven":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    lines=[
        "# HXL1 OEM/FRP eligibility providers and LinuxLoader entry dispatch",
        "",
        "**Source-attested stock HXL1 static analysis. No handset operation.**",
        "","Original BL SHA256: "+r["originalArchiveSha256"],
        "New read-only original Ghidra queries: "+str(r["newQueries"]),
        "",
        "## OEM and FRP eligibility initialization (source/native verified)","",
        "Original OEM native Evidence: "+r["initializerNative"]["evidenceId"],
        "- FUN_00060918 -> 0x35cb14 (FRP-related cached value)",
        "- FUN_00060790 -> 0x35cb18 (OEM_UNLOCK cached eligibility)",
        "- Return 0x10001 from either source triggers OEM cached-value clear",
        "- Successful source initialization sets 0x35cb1c = 1",
        "- Security authority and source integrity: UNKNOWN","",
        "## Main LinuxLoader function 0x17d8","",
        "Source Evidence: "+str(r["mainFunctionSource"]["sourceEvidence"]),
        "- Original pseudocode lines: "+str(r["mainFunctionSource"]["totalLines"]),
        "- Shared original source SHA256: "+r["mainFunctionSource"]["pseudocodeSha256"],
        "- Direct unlock/relock site status: both source verified",
        "- Native whole-function path authorization: UNKNOWN","",
    ]
    for site,_ in DIRECT_SITES:
        c=r["mainFunctionSource"]["directCalls"][site]
        lines += ["### "+site+" -> "+c["target"],"",
                  "- Ghidra source call line: "+str(c["sourceLine"]),
                  "","~~~c"]
        for row in c["context"]:
            lines.append(f"{row['line']:5d} | {row['source']}")
        lines += ["~~~",""]
    n=r["mainNative"]
    if n is not None:
        lines += ["## Native LinuxLoader entry branch-context windows","",
                  "- Original native Evidence: "+n["evidenceId"],
                  "- Total original native instructions: "+str(n["originalInstructionCount"]),
                  "- Native call instruction verified; branch dominance NOT proved.",""]
        for site,_ in DIRECT_SITES:
            w=n["callWindows"][site]
            lines += ["### "+site+" -> "+w["target"],"",
                      "- Branch hints: "+str(w["nearbyNativeBranchHints"]),
                      "","~~~asm",*w["instructions"],"~~~",""]
    else:
        lines += ["Native main-function evidence is planned, not yet collected.",""]
    lines += ["## Original OEM/FRP providers",""]
    for row in r["stateProviders"]:
        lines += ["### "+row["entry"]+" — "+row["kind"],""]
        f=row["function"]
        if f is None:
            lines += ["Function pseudocode not yet collected.",""]
        else:
            lines += [
                "- Source Evidence: "+f["evidenceId"],
                "- Original function calls: "+str(f["functionRefs"]),
                "- Original global references: "+str(f["globalRefs"]),
                "","~~~c"]
            for item in f["pseudocode"]:
                lines.append(f"{item['line']:5d} | {item['source']}")
            lines += ["~~~",""]
        native=row["native"]
        if native is not None:
            lines += [
                "- Original native Evidence: "+native["evidenceId"],
                "- Original native instruction count: "+str(native["instructionCount"]),
                "","~~~asm",*native["nativeInstructions"],"~~~",""]
    lines += ["## Outstanding gates","",
              "1. Reconstruct the 0x17d8 entry dispatch decision that selects",
              "   direct flash unlock/relock; check native branch reachability.",
              "2. Identify actual return/data sources for OEM helper 0x60790",
              "   and FRP helper 0x60918, including any protected monitor calls.",
              "3. Validate state trust/authorization separately from the",
              "   IsUnlocked cached value, Download Mode policy, and AVB.",
              "4. No firmware modifications or unlock are demonstrated.",""]
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
    a=p.parse_args()
    if not 30<=a.timeout<=1200:
        p.error("Timeout out of bounded range")
    try:
        root=a.input_dir.expanduser().resolve()
        report=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                     timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-oem-providers-entry.json").write_text(json.dumps(report,indent=2)+"\n")
        (out/"avb-oem-providers-entry.md").write_text(markdown(report))
    except (TriageError,OSError,KeyError,TypeError,ValueError) as exc:
        print("[STOP]",str(exc),file=sys.stderr)
        return 2
    print("[OEM-PROVIDER] 0x60790 -> 0x35cb18")
    print("[FRP-PROVIDER] 0x60918 -> 0x35cb14")
    print("[MAIN] 0x17d8 native", "ATTESTED" if report["mainNative"] else "PENDING")
    print("[REPORT]",out/"avb-oem-providers-entry.md")
    print("[LIMIT] Authorization/security-state origin and unlock remain unproved")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
