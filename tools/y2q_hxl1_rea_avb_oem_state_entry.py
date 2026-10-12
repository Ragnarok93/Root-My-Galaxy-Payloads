#!/usr/bin/env python3
"""Original HXL1 OEM_UNLOCK predicate return and direct unlock entry audit.

Reattests SHA-pinned native LinuxLoader 0x608c8 OEM flag getter:
  W0 <- [0x35cb18] on normal return;
  if [0x35cb1c] == 0, call 0x60af8 first.
Then obtains at most 10 original read-only Ghidra observations:
  xrefs at 0x35cb18 and 0x35cb1c;
  source function and instructions at 0x60af8;
  exact native instructions at four existing entry-route xrefs;
  source containing functions for only direct BL calls into 0x34238/0x34370.

This audit does not mutate firmware/device state, identify secure-world
authority, or presume that a direct entry route is reachable by an
unauthorized user. Saved original evidence remains SHA-validated.
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
    Runner, choose_targets, evidence, function_record, reference_sources, safe_segment,
)
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions, exact_instruction
from tools.y2q_hxl1_rea_avb_oem_unlock_routes import audit as verify_oem_routes

OEM = "0x608c8"
OEM_INIT = "0x60af8"
OEM_VALUE = "0x35cb18"
OEM_INIT_FLAG = "0x35cb1c"
ROUTE_SITES = (
    ("0x2f1f0","0x2f538"),
    ("0x1b48","0x34238"),
    ("0x1db0","0x34370"),
    ("0x185a4","0x674d8"),
)
EXPECTED_LOADS = (
    ("0x608d4","adrp","x9,0x35c000"),
    ("0x608e0","ldr","w8,[x9,#0xb1c]"),
    ("0x608e4","cbnz","w8,0x000608ec"),
    ("0x608e8","bl","0x00060af8"),
    ("0x608ec","adrp","x8,0x35c000"),
    ("0x608f4","ldr","w0,[x8,#0xb18]"),
    ("0x608f8","ldr","x8,[sp,#0x8]"),
    ("0x608fc","ldr","x9,[x9,#0x4b8]"),
    ("0x60900","cmp","x9,x8"),
    ("0x60904","b.ne","0x00060914"),
    ("0x60908","ldr","x30,[sp,#0x10]"),
    ("0x6090c","add","sp,sp,#0x20"),
    ("0x60910","ret",""),
    ("0x60914","bl","0x0001e81c"),
)
SITE_BRANCH = re.compile(r"^\s*bl\s+0x([0-9a-f]+)\s*$",re.I)
SOURCE_PAT = re.compile(
    r"FUN_00034238|FUN_00034370|OEM|unlock|lock|allow|"
    r"auth|secure|if\s*\(|return|FUN_|DAT_",re.I,
)
MAX_ORIGINAL_LINES = 4000


def verify_saved_native_return(ev:dict) -> dict:
    ops = parse_instructions(ev, OEM)
    if len(ops) != 20:
        raise TriageError("Original OEM flag function does not have pinned 20 native instructions")
    for address, mnemonic, operands in EXPECTED_LOADS:
        exact_instruction(ops,address,mnemonic,operands)
    tail=["0x608f4","0x608f8","0x608fc","0x60900",
          "0x60904","0x60908","0x6090c","0x60910"]
    observed=sorted((a for a in ops if 0x608f4<=int(a,16)<=0x60910),
                    key=lambda a:int(a,16))
    if observed!=tail:
        raise TriageError("Unknown original native instruction in OEM W0 return epilogue")
    if int("0x35c000",16)+0xb18!=int(OEM_VALUE,16):
        raise TriageError("OEM flag W0 load address calculation inconsistent")
    if int("0x35c000",16)+0xb1c!=int(OEM_INIT_FLAG,16):
        raise TriageError("OEM initialization guard address mismatch")
    return {
        "evidenceId":ev["evidence_id"],
        "normalReturnW0ReadFrom":OEM_VALUE,
        "byteOrWordWidth":"32-bit LDR W0",
        "returnRegisterEstablished":True,
        "initializationGuardReadFrom":OEM_INIT_FLAG,
        "whenGuardZeroCalls":OEM_INIT,
        "normalEpiloguePreservesW0":True,
        "helperReturnNotDirectlyUsed":True,
        "errorGuardNonreturnVerified":False,
        "flagIntegrityOrAuthorizationVerified":False,
    }


def verify_prior_sources(prior:dict)->dict:
    if (prior.get("sourceAttested") is not True
            or len(prior.get("verifiedRoutes",[]))!=4
            or len(prior.get("routeCallerXrefs",[]))!=4
            or prior.get("oemPredicate",{}).get("entry")!=OEM
            or prior.get("oemNative",{}).get("count")!=20):
        raise TriageError("Original HXL1 OEM route and predicate attestation missing")
    known={}
    expected={target:site for site,target in ROUTE_SITES}
    for row in prior["routeCallerXrefs"]:
        owner=row.get("function")
        if (owner in known or owner not in expected
                or row.get("total")!=1
                or row.get("referenceSites")!=[expected.get(owner)]
                or not isinstance(row.get("evidenceId"),str)):
            raise TriageError("Original HXL1 four entry-route xrefs differ")
        known[owner]=row
    if set(known)!=set(expected):
        raise TriageError("Original entry-route inventory incomplete")
    if prior.get("oemXrefSites")!=["0x67630"]:
        raise TriageError("Original 0x608c8 sole known xref changed")
    return known


def classify_native_xref(ev:dict,site:str,target:str)->dict:
    data=ev.get("normalized_result")
    if not isinstance(data,dict) or data.get("address")!=site:
        raise TriageError(f"Native reference at {site} is not original requested site")
    status=data.get("status")
    if status not in ("decoded","not-instruction-boundary","data",
                      "outside-memory","undecodable"):
        raise TriageError("Unknown native xref decoding status")
    raw=data.get("raw_disassembly")
    mnem=data.get("mnemonic")
    if status=="decoded" and (not isinstance(raw,str) or not isinstance(mnem,str)):
        raise TriageError("Original decoded entry xref has no native instruction")
    branch=SITE_BRANCH.fullmatch(raw) if status=="decoded" else None
    dest=hex(int(branch.group(1),16)) if branch else None
    if branch is not None and mnem.lower()!="bl":
        raise TriageError("Ghidra native branch mnemonic inconsistent")
    return {
        "xrefSite":site,"target":target,"evidenceId":ev["evidence_id"],
        "decodedStatus":status,"instruction":raw,
        "ownerHint":data.get("procedure"),
        "directBLToTarget":bool(dest==target and branch),
        "branchDestination":dest,
        "authorizedAndReachableProven":False,
    }


def caller_context(ev:dict,site:str)->dict:
    rec=function_record(ev,site)
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>280000:
        raise TriageError("Missing or oversized original route caller pseudocode")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=MAX_ORIGINAL_LINES:
        raise TriageError("Original Ghidra direct-entry caller exceeds line budget")
    hits=[i for i,line in enumerate(lines) if SOURCE_PAT.search(line)]
    include=set(range(min(len(lines),24)))
    for i in hits[:60]:
        include.update(range(max(0,i-4),min(len(lines),i+6)))
    indices=sorted(include)[:190]
    return {
        "site":site,"owner":rec["entry"],"sourceEvidence":ev["evidence_id"],
        "pseudoSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "totalLines":len(lines),
        "selectedSource":[{"line":i+1,"code":lines[i][:700]} for i in indices],
        "sourceTruncated":len(indices)<len(include) or len(hits)>60,
        "nativeRouteDominanceVerified":False,
        "policyConditionVerified":False,
    }


def init_function(ev:dict)->dict:
    rec=function_record(ev,OEM_INIT)
    if rec["entry"]!=OEM_INIT:
        raise TriageError("Original OEM flag initializer Ghidra owning function changed")
    pseudo=ev["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>280000:
        raise TriageError("OEM flag initializer Ghidra source missing/oversized")
    lines=pseudo.splitlines()
    if len(lines)>MAX_ORIGINAL_LINES:
        raise TriageError("Initializer original source line budget exceeded")
    return {
        "entry":OEM_INIT,"evidenceId":ev["evidence_id"],
        "pseudoSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "lines":len(lines),"excerpt":[{"line":i+1,"code":line[:780]}
                               for i,line in enumerate(lines[:180])],
        "truncated":len(lines)>180,
        "directCallees":sorted(set(re.findall(r"\bFUN_[0-9a-fA-F]{8}\b",pseudo))),
        "globalRefs":sorted(set(re.findall(r"\bDAT_[0-9a-fA-F]{8}\b",pseudo))),
        "trustedOEMSourceProven":False,
    }


def init_native(ev:dict)->dict:
    ins=parse_instructions(ev,OEM_INIT)
    if not 3<=len(ins)<=3200:
        raise TriageError("Original initializer native instructions out of bounds")
    ordered=sorted(ins,key=lambda a:int(a,16))
    return {
        "evidenceId":ev["evidence_id"],
        "nativeCount":len(ordered),
        "instructions":[a+": "+ins[a][0]+" "+ins[a][1] for a in ordered[:155]],
        "truncated":len(ordered)>155,
        "globalWriterVerified":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_oem_routes(root)
    verify_prior_sources(prior)
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    native=evidence(folder/"instructions-oem-flag-0x608c8.json",
                    sha=target.sha256,operation="read_function_instructions",
                    parameter="procedure",value=OEM)
    return_proof=verify_saved_native_return(native)
    if return_proof["evidenceId"]!=prior["oemNative"]["evidenceId"]:
        raise TriageError("OEM native evidence ID differs from authenticated previous audit")
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing/unsafe")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    references=[]
    for site,fn in ROUTE_SITES:
        ev=runner.obtain(
            target,["inspect-native-instruction",str(target.path),site],
            folder/("instruction-route-entry-"+safe_segment(site)+".json"),
            operation="inspect_native_instruction",parameter="address",value=site)
        observed=classify_native_xref(ev,site,fn) if ev else None
        result={"site":site,"target":fn,"native":observed,"caller":None}
        if fn in ("0x34238","0x34370") and observed and observed["directBLToTarget"]:
            fv=runner.obtain(
                target,["function",str(target.path),site],
                folder/("function-route-entry-"+safe_segment(site)+".json"),
                operation="analyze_function",parameter="procedure",value=site)
            if fv is not None:
                result["caller"]=caller_context(fv,site)
        references.append(result)
    refs=[]
    for addr in (OEM_VALUE,OEM_INIT_FLAG):
        rv=runner.obtain(
            target,["xrefs",str(target.path),addr],
            folder/("xrefs-oem-global-"+safe_segment(addr)+".json"),
            operation="xrefs",parameter="address",value=addr)
        hits=reference_sources(rv) if rv else []
        refs.append({
            "global":addr,"evidenceId":rv["evidence_id"] if rv else None,
            "total":len(hits),"sites":hits[:120],
            "displayTruncated":len(hits)>120,"writesProven":False,
        })
    initializer=runner.obtain(
        target,["function",str(target.path),OEM_INIT],
        folder/("function-oem-initializer-"+safe_segment(OEM_INIT)+".json"),
        operation="analyze_function",parameter="procedure",value=OEM_INIT)
    initializer_native=runner.obtain(
        target,["instructions",str(target.path),OEM_INIT],
        folder/("instructions-oem-initializer-"+safe_segment(OEM_INIT)+".json"),
        operation="read_function_instructions",parameter="procedure",value=OEM_INIT)
    return {
        "schemaVersion":1,"originalArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"STATIC_GHIDRA_EXECUTE" if execute else "SAVED_ONLY_PLAN",
        "newQueries":len(runner.planned),"predicateNative":return_proof,
        "routeEntries":references,"oemGlobalXrefs":refs,
        "initializerFunction":init_function(initializer) if initializer else None,
        "initializerNative":init_native(initializer_native) if initializer_native else None,
        "directUnlockWithoutAuthorizationProven":False,
        "oemFlagTrustAndWritePathProven":False,
        "signedBootOrFlashBypassProven":False,
        "deviceModified":False,
    }


def markdown(r:dict)->str:
    proof=r["predicateNative"]
    lines=[
        "# HXL1 original OEM_UNLOCK state source and direct-entry caller audit",
        "",
        "**Offline SHA-attested original Ghidra only. No bootloader unlock.**",
        "","BL archive SHA256: "+r["originalArchiveSha256"],
        "New Ghidra read-only queries: "+str(r["newQueries"]),
        "",
        "## 0x608c8 — original native return-register discrepancy resolved","",
        "- Original native Evidence: "+proof["evidenceId"],
        "- Original Ghidra decompilation declares void, but",
        "  ARM64 0x608f4 LDR W0,[X8,#0xb18] returns a 32-bit value",
        "  from 0x35cb18 on the normal RET at 0x60910.",
        "- 0x608e0 reads an initialization flag at 0x35cb1c;",
        "  if zero, 0x608e8 calls 0x60af8 before the final W0 load.",
        "- Normal epilogue 0x608f8..0x60910 preserves W0.",
        "- The actual writer, trust boundary, cryptographic",
        "  integrity, and privilege model remain unverified.","",
        "## Four native references to entry routes","",
    ]
    for row in r["routeEntries"]:
        n=row["native"]
        lines.extend(["### "+row["site"]+" -> "+row["target"],"",
                      "- Native Evidence: "+str(n["evidenceId"] if n else None),
                      "- Native instruction: "+str(n["instruction"] if n else "PENDING"),
                      "- Direct BL to target: "+str(n["directBLToTarget"] if n else False),
                      "- Owner hint: "+str(n["ownerHint"] if n else None),
                      "- Authorized or reachable on device: UNKNOWN",""])
        c=row["caller"]
        if c is not None:
            lines.extend(["#### Ghidra containing caller function "+c["owner"],"",
                          "- Original function Evidence: "+c["sourceEvidence"],
                          "- Native gate dominance: UNVERIFIED",
                          "","~~~c"])
            for x in c["selectedSource"]:
                lines.append(f"{x['line']:5d} | {x['code']}")
            lines.extend(["~~~",""])
    lines.extend(["## Source xrefs to OEM state globals",""])
    for item in r["oemGlobalXrefs"]:
        lines.extend(["- "+item["global"]+": "+str(item["total"])+" xrefs",
                      "  original Evidence: "+str(item["evidenceId"]),
                      "  source coordinates: "+str(item["sites"]),
                      "  source writes/addresses not yet independently classified.",""])
    f=r["initializerFunction"]
    lines.extend(["## Original 0x60af8 initializer",""])
    if f is not None:
        lines.extend(["- Original function Evidence: "+f["evidenceId"],
                      "- Decompilation lines: "+str(f["lines"]),
                      "- Direct-function lexical references: "+str(f["directCallees"]),
                      "- Global references: "+str(f["globalRefs"]),
                      "","~~~c"])
        for item in f["excerpt"]:
            lines.append(f"{item['line']:5d} | {item['code']}")
        lines.extend(["~~~",""])
    n=r["initializerNative"]
    if n is not None:
        lines.extend(["- Original native Evidence: "+n["evidenceId"],
                      "- Native instruction count: "+str(n["nativeCount"]),
                      "","~~~asm",*n["instructions"],"~~~",""])
    lines.extend(["## Unresolved proof gates","",
                  "1. Map original 0x34238 and 0x34370 entry callers to",
                  "   verified authorization/dispatch decisions, if any.",
                  "2. Classify actual writers of 0x35cb18 and its",
                  "   initialization sentinel 0x35cb1c.",
                  "3. Follow data origins in FUN_00060af8; do not assume",
                  "   it reflects secure-world trusted OEM unlock policy.",
                  "4. Distinguish cached flags, protected state, signed",
                  "   image enforcement, and Odin authorization.",
                  "5. No runtime device action or unlock demonstrated.",""])
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
        (out/"avb-oem-state-entry-audit.json").write_text(json.dumps(result,indent=2)+"\n")
        (out/"avb-oem-state-entry-audit.md").write_text(markdown(result))
    except (TriageError,OSError,ValueError,TypeError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[OEM-RETURN] W0 from",OEM_VALUE,"init-if-zero",OEM_INIT_FLAG)
    for row in result["routeEntries"]:
        n=row["native"]
        print("[ENTRY]",row["site"],"->",row["target"],
              "DIRECT_BL" if n and n["directBLToTarget"] else "UNKNOWN")
    print("[REPORT]",out/"avb-oem-state-entry-audit.md")
    print("[LIMIT] No authority, image-signature bypass or unlock demonstrated")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
