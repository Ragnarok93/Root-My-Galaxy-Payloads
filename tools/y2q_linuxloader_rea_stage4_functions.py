#!/usr/bin/env python3
"""Report Ghidra functions owning three verified HXL1 LinuxLoader xrefs."""
import argparse
import json
from pathlib import Path
import re
import sys

from tools.y2q_linuxloader_rea_stage4_xrefs import (
    LOADER_SHA256, REFS, AuditError, digest, parse_xrefs, validate_seed,
)

PAT = re.compile(r"^0x[0-9a-f]+$")
MAX_SIZE = 50000000


def validated(folder, label, src):
    f = folder / ("rea-stage4-function-" + label + ".json")
    if not f.is_file() or f.is_symlink() or f.stat().st_size > MAX_SIZE:
        raise AuditError("Missing/unsafe function Evidence: " + label)
    ev = json.loads(f.read_text())
    if (not isinstance(ev, dict) or "error" in ev or
            ev.get("operation") != "analyze_function" or
            ev.get("provider", {}).get("id") != "ghidra"):
        raise AuditError("Invalid REA function operation/provider")
    subject = ev.get("subject", {})
    if (subject.get("digest", {}).get("sha256") != LOADER_SHA256 or
            subject.get("architecture") != "arm64" or
            ev.get("parameters", {}).get("procedure") != src):
        raise AuditError("Wrong original PE identity or function query")
    fn = ev.get("normalized_result", {})
    if not isinstance(fn,dict) or not isinstance(fn.get("procedure"),dict):
        raise AuditError("No Ghidra function dossier")
    identity = fn["procedure"]
    entry = identity.get("address")
    body = identity.get("body", {})
    if (not isinstance(entry,str) or not PAT.fullmatch(entry) or
            not isinstance(src,str) or not PAT.fullmatch(src) or
            body.get("available") is not True or
            body.get("provenance") != "ghidra-function-body-address-set" or
            not isinstance(body.get("ranges"),list)):
        raise AuditError("Incomplete Ghidra function identity/body")
    def in_body(addr):
        n=int(addr,16)
        return any(isinstance(x,dict) and isinstance(x.get("start"),str)
                   and isinstance(x.get("end"),str) and PAT.fullmatch(x["start"])
                   and PAT.fullmatch(x["end"]) and
                   int(x["start"],16)<=n<=int(x["end"],16)
                   for x in body["ranges"])
    if not in_body(src) or not in_body(entry):
        raise AuditError("Function body does not contain authenticated xref and entry")
    if not isinstance(fn.get("pseudocode"),str):
        raise AuditError("Ghidra pseudocode field missing")
    if not isinstance(ev.get("evidence_id"),str):
        raise AuditError("Ghidra Evidence identifier missing")
    flow=fn.get("native_value_flow")
    if not isinstance(flow,dict) or not isinstance(flow.get("available"),bool):
        raise AuditError("Missing Ghidra pcode availability")
    return {"label":label,"xref":src,"entry":entry,"name":identity.get("name"),
            "body":body["ranges"],"evidenceId":ev["evidence_id"],
            "pcodeAvailable":flow["available"],"pcodeTruncated":flow.get("truncated"),
            "pseudocode":fn["pseudocode"],"evidenceFile":str(f)}


def analyze(folder):
    image=folder/"LinuxLoader-HXL1.efi"
    if image.is_symlink() or not image.is_file() or digest(image)!=LOADER_SHA256:
        raise AuditError("Original HXL1 LinuxLoader hash mismatch")
    results=[]
    for seed in REFS:
        label,_,string_addr,_=seed
        validate_seed(folder,seed)
        xrefs=parse_xrefs(folder/("rea-stage4-xrefs-"+label+".json"),string_addr)
        if len(xrefs["sourceAddresses"])!=1:
            raise AuditError("Original xref source not unique for "+label)
        src=xrefs["sourceAddresses"][0]
        try:
            entry=validated(folder,label,src)
            entry["status"]="VERIFIED_FUNCTION"
            entry["xrefEvidenceId"]=xrefs["sourceEvidenceId"]
        except (ValueError,OSError) as exc:
            entry={"label":label,"xref":src,"status":"FUNCTION_UNVERIFIED","reason":str(exc)}
        results.append(entry)
    groups={}
    for entry in results:
        if entry["status"]=="VERIFIED_FUNCTION":
            groups.setdefault(entry["entry"],[]).append(entry["label"])
    return {"loaderSha256":LOADER_SHA256,"functions":results,
            "sharedFunctions":[{"entry":k,"labels":v} for k,v in groups.items() if len(v)>1],
            "physicalKernelHandoffVerified":False,"runtimeDtbSelectionVerified":False}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--out",type=Path,default=Path.home()/
                   "s20-artifacts/hxl1-research/abl-linuxloader")
    p.add_argument("--verify-single",choices=[x[0] for x in REFS])
    a=p.parse_args()
    try:
        if a.verify_single:
            seed=next(x for x in REFS if x[0]==a.verify_single)
            refs=parse_xrefs(a.out/("rea-stage4-xrefs-"+seed[0]+".json"),seed[2])
            if len(refs["sourceAddresses"])!=1: raise AuditError("Nonunique xref")
            f=validated(a.out,seed[0],refs["sourceAddresses"][0])
            print("[VERIFIED FUNCTION]",f["entry"],f["name"])
            return 0
        result=analyze(a.out)
        (a.out/"rea-stage4-functions-audit.json").write_text(json.dumps(result,indent=2)+"\n")
        lines=["# Original HXL1 LinuxLoader — Ghidra function dossiers","",
               "Static Ghidra address evidence only. No physical kernel load proven.",""]
        for item in result["functions"]:
            print("["+item["status"]+"]",item["label"],item["xref"],item.get("entry","unknown"))
            lines += ["## "+item["label"],"","Status: "+item["status"],""]
            if item["status"]!="VERIFIED_FUNCTION":
                lines += ["Gap: "+item["reason"],""]
                continue
            lines += ["Function: "+str(item["name"])+" at "+item["entry"],"",
                      "Owning ranges: "+json.dumps(item["body"]),"",
                      "HighFunction p-code available: "+str(item["pcodeAvailable"]),"",
                      "Evidence ID: "+item["evidenceId"],"",
                      "Pseudocode (complete original retained in JSON):","","~~~c",
                      item["pseudocode"][:18000],"~~~",""]
        lines+=["Shared functions: "+json.dumps(result["sharedFunctions"]),"",
                "No runtime physical handoff established.",""]
        (a.out/"rea-stage4-functions-audit.md").write_text("\n".join(lines))
        print("[SHARED FUNCTIONS]",result["sharedFunctions"])
        print("[REPORT]",a.out/"rea-stage4-functions-audit.md")
        return 0 if all(i["status"]=="VERIFIED_FUNCTION" for i in result["functions"]) else 2
    except (ValueError,OSError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
