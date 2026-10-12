#!/usr/bin/env python3
"""Original-factory-byte-backed REA/Ghidra Stage 3 function/value-flow review.

Runs REAL Ghidra analyze_function via REA on the THREE bounded factory-Image
AArch64 ELF slices; never asks a decompiler to trust guessed C field labels.
Only Ghidra-authenticated function bodies/pseudocode/native P-code metadata
are accepted.  Static instruction chains are review leads.  No payload/header
writes, firmware execution, phone access, or security-gate promotion.

Default mode is read-only PLAN, which does NOT launch REA or create files.
Explicit --execute runs the three Ghidra queries (with bounded timeouts).
Existing complete Ghidra evidence may be rechecked without being overwritten.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from tools import y2q_hxl1_stage3_member_flow as flow
from tools import y2q_hxl1_stage3_offset_verification as prior
from tools import y2q_hxl1_rtmutex_displacement_attest as displacement
from tools import y2q_hxl1_porting_automation as port
from tools.y2q_hxl1_rea_security_audit import (
    Target,Runner,evidence,function_record,digest,TriageError,
)

ROOT=Path.home()/"s20-artifacts/hxl1-research"
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
REA_SCRIPT=Path.home()/"src/rea/scripts/rea.mjs"
ARCHIVE=Path.home()/"HXL1-Stage3-REA-Evidence.zip"
SLICES=Path.home()/"HXL1-Stage3-Code-Slices.zip"
FUNCTIONS=("remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi")
MAX_REA_JSON=32*1024*1024

class OffsetREAError(ValueError):pass

def insist(flag:bool,msg:str):
    if not flag:raise OffsetREAError("HXL1 REA Stage3 STOP: "+msg)

def identity(stage3_path:Path,original_image:Path,slices:Path,archived_rea:Path,
             source:Path)->tuple[dict,dict,dict]:
    """Check the actual ORIGINAL Image and the saved Ghidra/Clang10 dossier."""
    insist(stage3_path.is_file() and not stage3_path.is_symlink()
           and stage3_path.stat().st_size<4*1024*1024,
           "Original Stage3 report missing/unsafe")
    stage3=json.loads(stage3_path.read_text())
    saved=flow.analyze(stage3_path,source,archived_rea)
    insist(saved["registerFlowWorklist"]["matchedStaticChains"]<=9,
           "Unexpected source offset register chain inventory")
    insist(original_image.is_file() and not original_image.is_symlink()
           and port.sha256(original_image)==displacement.ORIGINAL_IMAGE_SHA,
           "Original factory Image hash does not match")
    with original_image.open("rb") as f:img=f.read()
    checked=prior.verify_rea_dossiers(slices,archived_rea,img)
    insist(set(checked)==set(FUNCTIONS),"Missing one of three original functions")
    for name in FUNCTIONS:
        binding=stage3["reaEvidence"]["savedGhidraDossiers"][name]
        insist(binding["sourceElfSha256"]==checked[name]["sourceElfSha256"]
               and checked[name]["originalStockByteAttestation"]
                     ["archivedGhidraInputMatchesOriginalFactoryImage"] is True,
               "Saved Ghidra slice no longer matches original Image "+name)
    return stage3,saved,checked

def extract_slices(archive:Path,records:dict,out:Path,*,write:bool)->list[dict]:
    """Bounded originals; existing extracted slices checked byte-for-byte."""
    insist(archive.is_file() and not archive.is_symlink(),
           "Original Ghidra code-slice ZIP missing")
    planned=[]
    with zipfile.ZipFile(archive) as zipped:
        for name in FUNCTIONS:
            info=records[name]
            va=info["originalStockByteAttestation"]["symbolVA"][2:]
            filename="isolated-"+name+"-"+va+".elf"
            member=zipped.getinfo(filename)
            insist(0<member.file_size<64*1024 and member.filename==filename,
                   "Original Ghidra bounded slice invalid "+name)
            raw=zipped.read(member)
            expected=info["sourceElfSha256"]
            insist(hashlib.sha256(raw).hexdigest()==expected,
                   "Original Ghidra ELF sha mismatch "+name)
            file=out/"inputs"/filename
            if write:
                file.parent.mkdir(parents=True,exist_ok=True)
                insist(not file.is_symlink(),"Existing extracted ELF symlink")
                if file.exists():
                    insist(file.is_file() and file.read_bytes()==raw,
                           "Existing extracted ELF changed "+name)
                else:
                    with file.open("xb") as f:f.write(raw)
            planned.append({
                "label":name, "originalSymbolVA":info["originalStockByteAttestation"]["symbolVA"],
                "providerInput":str(file),"sha256":expected,
                "originalStockBytes":info["originalStockByteAttestation"]["stockCodeBytes"],
                "originalKernelCodeSha256":info["originalStockByteAttestation"]["originalKernelFunctionBytesSha256"],
                "originalImageBytesIndependentlyVerified":True,
            })
    return planned

def parse_function_analysis(response:dict,record:dict)->dict:
    """Inspect actual REA/Ghidra function body + native value flow provenance."""
    sha=record["sha256"]
    insist(response.get("operation")=="analyze_function" and
           response.get("provider",{}).get("id")=="ghidra" and
           response.get("subject",{}).get("digest",{}).get("sha256")==sha and
           response.get("subject",{}).get("architecture")=="arm64" and
           response.get("parameters",{}).get("procedure")=="0x10000" and
           isinstance(response.get("evidence_id"),str),
           "Ghidra source/function mismatch "+record["label"])
    f=function_record(response,"0x10000")
    result=response["normalized_result"]
    native=result.get("native_value_flow")
    if not isinstance(native,dict):native={}
    pse=result["pseudocode"]
    insist(len(pse)<400000,"Unbounded Ghidra pseudocode")
    if native.get("available") is True:
        operations=native.get("operations")
        if operations is not None:
            insist(isinstance(operations,list) and len(operations)<30000,
                   "Unbounded Ghidra high P-code")
        native_status="GHIDRA_HIGH_PCODE_AVAILABLE"
    else:native_status="GHIDRA_HIGH_PCODE_UNAVAILABLE"
    return {
        "label":record["label"],"originalSymbolVA":record["originalSymbolVA"],
        "originalFactoryCodeSha256":record["originalKernelCodeSha256"],
        "isolatedInputElfSha256":record["sha256"],
        "provider":"ghidra","analyzeFunctionEvidenceId":response["evidence_id"],
        "isolatedProcedure":"0x10000","functionBodyVerified":True,
        "ghidraPseudocodeSha256":hashlib.sha256(pse.encode("utf-8")).hexdigest(),
        "pseudocodePresent":f["pseudocodePresent"],
        "nativeValueFlowState":native_status,
        "nativePcodeOperationCount":len(native.get("operations",[]))
             if isinstance(native.get("operations"),list) else None,
        "CFieldIdentitiesEstablishedByThisAnalysis":False,
        "factoryABIComplete":False,
    }

def run_pipeline(report:Path,image:Path,slices:Path,archive:Path,source:Path,
                 output:Path,*,execute:bool,rea_script:Path,node:str,
                 timeout:int)->dict:
    insist(output!=source and source not in output.parents and
           output!=Path(__file__).resolve().parents[1]
           and Path(__file__).resolve().parents[1] not in output.parents,
           "Ghidra evidence output cannot modify source or Git checkout")
    insist(not output.is_symlink(),"Output directory cannot be symlink")
    protected=(report,image,slices,archive,source)
    insist(all(output!=p and output not in p.parents for p in protected),
           "Output would replace an original factory research input")
    insist(output.parent.is_dir() and not output.parent.is_symlink(),
           "Ghidra output parent must exist and be an ordinary directory")
    insist(not any(p.is_symlink() for p in (output/"inputs",output/"ghidra")),
           "Ghidra output subdirectories cannot be symlinks")

    if execute:
        insist(rea_script.is_file() and not rea_script.is_symlink(),
               "REA engine missing or symlinked; --execute requires installed REA")
        insist(60<=timeout<=900,"Bounded Ghidra query timeout must be 60..900 sec")
    stage3,saved,verified=identity(report,image,slices,archive,source)
    entries=extract_slices(slices,verified,output,write=execute)
    if execute:
        output.mkdir(parents=True,exist_ok=True)
    results=[]
    runner=Runner(output,rea_script,run_commands=execute,
                  node=node,deadline=timeout,max_functions=3)
    for entry in entries:
        name=entry["label"]
        target=Target(name,Path(entry["providerInput"]),entry["sha256"],{})
        result=runner.obtain(
            target,["function",str(target.path),"0x10000"],
            output/"ghidra"/("analyze-"+name+".json"),
            operation="analyze_function",parameter="procedure",value="0x10000")
        if result is None:
            results.append({"label":name,"state":"PLANNED_GHIDRA_FUNCTION_QUERY",
                            "originalFactoryCodeSha256":entry["sha256"],
                            "factoryMemberOffsetsCertified":0})
        else:
            record=parse_function_analysis(result,entry)
            record["state"]="GHIDRA_FUNCTION_AND_SOURCE_BYTES_ATTESTED"
            results.append(record)
    status="ACTUAL_REA_GHIDRA_QUERIES_VALIDATED" if execute else "GHIDRA_QUERIES_PLANNED"
    result={
        "schemaVersion":1,"firmware":"G986U1UESCHXL1",
        "status":status,"originalKernelImageSha256":displacement.ORIGINAL_IMAGE_SHA,
        "savedStage3ReportSha256":port.sha256(report),
        "sourceGhidraArchiveSha256":port.sha256(archive),
        "sourceCodeSliceArchiveSha256":port.sha256(slices),
        "verifiedFunctions":results,
        "GhidraQueryCount":len(runner.planned) if not execute else len(results),
        "memberRegisterChainWorklist":saved["registerFlowWorklist"],
        "factoryMemberOffsetsCertified":0,"stage3Complete":False,
        "rootPayloadVerified":False,"kernelSuVerified":False,
        "phoneModified":False,
    }
    if execute:
        summary=output/"stage3-rea-native.json"
        insist(not summary.exists() and not summary.is_symlink(),
               "REA native summary already exists: never overwrite")
        with summary.open("x") as f:f.write(json.dumps(result,indent=2)+"\n")
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage3-report",type=Path,required=True)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--source",type=Path,default=SOURCE)
    p.add_argument("--slices",type=Path,default=SLICES)
    p.add_argument("--rea-evidence",type=Path,default=ARCHIVE)
    p.add_argument("--rea-script",type=Path,default=REA_SCRIPT)
    p.add_argument("--node",default="node")
    p.add_argument("--timeout",type=int,default=300)
    p.add_argument("--output-dir",type=Path,
      default=ROOT/("stage3-rea-native-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
    p.add_argument("--execute",action="store_true",
                   help="Actually invoke installed REA/Ghidra (plan-only otherwise)")
    a=p.parse_args()
    try:
        v=run_pipeline(
            a.stage3_report.expanduser().absolute(),a.kernel.expanduser().absolute(),
            a.slices.expanduser().absolute(),a.rea_evidence.expanduser().absolute(),
            a.source.expanduser().absolute(),a.output_dir.expanduser().absolute(),
            execute=a.execute,rea_script=a.rea_script.expanduser().absolute(),
            node=a.node,timeout=a.timeout)
        print("[REA/GHIDRA]",v["status"])
        for row in v["verifiedFunctions"]:
            print("[FUNCTION]",row["label"],row["state"],
                  row.get("nativeValueFlowState","PENDING"))
        print("[STATIC MEMBER REGISTER CHAINS]",
              v["memberRegisterChainWorklist"]["matchedStaticChains"],"/13")
        print("[CERTIFIED FACTORY C MEMBER OFFSETS] 0")
        if a.execute:print("[REPORT]",a.output_dir/"stage3-rea-native.json")
        else:print("[PLAN] No REA subprocess started and no output files written")
        return 0
    except (OSError,KeyError,ValueError,TypeError,TriageError,zipfile.BadZipFile) as exc:
        print("[STOP]",exc,file=sys.stderr);return 2

if __name__=="__main__":
    raise SystemExit(main())
