#!/usr/bin/env python3
"""Bounded ORIGINAL-factory REA/Ghidra HighFunction ABI research for HXL1.

Input is the saved original 31-word/13-member factory gate, exact original
kernel.bin, source headers, and the three REA source-byte-attested code slices.
REA/Ghidra analyze_function is executed on those *bounded* original ARM64 ELF
code slices, not a full 52-MB kernel or a local recompilation.

Decompilation and HighFunction p-code establish static dataflow leads, NOT
factory C member identity without branch-sensitive corroboration. Never
patches/loads firmware, publishes target.h, interacts with phone, or claims root.
"""
from __future__ import annotations
import argparse
import hashlib
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import zipfile

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_porting_automation as port
from tools import y2q_hxl1_rtmutex_displacement_attest as prior
from tools import y2q_hxl1_stage3_offset_verification as verify
from tools import y2q_hxl1_stage3_member_flow as member
from tools.y2q_hxl1_rea_security_audit import (
    Target, Runner, TriageError, evidence
)

ART=Path.home()/"s20-artifacts"
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
SLICE=Path.home()/"HXL1-Stage3-Code-Slices.zip"
REA_ARCHIVE=Path.home()/"HXL1-Stage3-REA-Evidence.zip"
REA_SCRIPT=Path.home()/"src/rea/scripts/rea.mjs"
LIMIT_JSON=8*1024*1024
FUNCTIONS=("remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi")

class AbiError(ValueError): pass
def require(ok,why):
    if not ok: raise AbiError("HXL1 REA ABI STOP: "+why)

def verify_source_and_archives(report_path:Path,kernel:Path,source:Path,
                               archive:Path,slices:Path)->tuple[dict,dict,dict]:
    require(report_path.is_file() and not report_path.is_symlink() and
            report_path.stat().st_size<LIMIT_JSON,"saved factory Stage3 report unsafe/missing")
    saved=json.loads(report_path.read_text())
    require(saved.get("schemaVersion")==1 and saved.get("firmware")=="G986U1UESCHXL1" and
            saved.get("stockOpcodeWitnessesVerified")==31 and
            len(saved.get("memberCandidates",[]))==13 and
            saved.get("stage3Complete") is False and
            saved.get("factoryMemberOffsetsVerified")==0,
            "original factory Stage3 attestation incompatible")
    recorded=saved.get("factoryInputIntegrity",{}).get("kernel.bin",{})
    require(recorded.get("state")=="VERIFIED" and
            recorded.get("actualSha256")==prior.ORIGINAL_IMAGE_SHA,
            "prior OEM kernel digest was not authenticated")
    require(kernel.is_file() and not kernel.is_symlink() and
            port.sha256(kernel)==prior.ORIGINAL_IMAGE_SHA,
            "current original kernel does not match factory digest")
    require(slices.is_file() and not slices.is_symlink() and
            archive.is_file() and not archive.is_symlink(),
            "original REA ELF slices or saved Ghidra evidence absent/unsafe")
    record=saved.get("reaEvidence",{})
    require(record.get("slicesSha256")==port.sha256(slices) and
            record.get("reaSha256")==port.sha256(archive) and
            record.get("state")=="31_ORIGINAL_OPCODE_WITNESSES_REA_ATTESTED",
            "saved exact-OEM REA archive digest/state mismatch")
    # Independently checks each slice's 1:1 code bytes against factory kernel.
    raw=kernel.read_bytes()
    dossiers=verify.verify_rea_dossiers(slices,archive,raw)
    original=member.analyze(report_path,source,archive)
    require(original["savedFactoryVerifierSha256"]==port.sha256(report_path),
            "source/machine code worklist has invalid saved input")
    return saved,dossiers,original

def bounded_slices(zip_path:Path,dossiers:dict)->dict[str,tuple[bytes,str]]:
    result={}
    with zipfile.ZipFile(zip_path,"r") as z:
        for name in FUNCTIONS:
            d=dossiers[name]
            va=d["originalStockByteAttestation"]["symbolVA"][2:]
            filename="isolated-"+name+"-"+va+".elf"
            meta=z.getinfo(filename)
            require(0<meta.file_size<65536,"oversized original REA input: "+name)
            blob=z.read(filename)
            digest=hashlib.sha256(blob).hexdigest()
            require(digest==d["sourceElfSha256"],"original REA input hash changed: "+name)
            result[name]=(blob,digest)
    return result

def check_function_evidence(ev:dict|None,name:str,digest:str)->dict:
    """Validate genuine Ghidra decompilation + HighFunction p-code availability."""
    if ev is None:
        return {"name":name,"state":"NOT_EXECUTED","ghidraFieldOffsetsCertified":0}
    require(ev.get("operation")=="analyze_function" and
            ev.get("provider",{}).get("id")=="ghidra" and
            ev.get("subject",{}).get("digest",{}).get("sha256")==digest and
            ev.get("parameters",{}).get("procedure")=="0x10000" and
            isinstance(ev.get("evidence_id"),str),
            "REA/Ghidra provider/source/function identity mismatch: "+name)
    result=ev.get("normalized_result")
    require(isinstance(result,dict) and isinstance(result.get("procedure"),dict),
            "Ghidra function result missing: "+name)
    function=result["procedure"]
    require(function.get("address")=="0x10000",
            "Ghidra entry changed for original slice: "+name)
    body=function.get("body",{})
    require(body.get("available") is True and
            isinstance(body.get("ranges"),list) and
            any(int(x.get("start","0"),16)<=0x10000<=int(x.get("end","0"),16)
                for x in body["ranges"] if isinstance(x,dict)),
            "Ghidra function body does not include original entry: "+name)
    text=result.get("pseudocode")
    flow=result.get("native_value_flow")
    require(isinstance(text,str) and isinstance(flow,dict) and
            isinstance(flow.get("available"),bool),
            "Ghidra pseudocode/P-code metadata missing: "+name)
    require(len(text)<=250000,"unbounded Ghidra pseudocode")
    return {
        "name":name,"state":"GHIDRA_HIGHFUNCTION_AVAILABLE"
            if flow["available"] and flow.get("truncated") is False and text.strip()
            else "GHIDRA_ANALYSIS_INCOMPLETE",
        "evidenceId":ev["evidence_id"],
        "originalElfSha256":digest,
        "procedure":"0x10000",
        "pseudocodeSha256":hashlib.sha256(text.encode()).hexdigest(),
        "pseudocodeLength":len(text),
        "pseudocodePreview":text[:3500],
        "highFunctionPcodeAvailable":flow["available"],
        "pcodeTruncated":flow.get("truncated"),
        "reportedPcodeOperationCount":len(flow["operations"])
            if isinstance(flow.get("operations"),list) else None,
        "ghidraFieldOffsetsCertified":0,
        "fullBranchSensitiveSourceToCMemberMapping":False,
    }

def stage3_summary(source_abi:dict,function_results:list[dict])->dict:
    candidates=source_abi["registerFlowWorklist"]["candidates"]
    source_map={}
    for f in candidates:
        source_map.setdefault(f["type"],[]).append(f)
    return {
        "schemaVersion":1,"target":"SM-G986U1/G986U1UESCHXL1",
        "originalStage3ReportSha256":source_abi["savedFactoryVerifierSha256"],
        "verifiedOriginalGhidraSlices":len(FUNCTIONS),
        "staticRegisterCandidates":len(candidates),
        "matchedSavedGhidraRegisterChains":source_abi["registerFlowWorklist"]["matchedStaticChains"],
        "ghidraFunctions":function_results,
        "memberGroups":{k:[{"member":x["member"],
                            "candidateComparisonOffset":x["comparisonOffset"],
                            "savedStaticChainMatched":x["staticGhidraChainMatched"],
                            "ghidraHighFunctionFieldIdentityCertified":False}
                           for x in rows]
                        for k,rows in source_map.items()},
        "factoryStructMemberOffsetsVerified":0,
        "completeFactoryAbiVerified":False,
        "stage3Complete":False,
        "rootOrKernelSuVerified":False,
        "physicalDeviceModified":False,
        "missingProof":"Original HighFunction/P-code register reachability plus source-expression-to-C-member mapping and independent factory compiler ABI evidence.",
    }

def validate_output(path:Path,inputs:list[Path]):
    require(not path.exists() and not path.is_symlink(),"new output directory required")
    for p in inputs:
        absolute=p.expanduser().absolute()
        require(path!=absolute and absolute not in path.parents,
                "cannot create outputs inside original evidence/source/repository")

def run(report:Path,kernel:Path,source:Path,slices:Path,archive:Path,
        rea:Path,output:Path,*,execute:bool,timeout:int=240,node:str="node")->dict:
    require(60<=timeout<=900,"bounded REA timeout must be 60..900s")
    validate_output(output,[report,kernel,source,slices,archive,Path(__file__).resolve().parents[1]])
    _,dossiers,saved=verify_source_and_archives(report,kernel,source,archive,slices)
    extracted=bounded_slices(slices,dossiers)
    if execute:
        require(rea.is_file() and not rea.is_symlink(),"REA host entrypoint absent/unsafe")
        # Do not run REA at all if the factory, source, and archived Ghidra input
        # checks fail; never overwrite existing partial evidence.
        output.mkdir(parents=True,exist_ok=False)
        (output/"subjects").mkdir()
        for name,(blob,_) in extracted.items():
            (output/"subjects"/(name+".elf")).write_bytes(blob)
    runner=Runner(output,rea,node=node,deadline=timeout,run_commands=execute)
    rows=[]
    for name in FUNCTIONS:
        blob,digest=extracted[name]
        subject=output/"subjects"/(name+".elf")
        target=Target(name,subject,digest,{})
        dest=output/("ghidra-function-"+name+".json")
        try:
            ev=runner.obtain(target,["function",str(subject),"0x10000"],dest,
                             operation="analyze_function",
                             parameter="procedure",value="0x10000")
            rows.append(check_function_evidence(ev,name,digest))
        except (OSError,ValueError,KeyError,TypeError) as e:
            rows.append({"name":name,"state":"GHIDRA_ANALYSIS_FAILED",
                         "error":str(e)[:800],"originalElfSha256":digest,
                         "ghidraFieldOffsetsCertified":0})
    outcome=stage3_summary(saved,rows)
    outcome["mode"]="REA_GHIDRA_ANALYZE_FUNCTION" if execute else "PLAN_ONLY"
    outcome["plannedCommands"]=runner.planned if not execute else []
    outcome["originalInputSha256"]={
      "kernel":prior.ORIGINAL_IMAGE_SHA,"archive":port.sha256(archive),
      "slices":port.sha256(slices),"source":prior.SOURCE_PINS["kernel/locking/rtmutex.c"]}
    if execute:
        with (output/"hxl1-ghidra-member-abi.json").open("x") as f:
            f.write(json.dumps(outcome,indent=2)+"\n")
        with (output/"hxl1-ghidra-member-abi.md").open("x") as f:
            f.write(markdown(outcome))
    return outcome

def markdown(r:dict)->str:
    rows=["# HXL1 factory RT-mutex ABI Ghidra HighFunction evidence","",
          "Original Samsung HXL1 factory kernel and source only; no root or flash.","",
          "| Bounded OEM function | Ghidra decompilation / P-code |",
          "|---|---|"]
    for item in r["ghidraFunctions"]:
        rows.append("| "+item["name"]+" | "+item["state"]+" |")
    rows += ["","Matched original static register chains: "+
             str(r["matchedSavedGhidraRegisterChains"])+"/13",
             "Ghidra analysis does not by itself provide original OEM C debug types.",
             "**Factory-certified member offsets: 0 until independently validated.**",
             "","Next: inspect saved complete Ghidra evidence JSON, correlate each "
             "dataflow/base with the pinned Samsung C source and Clang10 DWARF, "
             "then accept only uniquely attributable members.",""]
    return "\n".join(rows)

def main()->int:
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("--verified-stage3-report",required=True,type=Path)
    a.add_argument("--kernel",type=Path,default=ART/"kernel.bin")
    a.add_argument("--source",type=Path,default=SOURCE)
    a.add_argument("--slices",type=Path,default=SLICE)
    a.add_argument("--archive",type=Path,default=REA_ARCHIVE)
    a.add_argument("--rea",type=Path,default=REA_SCRIPT)
    a.add_argument("--node",default="node")
    a.add_argument("--execute",action="store_true")
    a.add_argument("--timeout",type=int,default=240)
    a.add_argument("--output-dir",type=Path)
    args=a.parse_args()
    out=(args.output_dir.expanduser().absolute() if args.output_dir else
         ART/"hxl1-research"/("stage3-rea-highfunction-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
    try:
        obj=run(args.verified_stage3_report.expanduser().absolute(),
                args.kernel.expanduser().absolute(),
                args.source.expanduser().absolute(),
                args.slices.expanduser().absolute(),
                args.archive.expanduser().absolute(),
                args.rea.expanduser().absolute(),out,
                execute=args.execute,timeout=args.timeout,node=args.node)
        print("[REA/GHIDRA]",obj["mode"])
        for entry in obj["ghidraFunctions"]:
            print("[FUNCTION]",entry["name"],entry["state"])
        print("[ORIGINAL MEMBER OFFSETS CERTIFIED] 0")
        if args.execute:print("[REPORT]",out/"hxl1-ghidra-member-abi.json")
        else:
            for command in obj["plannedCommands"]:
                print("[PLAN]",*command)
        return 2 if any(x["state"]=="GHIDRA_ANALYSIS_FAILED" for x in obj["ghidraFunctions"]) else 0
    except (OSError,ValueError,TypeError,KeyError,zipfile.BadZipFile) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
