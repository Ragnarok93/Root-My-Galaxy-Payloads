#!/usr/bin/env python3
"""Run fresh bounded REA/Ghidra over exact factory-byte-matched HXL1 code slices.

The existing Stage 3 offset verifier certifies 31 OEM opcode words and the
origin of the three isolated REA/Ghidra subjects. This tool actually calls
the configured REA/Ghidra provider to re-analyze those subjects: it requests
native instructions and a function/decompiler dossier per isolated entry.
All 13 previously hypothesized C-field displacements are treated as leads.
No automatic conversion of an untyped Ghidra byte displacement into an OEM C
member identity is allowed. Never deploy, flash, modify device, or target.h.

The default is PLAN ONLY. Run with --execute on the owner WSL host.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile
if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from tools import y2q_hxl1_porting_automation as port
from tools import y2q_hxl1_stage3_offset_verification as offset
from tools import y2q_hxl1_stage3_member_flow as flow
from tools import y2q_hxl1_rtmutex_displacement_attest as prior
from tools.y2q_hxl1_rea_security_audit import Runner,Target,function_record

ART=Path.home()/"s20-artifacts"
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
SLICES=Path.home()/"HXL1-Stage3-Code-Slices.zip"
REA_ARCHIVE=Path.home()/"HXL1-Stage3-REA-Evidence.zip"
REA_CLI=Path.home()/"src/rea/scripts/rea.mjs"
TARGETS=("remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi")
MAX_INPUT=4*1024*1024
MAX_FUNCTION_RECORD=8*1024*1024

class LiveProofError(ValueError):pass
def demand(check,reason):
    if not check:raise LiveProofError("HXL1 Stage3 REA STOP: "+reason)

def reconcile_original_dossiers(report:dict,verified:dict)->dict:
    """Upgrade a pre-byte-attestation Stage3 report in memory only.

    The owner generated a valid report with the 6bb5f68 schema which included
    Ghidra SHA/count records but NOT originalStockByteAttestation. Recompute
    that new field from the independent original factory Image and archived ELF
    bytes, and reject any discrepancy in the existing report's evidence.
    Never write an updated copy over the original report.
    """
    evidence=report.get("reaEvidence")
    demand(isinstance(evidence,dict),"saved Stage3 report missing REA inventory")
    saved=evidence.get("savedGhidraDossiers")
    demand(isinstance(saved,dict) and set(saved)==set(TARGETS)
           and set(verified)==set(TARGETS),"incompatible Ghidra dossier inventory")
    for name in TARGETS:
        old=saved[name]
        new=verified[name]
        demand(isinstance(old,dict),"malformed saved Ghidra entry: "+name)
        for key in ("sourceElfSha256","ghidraInstructionCount",
                    "actualGhidraRecordsIndependentlyChecked",
                    "sourceToCMemberFullDefUseCertified"):
            demand(old.get(key)==new[key],
                   "saved Ghidra dossier differs from factory revalidation: "
                   +name+"/"+key)
        old_attestation=old.get("originalStockByteAttestation")
        if old_attestation is not None:
            demand(old_attestation==new["originalStockByteAttestation"],
                   "old factory-byte attestation changed: "+name)
        demand(new["originalStockByteAttestation"] is not None and
               new["originalStockByteAttestation"].get(
                   "archivedGhidraInputMatchesOriginalFactoryImage") is True,
               "factory-byte attestation incomplete: "+name)
    return {**report, "reaEvidence":{
        **evidence,"savedGhidraDossiers":verified},
        "legacyStage3ReportRevalidatedInMemory":any(
            "originalStockByteAttestation" not in saved[name] for name in TARGETS)}


def saved_report(report_file:Path,artifacts:Path,source:Path,rea_archive:Path,slices:Path):
    demand(report_file.is_file() and not report_file.is_symlink() and
           report_file.stat().st_size<=MAX_INPUT,"original owner Stage3 report missing/unsafe")
    report=json.loads(report_file.read_text())
    demand(report.get("schemaVersion")==1 and report.get("firmware")=="G986U1UESCHXL1" and
           report.get("stockOpcodeWitnessesVerified")==31 and
           report.get("factoryMemberOffsetsVerified")==0 and
           report.get("stage3Complete") is False,
           "owner Stage3 report identity or honest gate mismatch")
    pin=port.check_factory_inputs(artifacts)
    demand(all(value["state"]=="VERIFIED" for value in pin.values()),
           "owner original firmware SHA256 mismatch")
    demand(report["factoryInputIntegrity"]==pin,
           "owner report no longer matches stock kernel/config")
    demand(report["reaEvidence"]["reaSha256"]==port.sha256(rea_archive) and
           report["reaEvidence"]["slicesSha256"]==port.sha256(slices) and
           report["reaEvidence"]["state"]=="31_ORIGINAL_OPCODE_WITNESSES_REA_ATTESTED",
           "original REA inputs changed after last owner's Stage3 verification")
    demand(len(report.get("memberCandidates",[]))==13,
           "missing registered offset hypotheses")
    known={(x["type"],x["memberPath"]):x["previousComparisonCandidateOffset"]
           for x in report["memberCandidates"]}
    demand(len(known)==13 and
           known=={(a,b):v for a,tbl in prior.FIELDS.items() for b,v in tbl.items()},
           "13 factory comparison member hypotheses changed")
    prior.source_headers(source)
    with (artifacts/"kernel.bin").open("rb") as f:kernel=f.read()
    dossiers=offset.verify_rea_dossiers(slices,rea_archive,kernel)
    demand(set(dossiers)==set(TARGETS),"missing complete original REA dossier")
    return reconcile_original_dossiers(report,dossiers),dossiers

def slice_manifest(report:dict,source_zip:Path):
    result={}
    with zipfile.ZipFile(source_zip,"r") as pack:
        for name in TARGETS:
            record=report["reaEvidence"]["savedGhidraDossiers"][name]
            va=record["originalStockByteAttestation"]["symbolVA"][2:]
            entry=f"isolated-{name}-{va}.elf"
            data=pack.read(entry)
            digest=hashlib.sha256(data).hexdigest()
            demand(digest==record["sourceElfSha256"] and
                   len(data)<64*1024 and
                   data[:6]==b"\x7fELF\x02\x01" and
                   int.from_bytes(data[18:20],"little")==183,
                   "Ghidra source ELF identity mismatch for "+name)
            result[name]={"archiveMember":entry,"sha256":digest,
                          "factoryStaticVA":record["originalStockByteAttestation"]["symbolVA"],
                          "fileBytes":data}
    return result

def native_map(ev:dict,expected_sha:str)->dict:
    demand(ev.get("operation")=="read_function_instructions" and
           ev.get("provider",{}).get("id")=="ghidra" and
           ev.get("subject",{}).get("digest",{}).get("sha256")==expected_sha and
           ev.get("parameters",{}).get("procedure")=="0x10000",
           "live REA native Ghidra provenance invalid")
    normalized=ev.get("normalized_result")
    rows=normalized.get("instructions") if isinstance(normalized,dict) else normalized
    demand(isinstance(rows,list) and 0<len(rows)<2048,
           "live REA native instruction list absent or unbounded")
    out={}
    for item in rows:
        match=re.fullmatch(r"\s*(0x[0-9a-fA-F]+):\s*(.+?)\s*",item) if isinstance(item,str) else None
        demand(match is not None,"invalid live Ghidra instruction text")
        pc=hex(int(match.group(1),16))
        demand(pc not in out,"duplicate Ghidra instruction address")
        out[pc]=match.group(2).lower()
    return out

def compare_live_native(live:dict,saved:dict):
    """No pseudo C-member promotion; require same factory native disassembly."""
    return {
        "savedInstructionCount":len(saved),
        "liveInstructionCount":len(live),
        "sameInstructionCoordinates":set(live)==set(saved),
        "differentOrMissingInstructionCount":sum(
             live.get(pc)!=asm for pc,asm in saved.items())+
             len(set(live)-set(saved)),
        "nativeIdenticalToFactoryBoundArchive":live==saved,
    }

def ghidra_member_displacement_leads(observed:dict)->list[dict]:
    """Index exact Ghidra memory operands for all 13 source-typed hypotheses.

    A matching immediate is not proof the base is that C object. In
    particular offsets 0x0, 0x10 and 0x18 alias multiple ARM64 structs.
    """
    members=[]
    rx=re.compile(r"\[\s*(x(?:[0-9]|[12][0-9]|30)|sp)\s*(?:,\s*#(0x[0-9a-f]+|[0-9]+))?\s*\]")
    for ty,fields in prior.FIELDS.items():
        for name,offset in fields.items():
            value=int(offset,16)
            matches=[]
            for fn,asm in observed.items():
                for pc,instruction in asm.items():
                    hit=rx.search(instruction)
                    if hit is None:continue
                    if (int(hit.group(2),0) if hit.group(2) else 0)!=value:continue
                    is_stack=hit.group(1)=="sp"
                    matches.append({"function":fn,"pc":pc,
                                    "base":hit.group(1),"instruction":instruction,
                                    "baseIsStack":is_stack,
                                    "evidenceClass":"STACK_FRAME_NOT_C_MEMBER" if is_stack
                                      else "UNTYPED_NONSTACK_OFFSET_LEAD"})
            members.append({
                "type":ty,"member":name,"comparisonDWARFOffset":offset,
                "exactFactoryGhidraMemoryOperandCandidates":matches[:48],
                "allCandidateSitesCount":len(matches),
                "nonstackOperandLeadCount":sum(not m["baseIsStack"] for m in matches),
                "stackFrameFalsePositiveCount":sum(m["baseIsStack"] for m in matches),
                "truncatedCandidateSites":len(matches)>48,
                "CFieldIdentityCertified":False,
            })
    return members

def review_genuine_ghidra(name:str,entry:str,ev:dict,sha:str):
    demand(ev.get("operation")=="analyze_function" and
           ev.get("provider",{}).get("id")=="ghidra" and
           ev.get("subject",{}).get("digest",{}).get("sha256")==sha and
           ev.get("parameters",{}).get("procedure")==entry,
           "Ghidra function dossier does not match exact isolated ELF")
    info=function_record(ev,entry)
    demand(info["entry"]==entry,"Ghidra recovered different function owner")
    data=ev["normalized_result"]
    proc=data["procedure"]
    pseudo=data.get("pseudocode","")
    demand(isinstance(pseudo,str) and len(pseudo)<500000,
           "unbounded or missing Ghidra decompiler text")
    # Ghidra's untyped synthetic ELF typically cannot reproduce the OEM
    # source's C field names. Show their presence only as review hints.
    member_tokens={f for ty,tbl in prior.FIELDS.items() for f in tbl
                   if "." not in f}
    referenced=[f for f in member_tokens
                if re.search(r"\b"+re.escape(f)+r"\b",pseudo)]
    highflow=data.get("native_value_flow")
    if not isinstance(highflow,dict):
        highflow={}
    native_ops=highflow.get("operations")
    high_complete=(
        highflow.get("available") is True
        and highflow.get("truncated") is False
        and highflow.get("omitted_operations_lower_bound")==0
        and highflow.get("known_omitted_inputs")==0
        and highflow.get("known_omitted_edges")==0
        and isinstance(native_ops,list) and bool(pseudo.strip())
    )
    return {"entry":info["entry"],"ghidraFunctionName":info["name"],
            "highPcodeCompleteWithinProviderLimits":high_complete,
            "highPcodeTruncated":highflow.get("truncated"),
            "retainedHighPcodeOperations":len(native_ops) if isinstance(native_ops,list) else None,
            "knownOmittedPcodeEdges":highflow.get("known_omitted_edges"),
            "knownOmittedPcodeInputs":highflow.get("known_omitted_inputs"),
            "ghidraFunctionBodyAvailable":True,
            "pcodeAvailable":info["pcodeAvailable"],
            "nativeValueFlowFieldPresent":isinstance(data.get("native_value_flow"),dict),
            "decompilerPseudocodeBytes":len(pseudo),
            "lexicalMemberNameHints":sorted(referenced),
            "lexicalNamesAreNotOEMTypeProof":True,
            "sourceAndRegisterToCFieldIdentityProven":False,
            "factoryMemberOffsetsCertified":0}

def run(saved:Path,artifacts:Path,source:Path,slices:Path,rea_archive:Path,
        rea_cli:Path,output:Path,execute:bool,timeout:int,node:str="node"):
    report,_=saved_report(saved,artifacts,source,rea_archive,slices)
    demand(not output.exists() and not output.is_symlink(),
           "output directory exists; do not overwrite prior forensic evidence")
    demand(output!=source and source not in output.parents and
           output!=artifacts and output!=Path(__file__).resolve().parents[1] and
           Path(__file__).resolve().parents[1] not in output.parents,
           "unsafe output location")
    if execute:
        demand(rea_cli.is_file() and not rea_cli.is_symlink(),
               "REA entrypoint missing/unsafe (configure ~/src/rea)")
    manifests=slice_manifest(report,slices)
    saved_instructions=flow.original_instructions(rea_archive,report)
    # Plan validates local inputs and prints bounded command intent; it neither
    # creates an output directory nor loads a provider.
    if not execute:
        return {"mode":"PLAN_ONLY","originalStage3Sha256":port.sha256(saved),
                "planned": [
                    {"function":name,"inputSha256":manifests[name]["sha256"],
                     "operations":["instructions","function"],
                     "entry":"0x10000"}
                    for name in TARGETS],
                "stage3Complete":False}
    output.mkdir(parents=True,exist_ok=False)
    runner=Runner(output,rea_cli,node=node,run_commands=True,deadline=timeout)
    rows={}
    observed={}
    for name in TARGETS:
        item=manifests[name]
        directory=output/name
        directory.mkdir()
        binary=directory/item["archiveMember"]
        with binary.open("xb") as f:f.write(item["fileBytes"])
        demand(port.sha256(binary)==item["sha256"],
               "materialized factory ELF differs from SHA pin")
        target=Target(name,binary,item["sha256"],{})
        n=runner.obtain(target,["instructions",str(binary),"0x10000"],
                        directory/"live-instructions.json",
                        operation="read_function_instructions",
                        parameter="procedure",value="0x10000")
        demand(n is not None,"live Ghidra instructions missing")
        live=native_map(n,item["sha256"])
        comparison=compare_live_native(live,saved_instructions[name])
        demand(comparison["nativeIdenticalToFactoryBoundArchive"],
               "fresh Ghidra native instructions differ from factory-attested archive for "+name)
        f=runner.obtain(target,["function",str(binary),"0x10000"],
                        directory/"live-function.json",
                        operation="analyze_function",parameter="procedure",value="0x10000")
        demand(f is not None,"live Ghidra function missing")
        info=review_genuine_ghidra(name,"0x10000",f,item["sha256"])
        observed[name]=live
        rows[name]={"sourceELFSha256":item["sha256"],
                    "originalStaticVA":item["factoryStaticVA"],
                    "freshGhidraInstructions":comparison,
                    "freshGhidraFunction":info,
                    "freshInstructionEvidenceId":n.get("evidence_id"),
                    "freshFunctionEvidenceId":f.get("evidence_id")}
    typed=flow.source_signature(source)
    existing=flow.correlate(observed,typed)
    out={"schemaVersion":1,"target":"SM-G986U1/G986U1UESCHXL1",
         "sourceOriginalFactoryKernelSha256":prior.ORIGINAL_IMAGE_SHA,
         "previousStage3ReportSha256":port.sha256(saved),
         "savedREAArchiveSha256":port.sha256(rea_archive),
         "savedIsolatedELFArchiveSha256":port.sha256(slices),
         "mode":"EXECUTE_FRESH_REA_GHIDRA",
         "functions":rows,"sourceTypedSignatureMatched":typed,
         "completeHighPcodeFunctions":sum(
             bool(entry["freshGhidraFunction"]["highPcodeCompleteWithinProviderLimits"])
             for entry in rows.values()),
         "memberCandidateRegisterFlow":existing,
         "liveNativeMemberDisplacementWorklist":ghidra_member_displacement_leads(observed),
         "comparedClang10Candidates":prior.FIELDS,
         "factoryMemberOffsetsVerified":0,
         "fullOEMStructABIProven":False,
         "stage3Complete":False,"rootOrKernelSuVerified":False,
         "deviceModified":False}
    with (output/"live-stage3-rea-review.json").open("x") as file:
        file.write(json.dumps(out,indent=2)+"\n")
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--verified-stage3-report",required=True,type=Path)
    p.add_argument("--artifacts",default=ART,type=Path)
    p.add_argument("--source",default=SOURCE,type=Path)
    p.add_argument("--slices",default=SLICES,type=Path)
    p.add_argument("--rea-archive",default=REA_ARCHIVE,type=Path)
    p.add_argument("--rea",default=REA_CLI,type=Path)
    p.add_argument("--output-dir",type=Path)
    p.add_argument("--node",default="node")
    p.add_argument("--timeout",type=int,default=240)
    p.add_argument("--execute",action="store_true",
                   help="Request six live, bounded Ghidra operations on the SHA-pinned code slices")
    args=p.parse_args()
    base=ART/"hxl1-research"/("stage3-rea-live-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output=(args.output_dir or base).expanduser().absolute()
    try:
        demand(30<=args.timeout<=900,"bounded timeout must be 30..900 seconds")
        result=run(args.verified_stage3_report.expanduser().absolute(),
                   args.artifacts.expanduser().absolute(),
                   args.source.expanduser().absolute(),
                   args.slices.expanduser().absolute(),
                   args.rea_archive.expanduser().absolute(),
                   args.rea.expanduser().absolute(),output,args.execute,args.timeout,args.node)
        print("[MODE]",result["mode"])
        if args.execute:
            print("[LIVE GHIDRA FUNCTIONS]",len(result["functions"]))
            print("[MEMBER REGISTER CHAINS]",
                  result["memberCandidateRegisterFlow"]["matchedStaticChains"],"/13")
            print("[COMPLETE GHIDRA HIGH P-CODE]",
                  result["completeHighPcodeFunctions"],"/3")
            print("[OEM FACTORY MEMBER OFFSETS CERTIFIED] 0")
            print("[REPORT]",output/"live-stage3-rea-review.json")
        else:
            print("[PLAN] Six REA/Ghidra operations (3 instructions + 3 function reviews)")
            print("[RUN WITH] --execute")
        return 0
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
