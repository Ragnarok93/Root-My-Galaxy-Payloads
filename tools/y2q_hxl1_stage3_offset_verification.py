#!/usr/bin/env python3
"""Independent original-HXL1 31-opcode and 13-member Clang10/REA evidence gate.

Stock instruction agreement and Clang10 rebuilt DWARF are NOT sufficient to
certify that a particular OEM C member caused an original load/store. Never
write target.h, execute an exploit, contact a phone or publish a feed.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
import re
import hashlib
import zipfile
from pathlib import Path
import subprocess
import shutil
import sys
if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_porting_automation as port
from tools import y2q_hxl1_clang10_checkpoint as checkpoint
from tools import y2q_hxl1_rtmutex_displacement_attest as prior
from tools import y2q_hxl1_stock_rtmutex_code_windows as original

ART=Path.home()/"s20-artifacts"
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
COMPARISON=ART/"hxl1-research/clang10-abi-comparison"
BUILD=Path.home()/"src/samsung-y2q-hxl1-clang10-abi-comparison"
SLICES=Path.home()/"HXL1-Stage3-Code-Slices.zip"
REA=Path.home()/"HXL1-Stage3-REA-Evidence.zip"
class ProofError(ValueError):pass

def insist(value,message):
    if not value:raise ProofError("HXL1 Stage 3 STOP: "+message)

def compiled_objects(root:Path):
    output=[]
    if root.is_symlink() or not root.is_dir():return output
    for basename in ("rtmutex.o","futex.o"):
        found=0
        for obj in root.rglob(basename):
            if obj.is_symlink() or not obj.is_file():continue
            if obj.stat().st_size>32*1024*1024:continue
            found+=1
            insist(found<=12,"ambiguous comparison build objects")
            with obj.open("rb") as fd:h=fd.read(20)
            arm=(len(h)==20 and h[:6]==b"\x7fELF\x02\x01" and
                 int.from_bytes(h[16:18],"little")==1 and
                 int.from_bytes(h[18:20],"little")==183)
            item={"file":str(obj),"sha256":port.sha256(obj),
                  "aarch64ET_REL":arm,"originalOEMObject":False}
            if arm and shutil.which("pahole"):
                item["dwarfDisplay"]={}
                for ty in ("rt_mutex","rt_mutex_waiter"):
                    try:
                        result=subprocess.run(["pahole","-C",ty,str(obj)],
                            capture_output=True,text=True,timeout=20)
                        item["dwarfDisplay"][ty]={
                            "found":result.returncode==0,
                            "output":result.stdout[:24000],
                            "factoryCompilerEquivalenceProven":False}
                    except (OSError,subprocess.TimeoutExpired):
                        item["dwarfDisplay"][ty]={"found":False,"reason":"pahole failed"}
            output.append(item)
    return output

def factory_words(raw:bytes,base:int=original.TEXT_VA):
    insist(raw[0x38:0x3c]==b"ARM\x64","not stock ARM64 Image")
    found=[]
    for name, (start,length,_,_) in prior.ELFS.items():
        va=int(start,16)
        index=va-base
        insist(0<=index<=len(raw)-length,"original factory code bounds invalid")
        for offset,expected in sorted(prior.WORDS[name].items()):
            insist(offset+4<=length,"invalid original witness offset")
            word=raw[index+offset:index+offset+4][::-1].hex()
            insist(word==expected,"factory original word differs: "+hex(va+offset))
            found.append({"function":name,"originalVA":hex(va+offset),
                          "opcode":word,"originalImageWordVerified":True,
                          "originalCFieldIdentityProven":False})
    insist(len(found)==31,"31 factory words were not validated")
    return found

def verify_rea_dossiers(slices:Path,rea:Path)->dict:
    """Independently re-read all three genuine bounded Ghidra instruction records."""
    rows={}
    with zipfile.ZipFile(slices) as zs, zipfile.ZipFile(rea) as zr:
        manifest=json.loads(zr.read("stage3-rea-correlation.json"))
        insist(manifest.get("status")=="STATIC_CODE_CORRELATION_ONLY" and
               manifest.get("firmware")=="G986U1UESCHXL1" and
               manifest.get("originalKernelSha256")==prior.ORIGINAL_IMAGE_SHA,
               "REA index firmware/status mismatch")
        for name,record in manifest["functions"].items():
            insist(name in ("remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi"),
                   "REA dossier names unexpectedly changed")
            va=record["symbolVA"][2:]
            elf_name="isolated-"+name+"-"+va+".elf"
            json_name="rea-slice-"+name+"-"+va+".json"
            elf=zs.read(elf_name)
            insist(len(elf)<64*1024,"unbounded REA ELF")
            sha=hashlib.sha256(elf).hexdigest()
            insist(sha==record["isolatedCode"]["sha256"],
                   "REA code slice digest mismatch "+name)
            doc=json.loads(zr.read(json_name))
            insist(doc.get("operation")=="read_function_instructions" and
                   doc.get("provider",{}).get("id")=="ghidra" and
                   doc.get("subject",{}).get("digest",{}).get("sha256")==sha and
                   doc.get("parameters",{}).get("procedure")=="0x10000",
                   "REA original Ghidra evidence provenance mismatch "+name)
            instructions=doc.get("normalized_result",{}).get("instructions")
            expected=record["reaInstructionCount"]
            insist(isinstance(instructions,list) and len(instructions)==expected and
                   0<len(instructions)<2048,"REA dossier instruction count mismatch "+name)
            size=record["isolatedCode"]["stockBytes"]
            observed=set()
            for line in instructions:
                match=re.match(r"^(0x[0-9a-fA-F]+):\s+.+$",line) if isinstance(line,str) else None
                insist(match is not None,"Malformed Ghidra instruction in "+name)
                address=int(match.group(1),16)
                insist(address>=0x10000 and address<0x10000+size and
                       (address-0x10000)%4==0 and address not in observed,
                       "REA instruction escaped/duplicated isolated original code")
                observed.add(address)
            rows[name]={"ghidraInstructionCount":len(instructions),
                        "sourceElfSha256":sha,
                        "actualGhidraRecordsIndependentlyChecked":True,
                        "sourceToCMemberFullDefUseCertified":False}
        insist(set(rows)=={"remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi"},
               "Three original Ghidra dossiers required")
    return rows

def audit(artifacts:Path,source:Path,comparison:Path,build:Path,
          slices:Path,rea:Path):
    pinned=port.check_factory_inputs(artifacts)
    insist(set(pinned)=={"kernel.bin","config.gz"} and
           all(v["state"]=="VERIFIED" for v in pinned.values()),
           "factory kernel/config SHA256 mismatch")
    with (artifacts/"kernel.bin").open("rb") as f:raw=f.read()
    words=factory_words(raw)
    check=checkpoint.audit(artifacts,comparison)
    objs=compiled_objects(build)
    if slices.is_file() and rea.is_file() and not slices.is_symlink() and not rea.is_symlink():
        result=prior.attest(slices,rea,source=source)
        insist(result["witnessCount"]==31,"REA archived evidence witness mismatch")
        dossiers=verify_rea_dossiers(slices,rea)
        rea_state={"state":"31_ORIGINAL_OPCODE_WITNESSES_REA_ATTESTED",
                   "slicesSha256":port.sha256(slices),
                   "reaSha256":port.sha256(rea),
                   "savedGhidraDossiers":dossiers,
                   "memberSpecificFactoryDefUseProven":False}
    else:rea_state={"state":"OWNER_REA_ARCHIVES_UNAVAILABLE",
                     "memberSpecificFactoryDefUseProven":False}
    members=[
        {"type":ty,"memberPath":path,"previousComparisonCandidateOffset":offset,
         "originalSourceMemberIdentityProven":False,
         "factoryCompiledMemberOffsetProven":False,
         "requiredNextEvidence":"Clang10 DWARF member + original stock instruction base-register and field-def/use mapping"}
        for ty,table in prior.FIELDS.items() for path,offset in table.items()
    ]
    insist(len(members)==13,"unexpected member inventory")
    return {"schemaVersion":1,"firmware":"G986U1UESCHXL1",
            "factoryInputIntegrity":pinned,
            "originalStockOpcodeWitnesses":words,
            "stockOpcodeWitnessesVerified":31,
            "comparisonReportSha256":check["originalReport"]["sha256"],
            "comparisonReportContentIndependentlyValidated":False,
            "comparisonDirectoryAarch64ObjectCount":check["aarch64ObjectCount"],
            "separateClang10BuildDirectory":str(build),
            "separateClang10Objects":objs,
            "separateClang10Aarch64ObjectCount":sum(1 for o in objs if o["aarch64ET_REL"]),
            "reaEvidence":rea_state,"memberCandidates":members,
            "factoryMemberOffsetsVerified":0,"completeFactoryAbiVerified":False,
            "stage3Complete":False,"runtimeRootOrKernelSuProven":False,
            "deviceModified":False}

def markdown(r):
    rows=["# HXL1 factory offset proof worklist","",
          "READ-ONLY: original code verification does not certify original C fields.","",
          "Factory stock opcode witnesses: "+str(r["stockOpcodeWitnessesVerified"])+"/31",
          "Clang10 AArch64 objects in comparison-report directory: "+str(r["comparisonDirectoryAarch64ObjectCount"]),
          "Clang10 AArch64 objects in separate build tree: "+str(r["separateClang10Aarch64ObjectCount"]),
          "REA: "+r["reaEvidence"]["state"],"",
          "| Type | Candidate member | Previous comparison value | Factory def-use |",
          "|---|---|---|---|"]
    for m in r["memberCandidates"]:
        rows.append("| "+m["type"]+" | "+m["memberPath"]+" | "+m["previousComparisonCandidateOffset"]+" | UNVERIFIED |")
    rows.extend(["","Next: independently bind candidate member paths to original source and exact factory instruction base registers in Ghidra; do not promote comparison DWARF to factory ABI.",""])
    return "\n".join(rows)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for flag,default in (("--artifacts",ART),("--source",SOURCE),
            ("--comparison",COMPARISON),("--object-root",BUILD),
            ("--slices",SLICES),("--rea",REA)):
        ap.add_argument(flag,type=Path,default=default)
    ap.add_argument("--output",type=Path)
    a=ap.parse_args()
    output=(a.output.expanduser().absolute() if a.output else
            ART/"hxl1-research"/("stage3-offset-verification-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")+".json"))
    try:
        insist(output.suffix==".json" and not output.exists() and not output.is_symlink(),
               "new JSON output required")
        for protected in (a.source,a.comparison,a.object_root,Path(__file__).resolve().parents[1]):
            p=protected.expanduser().absolute()
            insist(output!=p and p not in output.parents,
                   "cannot output into source/build/repository")
        report=audit(a.artifacts.expanduser().absolute(),a.source.expanduser().absolute(),
                     a.comparison.expanduser().absolute(),a.object_root.expanduser().absolute(),
                     a.slices.expanduser().absolute(),a.rea.expanduser().absolute())
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x") as f:f.write(json.dumps(report,indent=2)+"\n")
        with output.with_suffix(".md").open("x") as f:f.write(markdown(report))
        print("[STOCK ORIGINAL INSTRUCTIONS]",report["stockOpcodeWitnessesVerified"],"/31")
        print("[CLANG10 COMPARISON OBJ]",report["separateClang10Aarch64ObjectCount"])
        print("[REA]",report["reaEvidence"]["state"])
        print("[MEMBER CANDIDATES]",len(report["memberCandidates"]))
        print("[CERTIFIED FACTORY STRUCT OFFSETS]",0)
        print("[REPORT]",output)
        return 0
    except (OSError,ValueError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
