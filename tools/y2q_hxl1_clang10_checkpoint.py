#!/usr/bin/env python3
"""Read-only inventory and SHA attestation of existing HXL1 Clang10 comparison.

This tool does NOT compile or execute kernel code and does NOT interpret
unrecognized factory displacement report fields as confirmed OEM ABI offsets.
The exact original factory Image and config.gz must match pinned SHA256.
An owner-local JSON file is indexed, not promoted to factory debug truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_porting_automation as port

DEFAULT_ROOT=Path.home()/"s20-artifacts"
DEFAULT_DIRECTORY=DEFAULT_ROOT/"hxl1-research/clang10-abi-comparison"
MAX_REPORT_BYTES=8*1024*1024
MAX_OBJECTS=128
MAX_OBJECT_BYTES=32*1024*1024
TARGETS=("rt_mutex","rt_mutex_waiter","task_struct")

class CheckpointError(ValueError):
    pass

def safe_file(path:Path,max_bytes:int)->Path:
    if not path.is_file() or path.is_symlink() or path.stat().st_size>max_bytes:
        raise CheckpointError("Missing, symlinked or oversized report: "+str(path))
    return path

def stock_gate(root:Path)->dict:
    validated=port.check_factory_inputs(root)
    if set(validated)!={"kernel.bin","config.gz"} or any(
            item.get("state")!="VERIFIED" for item in validated.values()):
        raise CheckpointError("Original HXL1 factory kernel/config hash must match before indexing Clang10 reports")
    return validated

def enumerate_objects(folder:Path)->list[dict]:
    objects=[]
    for p in sorted(folder.rglob("*.o")):
        if p.is_symlink():
            raise CheckpointError("Symlinked Clang10 object cannot be inventoried")
        if not p.is_file():continue
        if len(objects)>=MAX_OBJECTS:
            raise CheckpointError("Too many Clang10 comparison objects")
        if p.stat().st_size>MAX_OBJECT_BYTES:
            raise CheckpointError("Oversized Clang10 comparison object")
        with p.open("rb") as file:
            first=file.read(20)
        # AArch64 ET_REL encoded in the standalone object header.
        elf_arm64_rel=(len(first)==20 and first[:6]==b"\x7fELF\x02\x01" and
                       int.from_bytes(first[16:18],"little")==1 and
                       int.from_bytes(first[18:20],"little")==183)
        objects.append({"relativePath":p.relative_to(folder).as_posix(),
                        "sha256":port.sha256(p),"sizeBytes":p.stat().st_size,
                        "aarch64RelocatableELF":elf_arm64_rel,
                        "oemBuiltOrShipped":False})
    return objects

def audit(factory:Path,directory:Path)->dict:
    if directory.is_symlink() or not directory.is_dir():
        raise CheckpointError("Missing or symlinked comparison directory")
    original=stock_gate(factory)
    file=safe_file(directory/"factory-displacement-comparison.json",MAX_REPORT_BYTES)
    payload=json.loads(file.read_text("utf-8"))
    if not isinstance(payload,dict):
        raise CheckpointError("Comparison report root must be JSON object")
    keys=sorted(k for k in payload if isinstance(k,str))
    if len(keys)>128 or any(not re.fullmatch(r"[\w.-]{1,80}",k) for k in keys):
        raise CheckpointError("Invalid or oversized comparison report structure")
    objects=enumerate_objects(directory)
    result={
        "schemaVersion":1,
        "target":"SM-G986U1/G986U1UESCHXL1",
        "purpose":"INDEX EXISTING CLANG10 COMPARISON EVIDENCE ONLY",
        "originalFirmwareHashesVerified":original,
        "comparisonRoot":str(directory),
        "originalReport":{
            "path":str(file),
            "sha256":port.sha256(file),
            "byteLength":file.stat().st_size,
            "topLevelFieldNames":keys,
            "contentInterpretation":"NOT_INDEPENDENTLY_VALIDATED",
            "candidate31FactoryInstructionsVerifiedByThisTool":False,
            "candidate13FactoryFieldsVerifiedByThisTool":False,
        },
        "aarch64ObjectInventory":objects,
        "aarch64ObjectCount":sum(1 for x in objects if x["aarch64RelocatableELF"]),
        "factoryCompilerAuthenticated":False,
        "factoryAbiAuthenticated":False,
        "fullFieldToInstructionMappingProven":False,
        "independentDwarfSourceBindingsVerified":False,
        "stage3PortingGatePassed":False,
        "runtimeGhostlockPrimitiveVerified":False,
        "rootVerified":False,
        "kernelSuLoaded":False,
        "phoneModified":False,
        "nextEvidence":"Independently validate field-to-source-def/use for every required stock function and attach authenticated Clang10 object and displacement proof, not just a filename or summary.",
    }
    return result

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts",type=Path,default=DEFAULT_ROOT)
    parser.add_argument("--comparison",type=Path,default=DEFAULT_DIRECTORY)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        factory=args.artifacts.expanduser().absolute()
        root=args.comparison.expanduser().absolute()
        output=args.output.expanduser().absolute()
        if (output.suffix!=".json" or output.is_symlink() or output.exists()
                or output==factory or factory==output.parent or output==root
                or root in output.parents):
            raise CheckpointError("Checkpoint output must be a fresh JSON outside comparison inputs")
        result=audit(factory,root)
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x",encoding="utf8") as file:
            json.dump(result,file,indent=2)
            file.write("\n")
        print("[CLANG10 ORIGINAL REPORT INDEXED]",result["originalReport"]["sha256"])
        print("[AARCH64 OBJECTS]",result["aarch64ObjectCount"])
        print("[FACTORY ABI CERTIFIED] NO")
        print("[STAGE 3] STILL REQUIRES INDEPENDENT SOURCE-TO-FIELD PROOF")
        print("[REPORT]",output)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
