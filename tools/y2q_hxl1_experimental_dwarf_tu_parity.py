#!/usr/bin/env python3
"""HXL1: compare experimental Clang18 rt_mutex DWARF member geometry across TUs.

Read-only, fingerprint-only diagnostic of TWO original SHA256-pinned,
successful experimental build objects, not Samsung factory Clang10 ABI.
The stock reconstructed kernel has no independently verified DWARF/BTF
field layout. An agreeing experimental pair is NOT factory ABI evidence.

Do not output numeric field offsets, member sizes or exploit parameters.
Hash a bounded canonical sequence of named direct members and their raw
DWARF location/bitfield attributes. Detect missing/ambiguous/incomplete
DIEs and reject unknown forms, without claiming full type equivalence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_attest_isolated_dwarf_objects as owner
from tools import y2q_hxl1_dwarf_gap_triage as gap

DIE=re.compile(r"^\s*<(\d+)><([0-9a-fA-F]+)>:\s*Abbrev Number:\s*\d+\s+\((DW_TAG_\w+)\)")
ATTR=re.compile(r"^\s*<[0-9a-fA-F]+>\s+(DW_AT_\w+)\s*:\s*(.*)$")
DIRECT_ATTRS=("DW_AT_data_member_location","DW_AT_data_bit_offset",
              "DW_AT_bit_offset","DW_AT_bit_size")
DEFAULT_OUT=Path.home()/"s20-artifacts/hxl1-research/rtmutex-experimental-tu-parity-01.json"
MAX_DWARF_TEXT=32*1024*1024

class ShapeError(ValueError):
    pass


def attr_text(value:str)->str:
    # DW_AT_name may use a string-table preamble; preserve only exact text.
    return value.rsplit(": ",1)[-1].strip()


def parse_shapes(text:str)->dict:
    """Only direct members, not nested typedefs or embedded structure DIEs."""
    stack=[]
    structs=[]
    for line in text.splitlines():
        m=DIE.match(line)
        if m:
            depth=int(m.group(1))
            while stack and stack[-1]["depth"]>=depth:
                item=stack.pop()
                if item["tag"]=="DW_TAG_structure_type":
                    structs.append(item)
            tag=m.group(3)
            item={"tag":tag,"depth":depth,"attrs":{},"members":[]}
            for ancestor in reversed(stack):
                if ancestor["tag"]=="DW_TAG_structure_type" and depth==ancestor["depth"]+1:
                    if tag=="DW_TAG_member":
                        ancestor["members"].append(item)
                    break
            stack.append(item)
            continue
        a=ATTR.match(line)
        if a and stack:
            stack[-1]["attrs"][a.group(1)]=a.group(2).strip()
    for item in reversed(stack):
        if item["tag"]=="DW_TAG_structure_type":
            structs.append(item)

    result={name:[] for name in owner.TARGET_TYPES}
    for rec in structs:
        name=attr_text(rec["attrs"].get("DW_AT_name",""))
        if name not in result:
            continue
        attrs=rec["attrs"]
        if "DW_AT_declaration" in attrs or "DW_AT_byte_size" not in attrs:
            continue
        if not rec["members"]:
            raise ShapeError("Complete named structure has no direct DWARF members: "+name)
        members=[]
        for index,member in enumerate(rec["members"]):
            ma=member["attrs"]
            field_name=attr_text(ma.get("DW_AT_name",""))
            if not field_name:
                # Anonymous member, including unions, needs a distinct evidence
                # mode instead of silently fabricating a field identifier.
                raise ShapeError("Anonymous direct member not supported: "+name)
            if "DW_AT_data_member_location" not in ma and "DW_AT_data_bit_offset" not in ma:
                raise ShapeError("Unlocated member cannot contribute to geometry: "+name)
            values=[ma.get(key,"") for key in DIRECT_ATTRS]
            # Unsupported location expression must not be promoted as comparable.
            if any("DW_OP_" in value for value in values):
                raise ShapeError("Nonconstant member location expression: "+name)
            members.append({"index":index,"name":field_name,"attrs":values})
        canonical={
            "type":name,
            "aggregateByteSizeText":attrs["DW_AT_byte_size"],
            "directMemberGeometry":members,
        }
        digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,
                         separators=(",",":")).encode()).hexdigest()
        result[name].append({
            "memberCount":len(members),
            "directGeometryFingerprintSha256":digest,
            "compilerTypeReferencesCompared":False,
            "nestedLayoutsCompared":False,
            "factoryAbiEquivalent":False,
        })
    return result


def compare(tables:dict)->dict:
    if set(tables)!=set(owner.PINNED_OBJECTS):
        raise ShapeError("Both exact SHA256-pinned original object identities required")
    output={}
    for typ in owner.TARGET_TYPES:
        row={}
        for rel,item in tables.items():
            values=item.get(typ,[])
            if len(values)!=1:
                raise ShapeError("Require exactly one complete candidate per object: "+typ)
            v=values[0]
            if v.get("factoryAbiEquivalent") is not False or v.get("nestedLayoutsCompared") is not False:
                raise ShapeError("Unsupported ABI proof promotion")
            row[rel]=v
        digests={v["directGeometryFingerprintSha256"] for v in row.values()}
        counts={v["memberCount"] for v in row.values()}
        output[typ]={
            "directGeometryConsistentAcrossTwoExperimentalObjects":
                len(digests)==1 and len(counts)==1,
            "perObjectFingerprintAndCount":row,
            "typeReferencesAndNestedLayoutsVerified":False,
            "factoryCompiledLayoutEstablished":False,
        }
    return {
        "classification":"EXPERIMENTAL_CLANG18_DWARF_DIRECT_MEMBER_GEOMETRY_ONLY",
        "device":"SM-G986U1",
        "firmware":"G986U1UESCHXL1",
        "sourceObjectSha256Pins":dict(owner.PINNED_OBJECTS),
        "typeChecks":output,
        "allDirectMemberFingerprintsAgree":all(
            x["directGeometryConsistentAcrossTwoExperimentalObjects"]
            for x in output.values()),
        "factoryAbiProven":False,
        "originalStockStructureOffsetsKnown":False,
        "typeNestedLayoutOrReferencesProven":False,
        "kernelRuntimeAddressesKnown":False,
        "runtimeExploitValidated":False,
        "kernelSuInstalled":False,
    }


def inspect_originals(doc:dict,source_report:Path)->dict:
    # This fully re-verifies the source, clone, .config, original object
    # hashes, Kbuild phases, readelf type declarations and pahole status.
    att=owner.check_source_and_objects(doc,source_report)
    if att.get("actualFactoryLayoutProven") is not False:
        raise ShapeError("Parent has elevated experimental DWARF to factory layout")
    tables={}
    for rel in owner.PINNED_OBJECTS:
        path=Path(doc["freshOutput"])/rel
        try:
            proc=subprocess.run(["readelf","--debug-dump=info","--wide",str(path)],
                  capture_output=True,text=True,check=False,timeout=30,
                  errors="replace")
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ShapeError("readelf unavailable: "+type(exc).__name__) from exc
        if proc.returncode or len(proc.stdout)>MAX_DWARF_TEXT:
            raise ShapeError("readelf dump failed or exceeded bound: "+rel)
        tables[rel]=parse_shapes(proc.stdout)
    result=compare(tables)
    result["parentBuildLogSha256"]=att["independentlyRecheckedBuildLogSha256"]
    result["sourceProvenanceVerified"]=True
    return result


def markdown(x:dict)->str:
    lines=["# HXL1 Clang18 RT-mutex direct-member geometry concordance","",
           "Both AArch64 objects are original owner SHA256-pinned build outputs.",
           "This audit compares **direct member names, declaration order, "
           "aggregate byte-size attribute and DWARF location/bitfield attributes**.",
           "It does not resolve DWARF type references or embedded/nested layouts.",
           "","| Type | Clang18 object agreement | Factory kernel proven |",
           "|---|---|---|"]
    for name,item in x["typeChecks"].items():
        lines.append("| "+name+" | "+
            str(item["directGeometryConsistentAcrossTwoExperimentalObjects"])+
            " | **No** |")
    lines+=["","No factory Clang10 build/debug information was recovered.",
            "A matched Clang18 structural fingerprint does not prove that Samsung's",
            "running shipping kernel uses those offsets or member layouts.",
            "No numeric offsets, pointer addresses, kernel writes, exploit or KernelSU.",
            ""]
    return "\n".join(lines)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report",type=Path,default=owner.DEFAULT_REPORT)
    p.add_argument("--out",type=Path,default=DEFAULT_OUT)
    args=p.parse_args()
    report=args.report.expanduser().absolute()
    target=args.out.expanduser().absolute()
    md=target.with_suffix(".md")
    if (target.suffix!=".json" or
        any(v.exists() or v.is_symlink() for v in (target,md)) or
        not target.parent.is_dir() or target.parent.is_symlink()):
        p.error("Select a fresh non-symlinked JSON/Markdown report path")
    try:
        result=inspect_originals(owner.load_evidence(report),report)
        # If the two Clang18 object shapes disagree, preserve the evidence,
        # but do not claim that even provisional direct geometry is consistent.
        with target.open("x") as f:
            json.dump(result,f,indent=2)
            f.write("\n")
        with md.open("x") as f:
            f.write(markdown(result))
    except (ShapeError,owner.AttestationError,OSError,ValueError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    for name,item in result["typeChecks"].items():
        print("[EXPERIMENTAL TU GEOMETRY]",name,
              "consistent",item["directGeometryConsistentAcrossTwoExperimentalObjects"])
    print("[REPORT]",md)
    print("[LIMIT] No factory Clang10 ABI, root/kernel address or KernelSU established")
    return 0


if __name__=="__main__":
    sys.exit(main())
