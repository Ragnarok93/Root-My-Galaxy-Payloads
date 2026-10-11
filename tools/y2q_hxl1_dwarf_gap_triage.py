#!/usr/bin/env python3
"""Root My Galaxy S20+ HXL1: why experimental Clang18 DWARF has no rt_mutex types.

Host-only, read-only diagnostic. Uses pinned Stage-3 kernel proof matrix and
only previously retained partial build objects. No compilation or payload,
no exploitation, no phone access and NO member-offset harvesting.

Pahole's 'not found' can mean: no object, no debug info, a forward
declaration, a split DWARF companion, filtered debug types, or a true lack
of this definition. Inspect object presence, Kbuild .cmd debug switches
and independently parsed readelf DWARF DIEs to distinguish possibilities.
A Clang18 complete DIE never proves the factory Clang10 ABI.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools import y2q_hxl1_kernel_proof_matrix as stage3
from tools import y2q_partial_samsung_dwarf_audit as objects
from tools import y2q_dwarf_type_presence as pahole

TARGET_TYPES=("rt_mutex_waiter","rt_mutex")
SELECTED_OBJECTS=(
    "kernel/locking/rtmutex.o",
    "kernel/futex.o",
    "init/init_task.o",
    "init/main.o",
    "arch/arm64/kernel/process.o",
    "arch/arm64/kernel/fpsimd.o",
)
MAX_OBJECT_SIZE=64*1024*1024
MAX_DEBUG_OUTPUT=32*1024*1024
READ_TIMEOUT=25
DIE_LINE=re.compile(r"^\s*<(\d+)><([0-9a-fA-F]+)>:\s*Abbrev Number:\s*\d+\s+\((DW_TAG_\w+)\)")
ATTRIBUTE_LINE=re.compile(r"^\s*<[0-9a-fA-F]+>\s+(DW_AT_\w+)\s*:\s*(.*)$")
SOURCE_REF=stage3.DEFAULT_BUILD

class GapError(ValueError):
    pass


def parse_named_struct_dies(readelf_text:str)->dict:
    """DIEs with exact DW_AT_name; never calculate DW_AT_data_member_location."""
    candidates=[]
    current=None
    for line in readelf_text.splitlines():
        die=DIE_LINE.match(line)
        if die:
            if current is not None:
                candidates.append(current)
            current={"kind":die.group(3),"depth":int(die.group(1)),
                     "offset":die.group(2),"attrs":{}}
            continue
        attr=ATTRIBUTE_LINE.match(line)
        if current is not None and attr:
            current["attrs"][attr.group(1)]=attr.group(2).strip()
    if current is not None:
        candidates.append(current)
    out={name:[] for name in TARGET_TYPES}
    for c in candidates:
        if c["kind"] not in ("DW_TAG_structure_type","DW_TAG_class_type"):
            continue
        a=c["attrs"]
        # Normal readelf: DW_AT_name : (indirect string, offset: 0x...): rt_mutex
        # Direct: DW_AT_name : rt_mutex
        name=a.get("DW_AT_name","").rsplit(": ",1)[-1].strip()
        if name not in TARGET_TYPES:
            continue
        incomplete="DW_AT_declaration" in a or "DW_AT_byte_size" not in a
        out[name].append({
            "dieOffset":"0x"+c["offset"],
            "kind":c["kind"],
            "completeTypeDefinition":not incomplete,
            "hasByteSizeAttribute":"DW_AT_byte_size" in a,
            "declarationAttributePresent":"DW_AT_declaration" in a,
            "hasSpecificationReference":"DW_AT_specification" in a,
            # Deliberately do not expose layout sizes or member offsets.
        })
    return out


def cmd_diagnostic(build:Path,rel:str)->dict:
    obj=build/rel
    cmd=obj.with_name("."+obj.name+".cmd")
    if cmd.is_symlink():
        raise GapError("Refusing symlinked Kbuild cmd file")
    if not cmd.is_file():
        return {"present":False,"message":"No retained Kbuild compile invocation"}
    if cmd.stat().st_size>2*1024*1024:
        raise GapError("Kbuild cmd file exceeds audit bound")
    text=cmd.read_text(encoding="utf-8",errors="replace")
    # Diagnostic categories only. No host paths or command details.
    flags={
        "fullDebugMinusG":bool(re.search(r"(?<!\S)-g(?:\s|$)",text)),
        "lineTablesOnly":bool(re.search(r"(?<!\S)-gline-tables-only(?:\s|$)",text)),
        "dwarfVersion4":bool(re.search(r"(?<!\S)-gdwarf-4(?:\s|$)",text)),
        "dwarfVersion5":bool(re.search(r"(?<!\S)-gdwarf-5(?:\s|$)",text)),
        "debugTypeSections":bool(re.search(r"(?<!\S)-fdebug-types-section(?:\s|$)",text)),
        "debugTypesPruned":bool(re.search(r"(?<!\S)-fno-standalone-debug(?:\s|$)",text)),
        "standaloneDebug":bool(re.search(r"(?<!\S)-fstandalone-debug(?:\s|$)",text)),
        "splitDwarf":bool(re.search(r"(?<!\S)-gsplit-dwarf(?:\s|$)",text)),
        "noDebug":bool(re.search(r"(?<!\S)-g0(?:\s|$)",text)),
    }
    return {"present":True,"debugSwitches":flags}


def inspect_object(build:Path,rel:str)->dict:
    path=build/rel
    base={"relativePath":rel,"experimentalOnly":True,
          "factoryLayoutAuthenticated":False}
    if path.is_symlink():
        return {**base,"classification":"SYMLINK_REFUSED"}
    if not path.is_file():
        return {**base,"classification":"OBJECT_MISSING",
                "kbuildCommand":cmd_diagnostic(build,rel)}
    if path.stat().st_size>MAX_OBJECT_SIZE:
        return {**base,"classification":"OBJECT_SIZE_EXCEEDS_BOUND"}
    info=objects.arm64_object(path)
    metadata=cmd_diagnostic(build,rel)
    if info.get("kind")!="ARM64_REL":
        return {**base,"classification":"NOT_ARM64_RELOCATABLE",
                "elfKind":info.get("kind"),"kbuildCommand":metadata}
    if not info.get("hasDwarf"):
        return {**base,"classification":"ELF_WITHOUT_DWARF_INFO",
                "elfKind":info["kind"],"kbuildCommand":metadata,
                "debugSections":info.get("debugSections",[])}
    try:
        result=subprocess.run(
            ["readelf","--debug-dump=info","--wide",str(path)],
            capture_output=True,text=True,timeout=READ_TIMEOUT,
            check=False,errors="replace"
        )
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {**base,"classification":"READELF_TOOL_ERROR",
                "diagnostic":type(exc).__name__,
                "kbuildCommand":metadata}
    if (len(result.stdout)>MAX_DEBUG_OUTPUT or
        len(result.stderr)>256*1024):
        return {**base,"classification":"DEBUG_DUMP_EXCEEDS_BOUND",
                "kbuildCommand":metadata}
    if result.returncode!=0:
        return {**base,"classification":"READELF_TOOL_ERROR",
                "readelfReturnCode":result.returncode,
                "diagnosticExcerpt":result.stderr[:200],
                "kbuildCommand":metadata}
    findings=parse_named_struct_dies(result.stdout)
    if any(x["completeTypeDefinition"]
           for x in findings.values() for x in x):
        classification="EXPERIMENTAL_COMPLETE_DIE_FOUND"
    elif any(findings.values()):
        classification="ONLY_FORWARD_OR_INCOMPLETE_DIE"
    else:
        classification="NO_NAMED_RT_MUTEX_DIE_IN_RETAINED_OBJECT"
    return {**base,
            "classification":classification,
            "elfKind":info["kind"],
            "debugSections":info.get("debugSections",[]),
            "kbuildCommand":metadata,
            "namedTypeDies":findings,
            "readelfSucceeded":True}


def audit(build:Path,prior:dict,prior_inventory:dict)->dict:
    if (prior.get("decisions",{}).get("originalCompiledStructureOffsetsVerified") is not False
        or prior.get("decisions",{}).get("ghostLockRuntimeApplicable") is not False
        or prior.get("decisions",{}).get("kernelSuCompatibleAndAuthorized") is not False):
        raise GapError("Stage-3 parent illegally asserts compiled exploit/root readiness")
    orig=prior_inventory
    if (orig.get("target")!=f"{stage3.TARGET} {stage3.FIRMWARE}"
        or orig.get("buildConfigSha256")!=objects.GENERATED_SHA
        or orig.get("originalHashPinsMatched") is not True):
        raise GapError("Exact HXL1 Clang18 object inventory not authenticated")
    selected=orig.get("selected")
    if not isinstance(selected,dict) or not set(SELECTED_OBJECTS).issubset(selected):
        raise GapError("Missing expected selected object statuses")
    probes={name:inspect_object(build,name) for name in SELECTED_OBJECTS}
    presence=prior.get("checks",{}).get("rtMutexTypePresence",{})
    if set(presence)!=set(TARGET_TYPES):
        raise GapError("Previous pahole type-presence result incomplete")
    result={
        "classification":"HXL1_EXPERIMENTAL_DWARF_GAP_DIAGNOSTIC_ONLY",
        "device":prior["device"],
        "exactSourceAndBuildPinsVerified":True,
        "partialBuildObjectCount":orig["objectCount"],
        "partialBuildArm64ObjectCount":orig["arm64RelCount"],
        "partialBuildArm64ObjectsWithDwarf":orig["arm64DwarfCount"],
        "originalFactoryCompilerComparable":False,
        "paholeCompleteDefinitions":{
            name:presence[name]["completeDefinitionsFound"]
            for name in TARGET_TYPES
        },
        "selectedObjectDiagnostics":probes,
        "fullOriginalFactoryAbiEstablished":False,
        "useForNativeExploitOffsets":False,
        "kernelSuInstallable":False,
        "rootDemonstrated":False,
        "nextAction":"If matching targeted objects lack complete DIEs, collect exact build flags and decide whether a separate non-deployable debug rebuild is useful. Original factory layouts remain unknown.",
    }
    return result


def markdown(doc:dict)->str:
    s=[
        "# SM-G986U1 HXL1 — why Clang18 DWARF lacks RT-mutex definitions",
        "",
        "**Source:** Exact pinned Samsung HXL1 source/config and retained partial",
        "Clang18 objects. Neither Clang18 ABI nor compiled structures are OEM-verified.",
        "",
        f"Objects: {doc['partialBuildObjectCount']}; ARM64: "
        f"{doc['partialBuildArm64ObjectCount']}; with DWARF: "
        f"{doc['partialBuildArm64ObjectsWithDwarf']}.","",
        "## Targeted object triage","",
        "| Object | Status | RT-mutex DIEs | RT-mutex-waiter DIEs | Kbuild .cmd |",
        "|---|---|---:|---:|---|"
    ]
    for name,v in doc["selectedObjectDiagnostics"].items():
        types=v.get("namedTypeDies",{})
        s.append(f"| {name} | {v['classification']} | "
                 f"{len(types.get('rt_mutex',[]))} | "
                 f"{len(types.get('rt_mutex_waiter',[]))} | "
                 f"{v.get('kbuildCommand',{}).get('present',False)} |")
        switches=v.get("kbuildCommand",{}).get("debugSwitches",{})
        if switches:
            s.append(f"- {name} debug switches: "+
                     ", ".join(f"{k}={z}" for k,z in switches.items()))
    s+=["","## Conclusions","",
        "Named DWARF tags are inspected separately from pahole's exit status.",
        "A missing tag in retained partial objects is NOT proof that the",
        "stock firmware lacks that type, nor that the CVE is safe/exploitable.",
        "**No numerical member offsets or factory-equivalent layouts are derived.**",
        "**No exploit, device changes, root or KernelSU performed.**",""]
    return "\n".join(s)


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build",type=Path,default=stage3.DEFAULT_BUILD)
    parser.add_argument("--source",type=Path,default=stage3.DEFAULT_SOURCE)
    parser.add_argument("--artifacts",type=Path,default=stage3.DEFAULT_ARTIFACTS)
    parser.add_argument("--references",type=Path,default=stage3.DEFAULT_REFERENCES)
    parser.add_argument("--out",type=Path,default=stage3.DEFAULT_ARTIFACTS/
                        "hxl1-research/kernel-dwarf-gap-triage.json")
    args=parser.parse_args()
    build=args.build.expanduser().resolve()
    source=args.source.expanduser().resolve()
    artifacts=args.artifacts.expanduser().resolve()
    references=args.references.expanduser().resolve()
    out=args.out.expanduser()
    if out.is_symlink() or out.with_suffix(".md").is_symlink():
        parser.error("Refuse symlinked output")
    out=out.resolve()
    if out.suffix!=".json" or any(out==x or x in out.parents for x in (build,source)):
        parser.error("Diagnostic outputs cannot overwrite source or partial build")
    try:
        proof=stage3.build_matrix(
            stage3.stock.make_inventory(source,artifacts),
            stage3.build.audit(build,source,artifacts),
            stage3.types.run(build),
            stage3.fixes.compare(source,references),
            stage3.readiness.analyze(
                json.loads(stage3.readiness.EVIDENCE.read_text()),
                artifacts,source,stage3.ROOT)
        )
        base=objects.audit(build,source,artifacts)
        result=audit(build,proof,base)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
        out.with_suffix(".md").write_text(markdown(result))
    except (OSError,ValueError,KeyError,stage3.stock.InventoryError,
            stage3.build.AuditError,stage3.fixes.AuditError,
            stage3.readiness.GateError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[PINNED] Original Samsung HXL1 config/source and experimental build")
    for key,item in result["selectedObjectDiagnostics"].items():
        print("[OBJECT]",key,item["classification"])
        for name,findings in item.get("namedTypeDies",{}).items():
            print(" ",name,"named DIEs",len(findings),
                  "complete",sum(t["completeTypeDefinition"] for t in findings))
    print("[REPORT]",out)
    print("[LIMIT] Clang18 only; OEM offsets, GhostLock, root and KernelSU UNVERIFIED")
    return 0

if __name__=="__main__":
    sys.exit(main())
