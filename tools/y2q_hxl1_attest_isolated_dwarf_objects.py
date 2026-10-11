#!/usr/bin/env python3
"""HXL1: independently attest the newly successful two-object Clang18 build.

Read-only post-build verification of the exact owner Oct 10/11 2026
run. Independently compares the original compiler report to actual object
bytes, validates the 4-patch source manifest, output .config, compiler
phases, retained Kbuild .cmd records, both pahole probes and named DWARF
structure DIEs. NO factory offsets, CVE payload, KernelSU or device I/O.

This is intentionally a *separate* frozen result from the older failed/
partial Clang18 build. Existing Stage-3 reports remain historical.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys

TOOLS_DIR=Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0,str(TOOLS_DIR))
if not __package__:
    sys.path.insert(0,str(TOOLS_DIR.parent))

from tools import y2q_hxl1_isolated_dwarf_objects as build
from tools import y2q_hxl1_dwarf_gap_triage as debug
from tools.prepare_samsung_vdso_compat import verify_compat
from tools import build_samsung_stock_kernel as source

# Original console evidence, Oct 10/11, 2026. Treat these digests as
# immutable build-output identities; never derive them from the report.
PINNED_OBJECTS={
    "kernel/locking/rtmutex.o":"12279b4dfdf74425c47ef3514540ab1333fff1045fd6b066d378714707eed1f2",
    "kernel/futex.o":"9adcfff8a44180d47bdb9f0ec40fb7ca646343eea939f74609f70b9975342e53",
}
TARGET_TYPES=("rt_mutex_waiter","rt_mutex")
PHASES=("olddefconfig","headers","target-objects")
SOURCE_SHA="d8a04e191bd0df1521c5483dab441a71279e978ea207ea57681c1cfc49b4e11d"
COMPAT_SHA="354b9f0e32a0b890babbc06470d9f9beb0cc2e8d069d7c73cdf5f6e2e9f0af5f"
CONFIG_SHA="97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09"
RUN_CLASS="EXPERIMENTAL_HXL1_CLANG18_TARGET_OBJECT_DWARF_NOT_FACTORY_ABI"
DEFAULT_REPORT=build.DEFAULT_REPORT
DEFAULT_OUT=Path.home()/"s20-artifacts/hxl1-research/rtmutex-dwarf-ias-01-attested.json"

class AttestationError(ValueError):
    pass

def require(condition:bool,msg:str)->None:
    if not condition:
        raise AttestationError("HXL1 object attestation rejected: "+msg)

def load_evidence(path:Path)->dict:
    require(path.is_file() and not path.is_symlink(),"saved compiler JSON missing or symlinked")
    if path.stat().st_size>4*1024*1024:
        raise AttestationError("compiler JSON unreasonably large")
    result=json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(result,dict),"compiler JSON must be an object")
    return result

def verify_report(data:dict)->dict:
    """Pure validation of report fields; don't trust labels as measurements."""
    require(data.get("firmware")=="G986U1UESCHXL1","exact stock firmware identity")
    require(data.get("stockSourceTreeSha256")==SOURCE_SHA,"source digest")
    require(data.get("experimentalSourceTreeSha256")==COMPAT_SHA,"clone digest")
    require(data.get("pinnedConfigSha256")==CONFIG_SHA,"experimental config hash")
    require(data.get("executeRequested") is True,"must be a real executed run")
    require(data.get("factoryCompiledOffsetsVerified") is False and
            data.get("physicalKernelBaseKnown") is False and
            data.get("rootOrKernelSUInstalled") is False,
            "factory/runtime/root boundary")
    require(data.get("targetOutputs")==list(build.TARGETS),
            "exact two-target Kbuild command set")
    commands=data.get("objectCommand")
    require(isinstance(commands,list) and len(commands)>2 and
            commands[-2:]==list(build.TARGETS) and
            all(isinstance(x,str) for x in commands) and
            "Image" not in commands and "modules" not in commands,
            "object command target selection")
    require(sum(x.startswith("O=") for x in commands)==1 and
            any(x=="ARCH=arm64" for x in commands),"AArch64 O= provenance")
    result=data.get("result")
    require(isinstance(result,dict) and
            result.get("phase")=="TARGET_COMMAND_COMPLETED",
            "the complete three-phase target compilation")
    phases=result.get("phaseResults")
    require(isinstance(phases,list) and
            [(p.get("phase"),p.get("returnCode")) for p in phases
             if isinstance(p,dict)]==[(p,0) for p in PHASES] and
            len(phases)==len(PHASES),
            "olddefconfig, prepare and target compile return codes")
    require(result.get("factoryAbiAuthenticated") is False and
            result.get("kernelImageCompiled") is False and
            result.get("rootOrKernelSUInstalled") is False,
            "build result must remain experimental")
    stored=result.get("targetInspection")
    require(isinstance(stored,dict) and
            set(stored)==set(PINNED_OBJECTS),
            "both original compiled object records")
    for rel,pin in PINNED_OBJECTS.items():
        record=stored[rel]
        require(record.get("status")=="ARM64_REL" and
                record.get("sha256")==pin and
                record.get("hasDwarf") is True and
                record.get("factoryLayoutAuthenticated") is False,
                "saved AArch64/DWARF identity: "+rel)
        require(record.get("paholeTypePresence")=={
            name:"PRESENT" for name in TARGET_TYPES
        },"saved pahole complete definitions: "+rel)
        named=record.get("readelfNamedTypes")
        require(isinstance(named,dict) and set(named)==set(TARGET_TYPES) and
                all(named[name].get("numberOfDIEs")==1 and
                    named[name].get("completeDefinitions")==1
                    for name in TARGET_TYPES),
                "saved readelf complete definitions: "+rel)
    return stored


def check_source_and_objects(data:dict,report_path:Path)->dict:
    """Independently rehash output .config/.o and rescan ELF and exact types."""
    saved=verify_report(data)
    original=Path(data["source"])
    clone=Path(data["experimentalClang18Source"])
    output=Path(data["freshOutput"])
    template=Path(data["originalConfigTemplate"])
    for p in (original,clone,output):
        require(p.is_dir() and not p.is_symlink(),"source/build tree absent or linked")
    manifest=verify_compat(original,clone)
    require(manifest.get("schema")==3 and
            manifest.get("stockTreeSha256")==SOURCE_SHA and
            manifest.get("compatTreeSha256")==COMPAT_SHA,
            "immutable four-patch source manifest")
    require(output!=(original) and output!=(clone) and
            original not in output.parents and clone not in output.parents,
            "build output must not overlap source")
    require(report_path==build.DEFAULT_REPORT,
            "only the expected original owner's one-time report is attested")
    log=Path(data.get("log",""))
    require(log==build.DEFAULT_LOG and log.is_file() and not log.is_symlink(),
            "original phase compiler log identity/availability")
    require(log.stat().st_size<=256*1024*1024,
            "original phase compiler log exceeds attestation bound")
    content=log.read_text(encoding="utf-8",errors="replace")
    actual_phases=re.findall(r"(?m)^PHASE=(\\S+)$",content)
    actual_exits=re.findall(r"(?m)^EXIT_CODE=(-?\\d+)$",content)
    require(tuple(actual_phases)==PHASES and
            actual_exits==["0","0","0"],
            "compiler log disagrees with saved JSON phase results")
    cfg=output/".config"
    require(cfg.is_file() and not cfg.is_symlink() and
            source.sha256_file(cfg)==CONFIG_SHA and
            template.is_file() and source.sha256_file(template)==CONFIG_SHA,
            "copied and original pinned Clang18 .config")
    command=data["objectCommand"]
    require("O="+str(output) in command and
            "-C" in command and
            command[command.index("-C")+1]==str(clone),
            "compiler Kbuild command is attached to the verified output and clone")
    observations={}
    for rel,sha in PINNED_OBJECTS.items():
        path=output/rel
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size<=64*1024*1024,
                "object missing, linked or oversized: "+rel)
        require(source.sha256_file(path)==sha,
                "compiled object SHA256 mismatch: "+rel)
        record=build.elf_audit.arm64_object(path)
        require(record.get("kind")=="ARM64_REL" and
                record.get("hasDwarf") is True,
                "must be real AArch64 relocatable with DWARF: "+rel)
        cmd=debug.cmd_diagnostic(output,rel)
        require(cmd.get("present") is True,
                "actual Kbuild .o.cmd missing: "+rel)
        probe=debug.inspect_object(output,rel)
        require(probe.get("classification")=="EXPERIMENTAL_COMPLETE_DIE_FOUND" and
                probe.get("readelfSucceeded") is True and
                probe.get("factoryLayoutAuthenticated") is False,
                "independent readelf report not complete: "+rel)
        die={}
        for typ in TARGET_TYPES:
            entries=probe.get("namedTypeDies",{}).get(typ,[])
            require(len(entries)==1 and
                    entries[0].get("completeTypeDefinition") is True and
                    entries[0].get("hasByteSizeAttribute") is True,
                    "missing complete DWARF DIE in "+rel+": "+typ)
            status=build.dwarf.probe(path,typ)["status"]
            require(status=="PRESENT","pahole independently missing "+typ+" from "+rel)
            die[typ]={"completeDefinitions":1,"paholeStatus":status,
                      "originalFactoryAbiProven":False}
        observations[rel]={
            "sha256":sha,"elfType":"AArch64 ET_REL",
            "originalFactoryStructureLayoutProven":False,
            "separateKbuildCommandRetained":True,
            "experimentalDWARFTypes":die,
            "previousCompilerRecordCorroboratesBytes":saved[rel]["sha256"]==sha,
        }
    return {
        "classification":RUN_CLASS,
        "device":"SM-G986U1",
        "firmware":"G986U1UESCHXL1",
        "stockOriginalTreeSha256":SOURCE_SHA,
        "exactFourPatchCloneSha256":COMPAT_SHA,
        "experimentalBuildConfigSha256":CONFIG_SHA,
        "phaseExitCodes":[{"phase":p,"returnCode":0} for p in PHASES],
        "independentlyRecheckedBuildLogSha256":source.sha256_file(log),
        "independentlyValidatedObjects":observations,
        "crossObjectCompleteTypePresenceAgrees":True,
        "actualFactoryLayoutProven":False,
        "provenRuntimeKernelAddress":False,
        "onDeviceCveExploitApplicable":False,
        "kernelSUInstalled":False,
        "buildOrPhoneModifiedByAttestation":False,
    }

def markdown(result:dict)->str:
    out=[
        "# HXL1 exact experimental Clang18 RT-mutex object attestation",
        "",
        "Stock firmware: SM-G986U1 / G986U1UESCHXL1.",
        "Original source digest: "+result["stockOriginalTreeSha256"],
        "Four-patch clone digest: "+result["exactFourPatchCloneSha256"],
        "Copied .config digest: "+result["experimentalBuildConfigSha256"],
        "Original compiler log digest: "+result["independentlyRecheckedBuildLogSha256"],
        "",
        "| Original target | Original SHA256 | DWARF rt_mutex | DWARF rt_mutex_waiter |",
        "|---|---|---|---|",
    ]
    for name,v in result["independentlyValidatedObjects"].items():
        out.append("| "+name+" | \`"+v["sha256"]+"\` | Complete in Clang18 | Complete in Clang18 |")
    out+=["","Three observed compilation phases completed with exit code 0.",
          "Pahole and readelf independently find both types complete in each target.",
          "Exact original object bytes match the owner's saved build report.",
          "Kbuild .cmd files are retained for both targets.",
          "",
          "**Factory ABI equivalence is NOT established.**",
          "No stock factory compiled member offsets, runtime load/KASLR,",
          "on-device vulnerability reproduction, KernelSU or root were validated.",
          "Nothing in this read-only pass modifies the build or phone.",
          ""]
    return "\n".join(out)

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report",type=Path,default=DEFAULT_REPORT)
    parser.add_argument("--out",type=Path,default=DEFAULT_OUT)
    args=parser.parse_args()
    original=args.report.expanduser().absolute()
    dest=args.out.expanduser().absolute()
    if (dest.exists() or dest.is_symlink() or
        dest.with_suffix(".md").exists() or dest.with_suffix(".md").is_symlink() or
        dest.suffix!=".json" or
        not dest.parent.is_dir() or dest.parent.is_symlink()):
        parser.error("Attestation report outputs must be fresh, separate JSON/Markdown files")
    try:
        doc=check_source_and_objects(load_evidence(original),original)
        with dest.open("x",encoding="utf-8") as out:
            json.dump(doc,out,indent=2)
            out.write("\n")
        with dest.with_suffix(".md").open("x",encoding="utf-8") as out:
            out.write(markdown(doc))
    except (AttestationError,OSError,ValueError,KeyError) as err:
        print("[STOP]",err,file=sys.stderr)
        return 2
    print("[VERIFIED] Two SHA256-pinned AArch64 relocatables built with experimental Clang18")
    print("[VERIFIED] 2x2 complete RT-mutex type declarations: readelf + pahole")
    print("[VERIFIED] Stock source and four-patch clone, pinned .config and 3 Kbuild phases")
    print("[REPORT]",dest.with_suffix(".md"))
    print("[LIMIT] Factory Clang10 ABI, physical load, CVE, root and KernelSU unverified")
    return 0

if __name__=="__main__":
    sys.exit(main())
