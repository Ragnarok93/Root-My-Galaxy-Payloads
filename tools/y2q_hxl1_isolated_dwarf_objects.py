#!/usr/bin/env python3
"""Isolated experimental HXL1 Clang18 RT-mutex object build; no Image/root.

DRY-RUN unless --execute. Reuses the previously authenticated pristine
Samsung source + audited 4-patch clone + stock-matching Clang18 .config.
Make output goes into a BRAND NEW O= directory; the two targets are ONLY
kernel/locking/rtmutex.o and kernel/futex.o. This compiler-generated
DWARF can never establish Samsung's OEM Clang10 offsets or rootability.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

# Older Samsung build helpers use absolute sibling imports when loaded
# standalone, so expose the sibling tools path as well as the repository root.
TOOLS_DIR=Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0,str(TOOLS_DIR))
if not __package__:
    sys.path.insert(0,str(TOOLS_DIR.parent))

from tools import build_samsung_stock_kernel as prior
from tools import y2q_partial_samsung_dwarf_audit as elf_audit
from tools import y2q_dwarf_type_presence as dwarf
from tools import y2q_hxl1_dwarf_gap_triage as die_audit
from tools.prepare_samsung_vdso_compat import (
    verify_compat, ARM64_ALTERNATIVE, INIT_MAIN
)

TARGETS=("kernel/locking/rtmutex.o","kernel/futex.o")
DEFAULT_STOCK=Path.home()/"src/samsung-y2q-hxl1-stock"
DEFAULT_CLONE=Path.home()/"src/samsung-y2q-hxl1-vdso-ias-extable-compat"
DEFAULT_TEMPLATE=Path.home()/"src/samsung-y2q-hxl1-config-clang18"
DEFAULT_OUTPUT=Path.home()/"src/samsung-y2q-hxl1-rtmutex-dwarf-ias-clang18"
DEFAULT_LOG=Path.home()/"s20-artifacts/samsung-hxl1-rtmutex-dwarf-ias-01.log"
DEFAULT_REPORT=Path.home()/"s20-artifacts/hxl1-research/rtmutex-dwarf-ias-01.json"
DEFAULT_AUDIT=Path.home()/"s20-artifacts/samsung-hxl1-source-audit.json"

class TargetBuildError(ValueError):
    pass


def check_new_out(stock:Path,clone:Path,template:Path,out:Path)->None:
    if out.exists() or out.is_symlink():
        raise TargetBuildError("Refusing to reuse/overwrite prior O= directory: "+str(out))
    if not out.parent.is_dir() or out.parent.is_symlink():
        raise TargetBuildError("New O= parent must be a normal existing directory")
    if str(out).startswith("/mnt/"):
        raise TargetBuildError("Build output must use native WSL Linux filesystem")
    for used in (stock,clone,template):
        if out==used or out in used.parents or used in out.parents:
            raise TargetBuildError("O= must be separate from stock, clone and prior experimental objects")


def check_paths(stock:Path,clone:Path,template:Path,out:Path,log:Path,report:Path)->None:
    check_new_out(stock,clone,template,out)
    for path in (log,report):
        if (path.exists() or path.is_symlink() or
            not path.parent.is_dir() or path.parent.is_symlink()):
            raise TargetBuildError("Refusing existing/symlinked log/report or missing parent: "+str(path))
        if str(path).startswith("/mnt/") or path.suffix not in (".log",".json"):
            raise TargetBuildError("Log/report must be .log/.json on native WSL filesystem")
        for used in (stock,clone,template,out):
            if path==used or used in path.parents or path in used.parents:
                raise TargetBuildError("Log/report cannot overlap original/experimental source or build")


def make_common(clone:Path,out:Path,clang:Path,gcc_prefix:str,dtc:Path,
                jobs:int)->list[str]:
    if not 1<=jobs<=8:
        raise TargetBuildError("Diagnostic compilation allows only 1–8 jobs")
    opts=[
        "make","-C",str(clone),"O="+str(out),"ARCH=arm64",
        "CROSS_COMPILE="+gcc_prefix,
        "CLANG_TRIPLE=aarch64-linux-gnu-",
        "REAL_CC="+str(clang),"CFP_CC="+str(clang),
        "DTC_EXT="+str(dtc),"CONFIG_BUILD_ARM64_DT_OVERLAY=y",
    ]
    asm="--target=aarch64-linux-gnu -integrated-as"
    cflags=" ".join([
        asm,
        prior.CGROUP_SUPPRESSION,
        "--ld-path="+gcc_prefix+"ld",
        prior.CROSS_LINKER_UNUSED_ARG_SUPPRESSION,
        *(row[2] for row in prior.CORE_COMPAT_WARNINGS),
    ])
    return opts+["KCFLAGS="+cflags,"KAFLAGS="+asm,"V=1","-j"+str(jobs)]


def plan(args:argparse.Namespace)->dict:
    stock=args.source.expanduser().absolute()
    clone=args.clone.expanduser().absolute()
    template=args.template.expanduser().absolute()
    out=args.output.expanduser().absolute()
    log=args.log.expanduser().absolute()
    report=args.report.expanduser().absolute()
    check_paths(stock,clone,template,out,log,report)
    if not args.gcc_prefix.startswith("/") or not args.gcc_prefix.endswith("-"):
        raise TargetBuildError("Absolute AArch64 GCC tool prefix required")
    gcc=Path(args.gcc_prefix+"gcc")
    ld=Path(args.gcc_prefix+"ld")
    clang=args.clang.expanduser().resolve()
    dtc=clone/"tools/dtc"
    for executable in (clang,gcc,ld,dtc):
        if not executable.is_file() or not os.access(executable,os.X_OK):
            raise TargetBuildError("Pinned compiler/linker/DTC executable missing: "+str(executable))
    if not template.is_dir() or template.is_symlink():
        raise TargetBuildError("Prior Clang18 O= template absent or linked")
    cfg=template/".config"
    if cfg.is_symlink() or not cfg.is_file() or prior.sha256_file(cfg)!=prior.GENERATED_CONFIG_SHA256:
        raise TargetBuildError("Original experimental Clang18 .config hash does not match HXL1")
    if prior.sha256_file(stock/"Makefile")!=prior.MAKEFILE_SHA256:
        raise TargetBuildError("Stock original Samsung Makefile hash changed")
    audit=prior.source_preflight_run(argparse.Namespace(
        source_dir=stock,audit_json=args.audit,
        clang_path=clang,gcc_prefix=args.gcc_prefix,linker_path=ld,
    ))
    if (not audit["makefileVersion"]["matchesExpected"] or
        audit["overlayVerification"]["verified"]!=40 or
        any(not x["matchesOfficialAudit"] for x in audit["deviceConfigs"].values())):
        raise TargetBuildError("Original audited source/overlay preflight invalid")
    manifest=verify_compat(stock,clone)
    if (manifest.get("schema")!=3 or
        set(manifest.get("patches",{}))!={*__import__("tools.prepare_samsung_vdso_compat",fromlist=["PATCHES"]).PATCHES,
            INIT_MAIN,ARM64_ALTERNATIVE}):
        raise TargetBuildError("Four-patch cloned source manifest or IAS fix not authenticated")
    python2=prior.find_python2(args.python2)
    if not python2:
        raise TargetBuildError("Real Python 2.7 required for legacy Samsung Kbuild")
    commands=make_common(clone,out,clang,args.gcc_prefix,dtc,args.jobs)
    return {
        "firmware":"G986U1UESCHXL1",
        "source":str(stock),
        "experimentalClang18Source":str(clone),
        "previousClang18OutputUntouched":str(template),
        "freshOutput":str(out),
        "originalConfigTemplate":str(cfg),
        "pinnedConfigSha256":prior.GENERATED_CONFIG_SHA256,
        "stockSourceTreeSha256":manifest["stockTreeSha256"],
        "experimentalSourceTreeSha256":manifest["compatTreeSha256"],
        "sourcePatchFiles":sorted(manifest["patches"]),
        "compiler":str(clang),
        "targetOutputs":list(TARGETS),
        "prepare":commands+["olddefconfig"],
        "prepareArch":commands+["prepare"],
        "objectCommand":commands+list(TARGETS),
        "python2":python2,
        "log":str(log),"report":str(report),
        "executeRequested":bool(args.execute),
        "experimentalOnly":True,
        "factoryCompiledOffsetsVerified":False,
        "physicalKernelBaseKnown":False,
        "rootOrKernelSUInstalled":False,
    }


def inspect_targets(out:Path)->dict:
    obs={}
    for target in TARGETS:
        obj=out/target
        if obj.is_symlink() or not obj.is_file():
            obs[target]={"status":"NOT_PRODUCED"}
            continue
        if obj.stat().st_size>64*1024*1024:
            obs[target]={"status":"OBJECT_TOO_LARGE"}
            continue
        elf=elf_audit.arm64_object(obj)
        record={"status":elf["kind"],"sha256":prior.sha256_file(obj),
                "hasDwarf":elf.get("hasDwarf",False),
                "factoryLayoutAuthenticated":False}
        if elf["kind"]=="ARM64_REL":
            record["paholeTypePresence"]={
                t:dwarf.probe(obj,t)["status"]
                for t in dwarf.STRUCTS
            }
            # Type declarations only; no layouts/size/member locations copied.
            diagnostic=die_audit.inspect_object(out,target)
            record["readelfNamedTypes"]={
                type_name:{
                    "numberOfDIEs":len(rows),
                    "completeDefinitions":sum(bool(x["completeTypeDefinition"])
                                              for x in rows)}
                for type_name,rows in diagnostic.get("namedTypeDies",{}).items()
            }
        obs[target]=record
    return obs


def execute(info:dict)->dict:
    output=Path(info["freshOutput"])
    template=Path(info["originalConfigTemplate"])
    log=Path(info["log"])
    output.mkdir(mode=0o755,exist_ok=False)
    shutil.copyfile(template,output/".config")
    if prior.sha256_file(output/".config")!=info["pinnedConfigSha256"]:
        raise TargetBuildError("New O= .config copy differs before Kbuild")
    status={"phase":"initialized","phaseResults":[]}
    environment=dict(os.environ)
    environment["PATH"]=str(Path(info["python2"]).parent)+os.pathsep+environment.get("PATH","")
    try:
        with log.open("x",encoding="utf-8",errors="replace") as lf:
            for phase,field in (("olddefconfig","prepare"),("headers","prepareArch"),
                                ("target-objects","objectCommand")):
                command=info[field]
                lf.write("PHASE="+phase+"\nCOMMAND="+json.dumps(command)+"\n")
                lf.flush()
                try:
                    proc=subprocess.run(command,cwd=None,env=environment,
                                        stdout=lf,stderr=subprocess.STDOUT,
                                        text=True,timeout=3600,check=False)
                    rc=proc.returncode
                except subprocess.TimeoutExpired:
                    rc=124
                lf.write("\nEXIT_CODE="+str(rc)+"\n")
                lf.flush()
                status["phaseResults"].append({"phase":phase,"returnCode":rc})
                if rc!=0:
                    status["phase"]="COMPILATION_FAILED_"+phase
                    break
                if prior.sha256_file(output/".config")!=info["pinnedConfigSha256"]:
                    status["phase"]="PINNED_CONFIG_CHANGED_"+phase
                    break
            else:
                status["phase"]="TARGET_COMMAND_COMPLETED"
    finally:
        status["targetInspection"]=inspect_targets(output)
    status.update({
        "kernelImageCompiled":False,"rootOrKernelSUInstalled":False,
        "sourceTreeModifiedByTool":False,
        "factoryAbiAuthenticated":False,
        "liveKernelAddressesLearned":False
    })
    return status


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=DEFAULT_STOCK)
    p.add_argument("--clone",type=Path,default=DEFAULT_CLONE)
    p.add_argument("--template",type=Path,default=DEFAULT_TEMPLATE)
    p.add_argument("--output",type=Path,default=DEFAULT_OUTPUT)
    p.add_argument("--log",type=Path,default=DEFAULT_LOG)
    p.add_argument("--report",type=Path,default=DEFAULT_REPORT)
    p.add_argument("--audit",type=Path,default=DEFAULT_AUDIT)
    p.add_argument("--clang",type=Path,default=Path("/usr/bin/clang"))
    p.add_argument("--gcc-prefix",default="/usr/bin/aarch64-linux-gnu-")
    p.add_argument("--python2",type=Path)
    p.add_argument("--jobs",type=int,default=2)
    p.add_argument("--execute",action="store_true")
    args=p.parse_args()
    try:
        info=plan(args)
        print("[VALIDATED ORIGINAL SOURCE]",info["stockSourceTreeSha256"])
        print("[VALIDATED EXACT FOUR-PATCH CLONE]",info["experimentalSourceTreeSha256"])
        print("[CLANG18 CONFIG]",info["pinnedConfigSha256"])
        for key in ("prepare","prepareArch","objectCommand"):
            print("[MAKE]",key,json.dumps(info[key]))
        if args.execute:
            prior.check_arm64_integrated_assembler(Path(info["compiler"]))
            prior.check_cgroup_layout_warning_compat(Path(info["compiler"]))
            prior.check_arm64_cross_linker(Path(info["compiler"]),
                                          Path(args.gcc_prefix+"ld"))
            prior.check_legacy_core_warnings(Path(info["compiler"]))
            print("[PROBES] Clang18 AArch64 assembler, linker and warning categories verified")
            result=execute(info)
            info["result"]=result
            with Path(info["report"]).open("x") as f:
                json.dump(info,f,indent=2)
                f.write("\n")
            print("[BUILD STATUS]",result["phase"])
            for name,value in result["targetInspection"].items():
                print("[OBJECT]",name,value)
            print("[LOG]",info["log"])
            print("[REPORT]",info["report"])
            print("[LIMIT] Experimental Clang18 type data, NOT factory offsets or root")
            if result["phase"]!="TARGET_COMMAND_COMPLETED":
                return 1
        else:
            print("[DRY RUN ONLY] No output source, old object or phone modified")
        return 0
    except (OSError,ValueError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
