#!/usr/bin/env python3
"""One-command HXL1 Stage 1–9 research-port evidence pipeline.

Runs *existing*, source-pinned, off-device verification/build utilities in
dependency order and emits one immutable, actionable porting gate report.
It does not pretend that an ABI inferred from Clang18 is factory Clang10;
does not invent a CVE primitive, hardware unlock, KernelSU loader or device
privileges. It NEVER flashes, contacts ADB/fastboot, launches guest QEMU,
mutates stock source, publishes an app feed or produces an active root payload.

Usage:
 python3 tools/y2q_hxl1_porting_automation.py --mode plan
 python3 tools/y2q_hxl1_porting_automation.py --mode run
"""
from __future__ import annotations
import argparse
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Optional

REPO=Path(__file__).resolve().parents[1]
ARTIFACTS=Path.home()/"s20-artifacts"
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
PINNED_KERNEL="ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
PINNED_CONFIG="1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd"
MAX_LOG=768*1024
MAX_REPORT=4*1024*1024
INCOMPLETE={"OPEN","PARTIAL","BLOCKED","DEFERRED"}
STAGE_NAMES={
    1:"Firmware identity",2:"Original firmware/source provenance",
    3:"Exact factory kernel structure and symbol ABI",
    4:"Physical bootloader handoff",5:"Runtime exploit parameters",
    6:"Native HXL1 profile and diagnostic",
    7:"KernelSU Linux 4.19 authorization and compatibility",
    8:"Production app/feed",9:"Recovery and release",
}

class PipelineError(ValueError):pass

@dataclass(frozen=True)
class Step:
    id:str
    stage:int
    script:str
    args:tuple[str,...]
    output:str|None
    dependencies:tuple[str,...]=()
    inputs:tuple[str,...]=()
    optional:bool=False

def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def check_factory_inputs(artifacts:Path)->dict:
    checks={}
    for name,pin in (("kernel.bin",PINNED_KERNEL),("config.gz",PINNED_CONFIG)):
        path=artifacts/name
        if not path.is_file() or path.is_symlink():
            checks[name]={"state":"MISSING_OR_UNSAFE","expectedSha256":pin}
            continue
        measured=sha256(path)
        checks[name]={"state":"VERIFIED" if measured==pin else "SHA256_MISMATCH",
                      "expectedSha256":pin,"actualSha256":measured}
    return checks

def tasks(repo:Path,artifacts:Path,source:Path,out:Path,ndk:Path|None)->list[Step]:
    script=lambda n:str(repo/"tools"/n)
    path=lambda name:str(out/name)
    scan=path("05-cve-source-candidate.json")
    diag=path("y2q-G986U1UESCHXL1-identity-diagnostic.so")
    binary=path("06-hxl1-identity-manifest.json")
    ndk_arg=str(ndk) if ndk else str(out/"MISSING_NDK")
    # All output paths are in this run's fresh directory; a step never
    # attempts to overwrite earlier forensic reports.
    return [
        Step("01_readiness",1,script("y2q_porting_readiness.py"),
             ("--source",str(source),"--artifacts",str(artifacts),"--repo",str(repo),
              "--output",path("01-port-readiness.json")),path("01-port-readiness.json"),
             inputs=("research/y2q-G986U1UESCHXL1/evidence.json",)),
        Step("03_layout",3,script("y2q_stage3_layout_inventory.py"),
             ("--source",str(source),"--artifacts",str(artifacts),
              "--output",path("03-stock-layout-inventory.json")),
             path("03-stock-layout-inventory.json")),
        Step("03_proof_matrix",3,script("y2q_hxl1_kernel_proof_matrix.py"),
             ("--source",str(source),"--artifacts",str(artifacts),
              "--output",path("03-factory-abi-proof-matrix.json")),
             path("03-factory-abi-proof-matrix.json")),
        Step("03_clang10_checkpoint",3,script("y2q_hxl1_clang10_checkpoint.py"),
             ("--artifacts",str(artifacts),
              "--comparison",str(artifacts/"hxl1-research/clang10-abi-comparison"),
              "--output",path("03-clang10-evidence-checkpoint.json")),
             path("03-clang10-evidence-checkpoint.json"),
             inputs=(str(artifacts/"hxl1-research/clang10-abi-comparison/factory-displacement-comparison.json"),),
             optional=True),
        Step("03_export_table",3,script("y2q_export_table_audit.py"),
             ("--kernel-bin",str(artifacts/"kernel.bin"),
              "--nm",str(artifacts/"hxl1-research/vmlinux-stock.nm"),
              "--config-gz",str(artifacts/"config.gz"),
              "--source-dir",str(source)),None),
        Step("04_boot_v2",4,script("y2q_stock_boot_v2_audit.py"),
             ("--artifacts",str(artifacts),"--output",path("04-stock-boot-v2.json")),
             path("04-stock-boot-v2.json")),
        Step("04_fdt_semantics",4,script("y2q_stock_fdt_semantic_audit.py"),
             ("--artifacts",str(artifacts),"--output",path("04-stock-fdt-semantics.json")),
             path("04-stock-fdt-semantics.json")),
        Step("05_ghostlock_binary",5,script("y2q_ghostlock_static_audit.py"),
             ("--kernel-bin",str(artifacts/"kernel.bin"),
              "--nm",str(artifacts/"hxl1-research/vmlinux-stock.nm"),
              "--analysis",str(artifacts/"hxl1-research/ghostlock-upstream-analysis-isolated.txt"),
              "--diagnostics",str(artifacts/"hxl1-research/ghostlock-upstream-diagnostics-isolated.txt"),
              "--output",path("05-ghostlock-original-binary.json")),
             path("05-ghostlock-original-binary.json"),
             inputs=(str(artifacts/"hxl1-research/ghostlock-upstream-analysis-isolated.txt"),
                     str(artifacts/"hxl1-research/ghostlock-upstream-diagnostics-isolated.txt")),
             optional=True),
        Step("05_source_candidate",5,script("y2q_research_toolchain.py"),
             ("scan","--audit-json",str(artifacts/"samsung-hxl1-source-audit.json"),
              "--stock-source",str(source),
              "--kernel-bin",str(artifacts/"kernel.bin"),
              "--boot-img",str(artifacts/"boot.img"),
              "--output",scan),scan,optional=True),
        Step("06_build_identity_only",6,script("y2q_research_toolchain.py"),
             ("build-probe","--scan-report",scan,"--ndk",ndk_arg,
              "--output",diag,"--manifest",binary),diag,
             dependencies=("05_source_candidate",),optional=True),
        Step("06_bundle_identity_only",6,script("y2q_research_toolchain.py"),
             ("bundle","--scan-report",scan,"--library",diag,
              "--manifest",binary,"--output",path("06-hxl1-diagnostics-only.zip")),
             path("06-hxl1-diagnostics-only.zip"),
             dependencies=("05_source_candidate","06_build_identity_only"),optional=True),
    ]

def validate_plan(steps:list[Step],out:Path,repo:Path,source:Path)->None:
    ids=[s.id for s in steps]
    if len(ids)!=len(set(ids)):raise PipelineError("Duplicate task identity")
    previous=set()
    for s in steps:
        if s.stage not in STAGE_NAMES or not s.script.startswith(str(repo/"tools")+"/"):
            raise PipelineError("Task outside tools or stage map")
        if not Path(s.script).is_file():raise PipelineError("Missing repository tool: "+s.script)
        if any(parent not in previous for parent in s.dependencies):
            raise PipelineError("Invalid dependency order in "+s.id)
        if s.output:
            p=Path(s.output)
            if p.parent!=out or p.is_symlink():
                raise PipelineError("Refuse external/symlinked output")
        previous.add(s.id)
    if out==source or source in out.parents or out==repo or repo in out.parents:
        raise PipelineError("Refuse outputs inside stock source or Git checkout")
    if out.is_symlink() or out.exists():
        raise PipelineError("Run output directory must be new: "+str(out))

def safe_text(output:str|bytes|None)->str:
    if output is None:return ""
    if isinstance(output,bytes):output=output.decode("utf8","replace")
    return output[-MAX_LOG:]

def run_step(step:Step, statuses:dict[str,str],log_dir:Path,
             timeout:int,env:dict[str,str])->dict:
    skipped=[key for key in step.dependencies if statuses.get(key)!="PASS"]
    result={"id":step.id,"stage":step.stage,
            "script":Path(step.script).name,
            "command":[sys.executable,step.script,*step.args],
            "status":"NOT_RUN","output":step.output,
            "rootOrKernelSuProven":False}
    if skipped:
        result.update(status="SKIP_DEPENDENCY",
                      reason="Prerequisite did not pass: "+", ".join(skipped))
        return result
    missing=[name for name in step.inputs if Path(name).is_absolute() and
             (not Path(name).is_file() or Path(name).is_symlink())]
    if missing and step.optional:
        result.update(status="SKIP_MISSING_PREREQUISITE",
                      reason="Original optional inputs not available: "+", ".join(missing))
        return result
    if step.id=="06_build_identity_only" and not (
            Path(step.args[4]).is_dir()):
        result.update(status="SKIP_MISSING_PREREQUISITE",
                      reason="Verified Android NDK path is not available")
        return result
    try:
        proc=subprocess.run([sys.executable,step.script,*step.args],
                            cwd=REPO,capture_output=True,text=True,
                            timeout=timeout,env=env,check=False)
        result["exitCode"]=proc.returncode
        content=safe_text(proc.stdout+"\n"+proc.stderr)
        (log_dir/(step.id+".log")).write_text(content)
        result["logFile"]=str(log_dir/(step.id+".log"))
        if proc.returncode!=0:
            result.update(status="FAIL",reason="Verifier/tool exited nonzero; inspect saved log")
        elif step.output and not Path(step.output).is_file():
            result.update(status="FAIL",reason="Tool succeeded without declared output")
        else:
            result["status"]="PASS"
            if step.output:
                result["sha256"]=sha256(Path(step.output))
    except (OSError,subprocess.TimeoutExpired) as exc:
        result.update(status="FAIL",reason=type(exc).__name__,
                      detail=safe_text(getattr(exc,"stderr",None)))
        (log_dir/(step.id+".log")).write_text(str(exc))
    return result

def validate_readiness(document:dict)->list[dict]:
    gates=document.get("gates")
    if (document.get("profile")!="y2q-G986U1UESCHXL1" or
        not isinstance(gates,list) or len(gates)!=9 or
        [g.get("stage") for g in gates]!=list(range(1,10)) or
        any(g.get("state") not in (INCOMPLETE|{"COMPLETE"}) for g in gates)):
        raise PipelineError("Baseline readiness report identity or stage shape invalid")
    if (document.get("payloadPortCompleted") is not False or
        document.get("temporaryRootVerified") is not False or
        document.get("kernelSuLoaded") is not False or
        document.get("includedInProductionFeed") is not False):
        raise PipelineError("Unexpected deployability claim in HXL1 source readiness")
    return [{"stage":i["stage"],"name":i["title"],"state":i["state"],
             "neededProof":i.get("nextProof")} for i in gates]

def summarize(manifest:dict)->str:
    lines=[
        "# HXL1 automated firmware-to-profile evidence run",
        "",
        "**This run cannot confer or prove root, KernelSU, bootloader unlock, or production readiness.**",
        f"Run: `{manifest['runId']}`",
        f"Stock original SHA verification: `{manifest['inputIntegrity']}`",
        "",
        "## Actual steps",
        "",
        "| Step | Stage | Result |",
        "|---|---:|---|",
    ]
    for step in manifest["steps"]:
        lines.append(f"| `{step['id']}` | {step['stage']} | {step['status']} |")
    lines += ["","## PORTING.md nine-stage gates","",
              "| Stage | Requirement | State |",
              "|---:|---|---|"]
    for i in manifest["stages"]:
        lines.append(f"| {i['stage']} | {i['name']} | {i['state']} |")
    lines += ["","## Remaining required proofs",""]
    for i in manifest["stages"]:
        if i["state"]!="COMPLETE":
            lines.append(f"- **Stage {i['stage']}:** {i['neededProof'] or 'Independent validation required'}")
    lines += ["","## What this pipeline cannot auto-assert","",
              "- Exact compiled **factory** ABI offsets do not follow from experimental Clang18 DWARF.",
              "- Static RT-mutex bug pattern is not live GhostLock exploitation or controlled kernel privileges.",
              "- Original QEMU virt kernel faults and secure-monitor requests do not establish physical root or Samsung secure-world behavior.",
              "- An unsigned KernelSU 4.19 module is not made loadable by a passing diagnostic.",
              "- No bootloader flash, physical-device changes, or support-feed publication are performed.",
              ""]
    return "\n".join(lines)

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","run"),default="run")
    p.add_argument("--artifacts",type=Path,default=ARTIFACTS)
    p.add_argument("--source",type=Path,default=SOURCE)
    p.add_argument("--ndk",type=Path,default=(
        Path(os.environ["ANDROID_NDK_HOME"]) if os.environ.get("ANDROID_NDK_HOME") else None))
    p.add_argument("--output-dir",type=Path,default=None)
    p.add_argument("--timeout-per-step",type=int,default=150)
    a=p.parse_args()
    try:
        if not 20<=a.timeout_per_step<=900:
            raise PipelineError("Choose bounded per-step timeout (20..900 seconds)")
        artifacts=a.artifacts.expanduser().absolute()
        source=a.source.expanduser().absolute()
        ndk=a.ndk.expanduser().absolute() if a.ndk else None
        stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        out=(a.output_dir.expanduser().absolute() if a.output_dir
             else artifacts/"hxl1-research"/("port-automation-"+stamp))
        pipeline=tasks(REPO,artifacts,source,out,ndk)
        validate_plan(pipeline,out,REPO,source)
        for row in pipeline:
            print("[PLAN]",row.id,"stage",row.stage,
                  "deps",",".join(row.dependencies) or "none")
        if a.mode=="plan":
            print("[NO EXECUTION] All proposed steps are off-device; outputs would be",out)
            return 0
        integrity=check_factory_inputs(artifacts)
        if any(item["state"]!="VERIFIED" for item in integrity.values()):
            raise PipelineError("Original factory kernel/config hash missing/mismatch; no analysis executed: "+
                                json.dumps(integrity))
        out.mkdir(parents=True,exist_ok=False)
        logs=out/"logs"
        logs.mkdir()
        # Disable incidental Python .pyc writes to source checkout.
        env=dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"]="1"
        status={}
        results=[]
        for task in pipeline:
            result=run_step(task,status,logs,a.timeout_per_step,env)
            status[task.id]=result["status"]
            results.append(result)
            print("[STEP]",task.id,result["status"])
        readiness_path=out/"01-port-readiness.json"
        stages=[]
        readiness_error=None
        if status.get("01_readiness")=="PASS":
            try:
                raw=readiness_path.read_bytes()
                if len(raw)>MAX_REPORT:raise PipelineError("Readiness report too large")
                stages=validate_readiness(json.loads(raw))
            except (OSError,ValueError,KeyError,TypeError) as e:
                readiness_error=str(e)
        if not stages:
            stages=[{"stage":n,"name":name,"state":"UNVERIFIED",
                     "neededProof":"Baseline readiness could not be independently established"}
                    for n,name in STAGE_NAMES.items()]
        manifest={
            "schemaVersion":1,
            "runId":out.name,
            "target":"SM-G986U1/G986U1UESCHXL1",
            "source":"docs/PORTING.md",
            "mode":"host-only read-only evidence + optional unprivileged identity diagnostic build",
            "inputIntegrity":integrity,
            "steps":results,
            "stages":stages,
            "baselineReadinessError":readiness_error,
            "proofLimitations":{
                "factoryAbiFullyVerified":False,
                "runtimeCveExploitationVerified":False,
                "authorizedKernelSuInstalled":False,
                "oemBootloaderUnlocked":False,
                "publishedInProductionFeed":False,
                "phoneChanged":False,
            },
        }
        report=out/"port-automation.json"
        report.write_text(json.dumps(manifest,indent=2)+"\n")
        (out/"port-automation.md").write_text(summarize(manifest))
        print("[NINE-STAGE]",[(s["stage"],s["state"]) for s in stages])
        print("[ROOT / KERNELSU / DEPLOYMENT] NOT VERIFIED")
        print("[REPORT]",out/"port-automation.md")
        print("[JSON]",report)
        return 0 if readiness_error is None and all(
            x["status"]!="FAIL" for x in results) else 2
    except (OSError,PipelineError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
