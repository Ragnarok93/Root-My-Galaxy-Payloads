#!/usr/bin/env python3
"""HXL1 Stage 3: why retained Clang18 lacks rtmutex.o and futex.o.

Read-only provenance diagnosis: verified Stage-3 evidence, original Kbuild
selection rules, and bounded historical kernel build logs. No make, no
compilation, no phone access, and no factory/experimental offset mixing.
"""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools import y2q_hxl1_kernel_proof_matrix as stage3
from tools import y2q_hxl1_dwarf_gap_triage as gap

TARGETS=("kernel/locking/rtmutex.o","kernel/futex.o")
RULES=("kernel/locking/Makefile","kernel/Makefile")
CONFIGS=("CONFIG_RT_MUTEXES","CONFIG_FUTEX","CONFIG_FUTEX_PI","CONFIG_DEBUG_INFO")
ERROR=re.compile(r"(?i)(?:\*\*\*|fatal error:|(?<!\w)error:|undefined reference|forbidden warning)")
OBJ=re.compile(r"(?i)\b(?:rtmutex|futex)\.(?:o|c)\b")
LOG_EXT={".log",".txt"}
MAX_LOGS=30
TAIL_BYTES=16*1024*1024

class BlockerError(ValueError):
    pass


def source_rules(source:Path)->dict:
    results={}
    for rel in RULES:
        file=source/rel
        if not file.is_file() or file.is_symlink() or file.stat().st_size>1024*1024:
            results[rel]={"status":"UNAVAILABLE","activeMatches":[]}
            continue
        matches=[]
        for n,line in enumerate(file.read_text(errors="replace").splitlines(),1):
            if OBJ.search(line) and not line.lstrip().startswith("#"):
                matches.append({"line":n,"expression":line.strip()[:260]})
        results[rel]={"status":"SCANNED","activeMatches":matches}
    return results


def stock_flags(artifacts:Path)->dict:
    cfg=gzip.decompress((artifacts/"config.gz").read_bytes()).decode("utf-8","replace")
    out={}
    for name in CONFIGS:
        m=re.search(r"(?m)^"+re.escape(name)+r"=(\S+)$",cfg)
        off=re.search(r"(?m)^# "+re.escape(name)+r" is not set$",cfg)
        out[name]=m.group(1) if m else "n" if off else "NOT_LISTED"
    return out


def scan_log(path:Path)->dict:
    if path.is_symlink() or not path.is_file():
        return {"status":"REFUSED_OR_MISSING"}
    size=path.stat().st_size
    if size>1024*1024*1024:
        return {"status":"FILE_TOO_LARGE","byteSize":size}
    with path.open("rb") as handle:
        tail_only=size>TAIL_BYTES
        if tail_only:
            handle.seek(size-TAIL_BYTES)
        text=handle.read(TAIL_BYTES).decode("utf-8","replace")
    if tail_only:
        text=text.partition("\n")[2]
    rows=[]
    other=[]
    target_mentions=0
    for line_no,line in enumerate(text.splitlines(),1):
        if len(line)>8192:
            line=line[:8192]
        target=bool(OBJ.search(line))
        err=bool(ERROR.search(line))
        target_mentions+=target
        if target and err:
            rows.append({"tailLine":line_no,"excerpt":line.strip()[:380]})
        elif err:
            other.append({"tailLine":line_no,"excerpt":line.strip()[:380]})
    return {"status":"PARTIAL_TAIL" if tail_only else "FULL_LOG",
            "byteSize":size,"complete":not tail_only,
            "targetMentions":target_mentions,
            "targetErrorLines":rows[:20],
            "otherErrors":other[:6]}


def logs_to_check(root:Path,explicit:list[Path])->list[Path]:
    if explicit:
        return list(dict.fromkeys(p.expanduser().absolute() for p in explicit))[:MAX_LOGS]
    if not root.is_dir():
        return []
    found=[]
    for p in root.rglob("*"):
        if len(found)>=300:
            break
        if (p.is_file() and not p.is_symlink() and
            p.suffix.lower() in LOG_EXT and
            re.search(r"(?i)(?:build|kernel|samsung|clang|rtmutex|futex)",
                      p.name)):
            found.append(p)
    return sorted(found,key=lambda p:p.stat().st_mtime,reverse=True)[:MAX_LOGS]


def reconcile(previous:dict,source:Path,artifacts:Path,logs:list[Path])->dict:
    if (previous.get("exactSourceAndBuildPinsVerified") is not True or
        previous.get("fullOriginalFactoryAbiEstablished") is not False or
        previous.get("rootDemonstrated") is not False):
        raise BlockerError("Untrusted preceding DWARF provenance")
    selected=previous.get("selectedObjectDiagnostics",{})
    targets={}
    for rel in TARGETS:
        entry=selected.get(rel)
        if not isinstance(entry,dict):
            raise BlockerError("Absent selected object evidence: "+rel)
        status=entry.get("classification")
        if status!="OBJECT_MISSING":
            raise BlockerError("Target is no longer reported missing: "+rel)
        targets[rel]={
            "classification":status,
            "retainedCompileCommand":entry.get("kbuildCommand",{}).get("present") is True,
            "matchingHistoricalDiagnostic":[],
            "compilationActuallyAttempted":"UNKNOWN",
            "specificFailureCauseEstablished":False,
        }
    diagnostics=[{"path":str(path),"result":scan_log(path)} for path in logs]
    for record in diagnostics:
        for row in record["result"].get("targetErrorLines",[]):
            for rel in TARGETS:
                stem=Path(rel).stem
                if re.search(r"\b"+stem+r"\.(?:o|c)\b",row["excerpt"],re.I):
                    targets[rel]["matchingHistoricalDiagnostic"].append(
                        {"log":record["path"],**row})
    for rel in TARGETS:
        targets[rel]["matchingHistoricalDiagnostic"] = \
            targets[rel]["matchingHistoricalDiagnostic"][:12]
    return {
        "classification":"HXL1_MISSING_RT_MUTEX_OBJECTS_BUILD_LOG_TRIAGE",
        "model":"SM-G986U1","firmware":"G986U1UESCHXL1",
        "originalSourceAndBuildHashesValidated":True,
        "targetObjects":targets,
        "originalKbuildRules":source_rules(source),
        "originalConfigFlags":stock_flags(artifacts),
        "logCandidatesChecked":len(diagnostics),
        "logEvidence":diagnostics,
        "stockCompilerAbiMatched":False,
        "sourceRootOrRuntimeExploitValidated":False,
        "productionKernelSUDeployable":False,
        "conclusion":
            "Missing .o files and absent .cmd records do not independently prove "
            "compiler errors. Target-matching historical errors are evidence of "
            "an attempt, but not proof of the exact final build stopping point.",
    }


def markdown(result:dict)->str:
    out=["# HXL1: kernel target-object build blocker triage","",
         "Two target .o files are absent from the Clang18 partial build.",
         "Do not infer a compilation error from the absence alone.","",
         "## Target evidence","",
         "| Object | Status | Retained compile command | Historical error lines |",
         "|---|---|---|---:|"]
    for name,item in result["targetObjects"].items():
        out.append("| "+name+" | "+item["classification"]+" | "+
                   str(item["retainedCompileCommand"])+" | "+
                   str(len(item["matchingHistoricalDiagnostic"]))+" |")
    out+=["","## Kbuild source rules",""]
    for file,body in result["originalKbuildRules"].items():
        out.append("### "+file+" ("+body["status"]+")")
        out.extend("- line "+str(x["line"])+": "+x["expression"]
                   for x in body["activeMatches"])
    out+=["","## Stock config flags",""]
    for name,value in result["originalConfigFlags"].items():
        out.append("- "+name+"="+value)
    out+=["","## Prior kernel build logs",""]
    if not result["logEvidence"]:
        out.append("No build logs automatically identified; use --log /exact/path/to/build.log.")
    for log in result["logEvidence"]:
        value=log["result"]
        out.append("### "+log["path"])
        out.append("- Coverage: "+value["status"]+
                   " (complete="+str(value.get("complete",False))+")")
        out.append("- Target mentions: "+str(value.get("targetMentions",0)))
        out.extend("- Target error: "+row["excerpt"] for row in
                   value.get("targetErrorLines",[])[:5])
        out.extend("- Other error: "+row["excerpt"] for row in
                   value.get("otherErrors",[])[:3])
    out+=["","## Proof boundary","",
          result["conclusion"],
          "Complete DWARF definitions in a future isolated Clang18 build still",
          "cannot authenticate Samsung's factory Clang10 field layouts.",
          "No compilation, phone changes, exploit, KernelSU or root.",""]
    return "\n".join(out)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=stage3.DEFAULT_SOURCE)
    p.add_argument("--artifacts",type=Path,default=stage3.DEFAULT_ARTIFACTS)
    p.add_argument("--build",type=Path,default=stage3.DEFAULT_BUILD)
    p.add_argument("--references",type=Path,default=stage3.DEFAULT_REFERENCES)
    p.add_argument("--log",action="append",type=Path,default=[])
    p.add_argument("--out",type=Path,default=stage3.DEFAULT_ARTIFACTS/
                   "hxl1-research/kernel-target-build-blockers.json")
    a=p.parse_args()
    source=a.source.expanduser().resolve()
    artifacts=a.artifacts.expanduser().resolve()
    build=a.build.expanduser().resolve()
    refs=a.references.expanduser().resolve()
    requested=a.out.expanduser()
    if requested.is_symlink() or requested.with_suffix(".md").is_symlink():
        p.error("Refuse linked report target")
    out=requested.resolve()
    if out.suffix!=".json" or any(out==z or z in out.parents
                                 for z in (source,build,stage3.ROOT)):
        p.error("Output must be outside stock source, build and code trees")
    try:
        proof=stage3.build_matrix(
            stage3.stock.make_inventory(source,artifacts),
            stage3.build.audit(build,source,artifacts),
            stage3.types.run(build),
            stage3.fixes.compare(source,refs),
            stage3.readiness.analyze(
                json.loads(stage3.readiness.EVIDENCE.read_text()),
                artifacts,source,stage3.ROOT))
        audit=stage3.build.audit(build,source,artifacts)
        previous=gap.audit(build,proof,audit)
        report=reconcile(previous,source,artifacts,
                         logs_to_check(artifacts,a.log))
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(report,indent=2)+"\n")
        out.with_suffix(".md").write_text(markdown(report))
    except (OSError,ValueError,KeyError,stage3.stock.InventoryError,
            stage3.build.AuditError,stage3.fixes.AuditError,
            stage3.readiness.GateError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for name,item in report["targetObjects"].items():
        print("[OBJECT]",name,item["classification"],
              "historical error lines",len(item["matchingHistoricalDiagnostic"]))
    print("[BUILD LOGS]",report["logCandidatesChecked"])
    print("[REPORT]",out.with_suffix(".md"))
    print("[LIMIT] Missing object != compiler failure; no OEM ABI or root")
    return 0

if __name__=="__main__":
    sys.exit(main())
