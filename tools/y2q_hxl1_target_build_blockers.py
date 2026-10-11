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
# Only known HXL1 Clang18 host build logs belong in automatic historical
# selection. REA diagnostics, notes and QEMU kernel builds are unrelated.
HXL1_LOG=re.compile(r"^samsung-hxl1-image-clang18-build(?:-[0-9]+)?\.log$")
MAX_LOGS=30
ERROR_CONTEXT_BEFORE=8
ERROR_CONTEXT_AFTER=4
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
    contexts=[]
    target_mentions=0
    lines=text.splitlines()
    for line_no,line in enumerate(lines,1):
        if len(line)>8192:
            line=line[:8192]
        target=bool(OBJ.search(line))
        err=bool(ERROR.search(line))
        target_mentions+=target
        if "unrecognized instruction mnemonic" in line.lower():
            start=max(0,line_no-1-ERROR_CONTEXT_BEFORE)
            stop=min(len(lines),line_no+ERROR_CONTEXT_AFTER)
            contexts.append({
                "errorTailLine":line_no,
                "surroundingLines":[
                    {"tailLine":j+1,"text":lines[j].strip()[:380]}
                    for j in range(start,stop)
                ],
            })
        if target and err:
            rows.append({"tailLine":line_no,"excerpt":line.strip()[:380]})
        elif err:
            other.append({"tailLine":line_no,"excerpt":line.strip()[:380]})
    return {"status":"PARTIAL_TAIL" if tail_only else "FULL_LOG",
            "byteSize":size,"complete":not tail_only,
            "targetMentions":target_mentions,
            "targetErrorLines":rows[:20],
            "otherErrors":other[:6],
            "assemblerMnemonicContexts":contexts[:4]}


def logs_to_check(root:Path,explicit:list[Path])->list[Path]:
    if explicit:
        if len(explicit)>MAX_LOGS:
            raise BlockerError("Too many explicit historical logs")
        selected=list(dict.fromkeys(p.expanduser().absolute() for p in explicit))
        for p in selected:
            if p.is_symlink() or not p.is_file():
                raise BlockerError("Explicit --log does not exist or is not a regular file: "+str(p))
            if p.stat().st_size>1024*1024*1024:
                raise BlockerError("Explicit --log exceeds 1GiB scan limit: "+str(p))
        return selected
    if not root.is_dir():
        return []
    found=[p for p in root.iterdir()
           if HXL1_LOG.fullmatch(p.name) and p.is_file() and not p.is_symlink()]
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
        for ctx in value.get("assemblerMnemonicContexts",[]):
            out.append("- **ARM64 assembler mnemonic failure context:**")
            out.extend("  - tail line "+str(line["tailLine"])+": "+line["text"]
                       for line in ctx["surroundingLines"])
    out+=["","## Proof boundary","",
          result["conclusion"],
          "Complete DWARF definitions in a future isolated Clang18 build still",
          "cannot authenticate Samsung's factory Clang10 field layouts.",
          "No compilation, phone changes, exploit, KernelSU or root.",""]
    return "\n".join(out)


def write_new_report_pair(requested:Path,report:dict)->tuple[Path,Path]:
    """Never overwrite the last verified auto-discovery report.

    A failed explicit --log request is rejected BEFORE this point.
    Exclusive creation preserves every earlier run for comparison.
    """
    requested.parent.mkdir(parents=True,exist_ok=True)
    for idx in range(1000):
        json_path=(requested if idx==0 else
                   requested.with_name(f"{requested.stem}-run-{idx:03d}.json"))
        md_path=json_path.with_suffix(".md")
        if (json_path.exists() or json_path.is_symlink() or
            md_path.exists() or md_path.is_symlink()):
            continue
        created=[]
        try:
            with json_path.open("x",encoding="utf-8") as handle:
                created.append(json_path)
                json.dump(report,handle,indent=2)
                handle.write("\n")
            with md_path.open("x",encoding="utf-8") as handle:
                created.append(md_path)
                handle.write(markdown(report))
        except Exception:
            for item in created:
                item.unlink(missing_ok=True)
            raise
        return json_path,md_path
    raise BlockerError("Report version limit reached; choose another --out path")


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
        logs=logs_to_check(artifacts,a.log)
        report=reconcile(previous,source,artifacts,logs)
        saved_json,saved_md=write_new_report_pair(out,report)
    except (OSError,ValueError,KeyError,stage3.stock.InventoryError,
            stage3.build.AuditError,stage3.fixes.AuditError,
            stage3.readiness.GateError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    for name,item in report["targetObjects"].items():
        print("[OBJECT]",name,item["classification"],
              "historical error lines",len(item["matchingHistoricalDiagnostic"]))
    print("[BUILD LOGS]",report["logCandidatesChecked"])
    print("[REPORT]",saved_md)
    print(markdown(report))
    print("[LIMIT] Missing object != compiler failure; no OEM ABI or root")
    return 0

if __name__=="__main__":
    sys.exit(main())
