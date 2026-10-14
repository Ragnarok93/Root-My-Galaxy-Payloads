#!/usr/bin/env python3
"""HXL1 LinuxLoader: authenticated cached callsite -> two bounded getter targets.

Offline only. Parses an already saved, SHA-pinned original LinuxLoader REA
cache summary. DOES NOT invoke REA, ADB, Ghidra, exploit or module loading.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

LOADER_SHA256="5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003"
ORIGINAL_PSEUDOCODE_SHA256="885c6f0fe59139c559194c6bf962b221bb0e5bbef8dedff501f12473d9adfc09"
CALLS=(
    ("dtbo", "0x23b00", "FUN_00023b00", "androidboot.dtbo_idx=", 252, 254),
    ("dtb",  "0x23b40", "FUN_00023b40", "androidboot.dtb_idx=", 261, 263),
)
EXPECTED_XREF={"dtbo-index":"0x2c308","dtb-index":"0x2c350"}

class ProvenanceError(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise ProvenanceError(reason)

def analyze(d: dict) -> dict:
    require(isinstance(d,dict), "Source summary must be an object")
    require(d.get("target")=="SM-G986U1/G986U1UESCHXL1" and
            d.get("originalLinuxLoaderSha256")==LOADER_SHA256 and
            d.get("sharedFunctionAnalysisEntry")=="0x2bdf8" and
            d.get("classification")=="VERIFIED_CACHED_ORIGINAL_CMDLINE_FUNCTION_NO_VALUE_FLOW" and
            d.get("cachedFunctionPseudocodeConsistent") is True,
            "Original HXL1 loader and shared formatter provenance not authenticated")
    refs=d.get("xrefEvidence",[])
    require(isinstance(refs,list) and len(refs)==2,"Missing original Ghidra refs")
    for ref in refs:
        require(isinstance(ref,dict) and ref.get("xrefSource")==EXPECTED_XREF.get(ref.get("label")) and
                ref.get("pcodeAvailable") is True and
                isinstance(ref.get("functionEvidenceId"),str) and
                ref["functionEvidenceId"].startswith("ev_"),
                "Original xref/function dossier mismatch")
    context=d.get("formatterContext",{})
    require(context.get("pseudocodeSha256")==ORIGINAL_PSEUDOCODE_SHA256 and
            context.get("indexLiteralLines")==[254,263] and
            context.get("pseudocodeLineCount")==398 and
            context.get("snippetTruncated") is False,
            "Cached original pseudocode identity/context mismatch")
    rows=context.get("boundedPseudocodeExcerpt",[])
    require(isinstance(rows,list) and len(rows)<120,"Invalid/oversized excerpt")
    by_line={}
    for row in rows:
        require(isinstance(row,dict) and
                type(row.get("line")) is int and
                isinstance(row.get("text"),str) and len(row["text"])<=240,
                "Invalid bounded excerpt row")
        require(row["line"] not in by_line, "Repeated original line number")
        by_line[row["line"]]=row["text"]
    require(re.search(r"cVar6\s*=\s*FUN_000235b0\(\);",by_line.get(250,"")) and
            "if (cVar6 == '\\0')" in by_line.get(251,""),
            "Cached conditional formatting gate not attested")
    extracted=[]
    for name,addr,callee,literal,call_line,fmt_line in CALLS:
        assignment=by_line.get(call_line,"")
        sentinel=by_line.get(call_line+1,"")
        formatted=by_line.get(fmt_line,"")
        require(re.search(r"iVar8\s*=\s*"+re.escape(callee)+r"\(\);",assignment) and
                "if (iVar8 != -1)" in sentinel and
                "FUN_0000ddc4(" in formatted and
                literal in formatted and
                re.search(r",iVar8\);",formatted),
                "Original call, sentinel and format use not jointly established: "+name)
        extracted.append({
            "indexKind":name,
            "immediateGetterFunction":callee,
            "ghidraStaticAnalysisTarget":addr,
            "functionEntryNotYetIndependentlyQueried":True,
            "callFromFormatterPseudocodeLine":call_line,
            "skipFormattingWhenReturnEquals":-1,
            "formatUsePseudocodeLine":fmt_line,
            "formatLiteral":literal,
            "immediateReturnToFormattingCorrelated":True,
            "upstreamGetterComputationVerified":False,
        })
    trace=d.get("savedNativeTrace",{})
    require(trace.get("verifiedValueFlow") is False and
            trace.get("state")=="SAVED_TRACE_FAILURE" and
            trace.get("code")=="cancelled",
            "Saved native trace state not the verified cancelled result")
    return {
        "schemaVersion":1,
        "target":"SM-G986U1/G986U1UESCHXL1",
        "classification":"VERIFIED_STATIC_FORMATTER_GETTER_CALLSITES_NO_SELECTOR_PROOF",
        "originalLinuxLoaderSha256":LOADER_SHA256,
        "cachedFormatterPseudocodeSha256":ORIGINAL_PSEUDOCODE_SHA256,
        "formatterEntry":"0x2bdf8",
        "formatterGate":"FUN_000235b0 returns zero in displayed conditional block",
        "callsiteEvidence":extracted,
        "suggestedBoundedNextTargets":[x["ghidraStaticAnalysisTarget"] for x in extracted],
        "allImmediateGetterCallsitesCorroborated":True,
        "getterInternalsOrSelectionAlgorithmVerified":False,
        "actualDtboIdx2OverlayIdentified":False,
        "actualDtbIdx0SelectionIdentified":False,
        "physicalKernelHandoffVerified":False,
        "deviceModified":False,
        "rootOrKernelSuDemonstrated":False,
        "limits":"Two distinct no-argument direct calls feed integer formatting "
                 "with -1 sentinel. Their computation and the meaning "
                 "of observed indices 0/2 remain unknown. Ghidra p-code "
                 "was marked truncated and the full native trace cancelled."
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cached-report",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    args=ap.parse_args()
    try:
        path=args.cached_report.expanduser().resolve()
        require(path.is_file() and not path.is_symlink() and
                0<path.stat().st_size<3_000_000,"Unsafe/missing cached report")
        report=analyze(json.loads(path.read_text(encoding="utf-8")))
        out=args.output.expanduser().resolve()
        repo=Path(__file__).resolve().parents[1]
        require(repo not in out.parents and repo!=out,
                "Refusing to write report inside repository")
        require(not out.exists() and not out.is_symlink(),
                "Refusing to overwrite prior evidence")
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("[ORIGINAL GETTERS] DTBO 0x23b00 / DTB 0x23b40")
        print("[DIRECT CALLS CORROBORATED] YES")
        print("[SELECTOR ALGORITHM / PHYSICAL HANDOFF] NOT VERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,ValueError,KeyError,TypeError) as error:
        print("[STOP]",error,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
