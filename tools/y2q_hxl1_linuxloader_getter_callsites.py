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
    require({x.get("label") for x in refs if isinstance(x,dict)}==set(EXPECTED_XREF),
            "Missing or duplicate original index xref labels")
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

def verify_getter_dossier(value: dict, expected_address: str,
                          loader_sha256: str = LOADER_SHA256) -> dict:
    """Verify REA actually decompiled the *requested* stock HXL1 getter.

    REA may return an enclosing or neighboring function. A successful JSON
    envelope, the echoed requested parameter, and a generic hex function
    address were previously insufficient to prove a matching function.
    This validates only dossier identity, not selector semantics.
    """
    require(isinstance(value, dict) and "error" not in value,
            "REA returned an error or non-object result")
    require(type(expected_address) is str and
            expected_address.lower() in {x[1] for x in CALLS},
            "Unexpected getter target")
    require(loader_sha256 == LOADER_SHA256,
            "Unpinned original HXL1 LinuxLoader")
    provider = value.get("provider")
    subject = value.get("subject")
    params = value.get("parameters")
    normalized = value.get("normalized_result")
    require(value.get("operation") == "analyze_function" and
            isinstance(provider, dict) and provider.get("id") == "ghidra",
            "Wrong analysis operation/provider")
    require(isinstance(subject, dict) and
            isinstance(subject.get("digest"), dict) and
            subject["digest"].get("sha256") == loader_sha256,
            "Original LinuxLoader digest mismatch")
    require(isinstance(params, dict) and
            isinstance(params.get("procedure"), str),
            "Missing requested procedure in REA response")
    require(isinstance(normalized, dict) and
            isinstance(normalized.get("procedure"), dict),
            "Missing normalized Ghidra function identity")
    actual = normalized["procedure"].get("address")
    require(isinstance(actual, str),
            "Missing Ghidra function entry address")
    try:
        target = int(expected_address, 16)
        echoed = int(params["procedure"], 16)
        entry = int(actual, 16)
    except (ValueError, TypeError) as error:
        raise ProvenanceError("Malformed requested/returned function address") from error
    require(target == echoed,
            "REA response requested a different procedure")
    require(target == entry,
            "REA returned a different Ghidra function entry")
    pseudo = normalized.get("pseudocode")
    require(isinstance(pseudo, str) and len(pseudo.strip()) >= 12,
            "Ghidra function pseudocode missing or empty")
    return {
        "classification": "ORIGINAL_GETTER_DOSSIER_IDENTITY_VERIFIED_ONLY",
        "originalLinuxLoaderSha256": loader_sha256,
        "requestedAddress": expected_address,
        "returnedFunctionEntry": hex(entry),
        "functionEntryMatchesRequested": True,
        "validGhidraPseudocodePresent": True,
        "getterIndexAlgorithmVerified": False,
        "selectedDtbOrOverlayAuthenticated": False,
        "physicalKernelHandoffVerified": False,
        "deviceModified": False,
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
