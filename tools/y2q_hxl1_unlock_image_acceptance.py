#!/usr/bin/env python3
"""HXL1 original boot-image acceptance boundary (LinuxLoader/Odin).

Query ONLY the two original HXL1 secure-image acceptance owners, both
previously located from independently SHA-pinned literal string xrefs:
  LinuxLoader 0x3f54 ("Skipping boot verification", xref 0x40f0)
  Odin        0x1b6a8 ("Blocked By OEM Lock", xref 0x1b3d4)

Revalidate complete earlier REA string->xref->Ghidra procedure proof via
the existing y2q_hxl1_rea_decision_path_review source audit.
Collect up to two additional full native instruction listings, and
report bounded Ghidra source conditions around actual decisions.
No secure authority or bypass is asserted solely from a log string;
we do not patch images, access handset, flash, or attempt an unlock.

The goal is to decide whether the cached lock state ever governs an
actual image acceptance branch. Pseudocode is evidence for hypotheses,
not native control-flow dominance or device security authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256,TriageError
from tools.y2q_hxl1_rea_security_audit import Runner,choose_targets,evidence,function_record,safe_segment
from tools.y2q_hxl1_rea_decision_path_review import audit as verify_strings_and_xrefs
from tools.y2q_hxl1_rea_avb_unlock_bitmask_clusters import full_native

# Both source coordinates, functions and exact strings are independent
# owner-captured HXL1 Ghidra evidence; all hashes must be revalidated.
TARGETS=(
    ("LinuxLoader","unlocked-skip","0x40f0","0x3f54",
     "Device is unlocked, Skipping boot verification"),
    ("Odin","custom-deny","0x1b3d4","0x1b6a8",
     "Blocked By OEM Lock"),
)
SOURCE_PATTERN=re.compile(
    r"unlock|lock|oem|skip|verify|custom|image|signature|"
    r"fail|error|if\s*\(|else|return|avb|boot|"
    r"FUN_0000|DAT_|result",re.I)
MAX_LINES=8000
MAX_NATIVE=5000
MAX_CONTEXT=260


def exact_saved_case(root:Path,target,seed:str,site:str,entry:str,word:str)->dict:
    folder=root/"rea-security-audit"/target.name
    fn=evidence(folder/("function-"+safe_segment(site)+".json"),
                sha=target.sha256,operation="analyze_function",
                parameter="procedure",value=site)
    identity=function_record(fn,site)
    if identity["entry"]!=entry:
        raise TriageError("Original "+target.name+" owner or xref changed")
    pseudo=fn["normalized_result"].get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>380000:
        raise TriageError("Original policy function pseudocode unavailable/oversized")
    lines=pseudo.splitlines()
    if not 3<=len(lines)<=MAX_LINES:
        raise TriageError("Original policy function line budget exceeded")
    if word.casefold() not in pseudo.casefold():
        raise TriageError("Original selected policy diagnostic disappeared: "+word)
    selected=set(range(min(14,len(lines))))
    hits=[i for i,l in enumerate(lines) if SOURCE_PATTERN.search(l)]
    for i in hits[:85]:
        selected.update(range(max(0,i-5),min(len(lines),i+7)))
    trimmed=sorted(selected)[:MAX_CONTEXT]
    return {
        "module":target.name,"seed":seed,
        "sourceEvidenceId":fn["evidence_id"],"nativeEntry":entry,
        "sourceXref":site,
        "sourceSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "fullGhidraPseudocodeLines":len(lines),
        "source":[{"line":i+1,"text":lines[i][:1000]} for i in trimmed],
        "excerptTruncated":len(selected)>len(trimmed) or len(hits)>85,
        "verifiedDiagnosticReference":True,
        "actualImageSignatureAuthorizationProven":False,
        "nativeBranchDominanceProven":False,
    }


def native_case(ev:dict,entry:str,site:str)->dict:
    ops=full_native(ev,entry)
    if not 6<=len(ops)<=MAX_NATIVE:
        raise TriageError("Original boot-verifier instruction budget exceeded")
    keys=sorted(ops,key=lambda s:int(s,16))
    # Site might fall into noncontiguous body ranges or Ghidra
    # secondary chunks; never imply same lexical native owner.
    src=keys.index(site) if site in ops else -1
    subset=keys[max(0,src-65):min(len(keys),src+70)] if src>=0 else keys[:100]
    return {
        "nativeEntry":entry,"nativeEvidenceId":ev["evidence_id"],
        "nativeInstructionCount":len(ops),
        "referencedStringInstructionPresent":src>=0,
        "nativeInstructions":[
            a+": "+ops[a][0]+(" "+ops[a][1] if ops[a][1] else "")
            for a in subset
        ],
        "exactOwnerStringBranchProven":False,
        "imageSignatureAcceptanceFromNativeProven":False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,node:str="node",
          timeout:int=240,recover_partials:bool=False)->dict:
    # Full seeded proof validates exact original firmware, string/xref,
    # Ghidra function and SHA-bound candidate, not just filename.
    previous=verify_strings_and_xrefs(root)
    if (previous.get("allFiveReferencesVerified") is not True
            or previous.get("qualifiedFunctionReferences")!=5):
        raise TriageError("Original five literal-xref-function Ghidra source chains incomplete")
    target_index={t.name:t for t in choose_targets(root)}
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("REA host entrypoint missing/unsafe")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    rows=[]
    for name,seed,site,entry,term in TARGETS:
        target=target_index[name]
        saved=exact_saved_case(root,target,seed,site,entry,term)
        native=runner.obtain(
            target,["instructions",str(target.path),entry],
            root/"rea-security-audit"/name/
                  ("instructions-unlock-acceptance-"+safe_segment(entry)+".json"),
            operation="read_function_instructions",parameter="procedure",value=entry)
        rows.append({
            "module":name,"seed":seed,"savedOriginalSource":saved,
            "originalNative":native_case(native,entry,site) if native else None,
            "runtimePolicyBypassProven":False,
        })
    return {
        "schemaVersion":1,"originalArchiveSha256":HXL1_BL_SHA256,
        "sourceAttested":True,
        "mode":"READ_ONLY_HXL1_GHIDRA" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),"acceptanceRoots":rows,
        "imageExecutionAuthorizationControlledByWritableFlagProven":False,
        "bootloaderUnlockProven":False,"deviceModified":False,
    }


def markdown(r:dict)->str:
    lines=[
        "# HXL1 boot-image acceptance — LinuxLoader versus Odin decision roots",
        "",
        "**Original SHA-pinned boot firmware only. Static security review.**",
        "","BL archive SHA256: "+r["originalArchiveSha256"],
        "New original read-only Ghidra queries: "+str(r["newQueries"]),
        "",
        "## Why this gate matters","",
        "The historical DID-based US S20+ service applies to BL v1;",
        "G986U1UESCHXL1 is binary C (12). Reporting a cached unlock",
        "or processing an EMC status response cannot establish acceptance",
        "of a custom boot image. These original functions contain the",
        "actual diagnostic hints for *verification skip* and *custom",
        "binary blocked by OEM lock*. Their native conditions and",
        "trusted-state sources are the high-value next proof targets.",
        "",
    ]
    for row in r["acceptanceRoots"]:
        s=row["savedOriginalSource"]
        lines += [
            "## "+row["module"]+" — "+row["seed"],"",
            "- Original function: "+s["nativeEntry"],
            "- Original literal reference site: "+s["sourceXref"],
            "- Source Evidence: "+s["sourceEvidenceId"],
            "- Full original Ghidra source lines: "+str(s["fullGhidraPseudocodeLines"]),
            "- Verified original diagnostic reference, NOT a skip or",
            "  OEM-authentication-bypass proof.","","~~~c",
        ]
        for obj in s["source"]:
            lines.append(str(obj["line"])+": "+obj["text"])
        lines += ["~~~",""]
        n=row["originalNative"]
        if n:
            lines += [
                "- Native Evidence: "+n["nativeEvidenceId"],
                "- Full native instruction count: "+str(n["nativeInstructionCount"]),
                "- Literal reference included in native result: "+
                  str(n["referencedStringInstructionPresent"]),
                "- Native branch dominance / signed-image acceptance: UNPROVEN.",
                "","~~~asm",*n["nativeInstructions"],"~~~","",
            ]
        else:
            lines += ["- Original native query not yet collected.",""]
    lines += [
        "## Explicit go/no-go for an HXL1 unlock method","",
        "1. Reconstruct the original LinuxLoader branch that *actually",
        "   omits signature verification*, not just its log message.",
        "2. Reconstruct Odin's custom-image acceptance/rejection result",
        "   from real original native branches rather than text alone.",
        "3. Prove both consumers consult a controllable and consistently",
        "   trusted state, or demonstrate a verified authorized state",
        "   transition for the exact HXL1 locked hardware.",
        "4. Distinguish AVB-vbmeta (Android) from Qualcomm ABL/XBL",
        "   authentication and rollback fuses. A cached unlocked byte",
        "   or writable persistent partition is not sufficient.",
        "5. No bootloader unlock or custom-image execution may be",
        "   claimed absent a reversible, authenticated device test.",
        "6. No device writes, signed boot edits, or arbitrary bootloader",
        "   cross-flashes are performed by this analyzer.","",
    ]
    return "\n".join(lines)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path,default=Path.home()/
                   "s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    p.add_argument("--node",default="node")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--recover-partials",action="store_true")
    p.add_argument("--timeout",type=int,default=240)
    a=p.parse_args()
    if not 30<=a.timeout<=1200:
        p.error("bounded timeout 30..1200")
    try:
        root=a.input_dir.expanduser().resolve()
        report=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                     timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"unlock-image-acceptance.json").write_text(json.dumps(report,indent=2)+"\n")
        (out/"unlock-image-acceptance.md").write_text(markdown(report))
    except (TriageError,OSError,ValueError,TypeError,KeyError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[ROOTS] LinuxLoader 0x3f54 / Odin 0x1b6a8")
    print("[NATIVE]",sum(bool(x["originalNative"]) for x in report["acceptanceRoots"]),"/2")
    print("[REPORT]",out/"unlock-image-acceptance.md")
    print("[LIMIT] No actual unlock or signed-image acceptance demonstrated")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
