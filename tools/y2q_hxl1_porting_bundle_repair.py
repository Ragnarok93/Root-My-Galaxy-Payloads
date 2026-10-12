#!/usr/bin/env python3
"""Finish one previously failed *diagnostics-only* HXL1 bundle without reruns.

Reads an existing, SHA-pinned port-automation run and its exact output files.
Rechecks factory kernel/config, successful scan + NDK diagnostic build results,
scan report, manifest and ELF bytes. Writes only a *new* recovered ZIP and a
separate repair report. Never alters the original run's JSON/logs or reruns
the nine-stage pipeline, CVE research, a bootloader, or the S20+ device.
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
# y2q_research_toolchain uses historic adjacent-source absolute imports.
# Register the tools directory as its own import root without code execution.
sys.path.insert(0,str(Path(__file__).resolve().parent))
from tools import y2q_hxl1_porting_automation as port

ROOT=Path.home()/"s20-artifacts"
RESEARCH=ROOT/"hxl1-research"
SCAN="05-cve-source-candidate.json"
MANIFEST="06-hxl1-identity-manifest.json"
LEGACY="06-hxl1-identity-diagnostic.so"
CANONICAL="y2q-G986U1UESCHXL1-identity-diagnostic.so"
RECOVERED="06-hxl1-diagnostics-only-recovered.zip"
REPORT="06-hxl1-bundle-repair.json"
MAX_JSON=2*1024*1024

class RepairError(ValueError):pass

def json_file(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_JSON:
        raise RepairError("Missing, symlinked, or oversized JSON evidence: "+str(path))
    data=json.loads(path.read_text("utf8"))
    if not isinstance(data,dict):
        raise RepairError("Evidence JSON is not an object")
    return data

def validate_run(folder:Path,artifacts:Path,*,allow_existing:bool=False)->dict:
    if folder.is_symlink() or not folder.is_dir():
        raise RepairError("Run directory must be an existing ordinary folder")
    if folder.parent!=artifacts/"hxl1-research" or not folder.name.startswith("port-automation-"):
        raise RepairError("Refuse non-HXL1 run location")
    integrity=port.check_factory_inputs(artifacts)
    if any(v["state"]!="VERIFIED" for v in integrity.values()):
        raise RepairError("Original pinned HXL1 factory input hashes not verified")
    record=json_file(folder/"port-automation.json")
    if record.get("target")!="SM-G986U1/G986U1UESCHXL1" or (
            record.get("runId")!=folder.name):
        raise RepairError("Prior automation record has wrong target/run")
    for k,v in integrity.items():
        if record.get("inputIntegrity",{}).get(k,{}).get("actualSha256")!=v["actualSha256"]:
            raise RepairError("Prior automation record factory hash changed")
    steps={s.get("id"):s for s in record.get("steps",[]) if isinstance(s,dict)}
    if (steps.get("05_source_candidate",{}).get("status")!="PASS" or
        steps.get("06_build_identity_only",{}).get("status")!="PASS" or
        steps.get("06_bundle_identity_only",{}).get("status")!="FAIL"):
        raise RepairError("This recovery accepts only scan/build PASS and bundle FAIL")
    scan=folder/SCAN
    manifest=folder/MANIFEST
    if not scan.is_file() or scan.is_symlink() or port.sha256(scan)!=steps["05_source_candidate"].get("sha256"):
        raise RepairError("Original source scan does not match prior successful SHA")
    candidates=[folder/LEGACY,folder/CANONICAL]
    matching=[p for p in candidates if p.is_file() and not p.is_symlink() and (
        port.sha256(p)==steps["06_build_identity_only"].get("sha256"))]
    if len(matching)!=1:
        raise RepairError("No unique prior SHA-pinned Android diagnostic library")
    library=matching[0]
    declared=json_file(manifest)
    if (declared.get("kind")!="RMG_HXL1_READ_ONLY_IDENTITY_NOT_ROOT" or
        declared.get("payload",{}).get("file")!=library.name or
        declared.get("payload",{}).get("sha256")!=port.sha256(library) or
        declared.get("scanReportSha256")!=port.sha256(scan) or
        declared.get("deploymentBlocked") is not True or
        declared.get("rootVerified") is not False or
        declared.get("publishInSupportFeed") is not False):
        raise RepairError("Manifest does not match the original non-root diagnostic")
    output=folder/RECOVERED
    audit=folder/REPORT
    if not allow_existing and (
            output.exists() or output.is_symlink() or audit.exists() or audit.is_symlink()):
        raise RepairError("Repair destination already exists; do not overwrite evidence")
    return {"scan":scan,"manifest":manifest,"library":library,"output":output,
            "audit":audit,"original":folder/"port-automation.json",
            "factoryIntegrity":integrity}

def repair(folder:Path,artifacts:Path)->dict:
    ctx=validate_run(folder,artifacts)
    from tools import y2q_research_toolchain as builder
    builder.command_bundle(SimpleNamespace(
        scan_report=ctx["scan"],manifest=ctx["manifest"],
        library=ctx["library"],output=ctx["output"]))
    with __import__("zipfile").ZipFile(ctx["output"]) as archive:
        members=set(archive.namelist())
        expected={"README.txt","candidate.json","diagnostic-manifest.json",
                  ctx["library"].name}
        if members!=expected:
            raise RepairError("Repaired ZIP contains unexpected members")
        if archive.read(ctx["library"].name)!=ctx["library"].read_bytes():
            raise RepairError("Repaired ZIP diagnostic ELF bytes differ")
    result={
        "schemaVersion":1,
        "status":"PREVIOUS_HXL1_DIAGNOSTIC_BUNDLE_RECOVERED",
        "originalNineStageReportUnmodified":True,
        "originalRun":str(ctx["original"]),
        "originalScanSha256":port.sha256(ctx["scan"]),
        "manifestSha256":port.sha256(ctx["manifest"]),
        "sourceLibraryName":ctx["library"].name,
        "sourceLibrarySha256":port.sha256(ctx["library"]),
        "recoveredZip":str(ctx["output"]),
        "recoveredZipSha256":port.sha256(ctx["output"]),
        "originalFirmwareInputHashes":ctx["factoryIntegrity"],
        "deployableRootPayload":False,
        "deviceModified":False,
    }
    ctx["audit"].write_text(json.dumps(result,indent=2)+"\n")
    return result

def verify_existing(folder:Path,artifacts:Path)->dict:
    """Read-only, fail-closed verification of prior recovered archive + audit.

    Existing data is never rewritten, regenerated, deleted or touched by
    command_bundle. Partial recovery is reported, not automatically repaired.
    """
    ctx=validate_run(folder,artifacts,allow_existing=True)
    output=ctx["output"]
    audit=ctx["audit"]
    if output.is_symlink() or audit.is_symlink():
        raise RepairError("Existing repair paths may not be symlinks")
    if not output.is_file() or not audit.is_file():
        if output.exists() or audit.exists():
            raise RepairError("Partial recovery output exists; preserve and inspect, do not overwrite")
        raise RepairError("No existing recovery output; use the normal repair command")
    saved=json_file(audit)
    expected={
        "schemaVersion":1,
        "status":"PREVIOUS_HXL1_DIAGNOSTIC_BUNDLE_RECOVERED",
        "originalNineStageReportUnmodified":True,
        "originalRun":str(ctx["original"]),
        "originalScanSha256":port.sha256(ctx["scan"]),
        "manifestSha256":port.sha256(ctx["manifest"]),
        "sourceLibraryName":ctx["library"].name,
        "sourceLibrarySha256":port.sha256(ctx["library"]),
        "recoveredZip":str(output),
        "recoveredZipSha256":port.sha256(output),
        "originalFirmwareInputHashes":ctx["factoryIntegrity"],
        "deployableRootPayload":False,
        "deviceModified":False,
    }
    for field,value in expected.items():
        if saved.get(field)!=value:
            raise RepairError("Existing recovery report failed evidence check: "+field)
    from tools import y2q_research_toolchain as builder
    candidate=builder.load_candidate(ctx["scan"])
    manifest=json_file(ctx["manifest"])
    builder.identity_ok(manifest.get("device"))
    if (manifest.get("device")!=candidate.get("device") or
        manifest.get("kind")!=builder.RESEARCH_KIND or
        manifest.get("deploymentBlocked") is not True or
        manifest.get("publishInSupportFeed") is not False or
        manifest.get("executableExploit") is not False or
        manifest.get("rootVerified") is not False or
        manifest.get("kernelWriteCapability") is not False or
        manifest.get("moduleLoadCapability") is not False or
        manifest.get("payload",{}).get("sizeBytes")!=ctx["library"].stat().st_size):
        raise RepairError("Original manifest is not the inert, exact-HXL1 diagnostic")
    builder.verify_elf_shared_aarch64(ctx["library"])
    expected_members={
        "README.txt":None,
        "candidate.json":ctx["scan"],
        "diagnostic-manifest.json":ctx["manifest"],
        ctx["library"].name:ctx["library"],
    }
    with zipfile.ZipFile(output,"r") as archive:
        members=archive.namelist()
        if len(members)!=len(expected_members) or set(members)!=set(expected_members):
            raise RepairError("Existing ZIP member names missing/duplicated/unsafe")
        for name,source in expected_members.items():
            info=archive.getinfo(name)
            if info.is_dir() or info.file_size>4*1024*1024:
                raise RepairError("Existing ZIP contains invalid member: "+name)
            actual=archive.read(name)
            if source is None:
                if b"RESEARCH-ONLY DEVICE IDENTITY DIAGNOSTIC" not in actual or b"no root exploit" not in actual:
                    raise RepairError("Existing ZIP README incorrectly describes diagnostic")
            elif actual!=source.read_bytes():
                raise RepairError("Existing ZIP member differs from original input: "+name)
        if archive.testzip() is not None:
            raise RepairError("Existing ZIP CRC check failed")
    return {
        "status":"EXISTING_HXL1_DIAGNOSTIC_BUNDLE_VERIFIED",
        "sourceRun":str(ctx["original"]),
        "verifiedRecoveredZip":str(output),
        "sha256":expected["recoveredZipSha256"],
        "archiveMatchesOriginalInputs":True,
        "originalReportUnmodifiedByThisCheck":True,
        "rootOrKernelSuVerified":False,
        "physicalDeviceTouched":False,
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir",required=True,type=Path)
    p.add_argument("--artifacts",type=Path,default=ROOT)
    controls=p.add_mutually_exclusive_group()
    controls.add_argument("--preflight-only",action="store_true")
    controls.add_argument("--verify-existing",action="store_true",
                          help="Read-only verification of recovered ZIP/report without rewriting either")
    args=p.parse_args()
    try:
        folder=args.run_dir.expanduser().absolute()
        artifacts=args.artifacts.expanduser().absolute()
        if args.verify_existing:
            result=verify_existing(folder,artifacts)
            print("[VERIFY]",result["status"])
            print("[ARCHIVE]",result["verifiedRecoveredZip"])
            print("[SHA256]",result["sha256"])
            print("[ORIGINAL REPORT / ROOT / KERNELSU] UNCHANGED")
            return 0
        if args.preflight_only:
            evidence=validate_run(folder,artifacts)
            print("[READY] Prior factory/scan/build outputs verified; nothing written")
            print("[LIBRARY]",evidence["library"])
            return 0
        result=repair(folder,artifacts)
        print("[REPAIR]",result["status"])
        print("[DIAGNOSTIC ZIP]",result["recoveredZip"])
        print("[BUNDLE SHA256]",result["recoveredZipSha256"])
        print("[ORIGINAL READINESS / ROOT / KERNELSU] UNCHANGED")
        return 0
    except (OSError,ValueError,TypeError,KeyError,zipfile.BadZipFile,RuntimeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
