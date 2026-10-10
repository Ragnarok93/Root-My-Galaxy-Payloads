#!/usr/bin/env python3
"""Exact HXL1 kernel Stage-3 evidence reconciliation (read-only, no root).

Runs existing independent verifiers against the original Samsung tree, stock
kernel/config, retained Clang18 .o files, RT-mutex patch references and the
nine-stage device profile. Never derives offsets from mismatched builds and
never promotes static code patterns into CVE exploitability or KernelSU.

Original artifact/source hashes are required; reports are written only to an
independent output directory, not stock source or experimental build trees.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools import y2q_stage3_layout_inventory as stock
from tools import y2q_partial_samsung_dwarf_audit as build
from tools import y2q_dwarf_type_presence as types
from tools import y2q_rtmutex_fix_audit as fixes
from tools import y2q_porting_readiness as readiness

TARGET="SM-G986U1"
FIRMWARE="G986U1UESCHXL1"
RELEASE="4.19.113-27095354"
EXPECTED_STRUCTS=tuple(stock.STRUCT_FILES)
REQUIRED_TYPES=tuple(types.STRUCTS)
DEFAULT_ARTIFACTS=Path.home()/"s20-artifacts"
DEFAULT_SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
DEFAULT_BUILD=Path.home()/"src/samsung-y2q-hxl1-config-clang18"
DEFAULT_REFERENCES=DEFAULT_ARTIFACTS/"hxl1-research/rtmutex-fix-review"
DEFAULT_OUTPUT=DEFAULT_ARTIFACTS/"hxl1-research/kernel-proof-matrix.json"
ROOT=Path(__file__).resolve().parents[1]


class ProofError(ValueError):
    pass


def require(ok:bool,what:str)->None:
    if not ok:
        raise ProofError("STOP: incompatible HXL1 kernel evidence: "+what)


def build_matrix(inventory:dict,partial:dict,dwarf:dict,rtmutex:dict,port:dict)->dict:
    """Consume real report schema contracts, not guessed field names.

    A present source declaration is not a compiled member layout.
    Clang18 type debug information cannot authenticate OEM Clang10 offsets.
    """
    require(inventory.get("model")==TARGET and
            inventory.get("firmware")==FIRMWARE and
            inventory.get("stockKernel")==RELEASE,
            "stock inventory identity")
    require(inventory.get("originalFileHashChecksPassed") is True,
            "stock kernel/config + source SHA256 pins")
    require(inventory.get("offsetsVerified") is False and
            inventory.get("sourceToLiveDeviceLayoutVerified") is False and
            inventory.get("root") is False,
            "source inventory wrongly promotes unknown layouts")
    require(isinstance(inventory.get("sourceDeclarations"),dict) and
            set(inventory["sourceDeclarations"])==set(EXPECTED_STRUCTS),
            "seven source declaration labels")
    require(all(x.get("verifiedOffsets") is False and
                x.get("configuredLayoutVerified") is False
                for x in inventory["sourceDeclarations"].values()),
            "source definitions have no verified compiled offsets")
    require(isinstance(inventory.get("analysisElf"),dict) and
            isinstance(inventory.get("sourceConfig"),dict),
            "original ELF/config inventory malformed")
    require(partial.get("target")==f"{TARGET} {FIRMWARE}" and
            partial.get("originalHashPinsMatched") is True and
            partial.get("buildConfigSha256")==build.GENERATED_SHA,
            "retained partial Clang18 original/source provenance")
    require(partial.get("factoryAbiVerified") is False and
            partial.get("numericOffsetsVerified") is False and
            partial.get("actualRootPayloadAvailable") is False and
            partial.get("phoneTouched") is False,
            "partial Clang18 objects wrongly promoted to OEM ABI/root")
    require(isinstance(partial.get("configParity"),dict) and
            isinstance(partial.get("selected"),dict) and
            isinstance(partial.get("objectCount"),int) and
            partial["objectCount"]>=0 and
            isinstance(partial.get("arm64DwarfCount"),int),
            "partial compiler/build comparison malformed")
    require(dwarf.get("target")==f"Samsung {TARGET} {FIRMWARE}" and
            dwarf.get("verifiedConfigSha256")==build.GENERATED_SHA and
            dwarf.get("zeroExitDoesNotProveTypePresence") is True,
            "exact type presence probe or compiler SHA")
    require(dwarf.get("stockFirmwareLayoutVerified") is False and
            dwarf.get("runtimeKernelCodeExecuted") is False and
            dwarf.get("rootVerified") is False,
            "type-presence results wrongly promoted to factory offsets")
    require(isinstance(dwarf.get("types"),dict) and
            set(dwarf["types"])==set(REQUIRED_TYPES),
            "rt_mutex/rt_mutex_waiter type presence")
    for key in REQUIRED_TYPES:
        entry=dwarf["types"][key]
        require(isinstance(entry.get("objectsChecked"),int) and
                entry["objectsChecked"]>=0 and
                isinstance(entry.get("completeDefinitionsFound"),int) and
                0<=entry["completeDefinitionsFound"]<=entry["objectsChecked"] and
                isinstance(entry.get("presentIn"),list) and
                isinstance(entry.get("ambiguousOrToolError"),list) and
                len(entry["presentIn"])==entry["completeDefinitionsFound"] and
                entry["objectsChecked"]==dwarf.get("aarch64ObjectsInspected"),
                "type presence/count for "+key)
    require(rtmutex.get("firmware")==f"{TARGET} / {FIRMWARE}" and
            rtmutex.get("stockKernel")==RELEASE and
            rtmutex.get("samsungSourceHashesVerified") is True,
            "stock original RT-mutex source")
    require(rtmutex.get("ownershipMismatchSourcePattern") is True and
            rtmutex.get("publishedFixDiffsComplete") is True,
            "source-only published RT-mutex patch comparison")
    require(rtmutex.get("runtimeCveReproduced") is False and
            rtmutex.get("onPhoneRootVerified") is False and
            rtmutex.get("kernelSuValidated") is False and
            rtmutex.get("deviceModified") is False,
            "RT-mutex source audit improperly asserts exploit/root")
    require(port.get("profile")==f"y2q-{FIRMWARE}" and
            port.get("firmware")==FIRMWARE and
            port.get("kernel")==RELEASE,
            "nine-stage porting identity")
    require(port.get("payloadPortCompleted") is False and
            port.get("ghostLockRuntimeValidated") is False and
            port.get("temporaryRootVerified") is False and
            port.get("kernelSuLoaded") is False and
            port.get("phoneChanged") is False and
            port.get("includedInProductionFeed") is False,
            "readiness incorrectly asserts deployable root/feed")
    gates=port.get("gates")
    require(isinstance(gates,list) and
            len(gates)==9 and
            [g.get("stage") for g in gates]==list(range(1,10)),
            "nine distinct stages required")
    require(gates[2].get("state") in ("OPEN","PARTIAL") and
            gates[3].get("state")=="OPEN" and
            gates[4].get("state")=="OPEN" and
            gates[6].get("state")=="BLOCKED" and
            gates[7].get("state")=="BLOCKED",
            "Stage 3/4/5/7/8 cannot be marked complete")

    declarations={
        name:{
            "definitionLocations":v["definitions"],
            "declarationPresent":bool(v["definitions"]),
            "factoryMemberOffsetsKnown":False,
        } for name,v in inventory["sourceDeclarations"].items()
    }
    struct_presence={
        key:{
            "completeDefinitionsFound":dwarf["types"][key]["completeDefinitionsFound"],
            "provisionalObjectNames":dwarf["types"][key]["presentIn"],
            "ambiguousOrToolError":dwarf["types"][key]["ambiguousOrToolError"],
            "factoryOffsetEquivalenceEstablished":False,
        } for key in REQUIRED_TYPES
    }
    compiler=partial["configParity"]
    return {
        "schemaVersion":1,
        "device":{"model":TARGET,"firmware":FIRMWARE,"kernel":RELEASE},
        "purpose":"HXL1 STATIC KERNEL PORTING EVIDENCE GATE - NOT EXPLOIT OR ROOT",
        "checks":{
            "stockHashesAndSourcePinned":True,
            "sourceDeclarations":declarations,
            "rawKernelBtfSearch":port["rawBtfSearch"],
            "recoveredAnalysisElf":inventory["analysisElf"],
            "partialCompilerBuild":{
                "provenance":"Experimental Clang18, NOT original factory Clang10",
                "objectsInspected":partial["objectCount"],
                "aarch64RelocatableObjects":partial["arm64RelCount"],
                "aarch64ObjectsWithDwarf":partial["arm64DwarfCount"],
                "generatedVsStockCompilerVersionEqual":
                    compiler.get("compilerVersionMatches"),
                "changedEffectiveConfigItems":compiler.get("commonDifferences",{}),
                "selectedObjects":partial["selected"],
                "factoryAbiAuthenticated":False,
            },
            "rtMutexTypePresence":struct_presence,
            "rtMutexSourceVsFix":{
                "pinnedOriginalSource":True,
                "sourcePatternMatchesPublishedBugReview":True,
                "upstreamDiffsChecked":True,
                "onDeviceCveApplicabilityProven":False,
                "runtimePrivilegeEscalationProven":False,
            },
            "readinessStages":[
                {"stage":g["stage"],"name":g["title"],"state":g["state"]}
                for g in gates],
        },
        "decisions":{
            "stage3":gates[2]["state"],
            "originalCompiledStructureOffsetsVerified":False,
            "compilerAbiEquivalentToFactoryProven":False,
            "originalRuntimeKernelPhysicalBaseMeasured":False,
            "perBootKernelSlideKnown":False,
            "samsungSecurityCompatibilityValidated":False,
            "ghostLockRuntimeApplicable":False,
            "kernelSuCompatibleAndAuthorized":False,
            "productionSupportFeedPermitted":False,
            "deviceModified":False,
        },
        "actionableProofGaps":[
            "Independent factory-configured rt_mutex/rt_mutex_waiter field layout proof; Clang18 partial object declarations are insufficient",
            "Exact live kernel address provenance without WSL /proc/iomem contamination",
            "Non-destructive on-device vulnerability applicability evidence; source-level current/waiter pattern alone is not runtime exploit proof",
            "Samsung RKP/KDP/DEFEX and signed module constraints for any authorized KernelSU integration",
        ],
    }


def markdown(r:dict)->str:
    source=r["checks"]
    dec=r["decisions"]
    out=[
        "# HXL1 — kernel Stage 3 proof matrix (read-only)","",
        "Exact device: SM-G986U1, G986U1UESCHXL1, 4.19.113-27095354.",
        "Original hashes/source verified, but no factory debug offsets or root.",
        "",
        "## Source declarations vs. compiled factory layouts","",
        "| Structure | Original declaration located | OEM compiled offsets verified |",
        "|---|---|---|",
    ]
    for name,entry in source["sourceDeclarations"].items():
        out.append(f"| {name} | {entry['declarationPresent']} | **No** |")
    out.extend([
        "","## Experimental Clang18 DWARF type presence","",
        "| Type | Complete definitions in retained objects | OEM equivalence |",
        "|---|---:|---|",
    ])
    for name,entry in source["rtMutexTypePresence"].items():
        out.append(f"| {name} | {entry['completeDefinitionsFound']} | **Unverified** |")
    p=source["partialCompilerBuild"]
    out.extend([
        "",
        f"Inspected objects: {p['objectsInspected']}; AArch64 ET_REL: "
        f"{p['aarch64RelocatableObjects']}; objects with DWARF: "
        f"{p['aarch64ObjectsWithDwarf']}.",
        f"Compiler version parity observed: "
        f"{p['generatedVsStockCompilerVersionEqual']}.",
        "Matching one compiler string, if present, would still not prove OEM ABI.",
        "No arbitrary offsets are accepted from this experimental build.",
        "",
        "## Source-level vulnerability evidence","",
        "Pinned RT-mutex source comparison and published initial/follow-up "
        "patch transcripts were verified. This establishes a **source review "
        "signal only**, not on-device CVE reproduction or successful root.",
        "",
        "## Porting gates","",
        "| Stage | Name | State |","|---:|---|---|",
    ])
    for g in source["readinessStages"]:
        out.append(f"| {g['stage']} | {g['name']} | {g['state']} |")
    out+=["","## Blockers (not installable)",""]
    out += ["- "+x for x in r["actionableProofGaps"]]
    out+=["",
          "**Deployment permitted:** NO. Original compiled field offsets, "
          "runtime physical kernel load, per-boot slide, root and KernelSU "
          "are not verified.",
          "No device was contacted or changed by this report.",""]
    return "\n".join(out)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=DEFAULT_SOURCE)
    p.add_argument("--artifacts",type=Path,default=DEFAULT_ARTIFACTS)
    p.add_argument("--build",type=Path,default=DEFAULT_BUILD)
    p.add_argument("--references",type=Path,default=DEFAULT_REFERENCES)
    p.add_argument("--output",type=Path,default=DEFAULT_OUTPUT)
    a=p.parse_args()
    source=a.source.expanduser().resolve()
    artifacts=a.artifacts.expanduser().resolve()
    generated=a.build.expanduser().resolve()
    reference=a.references.expanduser().resolve()
    requested=a.output.expanduser()
    if requested.is_symlink() or requested.with_suffix(".md").is_symlink():
        p.error("Refuse symlinked Stage-3 output targets")
    out=requested.resolve()
    if out.suffix!=".json" or any(
        p==out or p in out.parents for p in (
            source, generated, ROOT/"src",ROOT/"support")
    ):
        p.error("Output must be JSON outside stock source, compiler and app trees")
    try:
        original=stock.make_inventory(source,artifacts)
        provisional=build.audit(generated,source,artifacts)
        presence=types.run(generated)
        review=fixes.compare(source,reference)
        identity=json.loads(readiness.EVIDENCE.read_text(encoding="utf-8"))
        ports=readiness.analyze(identity,artifacts,source,ROOT)
        result=build_matrix(original,provisional,presence,review,ports)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
        out.with_suffix(".md").write_text(markdown(result))
    except (OSError,ValueError,KeyError,stock.InventoryError,
            build.AuditError,fixes.AuditError,readiness.GateError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    print("[PINNED] Exact original Samsung source, kernel and config")
    print("[EXPERIMENTAL] Clang18 objects:",result["checks"]["partialCompilerBuild"]["objectsInspected"])
    for name,data in result["checks"]["rtMutexTypePresence"].items():
        print("[TYPE PRESENCE]",name,data["completeDefinitionsFound"],"factory offsets UNVERIFIED")
    print("[CVE] Original rtmutex fix comparison is SOURCE-LEVEL ONLY")
    print("[STAGE 3]",result["decisions"]["stage3"],
          "OEM layout unverified, physical load unverified")
    print("[REPORT]",out)
    print("[LIMIT] No live kernel offsets, exploit, root, KernelSU or flash")
    return 0


if __name__=="__main__":
    sys.exit(main())
