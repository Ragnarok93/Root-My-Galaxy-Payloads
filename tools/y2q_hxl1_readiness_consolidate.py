#!/usr/bin/env python3
"""HXL1 read-only supplemental readiness consistency gate.

The source of truth for nine stage states remains y2q_porting_readiness.py.
No phone I/O, payload creation, kernel patch, runtime offset, root or module load.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

STAGES = ["COMPLETE", "COMPLETE", "PARTIAL", "OPEN", "OPEN", "OPEN",
          "BLOCKED", "BLOCKED", "DEFERRED"]
PINS = {
    "boot.img": "bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8",
    "kernel.bin": "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123",
    "config.gz": "1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd",
}
SECURITY = {"CONFIG_MODULE_SIG_FORCE": "y", "CONFIG_KPROBES": "n",
            "CONFIG_UH_RKP": "y", "CONFIG_KDP_CRED": "y",
            "CONFIG_SECURITY_DEFEX": "y", "CONFIG_FUTEX_PI": "y"}
BL_SHA = "f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b"

class EvidenceError(ValueError):
    pass

def insist(ok, msg):
    if not ok:
        raise EvidenceError(msg)

def read(path):
    insist(path.is_file() and not path.is_symlink() and
           0 < path.stat().st_size < 2_000_000, "Invalid source evidence file")
    raw = path.read_bytes()
    data = json.loads(raw)
    insist(isinstance(data, dict), "Expected JSON object")
    return data, hashlib.sha256(raw).hexdigest()

def audit(evidence, readiness=None, select=None, inventory=None):
    ident = evidence.get("identity", {})
    insist(evidence.get("profileId") == "y2q-G986U1UESCHXL1-research"
           and evidence.get("status") == "research-only"
           and ident.get("model") == "SM-G986U1"
           and ident.get("firmware") == "G986U1UESCHXL1"
           and ident.get("kernelRelease") == "4.19.113-27095354",
           "Wrong model/firmware/kernel")
    insist(all(evidence.get(k) is False for k in
               ("installable","publishInSupportFeed","rootVerified",
                "vulnerabilityVerified","moduleLoadVerified")),
           "Unsafe root or production claim")
    insist(all(evidence.get("artifacts",{}).get(k,{}).get("sha256")==v
               for k,v in PINS.items()), "Original firmware SHA pins mismatch")
    insist(all(evidence.get("kernelConfig",{}).get(k)==v
               for k,v in SECURITY.items()), "Kernel security config mismatch")
    live=evidence.get("hxl1LiveBootSecurityState20261010",{})
    insist(live.get("verifiedBootState")=="green" and
           live.get("flashLocked")=="1" and live.get("selinux")=="Enforcing"
           and live.get("phoneRootObserved") is False,
           "Original stock boot observations mismatch")
    boot=evidence.get("boot",{})
    insist(boot.get("headerVersion")==2 and
           boot.get("bootHashDescriptorVerified") is True and
           boot.get("manufacturerTrustChainVerified") is False,
           "Boot provenance contradiction")
    stages=evidence.get("hxl1NineStagePortReadiness",{}).get("nineStages",[])
    insist(len(stages)==9 and
           [g.get("number") for g in stages]==list(range(1,10)),
           "Incomplete/duplicate stage inventory")
    state=[("COMPLETE" if i==1 and r.get("state")=="COMPLETE_EXTRACTED_INPUTS"
            else r.get("state")) for i,r in enumerate(stages)]
    insist(state==STAGES,"Stage promotion or contradictory stage status")
    stage3=evidence.get("hxl1Stage3LayoutInventory",{})
    insist(stage3.get("fullCompiledStructOffsetsVerified") is False,
           "OEM ABI completion not proven")
    stage4=evidence.get("hxl1Stage4BootloaderDiscovery",{})
    insist(stage4.get("archive",{}).get("sha256")==BL_SHA and
           stage4.get("matchingOriginalBLDiscovered") is True and
           stage4.get("physicalKernelLoadAddressVerified") is False,
           "Physical handoff/BL provenance mismatch")
    ksu=evidence.get("hxl1KernelSuReadiness",{})
    insist(ksu.get("moduleLoadVerified") is False and
           ksu.get("deviceRootVerified") is False and
           ksu.get("supportFeedAllowed") is False and
           ksu.get("assessment",{}).get("normalUnsignedModuleLoadingPermitted") is False,
           "KernelSU trust/loading status changed")
    checks={"manifest":"PASS_STATIC_PINS_NO_RAW_REHASH",
            "portingReadinessReport":"NOT_SUPPLIED",
            "selectNumerics":"NOT_SUPPLIED",
            "debugArtifactScan":"NOT_SUPPLIED"}
    if readiness is not None:
        gates=readiness.get("gates",[])
        insist(len(gates)==9 and
               [g.get("stage") for g in gates]==list(range(1,10)) and
               [g.get("state") for g in gates]==STAGES and
               all(readiness.get(k) is False for k in
                   ("payloadPortCompleted","ghostLockRuntimeValidated",
                    "temporaryRootVerified","kernelSuLoaded")),
               "Authoritative porting readiness contradicts evidence")
        checks["portingReadinessReport"]="AGREES_ALL_NINE_STAGES"
    if select is not None:
        x=select.get("savedMachineCodeEvidence",{}).get(
            "numericSelectAllocationCrosswalk",{})
        insist(select.get("target")=="SM-G986U1/G986U1UESCHXL1" and
               select.get("selectStackAllocationSourceBytes")==256 and
               x.get("maximumNfdsUsingStack")==320 and
               x.get("firstNfdsRequiringDynamicAllocation")==321 and
               x.get("compiledArithmeticMatchesSourceCapacity") is True and
               x.get("crossSyscallReuseOrRootCertified") is False and
               select.get("runtimeStackReuseOrPrivilegeProven") is False,
               "Source/compiled select crosswalk overclaims or mismatches")
        checks["selectNumerics"]="CORROBORATED_STATIC_ONLY"
    if inventory is not None:
        classified=inventory.get("classificationCounts",{})
        insist(inventory.get("scanRoots")==["/home/main/s20-artifacts"] and
               inventory.get("truncated") is False and
               inventory.get("errorCount")==0 and
               inventory.get("scopeCompleteAtRequestedDepth") is True and
               sum(classified.values())==inventory.get("candidateFiles") and
               inventory.get("oemSymbolsAuthenticated") is False,
               "Debug-symbol inventory not consistent/complete to bounded depth")
        checks["debugArtifactScan"]="BOUNDED_COMPLETE_NOT_OEM_AUTHENTICATED"
        checks["unsearchedDeeperDirectories"]=inventory.get(
            "depthLimitedDirectoryCount")
    return {"schemaVersion":1,"profile":"y2q-G986U1UESCHXL1-research",
            "gateAuthority":"tools/y2q_porting_readiness.py",
            "nineStages":[{"stage":i,"state":v} for i,v in enumerate(state,1)],
            "checks":checks,"researchOnly":True,
            "originalKernelBytesIndependentlyRehashedByThisScript":False,
            "originalCompilerLocalLayoutVerified":False,
            "physicalLinuxKernelHandoffVerified":False,
            "livePrivilegeEscalationVerified":False,
            "kernelSuLoaded":False,
            "productionFeedAllowed":False}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("--evidence",required=True,type=Path)
    a.add_argument("--readiness",type=Path)
    a.add_argument("--select-crosswalk",type=Path)
    a.add_argument("--debug-inventory",type=Path)
    a.add_argument("--output",type=Path,required=True)
    args=a.parse_args()
    try:
        evidence,sha=read(args.evidence)
        inputs=[read(p) if p else (None,None) for p in
                (args.readiness,args.select_crosswalk,args.debug_inventory)]
        result=audit(evidence,*[v[0] for v in inputs])
        result["sha256OfInputReports"]={"evidence":sha,**{
            k:v[1] for k,v in zip(("readiness","select","debug"),inputs)
            if v[1] is not None}}
        report_path=args.output.expanduser().resolve()
        repository=Path(__file__).resolve().parents[1]
        insist(report_path != repository and repository not in report_path.parents,
               "Research report must be written outside the repository")
        insist(not report_path.exists() and not report_path.is_symlink(),
               "Refusing to overwrite an existing report")
        report_path.parent.mkdir(parents=True,exist_ok=True)
        report_path.write_text(json.dumps(result,indent=2)+"\n")
        print("[HXL1 STAGES]",",".join(g["state"] for g in result["nineStages"]))
        print("[ROOT / KERNELSU / FEED] NOT VALIDATED")
        print("[REPORT]",report_path)
        return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
