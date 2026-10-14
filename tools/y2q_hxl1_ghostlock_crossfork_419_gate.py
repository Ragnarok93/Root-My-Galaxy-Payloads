#!/usr/bin/env python3
"""Read-only HXL1 GhostLock 4.19 cross-fork feasibility gate.

Authenticates original Samsung rtmutex/futex source and a frozen K40 fork
documentation revision (Git blob SHA1). No offsets, exploit, payload, target.h,
KASLR values or device actions are produced.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_kernel419_compatibility as hxl1

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL_SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
FORK=Path.home()/"ghostlock-cve-2026-43499-4.19-k40"
FORK_URL="https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40"
FORK_BLOB_PINS={
    "docs/status.md":"5c9fd4a613741d267ac9bd660efcb3c0635b315f",
    "docs/specs/kernel-frame-placement-enumeration.md":"c4a6beccfdfc447f0fed8b42e4be99daa25294cf",
    "docs/specs/rt-waiter-placement-audit.md":"8e54b1346a934e66999a6a902bce27503130f206",
}
ADDITIONAL_VENDOR={
    "net/socket.c":{
        "sys_sendmsg":r"\b(?:SYSCALL_DEFINE3\s*\(\s*sendmsg|__sys_sendmsg)\b",
        "sendmsg_copy":r"\b(?:copy_msghdr_from_user|___sys_sendmsg|____sys_sendmsg)\b",
    },
    "fs/read_write.c":{
        "iov_copy":r"\b(?:rw_copy_check_uvector|import_iovec|copy_iovec_from_user)\b",
    },
}
class AuditStop(ValueError):
    pass

def require(ok,reason):
    if not ok:raise AuditStop(reason)

def safe_read(path:Path, max_size:int=2_000_000)->bytes:
    require(path.is_file() and not path.is_symlink() and
            0<path.stat().st_size<max_size,"Missing/unsafe file: "+str(path))
    return path.read_bytes()

def git_blob_id(raw:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\x00"+raw).hexdigest()

def verify_reference(fork:Path, pins:dict|None=None)->dict:
    pins=FORK_BLOB_PINS if pins is None else pins
    evidence={}
    documents={}
    for rel,blob in pins.items():
        raw=safe_read(fork/rel)
        require(git_blob_id(raw)==blob,"K40 reference revision drift: "+rel)
        documents[rel]=raw.decode("utf-8","strict")
        evidence[rel]={"gitBlobSha1":blob,"sha256":hashlib.sha256(raw).hexdigest(),
                       "bytes":len(raw)}
    status=documents["docs/status.md"]
    placement=documents["docs/specs/kernel-frame-placement-enumeration.md"]
    waiter=documents["docs/specs/rt-waiter-placement-audit.md"]
    require(bool(re.search(r"(?m)^\|\s*4 Root Chain\s*\|\s*blocked\s*\|",status)),
            "Pinned K40 status does not indicate root-chain blocked")
    require("sendmsg returned ret=65540" in status and
            "deterministic TCP blocking redesign" in status,
            "Pinned K40 sendmsg failure/redesign not visible")
    require("iovstack[8]" in placement and
            "TCP " in placement and "sendmsg" in placement,
            "Pinned K40 stack-placement design absent")
    require("rt_waiter" in waiter and "futex_wait_requeue_pi" in waiter,
            "Pinned K40 waiter source lineage absent")
    return {
       "referenceUrl":FORK_URL,
       "pinnedOriginalDocs":evidence,
       "rootChainStatus":"BLOCKED_IN_THIS_PINNED_REFERENCE_REVISION",
       "deviceSendmsgBlockingTrial":"PREMATURE_RETURN_OBSERVED_ON_K40",
       "subsequentRedesign":"OFFLINE_DESCRIBED_NOT_HXL1_VALIDATED",
       "k40StackWindow":"K40_ONLY_COMPILED_GEOMETRY_NOT_HXL1",
       "k40PhysicalConstantsPortable":False,
       "hxl1ExploitStatusEstablishedByReference":False,
    }

def audit(source:Path,fork:Path,*,source_pins=None,fork_pins=None)->dict:
    baseline=hxl1.review_source(source,pins=source_pins)
    checked={}
    for relative,patterns in ADDITIONAL_VENDOR.items():
        path=source/relative
        if not path.is_file():
            checked[relative]={"status":"SOURCE_NOT_AVAILABLE"}
            continue
        raw=safe_read(path,4_000_000)
        data=raw.decode("utf-8","strict")
        checked[relative]={
          "status":"SOURCE_TEXT_REVIEW_ONLY",
          "sha256":hashlib.sha256(raw).hexdigest(),
          "bytes":len(raw),
          "identifierPresence":{
             label:bool(re.search(pattern,data))
             for label,pattern in patterns.items()},
          "factoryCompiledStackLayoutCorroborated":False,
        }
    reference=verify_reference(fork,fork_pins)
    checks=baseline["sourceObservations"]
    require(checks.get("rtmutexRemoveWaiter")=="SOURCE_PATTERN_PRESENT_NOT_FACTORY_PROOF" and
            checks.get("rtmutexCurrentPiBlockedOn")=="SOURCE_PATTERN_PRESENT_NOT_FACTORY_PROOF" and
            checks.get("futexRequeue")=="SOURCE_PATTERN_PRESENT_NOT_FACTORY_PROOF",
            "Pinned HXL1 kernel source lacks verified GhostLock path indicators")
    return {
      "schemaVersion":1,
      "target":"SM-G986U1/G986U1UESCHXL1",
      "originalKernelRelease":"4.19.113-27095354",
      "scope":"STOCK_SAMSUNG_SOURCE_VS_PINNED_K40_419_STAGING_REVIEW",
      "stockKernelImageSha256":hxl1.hxl1.ORIGINAL_IMAGE_SHA,
      "pinnedSamsungCoreSource":baseline["sourceFilesSha256Pinned"],
      "samsungSourceIndicators":checks,
      "additionalSamsungSource":checked,
      "k40Reference":reference,
      "conclusions":{
         "originalSamsungSourcePathCorroborated":True,
         "originalFactoryCompiledWaiterObjectPlacementVerified":False,
         "identicalSendmsgStackGeometryDemonstrated":False,
         "k40FutexCollisionProofTransferable":False,
         "k40KASLRPhysicalBaseAndStructOffsetsTransferable":False,
         "liveCvePrimitiveDemonstratedOnHxl1":False,
         "runtimeGhostLockRootVerified":False,
         "stock419KernelSuLoadingVerified":False,
         "readyToGenerateHxl1TargetHeader":False,
      },
      "nextEvidenceTargets":[
         "Attest HXL1 sendmsg/futex compiler-generated frames if OEM disassembly becomes available",
         "Verify original HXL1 waiter layout and lifetime without alioth offsets",
         "Keep runtime exploit and authorized module-loading gates independent"
      ],
      "result":"FACTORY_STACK_AND_RUNTIME_PRIMITIVE_EVIDENCE_MISSING",
      "deviceModified":False,
    }

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ORIGINAL_SOURCE)
    parser.add_argument("--reference-fork",type=Path,default=FORK)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        source=args.source.expanduser().resolve()
        fork=args.reference_fork.expanduser().resolve()
        out=args.output.expanduser().resolve()
        require(not out.exists() and not out.is_symlink() and out!=ROOT and
                ROOT not in out.parents and out!=source and
                source not in out.parents and out!=fork and fork not in out.parents,
                "Refusing overwritten/in-tree evidence output")
        report=audit(source,fork)
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x",encoding="utf-8") as file:
            json.dump(report,file,indent=2)
            file.write("\n")
        print("[ORIGINAL SAMSUNG SOURCE] VERIFIED")
        print("[K40 REFERENCE] PINNED DOC REVISION VERIFIED")
        print("[K40 ROOT CHAIN] BLOCKED IN FROZEN REFERENCE")
        print("[HXL1 EXPLOIT AND MODULE] NOT VERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,UnicodeError,ValueError,KeyError,TypeError) as error:
        print("[STOP]",error,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
