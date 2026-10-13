#!/usr/bin/env python3
"""Read-only Samsung HXL1 kernel-4.19 source review against an alien K40 reference.

Neither the reference device's addresses nor its kernel object layouts may be
transplanted to HXL1. This script cannot generate a root payload, target.h or
physical header. Evidence is source hashes and explicit source text only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

REFERENCE={
 "url":"https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40",
 "device":"Redmi K40/alioth Snapdragon 870",
 "kernel":"4.19.157-perf-g9607d8651312",
 "bootHeader":3,
 "profile":"oplus-4.19.157-perf",
 "productionOffsetsTransferableToHXL1":False,
 "claimedWorkingRootForHXL1":False,
}
HXL1={
 "model":"SM-G986U1",
 "build":"G986U1UESCHXL1",
 "kernel":"4.19.113-27095354",
 "bootHeader":2,
 "originalImageSha256":"ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123",
}
CALLBACKS={
 "CONFIGFS_READ_FILE_OFF":"configfs_read_file",
 "CONFIGFS_WRITE_BIN_FILE_OFF":"configfs_write_bin_file",
 "CONFIGFS_READ_ITER_OFF":"configfs_read_iter",
 "CONFIGFS_BIN_WRITE_ITER_OFF":"configfs_bin_write_iter",
}
COMPARISON_WAITER_OFFSETS={
 "tree_entry":"0x0","pi_tree_entry":"0x18","task":"0x30",
 "lock":"0x38","prio":"0x40","deadline":"0x48",
}
SOURCE_CANDIDATES={
 "remove_waiter_present":("kernel/locking/rtmutex.c",r"\bstatic\s+void\s+remove_waiter\s*\("),
 "current_pi_lock":("kernel/locking/rtmutex.c",r"raw_spin_lock\s*\(\s*&current->pi_lock\s*\)"),
 "current_pi_blocked_on_clear":("kernel/locking/rtmutex.c",r"current->pi_blocked_on\s*=\s*NULL"),
 "proxy_lock_cleanup":("kernel/locking/rtmutex.c",r"if\s*\(\s*unlikely\s*\(ret\)\s*\)\s*remove_waiter\s*\("),
 "futex_requeue":("kernel/futex.c",r"\bfutex_requeue\s*\("),
}

def digest(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def review(source:Path)->dict:
    result={
      "schemaVersion":1,"reference":REFERENCE,"target":HXL1,
      "status":"UNKNOWN","checkedSource":{},
      "patternMatches":{},"symbolNaming":CALLBACKS,
      "different4_19Semantics":{
        "configfs":"K40 .read/.write functions are not .read_iter/.write_iter",
        "ashmem":"K40 prefix=0 is not established on HXL1",
        "kmalloc":"K40 cache-type count and pipe object size require HXL1 proof",
        "security":"K40 cred and seccomp layouts are not factory Samsung layouts",
        "addressSpace":"No K40 physical address, virtual-page base or KASLR constants transferable",
        "bootloader":"Outer Samsung ABL is ELF32/ARM; extracted LinuxLoader is PE AArch64",
      },
      "factoryStructOffsetsCertified":0,
      "sourceToBinaryEquivalenceCertified":False,
      "stage3Complete":False,"onDeviceRootVerified":False,
      "kernelSuDeploymentVerified":False,"deviceModified":False,
    }
    texts={}
    for relative in sorted({spec[0] for spec in SOURCE_CANDIDATES.values()}):
        p=source/relative
        if not p.is_file() or p.is_symlink():
            result["checkedSource"][relative]={"state":"MISSING_OR_UNSAFE"}
            result["status"]="SOURCE_MISSING_OR_UNSAFE"
            return result
        raw=p.read_bytes()
        if len(raw)>2*1024*1024:
            result["checkedSource"][relative]={"state":"OVERSIZED"}
            result["status"]="SOURCE_UNSAFE"
            return result
        texts[relative]=raw.decode("utf-8","replace")
        result["checkedSource"][relative]={"state":"HASHED","sha256":digest(raw),"bytes":len(raw)}
    for key,(file,pattern) in SOURCE_CANDIDATES.items():
        result["patternMatches"][key]=bool(re.search(pattern,texts[file],re.S))
    result["status"]=(
       "SAMSUNG_419_SOURCE_PATH_PRESENT_ABI_UNVERIFIED"
       if all(result["patternMatches"].values())
       else "SOURCE_PATTERN_MISMATCH_NEEDS_REVIEW"
    )
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    p.add_argument("--output",type=Path,help="New file only; never overwrite earlier evidence")
    a=p.parse_args()
    r=review(a.source.expanduser())
    if a.output is not None:
        out=a.output.expanduser().absolute()
        if out==a.source.expanduser().absolute() or a.source.expanduser().absolute() in out.parents or out.is_symlink():
            p.error("Refusing output inside source tree")
        out.parent.mkdir(parents=True,exist_ok=True)
        try:
            with out.open("x") as f:f.write(json.dumps(r,indent=2)+"\n")
        except FileExistsError:
            p.error("Report already exists; preserve original evidence")
    print("[SAMSUNG HXL1 KERNEL 4.19]",r["status"])
    print("[K40 OFFSETS TRANSFERABLE]",False)
    print("[FACTORY C-MEMBER OFFSETS CERTIFIED]",0)
    if a.output:print("[REPORT]",a.output)
    return 0 if r["status"]=="SAMSUNG_419_SOURCE_PATH_PRESENT_ABI_UNVERIFIED" else 2

if __name__=="__main__":
    raise SystemExit(main())
