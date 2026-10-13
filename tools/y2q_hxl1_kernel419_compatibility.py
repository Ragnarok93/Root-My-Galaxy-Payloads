#!/usr/bin/env python3
"""Read-only Samsung HXL1 4.19 source compatibility review vs Redmi K40 PoC.

The external reference targets Redmi K40 (alioth, 4.19.157). This checker
authenticates the *Samsung* 4.19.113 source first, records conservative
4.19-specific API evidence, and NEVER emits offsets, root modules, target.h,
firmware patches, or deployable payload metadata.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_rtmutex_displacement_attest as hxl1

REPO=Path(__file__).resolve().parents[1]
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
REFERENCE="https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40"
ADDITIONAL_SOURCES={
    "configfs":"fs/configfs/file.c",
    "ashmem":"drivers/staging/android/ashmem.c",
    "seccomp":"include/linux/seccomp.h",
    "cred":"include/linux/cred.h",
    "allocator":"mm/slab_common.c",
}
class SourceStop(ValueError): pass

def sha256(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def read_file(path:Path,*,required:bool=True)->tuple[str|None,str|None]:
    if path.is_symlink() or (required and not path.is_file()):
        raise SourceStop("Missing/unsafe original Samsung source: "+str(path))
    if not path.is_file():
        return None,None
    if path.stat().st_size>4*1024*1024:
        raise SourceStop("Unexpectedly large Samsung source: "+str(path))
    raw=path.read_bytes()
    return raw.decode("utf-8"),sha256(raw)

def present(code:str|None,expression:str)->str:
    if code is None:
        return "NOT_CHECKED_SOURCE_MISSING"
    return "SOURCE_PATTERN_PRESENT_NOT_FACTORY_PROOF" if re.search(
        expression,code,re.S) else "SOURCE_PATTERN_NOT_OBSERVED"

def review_source(source:Path,*,pins:dict[str,str]|None=None)->dict:
    """Fail closed if the canonical original rtmutex/futex inputs differ."""
    pins=hxl1.SOURCE_PINS if pins is None else pins
    required={}
    for name,pin in pins.items():
        code,digest=read_file(source/name)
        if digest!=pin:
            raise SourceStop("Factory-pinned Samsung source SHA mismatch: "+name)
        required[name]={"sha256":digest,"state":"SOURCE_SHA256_PIN_VERIFIED"}
    rt,_=read_file(source/"kernel/locking/rtmutex.c")
    ft,_=read_file(source/"kernel/futex.c")
    checked={}
    digests={}
    for label,rel in ADDITIONAL_SOURCES.items():
        body,digest=read_file(source/rel,required=False)
        checked[label]=body
        digests[label]={"path":rel,"sha256":digest,
                        "state":"PRESENT_NOT_FACTORY_BINARY_ATTESTED" if digest else
                                "NOT_CHECKED_SOURCE_MISSING"}
    facts={
        "rtmutexRemoveWaiter":
            present(rt,r"\bstatic\s+void\s+remove_waiter\s*\("),
        "rtmutexCurrentPiBlockedOn":
            present(rt,r"current->pi_blocked_on\s*=\s*NULL"),
        "rtmutexWaiterTaskReference":
            present(rt,r"waiter->task"),
        "futexRequeue":
            present(ft,r"\bfutex_requeue\s*\("),
        "configfsReadFile":
            present(checked["configfs"],r"\bconfigfs_read_file\s*\("),
        "configfsWriteBinFile":
            present(checked["configfs"],r"\bconfigfs_write_bin_file\s*\("),
        "seccompFilterCount":
            present(checked["seccomp"],r"\bfilter_count\b"),
        "credSecurityField":
            present(checked["cred"],r"\bsecurity\s*;"),
    }
    return {
       "schemaVersion":1,
       "target":{"model":"SM-G986U1","firmware":"G986U1UESCHXL1",
                 "kernel":"4.19.113-27095354","bootHeaderVersion":2,
                 "pinnedKernelSha256":hxl1.ORIGINAL_IMAGE_SHA},
       "externalReference":{"url":REFERENCE,"device":"Redmi K40 (alioth)",
                 "kernel":"4.19.157-perf-g9607d8651312",
                 "bootHeaderVersion":3,"copyCrossDeviceConstants":False},
       "reference419Differences":[
          {"area":"configfs","reference":"4.19 f_ops .read/.write instead of iter slots",
           "hxl1Rule":"Validate actual Samsung callback names and signatures"},
          {"area":"ashmem","reference":"No /dev/ashmem name-prefix assumption",
           "hxl1Rule":"Inspect exact Samsung implementation before any conclusion"},
          {"area":"allocator","reference":"Older kmalloc cache families and pipe geometry",
           "hxl1Rule":"Do not import Redmi cache counts or object sizes"},
          {"area":"security","reference":"Different cred/SELinux and seccomp member layouts",
           "hxl1Rule":"Do not import Redmi credential or seccomp offsets"},
          {"area":"rtmutex","reference":"Original Linux 4.19 waiter/PI cleanup behavior",
           "hxl1Rule":"Cross-correlate pinned source with OEM Ghidra High P-code"},
          {"area":"boot","reference":"K40 boot v3 vs Samsung boot v2",
           "hxl1Rule":"Samsung ABL is ELF32/ARM; extracted LinuxLoader is ARM64 EFI"},
       ],
       "sourceFilesSha256Pinned":required,
       "otherSourceFiles":digests,
       "sourceObservations":facts,
       "factoryMemberOffsetsCertified":0,
       "physicalKernelLoadValidated":False,
       "runtimeExploitVerified":False,
       "rootOrKernelSuVerified":False,
       "stage3Complete":False,
       "recommendation":"RESEARCH_ONLY_NO_TARGET_HEADER_PROMOTION",
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=SOURCE)
    p.add_argument("--output",type=Path,
                   help="New JSON outside repository and stock source; absent by default")
    a=p.parse_args()
    source=a.source.expanduser().absolute()
    try:
        result=review_source(source)
        if a.output:
            output=a.output.expanduser().absolute()
            if (output.exists() or output.is_symlink() or output==source or
                source in output.parents or output==REPO or REPO in output.parents or
                output.parent.is_symlink()):
                raise SourceStop("Refuse unsafe/existing evidence output")
            output.parent.mkdir(parents=True,exist_ok=True)
            with output.open("x") as handle:
                json.dump(result,handle,indent=2)
                handle.write("\n")
            print("[REPORT]",output)
        else:
            print(json.dumps(result,indent=2))
        print("[HXL1 4.19] ORIGINAL_SAMSUNG_SOURCE_COMPARISON_ONLY",file=sys.stderr)
        return 0
    except (OSError,UnicodeError,SourceStop) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
