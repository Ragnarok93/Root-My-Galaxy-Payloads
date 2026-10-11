#!/usr/bin/env python3
"""Source-gated, offline HXL1 RKP bitmap preflight for Samsung production-QEMU.

Never starts QEMU, writes guest RAM, patches security code or touches the phone.
The goal is to identify which firmware-specific semantics must be implemented
before an external QEMU secure-monitor plugin can plausibly emulate the kernel.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

TARGET="SM-G986U1/G986U1UESCHXL1"
FILES=(
    "include/linux/uh.h",
    "include/linux/rkp.h",
    "arch/arm64/mm/mmu.c",
    "init/main.c",
    "arch/arm64/mm/pgd.c",
)
DEFAULT_ABI=Path.home()/"s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-source-abi.json"
DEFAULT_REPORT=Path.home()/"s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-preflight.json"
STOCK_CMD_VALUES={
    "RKP_RKP_ROBUFFER_ALLOC":0x11,
    "RKP_RKP_ROBUFFER_FREE":0x12,
    "RKP_GET_RO_BITMAP":0x13,
    "RKP_GET_DBL_BITMAP":0x14,
    "RKP_GET_RKP_GET_BUFFER_BITMAP":0x15,
}

class PreflightError(ValueError):
    pass

def digest_source(path:Path)->dict:
    if not path.is_file() or path.is_symlink():
        raise PreflightError(f"Exact HXL1 source missing/symlink: {path}")
    raw=path.read_bytes()
    return {"sha256":hashlib.sha256(raw).hexdigest(),"text":raw.decode("utf-8","replace")}

def verify_prior_abi(abi:dict,sources:dict)->dict:
    if abi.get("target")!=TARGET or not abi.get("sourceCallCompatible"):
        raise PreflightError("Prior HXL1 ABI result not an exact-source match")
    source_files=abi.get("sourceFiles",{})
    if not isinstance(source_files,dict):
        raise PreflightError("Missing original-source SHA evidence")
    if source_files.get("uhSha256")!=sources["include/linux/uh.h"]["sha256"]:
        raise PreflightError("HXL1 uh.h changed since prior source ABI attestation")
    if source_files.get("rkpSha256")!=sources["include/linux/rkp.h"]["sha256"]:
        raise PreflightError("HXL1 rkp.h changed since prior source ABI attestation")
    regs=abi.get("gdbCapture",{}).get("registers",{})
    if (regs.get("X0")!="0xc300c002" or regs.get("X1")!="0x15" or
            regs.get("X2")!="0xffffff800a4dd0b8" or
            regs.get("X3")!="0x40000000"):
        raise PreflightError("Prior GDB registers differ from owner-observed bitmap SMC")
    return {"status":"PASSED_RECHECKED_SOURCE_DIGESTS_AND_SMC_CAPTURE",
            "sourceUhSha256":sources["include/linux/uh.h"]["sha256"],
            "sourceRkpSha256":sources["include/linux/rkp.h"]["sha256"],
            "priorSourceCallCompatible":True}

def command_ids(rkp:str)->dict:
    result={}
    for key,val in STOCK_CMD_VALUES.items():
        m=re.search(r"\b"+re.escape(key)+r"\s*=\s*(0[xX][0-9a-fA-F]+|\d+)",rkp)
        if not m:raise PreflightError(f"HXL1 source lacks {key}")
        parsed=int(m.group(1),0)
        result[key]={"sourceValue":hex(parsed),"expectedForBitmapABI":hex(val),
                     "matchesObservedProtocol":parsed==val}
    return result

def extract_c_body(text:str,name:str)->str:
    m=re.search(r"\b"+re.escape(name)+r"\s*\([^)]*\)\s*{",text)
    if not m:raise PreflightError(f"Source function {name} not found")
    pos=m.end()
    depth=1
    for i in range(pos,len(text)):
        if text[i]=="{":depth+=1
        elif text[i]=="}":
            depth-=1
            if depth==0:return text[pos:i]
    raise PreflightError(f"Unterminated {name} source body")

def compact(text:str)->str:
    return re.sub(r"\s+","",text)

def source_witnesses(sources:dict)->dict:
    rkp=sources["include/linux/rkp.h"]["text"]
    mmu=sources["arch/arm64/mm/mmu.c"]["text"]
    main=sources["init/main.c"]["text"]
    pgd=sources["arch/arm64/mm/pgd.c"]["text"]
    cmd=command_ids(rkp)
    body=extract_c_body(rkp,"rkp_check_bitmap")
    rob=extract_c_body(rkp,"rkp_ro_alloc")
    pg=extract_c_body(mmu,"paging_init")
    ini=extract_c_body(main,"rkp_init")
    pgd_body=extract_c_body(pgd,"pgd_alloc")
    sparse=re.search(r"typedef\s+struct\s+sparse_bitmap_for_kernel\s*{(.*?)}\s*sparse_bitmap_for_kernel_t\s*;",rkp,re.S)
    if not sparse:raise PreflightError("HXL1 sparse_bitmap_for_kernel_t declaration missing")
    fields=sparse.group(1)
    checks={
        "commandIdsMatchCapturedHxl1":all(x["matchesObservedProtocol"] for x in cmd.values()),
        "sparseUnitIs1GiB":bool(re.search(r"#define\s+SPARSE_UNIT_BIT\s+\(?30\b",rkp)),
        "sparseBitmapHasStartEndMaxnAndMap":all(re.search(x,fields) for x in
                   (r"\bu64\s+start_addr\s*;",r"\bu64\s+end_addr\s*;",
                    r"\bu64\s+maxn\s*;",r"\bchar\s*\*\s*\*\s*map\s*;")),
        "bitmapUsesPhysicalStartOffset": "offset=pa-kernel_bitmap->start_addr;" in compact(body),
        "bitmapIndexesBy1GiBUnit": bool(re.search(
            r"offset>>SPARSE_UNIT_BIT",compact(body))),
        "bitmapUsesPageSizedBits": "PAGE_SIZE" in body and
                                      "bit_offset" in body and "map_loc" in body,
        "bitmapMayReturnFallbackForMissingMap": "uninitialized_ret" in body,
        "robufferAllocationRequiresSmcOutputPointer":bool(re.search(
             r"\buh_call_static\s*\(\s*UH_APP_RKP\s*,\s*RKP_RKP_ROBUFFER_ALLOC",rob)),
        "robufferAllocationChecksOutputNotUnchanged": "0xDEAD" in rob and "BUG_ON" in rob,
        "pagingInvokesBitmapBeforeNormalMappings":
             (all(x in pg for x in ("rkp_robuffer_init();","map_kernel(pgdp);","map_mem(pgdp);")) and
              pg.index("rkp_robuffer_init();")<pg.index("map_kernel(pgdp);")<
              pg.index("map_mem(pgdp);")),
        "laterRkpInitFetchesTwoOtherBitmaps":
             "RKP_GET_RO_BITMAP" in ini and "RKP_GET_DBL_BITMAP" in ini,
        "laterRkpInitSendsStartCommand":"RKP_START" in ini,
        "pgdAllocationMayUseRkpPool":"rkp_ro_alloc()" in pgd_body,
        "pgdFreeRequiresBitmapOwnershipCheck":"is_rkp_ro_page(" in pgd,
    }
    return {"checks":checks,"commandIds":cmd,
            "allRequirementsConfirmed":all(checks.values()),
            "relevantWitnesses":{
              "pagingInitOrder":["rkp_robuffer_init()","map_kernel()","map_mem()"],
              "bitmapSparseUnitBytes":1<<30,
              "bitmapPhysicalAddressUnits":"PAGE_SIZE from exact kernel .config",
              "bitmapDescriptorFields":["start_addr","end_addr","maxn","map"],
              "robufferAllocationReturns":"Physical address stored via UH output pointer",
              "additionalRkpCommands":["RKP_GET_RO_BITMAP","RKP_GET_DBL_BITMAP","RKP_START",
                                       "RKP_RKP_ROBUFFER_ALLOC","RKP_RKP_ROBUFFER_FREE"],
            }}

def read_kernel_config(path:Path)->dict:
    if not path.is_file() or path.is_symlink():return {"status":"UNAVAILABLE"}
    try:
        if path.suffix==".gz":
            with gzip.open(path,"rt",encoding="utf-8",errors="replace") as f:
                text=f.read(4*1024*1024)
        else:
            text=path.read_text()
    except (OSError,EOFError) as e:
        raise PreflightError(f"Kernel config cannot be read: {e}")
    flags={key:bool(re.search(r"(?m)^"+key+r"=y$",text)) for key in
           ("CONFIG_UH_RKP","CONFIG_ARM64_4K_PAGES","CONFIG_ARM64_16K_PAGES","CONFIG_ARM64_64K_PAGES")}
    flags["status"]="SOURCE_CONFIG_ONLY_NOT_RUNTIME_GUEST_PROOF"
    flags["pageSizeBytes"]=(4096 if flags["CONFIG_ARM64_4K_PAGES"] else
                            16384 if flags["CONFIG_ARM64_16K_PAGES"] else
                            65536 if flags["CONFIG_ARM64_64K_PAGES"] else None)
    return flags

def preflight(abi:dict,sources:dict,config:dict)->dict:
    att=verify_prior_abi(abi,sources)
    witnesses=source_witnesses(sources)
    return {"target":TARGET,"previousAbiGate":att,
            "fileDigests":{p:{"sha256":v["sha256"]} for p,v in sources.items()},
            "exactSourceFindings":witnesses,"originalKernelConfig":config,
            "qemuAdapterReadiness":{
                "hxl1SmcDispatchIdsUnderstood":witnesses["checks"]["commandIdsMatchCapturedHxl1"],
                "bitmapStructureAndBootOrderUnderstood":witnesses["allRequirementsConfirmed"],
                "UHOwnedBitmapDescriptorMemoryAllocatedAndReserved":False,
                "UHProtectedPagePoolReservedAndAllocated":False,
                "QemuMemoryWritesAndBoundaryChecksImplemented":False,
                "SourceFaithfulEmulatorReady":False,
            },
            "doNotReuseForkUnchanged":{
                "applicationId0xc300c002":"Upstream fork calls KDP, exact HXL1 source calls RKP",
                "command0x15":"Upstream fork handles namespace flags, HXL1 requests buffer bitmap",
                "unknownSmcFallback":"Must NOT return generic success for unsupported UH commands",
            },
            "note":"Source evidence identifies emulator requirements, not a functioning "
                   "UH implementation, safe memory allocation, successful kernel boot, "
                   "bootloader unlock or KernelSU deployment."}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    p.add_argument("--prior-abi",type=Path,default=DEFAULT_ABI)
    p.add_argument("--config",type=Path,default=Path.home()/"s20-artifacts/config.gz")
    p.add_argument("--output",type=Path,default=DEFAULT_REPORT)
    a=p.parse_args()
    try:
        dest=a.output.expanduser().absolute()
        src_paths=[a.source_root/x for x in FILES]
        originals=[a.prior_abi,a.config]+src_paths
        if dest.exists() or dest.suffix!=".json" or dest in [x.expanduser().absolute() for x in originals]:
            raise PreflightError("Use a new JSON path; do not overwrite any evidence")
        if not a.prior_abi.is_file() or a.prior_abi.is_symlink():
            raise PreflightError("Previously confirmed HXL1 source ABI report missing")
        abi=json.loads(a.prior_abi.read_text())
        src={name:digest_source(a.source_root/name) for name in FILES}
        config=read_kernel_config(a.config)
        report=preflight(abi,src,config)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(report,indent=2)+"\n")
        for key,value in report["exactSourceFindings"]["checks"].items():
            print("[SOURCE]", "PASS" if value else "UNVERIFIED", key)
        print("[KERNEL PAGE SIZE]",config.get("pageSizeBytes"))
        print("[FORK]", "NOT READY; protected pool and descriptor reservation unimplemented")
        print("[REPORT]",dest)
        return 0 if report["exactSourceFindings"]["allRequirementsConfirmed"] else 3
    except (OSError,ValueError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
