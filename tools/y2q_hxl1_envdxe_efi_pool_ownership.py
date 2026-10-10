#!/usr/bin/env python3
"""HXL1 EnvDxe EFI pool ownership + bounded string length evidence audit.

Identifies precise stock AArch64 instructions in three SHA256-pinned original
Ghidra-verified routine windows, tracing the callback's 0x2618 allocation
and 0x2050 release. Distinguishes the bounded strlen-like routine at 0x3d04
from the actual 72->16-byte transfer inside the callback at 0x2030..0x2040.

No runtime allocation, physical RAM base, privilege escalation or root.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_envdxe_entry_strings import (
    ExtractionError, PE_SHA256, REPORT_DIR
)
from tools.y2q_hxl1_envdxe_callee_provenance import report as source_report
from tools.y2q_hxl1_envdxe_callback_cfg import analyze as callback_report
from tools.y2q_hxl1_envdxe_method_arm64_trace import original_window

# Exact 32-bit LE ARM64 opcodes recovered independently with llvm-objdump.
# Pin entire instruction words, not just branch targets or guessed names.
WRAPPER_WORDS={
    # AllocatePool helper, source 0x25d8 original executable window.
    "allocate-pool":{
        0x25e8:0x910023e2, # add x2, sp, #8: OUT VOID **Buffer
        0x25ec:0xf9419509, # ldr x9, [x8,#0x328]: BootServices
        0x25f0:0xf9402128, # ldr x8, [x9,#0x40]: AllocatePool
        0x25f4:0xd63f0100, # blr x8
        0x25f8:0xb7f80060, # tbnz x0,#63, error
        0x25fc:0xf94007e0, # ldr x0,[sp,#8]: allocated Buffer
        0x2604:0xaa1f03e0, # mov x0,xzr: error -> NULL
    },
    "boot-services-data-wrapper":{
        0x2618:0xaa0003e8, # mov x8,x0: size
        0x261c:0x321e03e0, # orr w0,wzr,#4: EfiBootServicesData
        0x2620:0xaa0803e1, # mov x1,x8: size
        0x2624:0x17ffffed, # b 0x25d8: pool allocation
    },
    # FreePool helper, source 0x26bc original executable window.
    "free-pool":{
        0x26c8:0xf9419509, # ldr x9,[x8,#0x328]: BootServices
        0x26cc:0xf9402529, # ldr x9,[x9,#0x48]: FreePool
        0x26d0:0xd63f0120, # blr x9
        0x26d4:0xaa0003e8, # mov x8,x0: EFI_STATUS
        0x26d8:0xb7f80068, # tbnz x8,#63 error
        0x26e0:0xd65f03c0, # ret
    },
    # This helper is bounded length, not record copying.
    "bounded-string-length":{
        0x3d0c:0xb40001e0, # cbz x0, invalid
        0x3d14:0xaa1f03e8, # mov x8,xzr: count=0
        0x3d18:0xb9404129, # ldr w9,[x9,#0x40]: max count
        0x3d24:0xeb09011f, # cmp x8,x9
        0x3d2c:0x91000400, # add x0,x0,#1
        0x3d30:0x91000508, # add x8,x8,#1
        0x3d34:0x3940000a, # ldrb w10,[x0]
        0x3d38:0x35ffff4a, # cbnz w10, loop
        0x3d3c:0xaa0803e0, # mov x0,x8
        0x3d44:0xd65f03c0, # ret
    },
}
REQUIRED_CFG_CALLS={
    "0x1ff0":"0x2618",
    "0x2004":"0x52cc",
    "0x2050":"0x26bc",
}
REQUIRED_XREF_SITES={
    "allocate-pool":{"0x2624","0x2638"},
    "free-pool":{"0x2050"},
    "bounded-string-length":{"0x3c60","0x3c74"},
}
SOURCE_NAMES={
    "allocate-pool":"secondary-ram-helper",
    "boot-services-data-wrapper":"secondary-ram-helper",
    "free-pool":"callback-tail-callee",
    "bounded-string-length":"record-copy-subroutine",
}
DIRECTIONS={
    "allocate-pool":"UEFI BootServices AllocatePool(+0x40), OUT pointer, status-to-pointer wrapper",
    "boot-services-data-wrapper":"AllocatePool memory type 4, size from caller, tail branch 0x25d8",
    "free-pool":"UEFI BootServices FreePool(+0x48), status-return wrapper",
    "bounded-string-length":"bounded null-terminated byte-count scan, NOT RAM record copy",
}


def word_at(raw:bytes,base:int,at:int)->int:
    offset=at-base
    if offset<0 or offset+4>len(raw) or offset%4:
        raise ExtractionError("Semantic source opcode coordinate outside original executable: "+hex(at))
    return struct.unpack_from("<I",raw,offset)[0]


def check_words(raw:bytes,base:int,word_map:dict[int,int],label:str)->dict:
    pinned={}
    for at,expected in word_map.items():
        found=word_at(raw,base,at)
        if found!=expected:
            raise ExtractionError("Exact ARM64 opcode mismatch at "+hex(at)+" in "+label)
        pinned[hex(at)]=f"0x{expected:08x}"
    return {"role":label,"opcodeCount":len(word_map),
            "originalOpcodeWords":pinned,"runtimePathExecuted":False}


def validate_sources(folder:Path)->dict:
    # Fail closed on original PE/Ghidra identity and full callback CFG.
    older=source_report(folder,strict=True)
    cb=callback_report(folder)
    if (older.get("originalEnvDxeSha256")!=PE_SHA256 or
        cb.get("originalEnvDxeSha256")!=PE_SHA256 or
        older.get("liveRamPartitionsMeasured") is not False or
        cb.get("runtimePhysicalRamKnown") is not False or
        cb.get("kernelPhysicalLoadKnown") is not False or
        cb.get("exploitOrRootAchieved") is not False):
        raise ExtractionError("Original source evidence or runtime proof boundary changed")

    original={
        item["role"]:item
        for item in older.get("additionalOriginalTargetReadbacks",[])
    }
    if len(original)!=3 or any(
        r["importedOriginalGhidraCode"] is None or
        r["staticXrefs"] is None or
        r["importedOriginalGhidraCode"]["match"] is not True
        for r in original.values()
    ):
        raise ExtractionError("Three independent Ghidra helper source attestations missing")

    by_role={}
    for label,source_name in SOURCE_NAMES.items():
        item=original[source_name]
        source=item["originalExecutable"]
        raw=bytes.fromhex(source["bytesHex"])
        base=int(source["staticAddress"],16)
        if label=="boot-services-data-wrapper":
            # This part is already in the previous independent 0x25d8
            # source window (ending at 0x2678): no new PE read.
            pass
        by_role[label]=check_words(raw,base,WRAPPER_WORDS[label],label)
        ref_set=set(item["staticXrefs"]["sources"])
        if not REQUIRED_XREF_SITES[label].issubset(ref_set):
            raise ExtractionError("EFI helper source references changed: "+label)
        by_role[label]["sourceWindowSha256"]=source["sha256"]
        by_role[label]["ghidraEvidenceId"]=item["importedOriginalGhidraCode"]["evidenceId"]
        by_role[label]["sourceNameCorrected"]=DIRECTIONS[label]

    reachable={x["pc"]:x["target"]
               for x in cb["cfg"]["reachableCalls"]}
    for callsite,target in REQUIRED_CFG_CALLS.items():
        if reachable.get(callsite)!=target:
            raise ExtractionError("Complete callback lost allocator/free static call "+callsite)
    if cb["cfg"].get("outOfWindowSuccessors")!=[]:
        raise ExtractionError("Callback bounded CFG no longer closed")

    return {
        "classification":"ORIGINAL_HXL1_RAM_CALLBACK_UEFI_POOL_MEMORY_OWNERSHIP",
        "originalEnvDxeSha256":PE_SHA256,
        "boundedCallbackSha256":cb["threeOriginalGhidraReadbacks"]["originalSha256"],
        "authenticatedSourceRoles":by_role,
        "callbackReusesEfiPoolAllocatorAt":"0x1ff0",
        "internalRamTableHelperCalledAt":"0x2004",
        "callbackFreesTemporaryEfiPoolAt":"0x2050",
        "bootServicesAllocatePoolOffset":"0x40",
        "bootServicesFreePoolOffset":"0x48",
        "bootServicesTablePointerProvenLive":False,
        "allocatedMemoryTypeValue":4,
        "allocatedMemoryTypeName":"EfiBootServicesData",
        "boundedStringLengthNotPartitionCopy":True,
        "recordConversionRemainsInCallbackAt":"0x2030-0x2040",
        "actualRuntimeAllocationObserved":False,
        "actualRuntimeFreeObserved":False,
        "runtimeRamTableObserved":False,
        "kernelPhysicalLoadObserved":False,
        "rootOrKernelSUInstalled":False,
    }


def markdown(x:dict)->str:
    out=[
        "# HXL1 EnvDxe: original EFI RAM callback memory ownership",
        "",
        "Stock EnvDxe SHA256: "+x["originalEnvDxeSha256"],
        "Complete bounded callback SHA256: "+x["boundedCallbackSha256"],"",
        "## ABI-corroborated helper identities","",
        "UEFI BOOT_SERVICES +0x40: AllocatePool(MemoryType, Size, VOID **Buffer)",
        "UEFI BOOT_SERVICES +0x48: FreePool(VOID *Buffer)",
        "UEFI boot memory type 4: EfiBootServicesData",
        "Source: https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html",
        "",
    ]
    for name,v in x["authenticatedSourceRoles"].items():
        out+=["### "+name,"",
              "**Evidence-backed description:** "+v["sourceNameCorrected"],
              "Original PE/Ghidra source SHA256: "+v["sourceWindowSha256"],
              "REA evidence ID: "+v["ghidraEvidenceId"],
              "Exact validated instructions: "+str(v["opcodeCount"])]
        out+=["- "+addr+": "+word for addr,word in v["originalOpcodeWords"].items()]
        out+=[""]
    out+=["## Static callback order","",
          "1. 0x1ff0 -> 0x2618 -> 0x25d8 (BootServicesData pool allocation)",
          "2. 0x2004 -> 0x52cc (internal RAM table provider)",
          "3. 0x2030..0x2040 (72-byte internal -> 16-byte EFI output record)",
          "4. 0x2050 -> 0x26bc (EFI FreePool on temporary allocation)",
          "",
          "The byte loop at 0x3d04 is a bounded string length helper;",
          "it must not be conflated with the callback's record copy.",
          "",
          "## Proof boundaries","",
          "These are code paths, not observed boot execution or heap activity.",
          "The original firmware's DRAM table values, kernel physical load,",
          "exploit applicability and KernelSU installation remain unproven.",""]
    return "\n".join(out)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out",type=Path,default=REPORT_DIR)
    args=ap.parse_args()
    try:
        result=validate_sources(args.out)
        (args.out/"rea-envdxe-efi-pool-ownership.json").write_text(json.dumps(result,indent=2)+"\n")
        (args.out/"rea-envdxe-efi-pool-ownership.md").write_text(markdown(result))
    except (ExtractionError,OSError,ValueError,KeyError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
    print("[POOL ALLOCATOR] 0x25d8 BootServices+0x40")
    print("[TYPE-4 WRAPPER] 0x2618 passes EfiBootServicesData")
    print("[POOL FREE] 0x26bc BootServices+0x48")
    print("[UNRELATED STRING SCAN] 0x3d04 not RAM-record copy")
    print("[REPORT]",args.out/"rea-envdxe-efi-pool-ownership.md")
    print("[LIMIT] No runtime physical RAM/kernel/privilege evidence")
    return 0

if __name__=="__main__":
    sys.exit(main())
