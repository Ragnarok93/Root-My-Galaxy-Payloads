#!/usr/bin/env python3
"""Offline original-HXL1 SMC and data-abort source dependency verification.

Pins the 35,168-byte compact runtime FDT and the original source Image,
rechecks retained QEMU exception events, decodes stock instructions, and
reports *candidate* faulting base registers. Neither FAR nor ELR records
the base register's actual value; a paired load may fault on either word.
No QEMU execution, OEM service interception, kernel modification or device I/O.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_compact_exception_audit as compact
from tools import y2q_hxl1_qemu_secure_monitor_gate as secure
from tools import y2q_hxl1_qemu_fault_sites as sites
from tools import y2q_hxl1_memblock_trace_gate as gate

TARGET=compact.TARGET
SOURCE_GUEST_FDT_BYTES=35168
COMPACT_INPUT_SHA="1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd"
FAR_BY_ELR={
    compact.KNOWN_FAULTS[0]:0x58,
    compact.KNOWN_FAULTS[1]:0x10,
}
EXPECTED_SITES=(compact.SMC_PC,*compact.KNOWN_FAULTS)

class FaultDependencyError(ValueError):
    pass

def classify_prior(prior:dict,image:bytes,raw_log:bytes,linked:dict)->dict:
    gate.valid_source(image)
    if (prior.get("target")!=TARGET or
        prior.get("status")!="ORIGINAL_IMAGE_CORRELATED_COMPACT_QEMU_EXCEPTIONS" or
        prior.get("originalFactoryImageSha256")!=gate.KERNEL_SHA or
        prior.get("reconstructedImageVaBase")!=hex(gate.VM_BASE) or
        prior.get("originalFactoryImageModified") is not False):
        raise FaultDependencyError("Prior original-image provenance fails closed")
    must_link={k:v for k,v in linked.items() if k!="exceptionFile"}
    if (prior.get("verifiedEvidenceLinks")!=must_link or
        must_link.get("compactInputSha256")!=COMPACT_INPUT_SHA or
        must_link.get("runtimeGuestFdtBytes")!=SOURCE_GUEST_FDT_BYTES):
        raise FaultDependencyError("Original compact FDT/runtime evidence differs from attested source")
    current=compact.extract_event_log(raw_log)
    if (current["totalExceptionMarkers"]!=prior.get("totalExceptionMarkers") or
        current["logSha256"]!=prior.get("exceptionLogSha256")):
        raise FaultDependencyError("Saved source log hash/event count changed")
    events=prior.get("events")
    if not isinstance(events,list) or len(events)!=3:
        raise FaultDependencyError("Expected precisely three retained original exception events")
    if {int(e["elr"],16) for e in events if e.get("elr")}!=set(EXPECTED_SITES):
        raise FaultDependencyError("Original SMC and both fault ELRs not uniquely retained")
    if len({e.get("line") for e in events})!=3:
        raise FaultDependencyError("Unexpected duplicated QEMU exception record")
    actual={int(e["elr"],16):e for e in current["events"]
            if e.get("elr") and int(e["elr"],16) in EXPECTED_SITES}
    if len(actual)!=3:
        raise FaultDependencyError("Actual QEMU exception log missing known sites")
    items=[]
    for e in events:
        pc=int(e["elr"],16)
        retained=actual[pc]
        for key in ("elr","esr","far","line"):
            if e.get(key)!=retained.get(key):
                raise FaultDependencyError("Saved exception record differs from raw QEMU log at "+hex(pc))
        original=sites.window(image,pc,gate.VM_BASE)
        expected_op=secure.EXPECTED[pc]
        if (original.get("status")!="ORIGINAL_STOCK_IMAGE_BYTES_FOUND" or
            original["originalOpcode"]!=expected_op or
            e.get("originalSource",{}).get("originalOpcode")!=expected_op):
            raise FaultDependencyError("Original factory instruction bytes do not corroborate ELR "+hex(pc))
        decoded=secure.decode(int(expected_op,16))
        src=sites.nearest_symbol
        row={
            "elr":hex(pc),"originalOpcode":expected_op,
            "factoryImageOffset":original["candidateImageOffset"],
            "instruction":decoded,
            "nearestRecoveredSymbol":e.get("nearestRecoveredSymbol"),
            "far":e.get("far"),"esr":e.get("esr"),
            "esrDecoded":e.get("esrDecoded"),
            "liveBaseRegisterRead":False,
            "liveInstructionOpcodeRead":False,
            "smcServiceReturnValueRead":False,
        }
        if pc==compact.SMC_PC:
            if decoded["instruction"]!="SMC" or decoded["immediate"]!=0:
                raise FaultDependencyError("Factory SMC #0 opcode missing")
            row["status"]="SMC_0_TRAP_SEEN_SERVICE_X0_AND_RETURN_UNVERIFIED"
            row["nextEvidence"]="Read the original guest X0-X6 before SMC, and X0 at the return boundary; check real Samsung UH ABI without inventing responses."
        else:
            if (e.get("far") is None or e.get("esr") is None or
                e["esrDecoded"] is None or
                e["esrDecoded"].get("category")!="DATA_ABORT_CURRENT_EL" or
                e["esrDecoded"].get("memoryAccess")!="read"):
                raise FaultDependencyError("Not a verified current-EL data-abort read")
            far=int(e["far"],16)
            if far!=FAR_BY_ELR[pc]:
                raise FaultDependencyError("Observed FAR does not match original owner-fault address")
            if decoded["instruction"] not in ("LDR_X_UNSIGNED_OFFSET","LDP_X_OFFSET"):
                raise FaultDependencyError("Unexpected source memory-read instruction")
            offset=decoded["byteOffset"]
            # AArch64 LDP can fault on the first or second 64-bit element.
            # FAR alone cannot select which element, nor attest Rn's value.
            possible_offsets=[offset] if decoded["instruction"]=="LDR_X_UNSIGNED_OFFSET" else [offset,offset+8]
            row.update(
                status="FACTORY_READ_FAULT_BASE_REGISTER_UNCAPTURED",
                expectedFar=hex(far),
                baseRegister=decoded["baseRegister"],
                candidateEffectiveOffsetsBytes=possible_offsets,
                candidateBaseValuesIfAddressCalculationSimple=[
                    hex((far-off)&((1<<64)-1)) for off in possible_offsets],
                zeroBaseConsistent=(far in possible_offsets),
                nullBaseProven=False,
                nextEvidence="Capture the actual base register, SP/ELR/FAR/ESR and call context at this original instruction before any platform/SMC causal claim.",
            )
        items.append(row)
    items.sort(key=lambda item:EXPECTED_SITES.index(int(item["elr"],16)))
    return {
        "status":"FACTORY_INSTRUCTION_DEPENDENCIES_OFFLINE_VERIFIED",
        "target":TARGET,
        "originalFactoryImageSha256":gate.KERNEL_SHA,
        "sourceCompactRuntimeFdtBytes":SOURCE_GUEST_FDT_BYTES,
        "sourceCompactOverrideSha256":COMPACT_INPUT_SHA,
        "events":items,
        "allThreeEventsCorrelatedToRawExceptionLog":True,
        "sameRunSmcCallArgumentsCaptured":False,
        "sameRunSmcReturnCaptured":False,
        "dataAbortBaseRegistersCaptured":False,
        "dataAbortCausedBySmcProven":False,
        "linuxMemblockReservationVerified":False,
        "secureMonitorFunctional":False,
        "secureRkpPoolReserved":False,
        "kernelBootedToUserspace":False,
        "originalFactoryKernelModified":False,
        "physicalDeviceTouched":False,
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--research-root",type=Path,default=root)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--input",type=Path,
                   default=root/"qemu-pc-compact-fdt-20261012/compact-original-exception-audit.json")
    p.add_argument("--output",type=Path,
                   default=root/"qemu-pc-compact-fdt-20261012/compact-fault-dependencies-v2.json")
    a=p.parse_args()
    try:
        output=a.output.expanduser().absolute()
        input_path=a.input.expanduser().absolute()
        if (output.suffix!=".json" or output.exists() or output.is_symlink() or
            output in (input_path,a.kernel.expanduser().absolute())):
            raise FaultDependencyError("Choose fresh JSON output; preserve original evidence")
        root=a.research_root.expanduser().absolute()
        image,linked=compact.verify_linked_evidence(root,a.kernel.expanduser().absolute())
        old=json.loads(gate.checked_file(input_path,320*1024))
        raw=gate.checked_file(linked["exceptionFile"],compact.MAX_LOG)
        report=classify_prior(old,image,raw,linked)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(report,indent=2)+"\n")
        for e in report["events"]:
            if e["instruction"]["instruction"]=="SMC":
                print("[STOCK SMC]",e["elr"],e["originalOpcode"],"SMC #0; X0 service NOT captured")
            else:
                print("[STOCK FAULT]",e["elr"],e["instruction"]["instruction"],
                      "base",e["baseRegister"],"FAR",e["far"],
                      "zero-base compatible",e["zeroBaseConsistent"])
        print("[SAME-RUN SMC RETURN] NOT VERIFIED")
        print("[DATA ABORT CAUSAL LINK TO SMC] NOT VERIFIED")
        print("[REPORT]",output)
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
