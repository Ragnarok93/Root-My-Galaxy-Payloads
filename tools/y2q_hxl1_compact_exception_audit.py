#!/usr/bin/env python3
"""Source-correlate actual compact-DTB HXL1 QEMU exception logs, offline only.

Cross-checks the original SHA-pinned Image, exact compact input construction,
owner's fully captured <=2MiB guest FDT, and the matching QMP capture
before interpreting exception ELRs, FARs and ESRs against original bytes.

QEMU's exception logs do not establish a genuine Samsung hypervisor,
Linux memory allocator correctness, RKP buffer availability, root, or boot.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_memblock_trace_gate as gate
from tools import y2q_hxl1_qemu_compact_fdt_capture as compact_capture
from tools import y2q_hxl1_qemu_exception_summary as summary
from tools import y2q_hxl1_qemu_fault_sites as sites
from tools import y2q_hxl1_qemu_fdt_size_recovery as recovery

MAX_LOG=16*1024*1024
MAX_SAMPLE=320*1024
SMC_PC=0xffffff80080a5794
KNOWN_FAULTS=(0xffffff80082ac90c,0xffffff80086de39c)
EVENT_START=re.compile(rb"(?m)^Taking exception\s+(\d+)\s+(\[[^\r\n]{1,90}\])")
ELR_RE=sites.ELR_RE
TARGET="SM-G986U1/G986U1UESCHXL1"

class CompactExceptionError(ValueError):
    pass

def extract_event_log(raw:bytes,limit:int=24)->dict:
    if len(raw)>MAX_LOG:
        raise CompactExceptionError("Exception log exceeds 16MiB bound")
    lines=raw.decode("utf8","replace").splitlines()
    events=[]
    total=0
    for i,line in enumerate(lines):
        if not line.startswith("Taking exception "):
            continue
        total+=1
        chunk=[line]
        for following in lines[i+1:i+9]:
            if following.startswith(("...","   ...")):
                chunk.append(following)
            else:
                break
        joined="\n".join(chunk)
        elr=ELR_RE.search(joined)
        far=sites.FAR_RE.search(joined)
        esr=sites.ESR_RE.search(joined)
        if len(events)<limit:
            events.append({
                "line":i+1,
                "kind":line[:120],
                "elr":hex(int(elr.group(1),16)) if elr else None,
                "far":hex(int(far.group(1),16)) if far else None,
                "esr":hex(int(esr.group(1),16)) if esr else None,
                "esrDecoded":sites.decode_esr(int(esr.group(1),16)) if esr else None,
            })
    return {"events":events,"totalExceptionMarkers":total,
            "retainedEventCount":len(events),
            "samplesTruncatedToLimit":total>len(events),
            "logSha256":hashlib.sha256(raw).hexdigest()}

def source_correlate(evidence:dict,image:bytes,symbols:dict)->dict:
    gate.valid_source(image)
    objdump=shutil.which("aarch64-linux-gnu-objdump")
    enriched=[]
    for e in evidence["events"]:
        event=dict(e)
        if event["elr"] is not None:
            va=int(event["elr"],16)
            opcode=sites.window(image,va,gate.VM_BASE)
            event["originalSource"]=opcode
            event["nearestRecoveredSymbol"]=sites.nearest_symbol(symbols,va)
            event["originalDisassembly"]=sites.disassemble(opcode,gate.VM_BASE,objdump)
            event["isKnownSamsungSmcCallsite"]=va==SMC_PC
            event["isEarlierObservedDataAbortElr"]=va in KNOWN_FAULTS
        event["executedGuestInstructionBytesIndependentlyRead"]=False
        enriched.append(event)
    smc=[e for e in enriched if e.get("isKnownSamsungSmcCallsite")]
    aborts=[e for e in enriched if e.get("isEarlierObservedDataAbortElr")]
    return {
        "status":"ORIGINAL_IMAGE_CORRELATED_COMPACT_QEMU_EXCEPTIONS",
        "target":TARGET,
        "originalFactoryImageSha256":gate.KERNEL_SHA,
        "reconstructedImageVaBase":hex(gate.VM_BASE),
        "recoveredSymbolMapSha256":symbols.get("sourceSha256"),
        "exceptionLogSha256":evidence["logSha256"],
        "totalExceptionMarkers":evidence["totalExceptionMarkers"],
        "events":enriched,
        "knownSmcSitePresentInRetainedEvents":bool(smc),
        "knownFaultSitesPresentInRetainedEvents":[
            hex(x) for x in KNOWN_FAULTS
            if any(e["elr"]==hex(x) for e in aborts)
        ],
        "noSmcEventDoesNotProveSmcAbsent":True,
        "guestSmcFunctionalityVerified":False,
        "guestLinuxMemblockAllocatorStateVerified":False,
        "rkpProtectedPoolReserved":False,
        "linuxUserspaceBootVerified":False,
        "physicalDeviceTouched":False,
        "originalFactoryImageModified":False,
        "caveat":"QEMU exception ELRs and reconstructed original Image symbols "
                 "do not prove the precise runtime instruction bytes or that "
                 "a vendor secure monitor service completed successfully.",
    }

def verify_linked_evidence(root:Path,image_path:Path)->tuple[bytes,dict]:
    image=gate.checked_file(image_path)
    gate.valid_source(image)
    source=gate.checked_file(root/"qemu-virt-dtb-20261011/qemu-virt.dtb",8*1024*1024)
    compact=root/"qemu-fdt-under-2m-20261012"
    override=gate.checked_file(compact/"compact-override.dtb",8*1024*1024)
    manifest=json.loads(gate.checked_file(compact/"compact-manifest.json",128*1024))
    checked=recovery.verify_recovery(source,override,manifest)
    cap=root/"qemu-compact-entry-fdt-20261012"
    fdt_raw=gate.checked_file(cap/"guest-compact-fdt.dtb",8*1024*1024)
    gdb=gate.checked_file(cap/"gdb-session.log",128*1024).decode("utf8","replace")
    runtime=compact_capture.verify_capture(fdt_raw,gdb)
    if not runtime["guestFdtWithin2MiB"]:
        raise CompactExceptionError("Original guest FDT not verified below 2MiB limit")
    recorded=json.loads(gate.checked_file(cap/"compact-fdt-audit.json",128*1024))
    for key in ("runtimeFdtSha256","guestFdtTotalBytes","status","diagSelfReservation"):
        if recorded.get(key)!=runtime.get(key):
            raise CompactExceptionError("Guest FDT file/report do not match")
    if recorded.get("compactOverrideSha256")!=checked["overrideSha256"]:
        raise CompactExceptionError("Guest FDT proof does not use compact input")
    qmp_dir=root/"qemu-pc-compact-fdt-20261012"
    qmp=json.loads(gate.checked_file(qmp_dir/"pc-sample-report.json",MAX_SAMPLE))
    if (qmp.get("target")!=TARGET or qmp.get("factorySha256")!=gate.KERNEL_SHA or
        qmp.get("mode")!="compact-canary" or
        qmp.get("inputDtbSha256")!=checked["overrideSha256"]):
        raise CompactExceptionError("Original QMP log not from verified compact source")
    if qmp.get("samplingError"):
        raise CompactExceptionError("QMP sampler reported error, cannot attest result")
    return image,{"compactInputSha256":checked["overrideSha256"],
                  "runtimeGuestFdtBytes":runtime["guestFdtTotalBytes"],
                  "runtimeGuestFdtSha256":runtime["runtimeFdtSha256"],
                  "qmpStatus":qmp.get("status"),
                  "qmpPcSequence":qmp.get("pcSequence"),
                  "exceptionFile":qmp_dir/"qemu-exceptions.log"}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--research-root",type=Path,default=root)
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,
                   default=root/"qemu-pc-compact-fdt-20261012/compact-original-exception-audit.json")
    a=p.parse_args()
    try:
        dest=a.output.expanduser().absolute()
        inputs=(a.kernel,a.nm)
        if dest.exists() or dest.is_symlink() or dest.suffix!=".json" or (
            dest in [q.expanduser().absolute() for q in inputs]):
            raise CompactExceptionError("Output must be fresh .json, original files preserved")
        image,linked=verify_linked_evidence(a.research_root.expanduser().absolute(),
                                            a.kernel.expanduser().absolute())
        raw=gate.checked_file(linked["exceptionFile"],MAX_LOG)
        events=extract_event_log(raw)
        if events["totalExceptionMarkers"]==0:
            raise CompactExceptionError("No QEMU exception event in recorded compact run")
        symbols=sites.load_recovered_symbols(a.nm)
        if symbols["status"]!="RECOVERED_NM_SYMBOLS_UNVERIFIED":
            raise CompactExceptionError("Reconstructed original Image symbol map absent")
        report=source_correlate(events,image,symbols)
        del linked["exceptionFile"]
        report["verifiedEvidenceLinks"]=linked
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(report,indent=2)+"\n")
        print("[COMPACT INPUT]",linked["compactInputSha256"])
        print("[RUNTIME FDT SIZE]",linked["runtimeGuestFdtBytes"])
        print("[QEMU EXCEPTIONS]",report["totalExceptionMarkers"])
        print("[KNOWN SMC RETAINED]",report["knownSmcSitePresentInRetainedEvents"])
        print("[KNOWN FAULT ELRS RETAINED]",report["knownFaultSitesPresentInRetainedEvents"])
        print("[SECURE MONITOR FUNCTIONALITY] NOT VERIFIED")
        print("[LINUX MEMBLOCK EXCLUSION] NOT VERIFIED")
        print("[REPORT]",dest)
        return 0
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
