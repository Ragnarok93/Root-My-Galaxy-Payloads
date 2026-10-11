#!/usr/bin/env python3
"""Read-only bounded summary of an existing HXL1 factory Image QEMU trace.

-d in_asm means *translation*, NOT that each logged TB was executed. This tool
only classifies already-retained evidence and never launches an emulator.
"""
from __future__ import annotations
import argparse
from collections import deque
from itertools import islice
import json
from pathlib import Path
import re
import sys
from tools import y2q_hxl1_qemu_trace_attest as att

EXCEPTION_START = re.compile(rb"(?i)\bTaking exception\s+\d+\b")
DETAIL_LINE = re.compile(rb"(?i)^\s*(?:\.\.\.)?(?:from EL|to EL|with ESR|with FAR|with ELR)")
SIGNAL_LINE = re.compile(rb"(?i)(?<!\w)(?:unimplemented|unhandled|invalid memory|"
                         rb"guest error|kernel panic|failed to|unknown register|unsupported)(?!\w)")
MAX_EVENTS = 16
MAX_LINE = 260

class SummaryError(ValueError):
    pass

def extract_events(data:bytes)->dict:
    lines=data.splitlines()
    exceptions=[]
    signals=[]
    count=0
    for i,line in enumerate(lines):
        if EXCEPTION_START.search(line):
            count+=1
            details=[line.strip()]
            for more in lines[i+1:i+9]:
                if DETAIL_LINE.search(more):
                    details.append(more.strip())
                elif not more.startswith((b"...",b" ")):
                    break
            row={"lineInSample":i+1,
                 "details":[x[:MAX_LINE].decode("utf8","replace")
                            for x in details[:8]]}
            if len(exceptions)<MAX_EVENTS:exceptions.append(row)
        elif SIGNAL_LINE.search(line) and len(signals)<MAX_EVENTS:
            signals.append({"lineInSample":i+1,
                            "message":line[:MAX_LINE].decode("utf8","replace")})
    pcs=list(islice(att.parsed_words(data),12))
    last=deque(att.parsed_words(data),maxlen=10)
    return {
        "exceptionLineCount":count,
        "exceptionExamples":exceptions,
        "signalExamples":signals,
        "firstTranslatedGuestPcOpcode":[{"pc":hex(pc),"opcode":f"{word:08x}"}
                                         for pc,word in pcs],
        "lastTranslatedGuestPcOpcode":[{"pc":hex(pc),"opcode":f"{word:08x}"}
                                        for pc,word in last],
        "sampleBytes":len(data),
    }

def summarize(report:dict,head:bytes,tail:bytes,trace_size:int,serial:bytes)->dict:
    if report.get("target")!="SM-G986U1/G986U1UESCHXL1":
        raise SummaryError("Wrong trace attestation target")
    if report.get("evidenceStatus")!="FACTORY_IMAGE_INSTRUCTION_CORRELATION":
        raise SummaryError("Existing report is not factory Image correlated")
    candidates=report.get("candidateImageStarts",[])
    best=[c for c in candidates
          if c.get("candidateImagePhysicalStart")=="0x40080000"]
    if len(best)!=1:raise SummaryError("Factory Image start candidate absent or ambiguous")
    match=best[0]
    if not match.get("multiInstructionBinaryCorrelation"):
        raise SummaryError("Correlated code evidence not present for 0x40080000")
    if match.get("uniqueMatchingImageOffsets",0)<4:
        raise SummaryError("Too few distinct Image offsets")
    return {
        "target":report["target"],
        "evidence":"CORRELATED_FACTORY_IMAGE_TRANSLATION_WITH_UNKNOWN_BOOT_PROGRESS",
        "originalTraceBytes":trace_size,
        "traceCoveragePartial":trace_size>len(head)+len(tail),
        "imageCandidatePc":"0x40080000",
        "matchedOriginalImageOffsets":match["uniqueMatchingImageOffsets"],
        "inRangeTraceOpcodeComparisons":match["traceWordComparisonsInImageRange"],
        "mismatchedOpcodeComparisons":match["mismatchedWordComparisons"],
        "firstMismatch":match["firstMismatch"],
        "headerEntryInstructionMatched":match["headerEntryInstructionMatched"],
        "highestMatchingImageOffsets":match.get("matchesEnd",[]),
        "head":extract_events(head),
        "tail":extract_events(tail),
        "serialExcerpt":serial[:2400].decode("utf8","replace"),
        "factoryImageTranslationCorrelated":True,
        "factoryKernelRuntimeEntryNotIndependentlyConfirmed":True,
        "lastExecutedPcEstablished":False,
        "hxl1UserspaceBootProven":False,
        "rtMutexKernelExecutionProven":False,
        "rootOrKernelSuProven":False,
        "interpretation":"QEMU -d in_asm logs translated code, not an ordered "
                         "executed-instruction trace. Head/tail are partial when "
                         "the original log exceeds the sample budget.",
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    base=Path.home()/"s20-artifacts/hxl1-research/qemu-first-failure-20261011"
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--report",type=Path,default=base/"offline-trace-format-v2.json")
    p.add_argument("--trace",type=Path,default=base/"tcg-instructions.log")
    p.add_argument("--serial",type=Path,default=base/"serial-console.log")
    p.add_argument("--output",type=Path,default=base/"exception-summary.json")
    args=p.parse_args()
    try:
        out=args.output.expanduser().absolute()
        sources=(args.kernel,args.report,args.trace,args.serial)
        if out.exists() or out.suffix!=".json" or out in [x.expanduser().absolute() for x in sources]:
            raise SummaryError("Use fresh JSON output; never overwrite source evidence")
        if not args.report.is_file() or args.report.is_symlink():
            raise SummaryError("Existing opcode attestation report missing/unsafe")
        if not args.serial.is_file() or args.serial.is_symlink():
            raise SummaryError("Existing serial evidence missing/unsafe")
        # Existing true Image SHA-256 must be checked again for provenance.
        att.checked_image(args.kernel)
        report=json.loads(args.report.read_text())
        head,tail,total=att.sample_trace(args.trace)
        with args.serial.open("rb") as f:serial=f.read(128*1024)
        summary=summarize(report,head,tail,total,serial)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(summary,indent=2)+"\n")
        print("[FACTORY IMAGE] 0x40080000 matching distinct offsets:",
              summary["matchedOriginalImageOffsets"])
        print("[MATCHES END]",",".join(summary["highestMatchingImageOffsets"]))
        print("[MISMATCH COMPARISONS]",summary["mismatchedOpcodeComparisons"])
        print("[TRACE BYTES]",total,"[PARTIAL]",summary["traceCoveragePartial"])
        for key in ("head","tail"):
            events=summary[key]
            print(f"[{key.upper()}] exception lines:",events["exceptionLineCount"])
            for entry in events["exceptionExamples"][:3]:
                print("   "," | ".join(entry["details"][:5]))
            for entry in events["signalExamples"][:3]:
                print("   signal:",entry["message"])
            if events["firstTranslatedGuestPcOpcode"]:
                print("   first translated PC:",events["firstTranslatedGuestPcOpcode"][0]["pc"])
            if events["lastTranslatedGuestPcOpcode"]:
                print("   last translated PC:",events["lastTranslatedGuestPcOpcode"][-1]["pc"])
        print("[REPORT]",out)
        print("[LIMIT] -d in_asm does not identify last EXECUTED PC or a Linux boot")
        return 0
    except (OSError,ValueError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr);return 2

if __name__=="__main__":
    raise SystemExit(main())
