#!/usr/bin/env python3
"""Offline instruction-word correlation of existing QEMU AArch64 trace vs HXL1 Image.

Never boots QEMU, patches an Image, contacts a phone, or assumes a boot from
translated boot-stub code. Reads bounded head/tail log samples to limit RAM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

KERNEL_HASH = "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
INSTRUCTION = re.compile(rb"(?m)^\s*0x([0-9a-fA-F]{7,16}):\s+([0-9a-fA-F]{8})(?=\s)")
HEAD_BYTES = 12 * 1024 * 1024
TAIL_BYTES = 3 * 1024 * 1024
MAX_EVIDENCE = 18

class EvidenceError(ValueError):
    pass

def checked_image(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError("Original kernel Image missing or symlinked")
    image = path.read_bytes()
    if hashlib.sha256(image).hexdigest() != KERNEL_HASH:
        raise EvidenceError("Original HXL1 kernel Image digest mismatch")
    if len(image) < 64 or image[0x38:0x3c] != b"ARM\x64":
        raise EvidenceError("Original Image has no valid ARM64 header")
    return image

def sample_trace(path: Path) -> tuple[bytes,bytes,int]:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError("Existing QEMU trace missing or symlinked")
    size = path.stat().st_size
    with path.open("rb") as f:
        head = f.read(HEAD_BYTES)
        if size > HEAD_BYTES:
            f.seek(max(HEAD_BYTES, size-TAIL_BYTES))
            tail = f.read(TAIL_BYTES)
        else:
            tail = b""
    return head,tail,size

def parsed_words(blob: bytes):
    # QEMU's -d in_asm emits physical AArch64 PC, opcode, mnemonic per line.
    # Filter for actual 32-bit AArch64 opcodes; not arbitrary regex numbers.
    for m in INSTRUCTION.finditer(blob):
        yield int(m.group(1),16), int(m.group(2),16)

def candidate_bases(image:bytes, extra:list[int]) -> list[int]:
    text_offset=int.from_bytes(image[8:16],"little")
    bases=[0x40000000+text_offset,0x80000000+text_offset]
    for x in extra:
        if x < 0 or x % 4:raise EvidenceError("Candidate kernel PA must be positive and 4-byte aligned")
        if x not in bases:bases.append(x)
    return bases

def match_words(image: bytes, trace: bytes, bases: list[int])->tuple[list[dict],int]:
    matches={}
    count=0
    for pc,word in parsed_words(trace):
        count+=1
        for base in bases:
            off=pc-base
            if 0<=off<=len(image)-4 and off%4==0:
                expected=int.from_bytes(image[off:off+4],"little")
                is_match=expected==word
                row=matches.setdefault(base,{"compared":0,"matched":{},"mismatched":0,
                                            "firstMismatch":None})
                row["compared"]+=1
                if is_match:
                    row["matched"][off]=(pc,word)
                else:
                    row["mismatched"]+=1
                    if row["firstMismatch"] is None:
                        row["firstMismatch"]={"pc":hex(pc),"imageOffset":hex(off),
                                              "observedOpcode":hex(word),"imageOpcode":hex(expected)}
    reports=[]
    for base in bases:
        row=matches.get(base,{"compared":0,"matched":{},"mismatched":0,"firstMismatch":None})
        offsets=sorted(row["matched"])
        unique={v[1] for v in row["matched"].values()}
        # A header-entry observation alone is never enough. Require multiple
        # distinct matched original Image instructions; useful as a lead only.
        corroborated=len(offsets)>=4 and len(unique)>=3
        reports.append({
            "candidateImagePhysicalStart":hex(base),
            "traceWordComparisonsInImageRange":row["compared"],
            "uniqueMatchingImageOffsets":len(offsets),
            "mismatchedWordComparisons":row["mismatched"],
            "firstMismatch":row["firstMismatch"],
            "headerEntryInstructionMatched":0 in row["matched"],
            "multiInstructionBinaryCorrelation":corroborated,
            "sampleMatches":[{"pc":hex(row["matched"][o][0]),"imageOffset":hex(o),
                              "opcode":f"{row['matched'][o][1]:08x}"}
                             for o in offsets[:MAX_EVIDENCE]],
            "matchesEnd":[hex(o) for o in offsets[-5:]],
        })
    return reports,count

def analyze(image:bytes,head:bytes,tail:bytes,serial:bytes,extra_bases:list[int],total_size:int)->dict:
    if not image or image[0x38:0x3c]!=b"ARM\x64":
        raise EvidenceError("Invalid original ARM64 Image")
    bases=candidate_bases(image,extra_bases)
    results,head_count=match_words(image,head,bases)
    tail_results,tail_count=match_words(image,tail,bases)
    # Expose a small PC sample even if none match the hypothesized load bases.
    # That enables an address-mapping diagnosis without sharing a huge TCG log.
    head_pcs=[{"pc":hex(pc),"word":f"{w:08x}"}
              for pc,w in list(parsed_words(head))[:20]]
    tail_pcs=[{"pc":hex(pc),"word":f"{w:08x}"}
              for pc,w in list(parsed_words(tail))[-12:]]
    # Preserve head and tail as separate observations rather than mistakenly
    # counting a repeated instruction in the tail as another independent match.
    head_results={r["candidateImagePhysicalStart"]:r for r in results}
    tail_results={r["candidateImagePhysicalStart"]:r for r in tail_results}
    combined=[]
    for base in bases:
        key=hex(base)
        a=head_results[key];b=tail_results[key]
        x={**a,"tailUniqueMatchingImageOffsets":b["uniqueMatchingImageOffsets"],
           "tailHeaderEntryInstructionMatched":b["headerEntryInstructionMatched"],
           "tailMultiInstructionBinaryCorrelation":b["multiInstructionBinaryCorrelation"],
           "tailSampleMatches":b["sampleMatches"][:6]}
        combined.append(x)
    flags={
        "sampledTraceHasArm64Opcodes":head_count+tail_count>0,
        "factoryImageCorrelatedInHead":any(r["multiInstructionBinaryCorrelation"] for r in results),
        "factoryImageCorrelatedInTail":any(r["multiInstructionBinaryCorrelation"] for r in tail_results),
        "factoryKernelEntryIndependentlyEstablished":False,
        "samsungKernelBooted":False,
        "rootOrKernelSuVerified":False,
    }
    text=serial.decode("utf8","replace").lower()
    flags["linuxBootBannerSeen"]="booting linux on physical cpu" in text
    flags["linuxVersionSeen"]="linux version " in text
    flags["panicTextSeen"]="kernel panic" in text
    status=("FACTORY_IMAGE_INSTRUCTION_CORRELATION" if
            flags["factoryImageCorrelatedInHead"] or flags["factoryImageCorrelatedInTail"]
            else "NO_FACTORY_IMAGE_INSTRUCTION_CORRELATION_IN_SAMPLED_TRACE")
    return {
        "target":"SM-G986U1/G986U1UESCHXL1",
        "evidenceStatus":status,
        "firstPartBytesExamined":len(head),
        "lastPartBytesExamined":len(tail),
        "originalTraceTotalBytes":total_size,
        "traceCoveragePartial":total_size>len(head)+len(tail),
        "parsedAarch64OpcodeLines":head_count+tail_count,
        "translatedPcHeadSample":head_pcs,
        "translatedPcTailSample":tail_pcs,
        "firstTraceLines":head[:2500].decode("utf8","replace").splitlines()[:14],
        "candidateImageStarts":combined,
        "evidenceFlags":flags,
        "note":"Original QEMU boot stub, translated memory and Image words have different proof levels. "
               "Even an opcode match does not prove guest kernel boot or runtime exploitability.",
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    base=Path.home()/"s20-artifacts/hxl1-research/qemu-first-failure-20261011"
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--trace",type=Path,default=base/"tcg-instructions.log")
    p.add_argument("--serial",type=Path,default=base/"serial-console.log")
    p.add_argument("--output",type=Path,default=base/"offline-trace-attestation.json")
    p.add_argument("--physical-base",action="append",type=lambda x:int(x,0),default=[],
                   help="Additional candidate Image physical start, hex or decimal")
    args=p.parse_args()
    try:
        out=args.output.expanduser().absolute()
        originals=[args.kernel,args.trace,args.serial]
        if out.exists() or out.suffix!=".json" or any(
            out==x.expanduser().absolute() for x in originals):
            raise EvidenceError("Refuse report overwrite or evidence replacement; choose a fresh JSON file")
        image=checked_image(args.kernel)
        head,tail,total_size=sample_trace(args.trace)
        if not args.serial.is_file() or args.serial.is_symlink():
            raise EvidenceError("Original QEMU serial file missing or symlinked")
        with args.serial.open("rb") as f:
            serial=f.read(128*1024)
        result=analyze(image,head,tail,serial,args.physical_base,total_size)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
    except (OSError,ValueError) as exc:
        print("[STOP]",exc,file=sys.stderr)
        return 2
    print("[EVIDENCE]",result["evidenceStatus"])
    print("[TRACE OPCODES]",result["parsedAarch64OpcodeLines"])
    for r in result["candidateImageStarts"]:
        print("[BASE]",r["candidateImagePhysicalStart"],
              "compared",r["traceWordComparisonsInImageRange"],
              "matched",r["uniqueMatchingImageOffsets"],
              "tail-matched",r["tailUniqueMatchingImageOffsets"],
              "entry-word",r["headerEntryInstructionMatched"])
    print("[REPORT]",out)
    print("[LIMIT] No kernel entry, boot, exploit or KernelSU inferred from this trace alone")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
