#!/usr/bin/env python3
"""Read-only HXL1 QEMU exception ELR/ESR/FAR attribution to original Image bytes.

The recovered vmlinux VA base / nm symbols are heuristic until corroborated;
we never infer boot success, exploitability, root, or an executed final PC.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_qemu_trace_attest as att

VM_BASE = 0xffffff8008080000  # vmlinux-to-elf recovered virtual base, NOT runtime KASLR
TARGET = "SM-G986U1/G986U1UESCHXL1"
ELR_RE = re.compile(r"\bwith ELR\s+(0x[0-9a-fA-F]+)\b")
ESR_RE = re.compile(r"\bwith ESR\s+(?:0x[0-9a-fA-F]+/)?(0x[0-9a-fA-F]+)\b")
FAR_RE = re.compile(r"\bwith FAR\s+(0x[0-9a-fA-F]+)\b")
NM_RE = re.compile(r"^\s*([0-9a-fA-F]{8,16})\s+([A-Za-z])\s+(\S+)")
MAX_EVENTS = 12
WINDOW_WORDS = 8

class AttributionError(ValueError):
    pass


def load_recovered_symbols(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        return {"status": "MISSING_RECOVERED_SYMBOL_MAP", "entries": []}
    h = hashlib.sha256()
    entries = []
    with path.open("rb") as f:
        for line in f:
            h.update(line)
            m = NM_RE.match(line.decode("utf8", "replace"))
            if not m:
                continue
            addr, stype, name = int(m.group(1), 16), m.group(2), m.group(3)
            if stype in ("T", "t", "W", "w"):
                entries.append((addr, stype, name))
    entries.sort()
    return {"status": "RECOVERED_NM_SYMBOLS_UNVERIFIED",
            "sourceSha256": h.hexdigest(),
            "entries": entries}


def nearest_symbol(symbols: dict, address: int) -> dict:
    entries = symbols["entries"]
    if not entries:
        return {"status": "NO_RECONSTRUCTED_TEXT_SYMBOL"}
    i = bisect.bisect_right(entries, (address, "z", "\uffff")) - 1
    if i < 0:
        return {"status": "NO_LOWER_OR_EQUAL_RECONSTRUCTED_TEXT_SYMBOL"}
    base, code, name = entries[i]
    return {
        "status": "NEAREST_LOWER_OR_EQUAL_RECOVERED_SYMBOL_UNVERIFIED",
        "name": name, "type": code, "address": hex(base),
        "distance": hex(address - base),
        "caveat": "Symbol is inferred from reconstructed vmlinux; distance is "
                  "not proof that ELR lies inside its original function body.",
    }


def decode_esr(esr: int) -> dict:
    ec = (esr >> 26) & 0x3f
    result = {"raw": hex(esr), "ec": hex(ec),
              "instructionLength32": bool((esr >> 25) & 1)}
    if ec == 0:
        result["category"] = "UNKNOWN_OR_UNCATEGORIZED_EXCEPTION"
        result["caveat"] = "QEMU called this undefined instruction; cannot infer cause without original opcode."
    elif ec == 0x25:
        fsc = esr & 0x3f
        result.update(category="DATA_ABORT_CURRENT_EL",dfsc=hex(fsc),
                      memoryAccess="write" if (esr >> 6) & 1 else "read",
                      stage1WalkFaultFlag=bool((esr >> 7) & 1))
        if 4 <= fsc <= 7:
            result["faultClass"] = f"TRANSLATION_FAULT_LEVEL_{fsc - 4}"
        else:
            result["faultClass"] = "OTHER_DATA_ABORT_STATUS"
    else:
        result["category"] = "OTHER_EXCEPTION_CLASS"
    return result


def parse_event(event: dict, source: str) -> dict:
    lines=event.get("details")
    if not isinstance(lines,list) or not lines:
        raise AttributionError("Malformed exception event: no detail lines")
    text="\n".join(str(x) for x in lines)
    def parse(field, regex, required=False):
        match=regex.search(text)
        if required and not match:
            raise AttributionError(f"Missing {field} in exception details")
        return int(match.group(1),16) if match else None
    return {"source": source, "qemuDescription": lines[0],
            "elr": parse("ELR",ELR_RE,True),
            "esr": parse("ESR",ESR_RE),
            "far": parse("FAR",FAR_RE),
            "traceSampleLine": event.get("lineInSample")}


def window(image: bytes, va: int, virtual_base: int) -> dict:
    off=va-virtual_base
    if off<0 or off+4>len(image) or off%4:
        return {"status":"ELR_OUTSIDE_OR_UNALIGNED_TO_ORIGINAL_IMAGE",
                "candidateImageOffset":hex(off)}
    first=max(0,off-WINDOW_WORDS*4)
    last=min(len(image),off+(WINDOW_WORDS+1)*4)
    first &= ~3
    last &= ~3
    words=[]
    for x in range(first,last,4):
        words.append({"va":hex(virtual_base+x), "imageOffset":hex(x),
                      "opcode":f"{int.from_bytes(image[x:x+4],'little'):08x}",
                      "faultingElr":x==off})
    return {"status":"ORIGINAL_STOCK_IMAGE_BYTES_FOUND",
            "candidateImageOffset":hex(off),
            "originalOpcode":f"{int.from_bytes(image[off:off+4],'little'):08x}",
            "words":words}


def disassemble(window_record:dict, virtual_base:int, objdump_path:str|None) -> dict:
    if window_record["status"]!="ORIGINAL_STOCK_IMAGE_BYTES_FOUND":
        return {"status":"IMAGE_OFFSET_UNAVAILABLE"}
    if not objdump_path:
        return {"status":"AARCH64_OBJDUMP_MISSING"}
    words=window_record["words"]
    content=b"".join(int(w["opcode"],16).to_bytes(4,"little") for w in words)
    with tempfile.TemporaryDirectory(prefix="hxl1-original-opcodes-") as td:
        path=Path(td)/"slice.bin"
        path.write_bytes(content)
        cmd=[objdump_path,"-D","-b","binary","-m","aarch64",
             "--adjust-vma="+words[0]["va"],str(path)]
        try:
            output=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
        except (OSError,subprocess.TimeoutExpired) as e:
            return {"status":"OBJDUMP_FAILED","error":str(e)}
    if output.returncode:
        return {"status":"OBJDUMP_FAILED",
                "stderr":output.stderr[-700:]}
    # The disassembly is only of the original image's local instruction bytes.
    lines=output.stdout.splitlines()
    rows=[l for l in lines if re.match(r"^\s*[0-9a-fA-F]+:\s+",l)]
    return {"status":"ORIGINAL_IMAGE_WINDOW_DISASSEMBLED",
            "lines":rows[:2*WINDOW_WORDS+1]}


def build_report(summary:dict, image: bytes, symbols:dict,
                 objdump_path:str|None, virtual_base:int=VM_BASE)->dict:
    if summary.get("target")!=TARGET or not summary.get("factoryImageTranslationCorrelated"):
        raise AttributionError("Original HXL1 factory Image evidence gate not satisfied")
    events=[]
    for key in ("head","tail"):
        for event in summary.get(key,{}).get("exceptionExamples",[])[:MAX_EVENTS]:
            e=parse_event(event,key)
            e["virtualImageBaseAssumption"]=hex(virtual_base)
            e["esrDecoded"]=decode_esr(e["esr"]) if e["esr"] is not None else None
            e["originalImage"]=window(image,e["elr"],virtual_base)
            e["recoveredNearestSymbol"]=nearest_symbol(symbols,e["elr"])
            e["originalImageDisassembly"]=disassemble(e["originalImage"],virtual_base,objdump_path)
            e["originalImageOpcodeMatchesExecutedGuestMemoryUnverified"]=True  # We have original bytes, no guest memory dump
            events.append(e)
    return {
        "target":TARGET,
        "sourceEvidence":"owner-retained-QEMU-exception-summary.json",
        "originalKernelImageSha256":att.KERNEL_HASH,
        "virtualBase":hex(virtual_base),
        "virtualBaseStatus":"RECONSTRUCTED_ELF_BASE_ASSUMPTION_NOT_RUNTIME_KASLR_MEASUREMENT",
        "symbolMapStatus":symbols["status"],
        "symbolMapSha256":symbols.get("sourceSha256"),
        "exceptionCountInRetainedSummary":len(events),
        "exceptions":events,
        "factoryImageTranslationCorrelated":True,
        "factoryKernelReachedUserspace":False,
        "lastExecutedInstructionEstablished":False,
        "bootloaderUnlockOrRootProven":False,
        "note":"ELR is reported by QEMU for a taken exception, but the "
               "reconstructed address-to-source mapping and recovered symbol "
               "names must be checked against original bytes; no hardware "
               "fidelity or kernel exploitability conclusion follows.",
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    base=Path.home()/"s20-artifacts/hxl1-research"
    prior=base/"qemu-first-failure-20261011"
    p.add_argument("--kernel",type=Path,default=Path.home()/"s20-artifacts/kernel.bin")
    p.add_argument("--summary",type=Path,default=prior/"exception-summary.json")
    p.add_argument("--nm",type=Path,default=base/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,default=prior/"original-fault-sites.json")
    p.add_argument("--virtual-base",type=lambda x:int(x,0),default=VM_BASE)
    a=p.parse_args()
    try:
        dest=a.output.expanduser().absolute()
        source_paths=[a.kernel,a.summary,a.nm]
        if dest.exists() or dest.suffix!=".json" or dest in [x.expanduser().absolute() for x in source_paths]:
            raise AttributionError("Use fresh JSON output; do not overwrite retained evidence")
        if not a.summary.is_file() or a.summary.is_symlink():
            raise AttributionError("Existing original-QEMU exception summary missing/unsafe")
        image=att.checked_image(a.kernel)
        summary=json.loads(a.summary.read_text())
        symbols=load_recovered_symbols(a.nm)
        objdump=shutil.which("aarch64-linux-gnu-objdump")
        report=build_report(summary,image,symbols,objdump,a.virtual_base)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(report,indent=2)+"\n")
        print("[FACTORY IMAGE]",report["originalKernelImageSha256"])
        print("[VIRTUAL BASE]",report["virtualBase"],report["virtualBaseStatus"])
        print("[SYMBOLS]",report["symbolMapStatus"])
        for i,e in enumerate(report["exceptions"],1):
            v=e["originalImage"]
            ss=e["recoveredNearestSymbol"]
            esr=e["esrDecoded"] or {}
            print(f"[EXCEPTION {i}]", e["qemuDescription"],
                  "ELR",hex(e["elr"]),
                  "offset",v["candidateImageOffset"],
                  "opcode",v.get("originalOpcode","unavailable"))
            print("   ESR",esr.get("raw","missing"),esr.get("category","unknown"),
                  esr.get("faultClass",""),"FAR",
                  hex(e["far"]) if e["far"] is not None else "[not reported]")
            print("   nearest recovered:",ss.get("name","[none]"),
                  "+",ss.get("distance","[n/a]"),
                  "| disassembly",e["originalImageDisassembly"]["status"])
        print("[REPORT]",dest)
        print("[LIMIT] Image bytes and recovered symbols are not proof of guest platform correctness/root")
        return 0
    except (OSError,ValueError,json.JSONDecodeError) as e:
        print("[STOP]",e,file=sys.stderr);return 2


if __name__=="__main__":
    raise SystemExit(main())
