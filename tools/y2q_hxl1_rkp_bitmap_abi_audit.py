#!/usr/bin/env python3
"""Read-only source-vs-GDB ABI audit for stock HXL1 RKP bitmap SMC #0.

The tool never launches QEMU, calls ADB, or modifies the stock kernel.
Checks the retained *local HXL1 source tree*, not a newer Samsung QEMU fork.
The recovered nm map is heuristic: source/ELF reconstruction is not a substitute
for a booted, source-faithful HXL1 kernel or real UH hypervisor implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED_SMC_PC=0xffffff80080a5794
EXPECTED_OPCODE="d4000003"
RKP_REGISTERS=("X0","X1","X2","X3","X4","X5","X6")
NUM_RE=re.compile(r"(0x[0-9a-fA-F]+|\d+)")
GDB_REG_RE=re.compile(r"\b(X[0-6])=(0x[0-9a-fA-F]+)\b")
SYMBOL_RE=re.compile(r"^\s*([0-9a-fA-F]{8,16})\s+([A-Za-z])\s+(rkp_s_bitmap_buffer)\s*$")
MACRO_APP_RE=re.compile(r"(?m)^\s*#\s*define\s+APP_RKP\s+([0-9]+)\b")
MACRO_PREFIX_RE=re.compile(r"(?m)^\s*#\s*define\s+UH_PREFIX\s+(.+)$")
RKP_CMD_RE=re.compile(r"\bRKP_GET_RKP_GET_BUFFER_BITMAP\s*=\s*(0x[0-9a-fA-F]+|\d+)\b")
BITMAP_FUNC_RE=re.compile(r"\brkp_robuffer_init\s*\(\s*void\s*\)\s*{([^}]*)}",re.S)
UH_APPID_RE=re.compile(r"(?m)^\s*#\s*define\s+UH_APPID\s*\(\s*APP_ID\s*\)\s+(.+)$")

class AuditError(ValueError):
    pass

def secure_read(path:Path)->tuple[str,str]:
    if not path.is_file() or path.is_symlink():
        raise AuditError(f"Expected ordinary source file missing: {path}")
    b=path.read_bytes()
    return b.decode("utf-8","replace"),hashlib.sha256(b).hexdigest()

def parse_source(uh:str,rkp:str)->dict:
    m=MACRO_APP_RE.search(uh)
    p=MACRO_PREFIX_RE.search(uh)
    call=UH_APPID_RE.search(uh)
    cmd=RKP_CMD_RE.search(rkp)
    fn=BITMAP_FUNC_RE.search(rkp)
    if not all((m,p,call,cmd,fn)):
        absent=[name for name,entry in (("APP_RKP",m),("UH_PREFIX",p),
             ("UH_APPID(APP_ID)",call),("RKP_GET_RKP_GET_BUFFER_BITMAP",cmd),
             ("rkp_robuffer_init(void)",fn)) if entry is None]
        raise AuditError("Original-source ABI definitions missing: "+", ".join(absent))
    prefix_num=NUM_RE.search(p.group(1))
    if not prefix_num:
        raise AuditError("UH_PREFIX value is not a recognizable literal")
    app=int(m.group(1),10)
    prefix=int(prefix_num.group(1),0)
    command=int(cmd.group(1),0)
    fn_text=fn.group(1)
    # Treat any unusual macro expansion as unresolved; do not extrapolate
    # the fork's packed app ID rules onto exact HXL1 source.
    app_expr=call.group(1).strip()
    expected_macros=("0xFF", "UH_PREFIX")
    macro_shape_ok=all(x in app_expr for x in expected_macros)
    call_requirements=("uh_call(", "UH_APP_RKP", "RKP_GET_RKP_GET_BUFFER_BITMAP",
                       "&rkp_s_bitmap_buffer", "memstart_addr")
    collapsed="".join(fn_text.split())
    function_match=all("".join(x.split()) in collapsed for x in call_requirements)
    return {
        "appRkp":app,"prefix":hex(prefix),
        "appIdExpansion":app_expr,
        "appIdMacroShapeRecognized":macro_shape_ok,
        "computedUhAppRkp":hex(prefix|(app&0xff)) if macro_shape_ok else None,
        "rkpGetBufferBitmapCommand":hex(command),
        "rkpRobufferInitPassesBitmapAndMemstart":function_match,
        "rkpRobufferInitSource":fn_text.strip()[:700],
        "expectedEmulationMeaning":"RKP_GET_RKP_GET_BUFFER_BITMAP",
        "kernelSourceDoesNotProveHypervisorResponse":True,
    }

def parse_gdb_log(content:str)->dict:
    if "HXL1_SMC_BREAKPOINT_HIT" not in content:
        raise AuditError("GDB log contains no confirmed stock SMC breakpoint hit")
    hit=re.search(r"\bHXL1_SMC_BREAKPOINT_HIT PC=(0x[0-9a-fA-F]+)",content)
    if not hit or int(hit.group(1),16)!=EXPECTED_SMC_PC:
        raise AuditError("GDB did not stop at the pinned original HXL1 SMC instruction")
    op_line=re.search(r"(?m)^\s*0x([0-9a-fA-F]+):\s*(0x[0-9a-fA-F]{8})\s*$",content)
    if not op_line or int(op_line.group(1),16)!=EXPECTED_SMC_PC or op_line.group(2).lower()!=("0x"+EXPECTED_OPCODE):
        raise AuditError("GDB does not independently verify stock SMC opcode")
    regs={}
    for name,val in GDB_REG_RE.findall(content):
        parsed=int(val,16)
        if name in regs and regs[name]!=parsed:
            raise AuditError(f"Conflicting {name} values in GDB evidence")
        regs[name]=parsed
    if any(x not in regs for x in RKP_REGISTERS):
        raise AuditError("Original GDB evidence is missing at least one X0-X6 value")
    return {"pc":hex(EXPECTED_SMC_PC),"opcode":EXPECTED_OPCODE,
            "registers":{k:hex(regs[k]) for k in RKP_REGISTERS},
            "rawRegisters":regs}

def recovered_bitmap_symbol(nm:Path,guest_va:int)->dict:
    if not nm.is_file() or nm.is_symlink():
        return {"status":"RECOVERED_NM_UNAVAILABLE","name":"rkp_s_bitmap_buffer"}
    matches=[]
    with nm.open("r",encoding="utf-8",errors="replace") as f:
        for line in f:
            m=SYMBOL_RE.match(line)
            if m:
                matches.append({"address":int(m.group(1),16),
                                "type":m.group(2)})
    found=[m for m in matches if m["address"]==guest_va]
    return {
        "status":"RECOVERED_SYMBOL_ADDRESS_CORRELATES" if found else
                 ("RECOVERED_SYMBOL_MISSING" if not matches else
                  "RECOVERED_SYMBOL_ADDRESS_DIFFERS"),
        "symbolName":"rkp_s_bitmap_buffer",
        "guestX2":hex(guest_va),
        "recoveredSymbolCandidates":[hex(x["address"]) for x in matches[:15]],
        "addressMatched":bool(found),
        "caveat":"Recovered nm map was reconstructed from stock binary without factory DWARF; "
                 "a matching address corroborates pointer identity, not a working hypervisor.",
    }

def analyze(source:dict,gdb:dict,symbol:dict,source_paths:dict)->dict:
    r=gdb["rawRegisters"]
    app_expected=source.get("computedUhAppRkp")
    cmd_expected=source.get("rkpGetBufferBitmapCommand")
    valid=(app_expected==hex(r["X0"]) and cmd_expected==hex(r["X1"]) and
           source["rkpRobufferInitPassesBitmapAndMemstart"])
    return {
        "target":"SM-G986U1/G986U1UESCHXL1",
        "gdbCapture":{"pc":gdb["pc"],"opcode":gdb["opcode"],
                      "registers":gdb["registers"]},
        "sourceAudit":source,
        "sourceFiles":source_paths,
        "pointerCorrelation":symbol,
        "abiOutcome":"EXACT_LOCAL_SOURCE_DEFINITIONS_MATCH_CAPTURED_RKP_BITMAP_CALL"
                     if valid else "LOCAL_SOURCE_ABI_MISMATCH_OR_UNVERIFIED",
        "sourceCallCompatible":valid,
        "x3MemstartObserved":gdb["registers"]["X3"],
        "x3IsQemuVirtRamBase":r["X3"]==0x40000000,
        "x6IsAnUhCallArgument":False,
        "x6Caveat":"Original uh_call prototype declares four explicit arguments after app ID "
                   "and command. X6 may contain unrelated register state; do not infer semantics.",
        "criticalForkAbiCollision":{
            "observedAppId":hex(r["X0"]),
            "forkNamesSameId":"KDP",
            "examinedSM8250KernelNamesSameId":"RKP",
            "forkCommand0x15":"KDP_SET_NS_FLAGS",
            "examinedSM8250KernelCommand0x15":"RKP_GET_RKP_GET_BUFFER_BITMAP",
            "conclusion":"Never route this HXL1 SMC to the fork's KDP_SET_NS_FLAGS handler "
                         "without proving a different ABI in original HXL1 source.",
        },
        "noGuestMemoryMutated":True,
        "noQemuExecutedByThisAnalyzer":True,
        "sourceFaithfulGuestOrKernelSuProven":False
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    root=Path.home()/"s20-artifacts/hxl1-research"
    p.add_argument("--gdb-log",type=Path,default=root/"qemu-smc-registers-20261011/gdb-session.log")
    p.add_argument("--nm",type=Path,default=root/"vmlinux-stock.nm")
    p.add_argument("--output",type=Path,default=root/"qemu-smc-registers-20261011/rkp-bitmap-source-abi.json")
    a=p.parse_args()
    try:
        uh_path=a.source_root/"include/linux/uh.h"
        rkp_path=a.source_root/"include/linux/rkp.h"
        out=a.output.expanduser().absolute()
        sources=(uh_path,rkp_path,a.gdb_log,a.nm)
        if out.suffix!=".json" or out.exists() or out in [x.expanduser().absolute() for x in sources]:
            raise AuditError("Use a fresh JSON output file; do not overwrite evidence")
        uh,uh_hash=secure_read(uh_path)
        rkp,rkp_hash=secure_read(rkp_path)
        log,log_hash=secure_read(a.gdb_log)
        src=parse_source(uh,rkp)
        capture=parse_gdb_log(log)
        symbol=recovered_bitmap_symbol(a.nm,capture["rawRegisters"]["X2"])
        result=analyze(src,capture,symbol,{"uhPath":str(uh_path),
              "uhSha256":uh_hash,"rkpPath":str(rkp_path),
              "rkpSha256":rkp_hash,"gdbLogSha256":log_hash})
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
        print("[HXL1 SOURCE]",result["abiOutcome"])
        print("[APP]",src["computedUhAppRkp"],"command",src["rkpGetBufferBitmapCommand"])
        print("[GDB]",capture["registers"])
        print("[X2 SYMBOL]",symbol["status"],
              ",".join(symbol.get("recoveredSymbolCandidates",[])))
        print("[COLLISION] Fork's 0xc300c002/KDP_SET_NS_FLAGS does not match SM8250 source RKP bitmap ABI")
        print("[REPORT]",out)
        print("[LIMIT] Original source mapping does not emulate UH, boot Linux, unlock bootloader or install KernelSU")
        return 0 if result["sourceCallCompatible"] else 3
    except (OSError,ValueError,KeyError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
