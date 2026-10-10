#!/usr/bin/env python3
"""HXL1 EnvDxe GetRamPartitions: prove callback continuation and 72->16 byte copy.

Entirely host-side. Requires hash-pinned original PE, existing verified REA
windows at 0x1f74 and 0x1fe8, and one NEW 20-byte read at 0x2048.
No Android connection, exploit actions, physical memory, or firmware writes.
The bounded CFG is a static approximation: it does not prove execution.
"""
from __future__ import annotations
import argparse
import json
import struct
from collections import deque
from pathlib import Path
import sys
if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from tools.y2q_hxl1_envdxe_entry_strings import (
    PE_SHA256,REPORT_DIR,ExtractionError,evidence_json
)
from tools.y2q_hxl1_envdxe_method_arm64_trace import (
    original_window,imported_window,arm64_edges
)
from tools.y2q_hxl1_envdxe_helper_batch import (
    report as helper_audit,imported_code
)

BASE=0x1f74
END=0x205c          # observed start of different 0x205c EFI initializer
NEW_START=0x2048
NEW_SIZE=20
NEW_EVIDENCE="rea-envdxe-callback-cfg-tail-2048.json"
REQUIRED_BRANCHES={
    0x1fa4:("BL",0x52cc),
    0x1fc4:("B.cond",0x1fe8),
    0x1ff0:("BL",0x2618),
    0x2004:("BL",0x52cc),
    0x2010:("B",0x1fd8),
    0x2018:("B",0x1fd8),
}
# Condition-code bits are not part of an ARM64 conditional branch target.
# Enforce each complete original word as well as the branch target, so a
# condition flip cannot silently pass our static reachability proof.
BRANCH_WORDS={
    0x1fa4:0x94000cca,
    0x1fc4:0x54000129,
    0x1ff0:0x9400018a,
    0x2004:0x94000cb2,
    0x2010:0x17fffff2,
    0x2018:0x17fffff0,
}
# These are raw words from the original 96-byte, Ghidra-matched 0x1fe8
# segment. They constrain the observed 72-byte temporary-record and
# 16-byte output-record strides without guessing the unknown boot data.
RECORD_WORDS={
    0x1fe8:0x8b0a0d4c,  # add x12,x10,x10,lsl #3 (9*n)
    0x1fec:0xd37df180,  # lsl x0,x12,#3 (72*n)
    0x2024:0x9100226a,  # add x10,x19,#8
    0x2028:0x9100a28b,  # add x11,x20,#0x28
    0x2030:0xf85f816d,  # ldur x13,[x11,#-8]
    0x2038:0xf81f814d,  # stur x13,[x10,#-8]
    0x203c:0xf844856e,  # ldr x14,[x11],#0x48
    0x2040:0xf801054e,  # str x14,[x10],#0x10
}
NEEDED_REACHABLE=(0x1f74,0x1fa4,0x1fc4,0x1fe4,0x1fe8,
                  0x1ff0,0x2004,0x2030,0x203c,0x2040,0x2044)


def validate_tail(folder:Path)->dict:
    orig=original_window(folder,hex(NEW_START),NEW_SIZE)
    ev=evidence_json(folder,NEW_EVIDENCE)
    obj=ev.get("normalized_result")
    if (ev.get("operation")!="read_bytes" or
        ev.get("parameters",{}).get("address")!=hex(NEW_START) or
        ev.get("parameters",{}).get("length")!=NEW_SIZE or
        not isinstance(obj,dict) or obj.get("address")!=hex(NEW_START) or
        obj.get("requested_bytes")!=NEW_SIZE or
        obj.get("returned_bytes")!=NEW_SIZE or obj.get("complete") is not True or
        obj.get("bytes_hex")!=orig["bytesHex"]):
        raise ExtractionError("Original Ghidra callback final 20-byte tail disagrees with pinned PE")
    return {"evidenceId":ev["evidence_id"],"sha256":orig["sha256"],
            "originalBytesMatchGhidra":True}


def full_bytes(folder:Path)->tuple[bytes,dict]:
    src=original_window(folder,hex(BASE),END-BASE)
    raw=bytes.fromhex(src["bytesHex"])
    if len(raw)!=END-BASE:
        raise ExtractionError("Full bounded callback not backed by original executable bytes")
    a=original_window(folder,hex(BASE),128)
    b=original_window(folder,"0x1fe8",96)
    match_a=imported_window(folder,"get-ram-partitions","0x1f74",a)
    match_b=imported_code(folder,"post-callback-code","0x1fe8",96,b)
    if raw[:128]!=bytes.fromhex(a["bytesHex"]):
        raise ExtractionError("Callback body differs from previously verified entrypoint")
    if raw[0x1fe8-BASE:0x2048-BASE]!=bytes.fromhex(b["bytesHex"]):
        raise ExtractionError("Callback continuation differs from verified post-RET window")
    tail=validate_tail(folder)
    # Three independent Ghidra readbacks cover [0x1f74,0x205c) with overlap.
    return raw,{"originalSha256":src["sha256"],"firstRead":match_a["evidenceId"],
                "continuationRead":match_b["evidenceId"],
                "finalTail":tail,"continuousOriginalAndImportedCoverage":True}


def bounded_cfg(raw:bytes,base:int=BASE)->dict:
    if base%4 or len(raw)%4 or not raw:
        raise ExtractionError("ARM64 CFG requires nonempty 4-byte-aligned code")
    end=base+len(raw)
    indexed={int(e["instructionAddress"],16):e for e in arm64_edges(raw,base)}
    visited=set()
    pending=deque([base])
    exits=[]
    branches=[]
    calls=[]
    outside=[]
    while pending:
        at=pending.popleft()
        if at in visited:
            continue
        if at<base or at>=end or (at-base)%4:
            outside.append(hex(at))
            continue
        visited.add(at)
        edge=indexed.get(at)
        kind=edge["mnemonicClass"] if edge else "FALLTHROUGH"
        next_pc=at+4
        targets=[]
        if kind in ("RET","BR"):
            exits.append({"pc":hex(at),"kind":kind})
        elif kind=="B":
            targets=[int(edge["directBranchTarget"],16)]
        elif kind in ("B.cond","CBZ","CBNZ","TBZ","TBNZ"):
            targets=[int(edge["directBranchTarget"],16),next_pc]
        elif kind=="BL":
            calls.append({"pc":hex(at),"target":edge["directBranchTarget"]})
            targets=[next_pc]
        else:
            # BLR is an indirect call with a possible return, not a branch
            # into the unknown callee. ADRP/load/store/etc. also fall through.
            if kind=="BLR":
                calls.append({"pc":hex(at),"target":None})
            targets=[next_pc]
        if kind in ("B","B.cond","CBZ","CBNZ","TBZ","TBNZ"):
            branches.append({"pc":hex(at),"kind":kind,
                             "target":edge["directBranchTarget"]})
        pending.extend(targets)
        if len(visited)>4096:
            raise ExtractionError("Static callback CFG exceeds bounded instruction count")
    return {
        "addressStart":hex(base),"addressExclusiveEnd":hex(end),
        "reachableInstructionCount":len(visited),
        "reachableInstructionAddresses":[hex(x) for x in sorted(visited)],
        "returnsAndUnresolvedIndirectJumps":exits,
        "reachableDirectBranches":branches,"reachableCalls":calls,
        "outOfWindowSuccessors":sorted(set(outside)),
        "completeGhidraFunctionVerified":False,
        "runtimeControlFlowMeasured":False,
    }


def analyze(folder:Path)->dict:
    # Reuse eight original windows and all four xref results; don't redo reads.
    earlier=helper_audit(folder,strict=True)
    if earlier.get("originalEnvDxeSha256")!=PE_SHA256 or (
        earlier.get("bootTimeRamTableValuesMeasured") is not False or
        earlier.get("rootPrivilegeDemonstrated") is not False):
        raise ExtractionError("Parent proof promotes static data to runtime privileges")
    refs=[x for x in earlier["targetedXrefs"]
          if x["label"]=="post-callback-code"]
    if len(refs)!=1 or "0x1fc4" not in refs[0]["references"]:
        raise ExtractionError("Ghidra did not corroborate the callback branch to 0x1fe8")
    raw,reads=full_bytes(folder)
    edge_map={int(e["instructionAddress"],16):e for e in arm64_edges(raw,BASE)}
    for at,(kind,target) in REQUIRED_BRANCHES.items():
        expected_word=BRANCH_WORDS[at]
        if struct.unpack_from("<I",raw,at-BASE)[0]!=expected_word:
            raise ExtractionError("Original callback ARM64 branch opcode changed: "+hex(at))
        e=edge_map.get(at)
        if e is None or e["mnemonicClass"]!=kind or e["directBranchTarget"]!=hex(target):
            raise ExtractionError("Original HXL1 callback control-flow identity changed: "+hex(at))
    words={}
    for at,word in RECORD_WORDS.items():
        actual=struct.unpack_from("<I",raw,at-BASE)[0]
        if actual!=word:
            raise ExtractionError("Original 72-to-16 record transfer code changed: "+hex(at))
        words[hex(at)]=f"0x{word:08x}"
    cfg=bounded_cfg(raw)
    visited=set(cfg["reachableInstructionAddresses"])
    if not all(hex(at) in visited for at in NEEDED_REACHABLE):
        raise ExtractionError("Original branch graph does not reach callback transfer path")
    calls={x["pc"]:x["target"] for x in cfg["reachableCalls"]}
    if calls.get("0x1ff0")!="0x2618" or calls.get("0x2004")!="0x52cc":
        raise ExtractionError("Callback's second helper call not actually reachable")
    return {
        "classification":"VERIFIED_ORIGINAL_HXL1_STATIC_GETRAMPARTITIONS_CONTINUATION",
        "originalEnvDxeSha256":PE_SHA256,
        "callbackStaticEntrypoint":"0x1f74",
        "callbackProvisionalExclusiveBoundary":"0x205c",
        "boundaryGhidraFunctionVerified":False,
        "threeOriginalGhidraReadbacks":reads,
        "retAt1fe4IsOnlyOnePath":True,
        "observedIntraCallbackContinuation":"0x1fc4 -> 0x1fe8",
        "returnPathAt1fe4Reachable":True,
        "recordTransferStaticEvidence":{
            "internalRecordStrideBytes":72,
            "externalOutputStrideBytes":16,
            "twoUint64FieldsCopiedPerOutputRecord":True,
            "architectureOpcodeEvidence":words,
            "runtimeValuesMeasured":False,
        },
        "cfg":cfg,
        "runtimePhysicalRamKnown":False,
        "kernelPhysicalLoadKnown":False,
        "exploitOrRootAchieved":False,
    }


def markdown(value:dict)->str:
    c=value["cfg"]
    lines=[
        "# HXL1 original EnvDxe — GetRamPartitions full continuation (static)",
        "","Original PE: "+value["originalEnvDxeSha256"],"",
        "Code interval: [0x1f74,0x205c); 0x205c is a previously",
        "observed neighboring code entry, NOT a proven function boundary.",
        "Three overlapping/pinned Ghidra readbacks cover this interval.",
        "Callback 0x1fc4 CONDITIONALLY JUMPS to 0x1fe8 across RET 0x1fe4.",
        "Therefore 0x1ff0 and 0x2004 BELONG to a REACHABLE continuation.",
        "The old 'post-callback' classification is incorrect.","",
        "## Observed record copy mechanism","",
        "The 0x1fe8/0x1fec instruction pair computes 72 * count.",
        "0x2030/0x2038 and 0x203c/0x2040 copy two 64-bit values.",
        "The internal record pointer advances 0x48 bytes (72);",
        "the output pointer advances 0x10 bytes (16).",
        "This reconciles the original firmware internal 72-byte layout",
        "with the 16-byte LinuxLoader output ABI, statically only.","",
        "## Exact provenance","",
        "- Entry window REA ID: "+value["threeOriginalGhidraReadbacks"]["firstRead"],
        "- Continuation REA ID: "+value["threeOriginalGhidraReadbacks"]["continuationRead"],
        "- Newly verified final 20 bytes REA ID: "+
            value["threeOriginalGhidraReadbacks"]["finalTail"]["evidenceId"],
        "- Complete bounded code SHA256: "+
            value["threeOriginalGhidraReadbacks"]["originalSha256"],
        "","## Reachable static calls","",
        "| Instruction | Direct static target |",
        "|---|---|"]
    lines += ["| "+x["pc"]+" | "+str(x["target"])+" |" for x in c["reachableCalls"]]
    lines += ["","## Reachable conditional/unconditional branches","",
              "| Instruction | Kind | Direct target |","|---|---|---|"]
    lines += ["| "+x["pc"]+" | "+x["kind"]+" | "+str(x["target"])+" |"
              for x in c["reachableDirectBranches"]]
    lines += ["","## Static exits and window limits",""]
    lines += ["- "+x["pc"]+" "+x["kind"]
              for x in c["returnsAndUnresolvedIndirectJumps"]]
    lines += ["","Successors outside inspected interval: "+
              ", ".join(c["outOfWindowSuccessors"]), "",
              "No actual EFI runtime invocation or RAM table contents were read.",
              "No Linux physical load, runtime kernel slide, exploit, root or KernelSU proved.",""]
    return "\n".join(lines)


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,default=REPORT_DIR)
    parser.add_argument("--verify-tail",action="store_true")
    args=parser.parse_args()
    try:
        if args.verify_tail:
            print("[VERIFIED ORIGINAL HXL1 FINAL TAIL]",validate_tail(args.out))
            return 0
        result=analyze(args.out)
        (args.out/"rea-envdxe-getram-full-cfg.json").write_text(
            json.dumps(result,indent=2)+"\n")
        (args.out/"rea-envdxe-getram-full-cfg.md").write_text(markdown(result))
    except (ExtractionError,OSError,ValueError,KeyError,IndexError) as exc:
        print("[STOP]",str(exc),file=sys.stderr)
        return 2
    print("[VERIFIED CFG] branch 0x1fc4 -> 0x1fe8 bypasses earlier RET")
    print("[VERIFIED COPY] internal 72-byte stride -> output 16-byte stride")
    print("[STATIC CALLS]",len(result["cfg"]["reachableCalls"]))
    print("[REPORT]",args.out/"rea-envdxe-getram-full-cfg.md")
    print("[LIMIT] Static firmware control flow, no boot-time DRAM/kernel physical values")
    return 0

if __name__=="__main__":
    sys.exit(main())
