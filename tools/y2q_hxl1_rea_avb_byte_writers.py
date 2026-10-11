#!/usr/bin/env python3
"""Original HXL1 AVB returned-byte/native writer-site investigation.

Re-validates saved Ghidra Evidence for the 0xb2bc/0x33770 ABI and
DAT_00351055 xref inventory. Proves a *native* byte load into W0 from
0x351055 on the normal 0x33770 return path and W0->W8->output-byte
transfer in its 0xb2bc AVB callback. It then requests exactly eight
original static instruction observations at remaining global xref sites.

All addresses originate from the owner's SHA-pinned HXL1 firmware.
Cross-reference instructions are NOT automatically data writes.
Default PLAN ONLY; --execute runs read-only, bounded Ghidra queries.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, evidence, reference_sources, safe_segment
)
from tools.y2q_hxl1_rea_avb_global_abi import audit as verify_global_abi

SOURCE_FN = "0x33770"
CALLBACK_FN = "0xb2bc"
STATE_GLOBAL = "0x351055"
KNOWN_READS = ("0x337b0", "0x337d0")
REMAINING_REFS = (
    "0x33ccc", "0x33ce8", "0x33d08", "0x33ee0",
    "0x34278", "0x34294", "0x343b0", "0x343cc",
)
ALL_REFS = set(KNOWN_READS + REMAINING_REFS)
INSTRUCTION_PATTERN = re.compile(r"^\s*(0x[0-9a-f]+):\s+([a-z][a-z0-9.]*)\s*(.*?)\s*$", re.I)


def parse_instructions(ev: dict, entry: str) -> dict[str, tuple[str,str]]:
    payload = ev.get("normalized_result")
    rows = payload if isinstance(payload, list) else (
        payload.get("instructions") if isinstance(payload, dict) else None
    )
    if not isinstance(rows, list) or len(rows) > 2000 or len(rows) < 6:
        raise TriageError(f"Unrecognized original {entry} native-instruction list")
    instructions = {}
    for line in rows:
        if isinstance(line, dict):
            addr = line.get("address")
            mnemonic = line.get("mnemonic")
            operand = line.get("operands")
            if not (isinstance(addr,str) and isinstance(mnemonic,str)
                    and isinstance(operand,str)):
                raise TriageError("Unrecognized original native-instruction record")
        elif isinstance(line,str):
            match = INSTRUCTION_PATTERN.fullmatch(line)
            if match is None:
                raise TriageError("Unrecognized Ghidra native-instruction listing")
            addr,mnemonic,operand=match.groups()
        else:
            raise TriageError("Unsupported original native instruction row")
        try:
            addr = hex(int(addr,16))
        except ValueError as exc:
            raise TriageError("Invalid original native instruction address") from exc
        if addr in instructions:
            raise TriageError("Duplicate original instruction address")
        instructions[addr] = (mnemonic.lower(),re.sub(r"\s+","",operand.lower()))
    return instructions


def exact_instruction(insns: dict, address: str, mnemonic: str, operand: str):
    actual = insns.get(address)
    expect = (mnemonic, re.sub(r"\s+","",operand.lower()))
    if actual != expect:
        raise TriageError(f"Original ARM64 instruction changed at {address}: {actual}")


def native_byte_contract(cb_ev: dict, src_ev: dict) -> dict:
    cb = parse_instructions(cb_ev, CALLBACK_FN)
    src = parse_instructions(src_ev, SOURCE_FN)
    required_cb = (
        ("0xb2c0", "cbz", "x1,0x0000b2dc"),
        ("0xb2c4", "mov", "x19,x1"),
        ("0xb2c8", "bl", "0x00033770"),
        ("0xb2cc", "mov", "w8,w0"),
        ("0xb2d0", "mov", "w0,wzr"),
        ("0xb2d4", "strb", "w8,[x19]"),
        ("0xb2d8", "b", "0x0000b304"),
        ("0xb300", "mov", "w0,#0x2"),
        ("0xb308", "ret", ""),
    )
    required_src = (
        ("0x3378c", "b.eq", "0x000337c4"),
        ("0x3379c", "b.eq", "0x000337c4"),
        ("0x337a0", "adrp", "x8,0x351000"),
        ("0x337a4", "add", "x8,x8,#0x48"),
        ("0x337b0", "ldrb", "w3,[x8,#0xd]"),
        ("0x337c4", "adrp", "x8,0x351000"),
        ("0x337c8", "add", "x8,x8,#0x48"),
        ("0x337d0", "ldrb", "w0,[x8,#0xd]"),
        ("0x337e0", "b.ne", "0x000337f0"),
        ("0x337ec", "ret", ""),
        ("0x337f0", "bl", "0x0001e81c"),
    )
    for a,m,o in required_cb:
        exact_instruction(cb,a,m,o)
    for a,m,o in required_src:
        exact_instruction(src,a,m,o)
    # Continuity matters: the path after the final ldrb w0 must not
    # contain any other W0 producer, BL, or unconditional branch
    # before the normal epilogue. All those instructions are pinned.
    normal_tail = [
        "0x337d0","0x337d4","0x337d8","0x337dc",
        "0x337e0","0x337e4","0x337e8","0x337ec",
    ]
    if sorted(
        (a for a in src if int("0x337d0",16) <= int(a,16) <= int("0x337ec",16)),
        key=lambda a:int(a,16)
    ) != normal_tail:
        raise TriageError("Unknown native instruction inserted into normal W0 return path")
    tail = [src[a] for a in normal_tail]
    if tail != [
        ("ldrb","w0,[x8,#0xd]"),
        ("ldr","x8,[sp,#0x8]"),
        ("ldr","x9,[x9,#0x4b8]"),
        ("cmp","x9,x8"),
        ("b.ne","0x000337f0"),
        ("ldr","x30,[sp,#0x10]"),
        ("add","sp,sp,#0x20"),
        ("ret",""),
    ]:
        raise TriageError("Native W0 or stack-guard epilogue semantics changed")
    expected_sequence = [
        "0xb2c8","0xb2cc","0xb2d0","0xb2d4"
    ]
    if sorted(
        (a for a in cb if int("0xb2c8",16) <= int(a,16) <= int("0xb2d4",16)),
        key=lambda a:int(a,16)
    ) != expected_sequence:
        raise TriageError("Unknown native instruction inserted into callback byte transfer")
    # Effective address is formed by ADRP base + offset, then byte read.
    effective = 0x351000 + 0x48 + 0xD
    if effective != int(STATE_GLOBAL,16):
        raise TriageError("Original state global effective address mismatch")
    return {
        "originalCallbackInstructionsEvidenceId":cb_ev["evidence_id"],
        "originalSourceInstructionsEvidenceId":src_ev["evidence_id"],
        "nativeByteLoad":"0x337d0",
        "returnedByteAddress":STATE_GLOBAL,
        "effectiveAddressProof":"0x351000 + 0x48 + 0x0d",
        "normalPathReturnsLoadedW0":True,
        "logBranchSeparatelyLoadsW3":"0x337b0",
        "callbackConsumesW0At":"0xb2cc",
        "callbackStoresByteAt":"0xb2d4",
        "callbackStatusSuccessW0SetAt":"0xb2d0",
        "callbackErrorStatusW0SetAt":"0xb300",
        "guardFailurePath":"0x337f0",
        "guardFailureNoreturnIndependentProof":False,
        "stateOriginOrTrustProven":False,
    }


def classify_xref_instruction(ev: dict, coordinate: str) -> dict:
    data = ev.get("normalized_result")
    if not isinstance(data, dict) or data.get("address") != coordinate:
        raise TriageError("Ghidra exact native xref-instruction mismatch")
    status = data.get("status")
    if status not in ("decoded","not-instruction-boundary","data",
                      "undecodable","outside-memory"):
        raise TriageError("Unexpected exact Ghidra instruction status")
    mn = data.get("mnemonic")
    if status == "decoded" and not isinstance(mn,str):
        raise TriageError("Decoded original instruction missing mnemonic")
    mnemonic = mn.lower() if isinstance(mn,str) else ""
    # An ADRP reference can precede a LOAD/STORE via ADRP+ADD+LDR/STR.
    # Categorize the INSTRUCTION only; avoid treating a global xref
    # at an address-formation instruction as a read or write.
    kind = ("store-instruction" if mnemonic.startswith(("str","stp","stur"))
            else "load-instruction" if mnemonic.startswith(("ldr","ldp","ldur"))
            else "address-formation" if mnemonic in ("adr","adrp","add")
            else "other-or-unknown")
    return {
        "xref":coordinate,"evidenceId":ev["evidence_id"],
        "status":status,"nativeInstruction":data.get("raw_disassembly"),
        "mnemonic":mn,"owningProcedure":data.get("procedure"),
        "instructionKind":kind,
        "writesGlobalAt0x351055Proven":False,
        "addressAndAliasResolutionProven":False,
        "nativeInstructionContextRequired":True,
    }


def audit(root: Path, *, execute:bool=False, rea:Path|None=None,
          node:str="node", timeout:int=240, recover_partials:bool=False) -> dict:
    prior=verify_global_abi(root)
    if (prior.get("originalSourceVerified") is not True
            or len(prior.get("instructions",[])) != 2
            or len(prior.get("globalReferences",[])) != 2):
        raise TriageError("Original ABI and xref evidence not attested")
    targets={t.name:t for t in choose_targets(root)}
    target=targets["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    cb=evidence(folder/"instructions-0xb2bc.json",sha=target.sha256,
                operation="read_function_instructions",parameter="procedure",
                value=CALLBACK_FN)
    src=evidence(folder/"instructions-0x33770.json",sha=target.sha256,
                 operation="read_function_instructions",parameter="procedure",
                 value=SOURCE_FN)
    returned_byte=native_byte_contract(cb,src)
    xrefs=evidence(folder/"xrefs-global-0x351055.json",
                   sha=target.sha256,operation="xrefs",parameter="address",
                   value=STATE_GLOBAL)
    refs=reference_sources(xrefs)
    if set(refs) != ALL_REFS or len(refs) != len(ALL_REFS):
        raise TriageError("Original HXL1 IsUnlocked xref inventory differs")
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing/unsafe")
    runner=Runner(root/"rea-security-audit",
                  rea or Path("/not-installed/rea.mjs"),node=node,
                  run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    findings=[]
    for address in REMAINING_REFS:
        response=runner.obtain(
            target,["inspect-native-instruction",str(target.path),address],
            folder/("instruction-xref-"+safe_segment(address)+".json"),
            operation="inspect_native_instruction",parameter="address",
            value=address)
        findings.append({
            "address":address,
            "observation":classify_xref_instruction(response,address)
                          if response is not None else None,
            "status":"SOURCE_ATTESTED" if response is not None else "PLANNED",
        })
    return {
        "schemaVersion":1,"originalArchiveSha256":HXL1_BL_SHA256,
        "originalSourcesVerified":True,
        "mode":"STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "newQueries":len(runner.planned),
        "byteReturnPath":returned_byte,
        "globalXrefsEvidenceId":xrefs["evidence_id"],
        "globalReferenceCount":len(refs),
        "readSites":list(KNOWN_READS),
        "remainingSites":findings,
        "globalWriterVerified":False,
        "secureStateOriginVerified":False,
        "oemAuthorizationBypassVerified":False,
        "deviceModified":False,
    }


def markdown(r:dict) -> str:
    c=r["byteReturnPath"]
    lines=[
        "# HXL1 original AVB native returned byte / global writer reconnaissance",
        "", "**Pinned original Ghidra sources. No handset operation or unlock.**",
        "", "HXL1 BL SHA256: "+r["originalArchiveSha256"],
        "New read-only Ghidra queries: "+str(r["newQueries"]),
        "Original native callback Evidence: "+c["originalCallbackInstructionsEvidenceId"],
        "Original native source Evidence: "+c["originalSourceInstructionsEvidenceId"],
        "",
        "## Native ABI conflict resolved for normal return",
        "",
        "- 0x337c4 ADRP X8 0x351000",
        "- 0x337c8 ADD X8 X8 #0x48",
        "- 0x337d0 LDRB W0 [X8,#0xd] — reads byte at 0x351055",
        "- 0x337d4..0x337ec guard/epilogue preserve W0 on normal return",
        "- 0xb2c8 BL 0x33770",
        "- 0xb2cc MOV W8,W0; 0xb2d0 MOV W0,WZR",
        "- 0xb2d4 STRB W8,[X19] — copies returned byte to output",
        "- 0xb300 MOV W0,#2 on null pointer branch (separate status)",
        "- 0x337f0 stack-guard failure calls 0x1e81c; no normal",
        "  return from that failure path independently demonstrated.",
        "",
        "This is native read/return proof, NOT provenance, integrity,",
        "immutability or security authority of the value.",
        "",
        "## Original 0x351055 xrefs",
        "",
        "- All "+str(r["globalReferenceCount"])+" refs verified (Evidence: "+
          r["globalXrefsEvidenceId"]+")",
        "- 0x337b0 and 0x337d0: observed LDRB reads",
        "- Eight other source-identified reference sites:",
        "",
    ]
    for entry in r["remainingSites"]:
        o=entry["observation"]
        lines += [
            "### "+entry["address"],"",
            "- Status: "+entry["status"],
        ]
        if o is not None:
            lines += [
                "- Instruction: "+str(o["nativeInstruction"]),
                "- Ghidra-owning function: "+str(o["owningProcedure"]),
                "- Instruction-only category: "+o["instructionKind"],
                "- Actual write to 0x351055 proven: False",
                "- Evidence: "+o["evidenceId"],
            ]
        lines.append("")
    lines += [
        "## Next proof gates","",
        "1. Inspect full native register/address formation around each",
        "   candidate storing instruction. An xref at ADRP is not a write.",
        "2. Identify the original object or function that initializes",
        "   DAT_00351055, its caller inputs and its trusted-data origin.",
        "3. Keep LinuxLoader's reported AVB device_state distinct from",
        "   separate OEM flashing/image-authentication authorization.",
        "4. No secure-state edit, device modification, or unlock is proven.",
        "",
    ]
    return "\n".join(lines)


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir",type=Path,
                    default=Path.home()/"s20-artifacts/hxl1-research/bootloader-unlock")
    ap.add_argument("--rea",type=Path,
                    default=Path.home()/"src/rea/scripts/rea.mjs")
    ap.add_argument("--node",default="node")
    ap.add_argument("--execute",action="store_true")
    ap.add_argument("--recover-partials",action="store_true")
    ap.add_argument("--timeout",type=int,default=240)
    a=ap.parse_args()
    if not 30<=a.timeout<=1200:
        ap.error("Timeout outside supported original static Ghidra range")
    try:
        root=a.input_dir.expanduser().resolve()
        r=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                timeout=a.timeout,recover_partials=a.recover_partials)
        out=root/"rea-security-audit"
        (out/"avb-byte-writer-sites.json").write_text(json.dumps(r,indent=2)+"\n")
        (out/"avb-byte-writer-sites.md").write_text(markdown(r))
    except (TriageError,OSError,KeyError,ValueError,TypeError) as e:
        print("[STOP]",str(e),file=sys.stderr)
        return 2
    print("[NATIVE] 0x33770 -> W0 byte loaded from",STATE_GLOBAL)
    print("[CALLBACK] 0xb2bc -> store byte to output and status 0")
    print("[XREFS]",len(r["readSites"]),"known reads,",
          len(r["remainingSites"]),"remaining reference sites")
    print("[REPORT]",out/"avb-byte-writer-sites.md")
    print("[LIMIT] State writers/authority, OEM flash policy and unlock unverified")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
