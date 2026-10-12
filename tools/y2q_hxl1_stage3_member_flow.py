#!/usr/bin/env python3
"""Source-pinned Ghidra register-chain worklist for factory HXL1 Stage 3.

Consumes a SAVED full-factory Stage3 report and the exact archived Ghidra
instruction records; does not repeat the factory analysis. A matched static
register chain is NOT a factory C-field identity, OEM DWARF, runtime event,
root exploit, or authorization to write target.h.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import re
import sys
import zipfile
if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_rtmutex_displacement_attest as prior
from tools import y2q_hxl1_porting_automation as port

ART=Path.home()/"s20-artifacts"
SOURCE=Path.home()/"src/samsung-y2q-hxl1-stock"
REA=Path.home()/"HXL1-Stage3-REA-Evidence.zip"
class FlowError(ValueError):pass
def require(ok,message):
    if not ok:raise FlowError("HXL1 member-flow STOP: "+message)

# Explicit original Ghidra instruction chains, with saved OEM source bytes
# authenticated by the immediately preceding Stage 3 verifier. These are
# STATIC potential paths; branch reachability and member identity NOT proven.
CHAINS=(
 ("rt_mutex","waiters.rb_leftmost",(("0x10018","ldr x22, [x0, #0x18]"),),"lock argument","DIRECT"),
 ("rt_mutex","waiters.rb_root.rb_node",(("0x1001c","mov x19, x0"),("0x100a8","ldr x8, [x19, #0x10]")),"lock argument -> x19","DIRECT"),
 ("rt_mutex","owner",(("0x1001c","mov x19, x0"),("0x1003c","ldr x24, [x19, #0x20]")),"lock argument -> x19","DIRECT"),
 ("rt_mutex_waiter","tree_entry",(("0x10020","mov x23, x1"),("0x10048","ldr x8, [x23]")),"waiter argument -> x23","NESTED_RB_NODE"),
 ("rt_mutex_waiter","pi_tree_entry",(("0x10020","mov x23, x1"),("0x1008c","ldr x8, [x23, #0x18]!")),"waiter argument -> x23","NESTED_RB_NODE"),
 ("task_struct","pi_lock",(("0x10034","mrs x20, sp_el0"),("0x10038","add x21, x20, #0x8c8")),"sp_el0 -> x20","CURRENT_TASK"),
 ("task_struct","pi_blocked_on",(("0x10034","mrs x20, sp_el0"),("0x10068","str xzr, [x20, #0x8f8]")),"sp_el0 -> x20","CURRENT_TASK"),
 ("task_struct","pi_waiters.rb_root.rb_node",(("0x1001c","mov x19, x0"),("0x1003c","ldr x24, [x19, #0x20]"),("0x10078","and x21, x24, #-0x2"),("0x100c4","ldr x12, [x21, #0x8e0]")),"lock owner -> masked task x21","CONDITIONAL_OWNER"),
 ("task_struct","pi_waiters.rb_leftmost",(("0x1001c","mov x19, x0"),("0x1003c","ldr x24, [x19, #0x20]"),("0x10078","and x21, x24, #-0x2"),("0x10138","ldr x8, [x21, #0x8e8]")),"lock owner -> masked task x21","CONDITIONAL_OWNER"),
)
UNMAPPED={
 ("rt_mutex_waiter","task"),("rt_mutex_waiter","lock"),
 ("rt_mutex_waiter","prio"),("rt_mutex_waiter","deadline")
}

def original_instructions(archive:Path,stage3:dict)->dict:
    require(archive.is_file() and not archive.is_symlink(),"Ghidra ZIP missing/unsafe")
    recorded=stage3["reaEvidence"]
    require(recorded["state"]=="31_ORIGINAL_OPCODE_WITNESSES_REA_ATTESTED" and
            recorded["reaSha256"]==port.sha256(archive),
            "saved original REA digest does not match")
    originals=recorded["savedGhidraDossiers"]
    require(set(originals)=={"remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi"},
            "all three original Ghidra dossiers are required")
    result={}
    with zipfile.ZipFile(archive,"r") as z:
        for name,dossier in originals.items():
            attested=dossier.get("originalStockByteAttestation") or {}
            require(attested.get("archivedGhidraInputMatchesOriginalFactoryImage") is True and
                    dossier.get("actualGhidraRecordsIndependentlyChecked") is True,
                    "dossier not authenticated against original factory Image")
            va=attested["symbolVA"][2:]
            member="rea-slice-"+name+"-"+va+".json"
            info=z.getinfo(member)
            require(info.file_size<1024*1024,"oversized REA record")
            document=json.loads(z.read(member))
            require(document["operation"]=="read_function_instructions" and
                    document["provider"]["id"]=="ghidra" and
                    document["subject"]["digest"]["sha256"]==dossier["sourceElfSha256"] and
                    document["parameters"]["procedure"]=="0x10000",
                    "Ghidra provider/function/ELF mismatch")
            instructions=document["normalized_result"]["instructions"]
            require(len(instructions)==dossier["ghidraInstructionCount"],"Ghidra instruction count mismatch")
            mapping={}
            for line in instructions:
                m=re.fullmatch(r"(0x[0-9a-fA-F]+):\s*(.+)",line)
                require(m is not None,"bad Ghidra instruction")
                address=hex(int(m.group(1),16))
                require(address not in mapping,"duplicated PC")
                mapping[address]=m.group(2).lower().strip()
            result[name]=mapping
    return result

def source_signature(source:Path)->bool:
    # The original HXL1 source C and headers are SHA/source-declaration checked.
    prior.source_headers(source)
    file=source/"kernel/locking/rtmutex.c"
    text=file.read_text()
    return bool(re.search(r"\b(?:static\s+)?void\s+(?:__sched\s+)?remove_waiter\s*"
                         r"\(\s*struct\s+rt_mutex\s*\*\s*lock\s*,\s*"
                         r"struct\s+rt_mutex_waiter\s*\*\s*waiter\s*\)",text))

def correlate(instructions:dict,typed_signature:bool)->dict:
    registered={(ty,name) for ty,fields in prior.FIELDS.items() for name in fields}
    require(registered=={(ty,name) for ty,name,*_ in CHAINS}|UNMAPPED,
            "13-member registry changed")
    entries=[]
    for ty,field,chain,origin,kind in CHAINS:
        steps=[{"pc":pc,"expected":value,"matched":instructions.get("remove_waiter",{}).get(pc)==value}
               for pc,value in chain]
        verified=typed_signature and all(step["matched"] for step in steps)
        entries.append({"type":ty,"member":field,"comparisonOffset":prior.FIELDS[ty][field],
                        "registerOriginHypothesis":origin,"pathClass":kind,
                        "staticGhidraChainMatched":verified,
                        "steps":steps,"factoryCMemberIdentityCertified":False,
                        "limitations":"Static candidate, not path-complete dataflow or OEM debug member identification"})
    for ty,field in sorted(UNMAPPED):
        entries.append({"type":ty,"member":field,"comparisonOffset":prior.FIELDS[ty][field],
                        "staticGhidraChainMatched":False,"factoryCMemberIdentityCertified":False,
                        "limitations":"No trusted original register-to-member chain"})
    return {"candidates":entries,
            "matchedStaticChains":sum(x["staticGhidraChainMatched"] for x in entries),
            "factoryCertifiedMemberOffsets":0}

def analyze(report_file:Path,source:Path,archive:Path)->dict:
    require(report_file.is_file() and not report_file.is_symlink() and
            report_file.stat().st_size<4*1024*1024,"saved Stage3 report missing/unsafe")
    stage3=json.loads(report_file.read_text())
    require(stage3.get("schemaVersion")==1 and stage3.get("firmware")=="G986U1UESCHXL1" and
            stage3.get("stockOpcodeWitnessesVerified")==31 and
            len(stage3.get("memberCandidates",[]))==13 and
            stage3.get("factoryMemberOffsetsVerified")==0 and
            stage3.get("stage3Complete") is False and
            stage3.get("runtimeRootOrKernelSuProven") is False,
            "saved original 31/13 factory-check report invalid")
    original=stage3.get("factoryInputIntegrity",{}).get("kernel.bin",{})
    require(original.get("state")=="VERIFIED" and
            original.get("actualSha256")==prior.ORIGINAL_IMAGE_SHA,
            "saved stock Image digest pin is missing")
    known={(a["type"],a["memberPath"]):a["previousComparisonCandidateOffset"]
           for a in stage3["memberCandidates"]}
    require(len(known)==13 and
            known=={(ty,name):offset for ty,fields in prior.FIELDS.items() for name,offset in fields.items()},
            "saved 13 offset candidates mismatch source registry")
    typed=source_signature(source)
    original_asm=original_instructions(archive,stage3)
    return {"schemaVersion":1,"firmware":"G986U1UESCHXL1",
            "sourceTypedRemoveWaiterSignature":typed,
            "savedFactoryVerifierSha256":port.sha256(report_file),
            "archivedREAInputSha256":port.sha256(archive),
            "registerFlowWorklist":correlate(original_asm,typed),
            "factoryMemberOffsetsVerified":0,"stage3Complete":False,
            "rootOrKernelSuVerified":False,"deviceModified":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified-stage3-report",required=True,type=Path)
    parser.add_argument("--source",default=SOURCE,type=Path)
    parser.add_argument("--rea",default=REA,type=Path)
    parser.add_argument("--output",type=Path)
    a=parser.parse_args()
    out=(a.output.expanduser().absolute() if a.output else
         ART/"hxl1-research"/("stage3-member-flow-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")+".json"))
    try:
        require(out.suffix==".json" and not out.exists() and not out.is_symlink(),"fresh JSON output required")
        for protect in (a.source,a.rea,a.verified_stage3_report,Path(__file__).resolve().parents[1]):
            p=protect.expanduser().absolute()
            require(out!=p and p not in out.parents,"unsafe source or evidence output path")
        d=analyze(a.verified_stage3_report.expanduser().absolute(),
                  a.source.expanduser().absolute(),a.rea.expanduser().absolute())
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x") as f:f.write(json.dumps(d,indent=2)+"\n")
        print("[SOURCE SIGNATURE MATCHED]",d["sourceTypedRemoveWaiterSignature"])
        print("[STATIC REGISTER CHAINS]",d["registerFlowWorklist"]["matchedStaticChains"],"/13")
        print("[FACTORY MEMBER OFFSETS CERTIFIED] 0")
        print("[REPORT]",out)
        return 0
    except (OSError,KeyError,ValueError,TypeError,zipfile.BadZipFile) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
