#!/usr/bin/env python3
"""Original HXL1 AVB persisted IsUnlocked setter caller authority audit.

Attest the original SHA-pinned 0x33c88/0x33da8 xrefs, then inspect the
five *actual* xref instructions. Only if 0x33a08/0x33b20 are decoded
direct branches to 0x33c88, ask Ghidra for their containing functions.
For verified BL sites, also obtain native instructions for the containing
function to display bounded W0 input candidates without fabricating CFG.

All work is static and host-side. No firmware operation, phone access,
unlock or assumption that any state byte is securely authorized.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.y2q_hxl1_bootloader_unlock_audit import HXL1_BL_SHA256, TriageError
from tools.y2q_hxl1_rea_security_audit import (
    Runner, choose_targets, function_record, safe_segment,
)
from tools.y2q_hxl1_rea_avb_state_persistence import audit as verify_persistence
from tools.y2q_hxl1_rea_avb_byte_writers import parse_instructions

SETTER = "0x33c88"
INITIALIZER = "0x33da8"
SITES = {
    SETTER: ("0x33a08","0x33b20"),
    INITIALIZER: ("0x1948","0x5c0c0","0x5c19c"),
}
ALL_SITES = tuple((fn,site) for fn,refs in SITES.items() for site in refs)
DIRECT_BRANCH = re.compile(
    r"^\s*(bl|b)\s+0x([0-9a-f]+)\s*$",re.I,
)
FUN_CALL = re.compile(r"\bFUN_00033c88\s*\(",re.I)
GUIDANCE = re.compile(
    r"FUN_00033c88|IsUnlocked|unlock|oem|secure|state|lock|"
    r"error|return|switch|if\s*\(|FUN_|DAT_",re.I,
)
MAX_PSEUDO = 250000
MAX_NATIVE_INSTRUCTIONS = 5000
MAX_CALL_CONTEXT_BEFORE = 60
MAX_CALL_CONTEXT_AFTER = 12

# A64 may define W0 through a call return, an instruction targeting X0,
# a conditional select, or a path-dependent phi. Never elevate a
# convenient lexical predecessor into a unique reaching definition.
POTENTIAL_W0_DEST = {
    "mov", "movk", "movz", "movn", "orr", "and", "eor",
    "add", "sub", "adr", "adrp", "ldr", "ldrb", "ldrh",
    "ldrsb", "ldrsw", "sxtw", "uxth", "uxtb", "csel",
    "csinc", "csinv", "csneg", "cmp", "cset", "csetm",
}


def verified_original_xrefs(persisted: dict) -> None:
    if persisted.get("sourceAttested") is not True:
        raise TriageError("Original HXL1 persisted-state source not authenticated")
    if persisted.get("globalAddress") != "0x351055":
        raise TriageError("Unexpected original IsUnlocked output byte")
    owners = persisted.get("functionXrefs")
    if not isinstance(owners,list) or len(owners)!=2:
        raise TriageError("Source-backed setter/init xrefs not complete")
    found={}
    for item in owners:
        if not isinstance(item,dict):
            raise TriageError("Invalid owner xref")
        target = item.get("function")
        sites = item.get("sites")
        if target in found or target not in SITES or not isinstance(sites,list):
            raise TriageError("Unknown original setter/init xref set")
        if not isinstance(item.get("evidenceId"),str) or not item["evidenceId"]:
            raise TriageError("Original xref Evidence ID missing")
        found[target]=sites
    for fn,expected in SITES.items():
        observed = found.get(fn)
        if not isinstance(observed,list) or len(observed)!=len(expected) or set(observed)!=set(expected):
            raise TriageError(f"HXL1 {fn} caller-site inventory changed")


def inspect_xref(ev:dict,site:str,target:str)->dict:
    data=ev.get("normalized_result")
    if not isinstance(data,dict) or data.get("address")!=site:
        raise TriageError("Original Ghidra native xref coordinate mismatched")
    status=data.get("status")
    if status not in ("decoded","data","not-instruction-boundary",
                      "outside-memory","undecodable"):
        raise TriageError("Original native xref status invalid")
    asm=data.get("raw_disassembly")
    mnemonic=data.get("mnemonic")
    if status=="decoded" and (not isinstance(asm,str) or not isinstance(mnemonic,str)):
        raise TriageError("Decoded native caller lacks disassembly and mnemonic")
    direct = DIRECT_BRANCH.fullmatch(asm) if isinstance(asm,str) and status=="decoded" else None
    branch_to = hex(int(direct.group(2),16)) if direct else None
    if direct is not None and direct.group(1).lower() != mnemonic.lower():
        raise TriageError("Provider native xref mnemonic differs from disassembly")
    return {
        "site":site,"xrefTarget":target,
        "evidenceId":ev["evidence_id"],
        "status":status,"nativeInstruction":asm,
        "mnemonic":mnemonic,"owningProcedure":data.get("procedure"),
        "directBranchToTarget":branch_to==target and direct is not None,
        "directBranchMnemonic":direct.group(1).lower() if direct else None,
        "otherBranchDestination":branch_to if branch_to!=target else None,
        "observedSourceW0Value":False,
        "setterCallerAuthorizationProven":False,
    }


def source_caller(ev:dict,site:str)->dict:
    data=ev.get("normalized_result",{})
    rec=function_record(ev,site)
    pseudo=data.get("pseudocode")
    if not isinstance(pseudo,str) or not pseudo.strip() or len(pseudo)>MAX_PSEUDO:
        raise TriageError("Original setter caller pseudocode missing/oversized")
    lines=pseudo.splitlines()
    if len(lines)>6000:
        raise TriageError("Original caller exceeds bounded line budget")
    # Ghidra can elide a low-level call due to an indirect thunk.
    # Merely finding an xref and a caller does not prove argument W0's source.
    calls=[i for i,x in enumerate(lines) if FUN_CALL.search(x)]
    anchors=[i for i,x in enumerate(lines) if GUIDANCE.search(x)]
    keep=set(range(min(28,len(lines))))
    for i in (calls[:20]+anchors[:50]):
        keep.update(range(max(0,i-5),min(len(lines),i+7)))
    subset=sorted(keep)[:220]
    return {
        "site":site,"entry":rec["entry"],"pseudocodeEvidenceId":ev["evidence_id"],
        "pcodeAvailable":rec["pcodeAvailable"],
        "totalPseudocodeLines":len(lines),
        "pseudocodeSha256":hashlib.sha256(pseudo.encode()).hexdigest(),
        "setterCallLineCandidates":[i+1 for i in calls[:32]],
        "callerContext":[{"line":i+1,"code":lines[i][:750]} for i in subset],
        "excerptTruncated":len(keep)>len(subset) or len(anchors)>50,
        "argumentW0NativeDefinitionVerified":False,
        "policyDecisionVerified":False,
    }


def native_w0_window(ev: dict, site: str, owner: str) -> dict:
    """Review the original native argument register without guessing CFG.

    The full function instruction list is source-proven; a linear
    instruction window is *not* a path-validated backward slice.
    """
    ops = parse_instructions(ev, owner)
    if not 3 <= len(ops) <= MAX_NATIVE_INSTRUCTIONS:
        raise TriageError("Original setter caller native listing too small or excessive")
    if ops.get(site) != ("bl", "0x00033c88"):
        raise TriageError(f"Native setter BL at {site} inconsistent with Ghidra xref")
    addresses = sorted(ops, key=lambda x: int(x, 16))
    i = addresses.index(site)
    first = max(0, i - MAX_CALL_CONTEXT_BEFORE)
    last = min(len(addresses), i + MAX_CALL_CONTEXT_AFTER + 1)
    excerpt = [
        {"address": a, "mnemonic": ops[a][0], "operands": ops[a][1]}
        for a in addresses[first:last]
    ]
    possible_defs = []
    for a in addresses[first:i]:
        mnemonic, operands = ops[a]
        dest = operands.split(",", 1)[0]
        if (mnemonic in POTENTIAL_W0_DEST and dest in ("x0","w0")
                and mnemonic not in ("cmp",)):
            possible_defs.append({
                "address": a, "mnemonic": mnemonic, "operands": operands,
                "note": "lexical predecessor only; reachability unknown",
            })
        elif mnemonic.startswith(("bl", "blr")):
            possible_defs.append({
                "address": a, "mnemonic": mnemonic, "operands": operands,
                "note": "prior call may produce W0; ABI semantics unverified",
            })
    return {
        "owner": owner, "site": site,
        "evidenceId": ev["evidence_id"],
        "totalNativeInstructions": len(ops),
        "fullOwnerNativeSourceAttested": True,
        "exactSetterBranchVerified": True,
        "sourceRegister": "w0",
        "linearWindow": excerpt,
        "possibleW0Definitions": possible_defs[-32:],
        "earlierContextTruncated": first > 0,
        "laterContextTruncated": last < len(addresses),
        "nativeW0ReachingDefinitionVerified": False,
        "completeControlFlowProven": False,
        "callerSecurityAuthorizationProven": False,
    }


def audit(root:Path,*,execute:bool=False,rea:Path|None=None,
          node:str="node",timeout:int=240,recover_partials:bool=False)->dict:
    prior=verify_persistence(root)
    verified_original_xrefs(prior)
    if prior.get("storageHelperPseudocode") is None or prior.get("storageHelperNative") is None:
        raise TriageError("Original VB protocol dispatcher dossier missing")
    if execute and (rea is None or not rea.is_file() or rea.is_symlink()):
        raise TriageError("Original REA script missing or unsafe")
    target={t.name:t for t in choose_targets(root)}["LinuxLoader"]
    folder=root/"rea-security-audit"/"LinuxLoader"
    runner=Runner(root/"rea-security-audit",rea or Path("/not-installed/rea.mjs"),
                  node=node,run_commands=execute,deadline=timeout,
                  recover_partials=recover_partials)
    inspected=[]
    for fn,site in ALL_SITES:
        response=runner.obtain(
            target,["inspect-native-instruction",str(target.path),site],
            folder/("instruction-caller-"+safe_segment(site)+".json"),
            operation="inspect_native_instruction",parameter="address",value=site,
        )
        facts=inspect_xref(response,site,fn) if response else None
        inspected.append({"site":site,"target":fn,"native":facts,
                          "status":"VERIFIED" if facts else "PLANNED",
                          "callerFunction":None,"callerNative":None})
        # Only follow precisely observed direct setter branches.
        if fn==SETTER and facts is not None and facts["directBranchToTarget"]:
            owner=runner.obtain(
                target,["function",str(target.path),site],
                folder/("function-caller-"+safe_segment(site)+".json"),
                operation="analyze_function",parameter="procedure",value=site,
            )
            if owner is not None:
                source = source_caller(owner, site)
                inspected[-1]["callerFunction"] = source
                if facts["directBranchMnemonic"] == "bl":
                    entry = source["entry"]
                    native = runner.obtain(
                        target, ["instructions", str(target.path), entry],
                        folder/("instructions-caller-owner-"+safe_segment(entry)+".json"),
                        operation="read_function_instructions",
                        parameter="procedure", value=entry,
                    )
                    if native is not None:
                        inspected[-1]["callerNative"] = native_w0_window(native, site, entry)
    return {
        "schemaVersion":1,"archiveSha256":HXL1_BL_SHA256,
        "mode":"STATIC_GHIDRA_EXECUTE" if execute else "PLAN_ONLY",
        "sourceAttested":True,"requestedQueries":len(runner.planned),
        "originalStorageDispatcher":"0x2ae38",
        "persistentProtocolMethodOffset":"0x8",
        "protocolGuidAddress":"0xef930",
        "directNativeSites":inspected,
        "setterW0InputAuthorityVerified":False,
        "secureBootOrOdinAuthorizationVerified":False,
        "persistentIntegrityOrSecurityProven":False,
        "bootloaderUnlockProven":False,
        "deviceModified":False,
    }


def markdown(report:dict)->str:
    rows=[
        "# Original HXL1 AVB setter input caller and initialization provenance",
        "","**All evidence from original SHA-pinned Ghidra/REA.**",
        "No signed-image bypass or bootloader unlock demonstrated.",
        "","Archive SHA256: "+report["archiveSha256"],
        "New original static Ghidra queries: "+str(report["requestedQueries"]),
        "","## Five original xref-site native instruction observations","",
    ]
    for item in report["directNativeSites"]:
        rows += [
            "### "+item["site"]+" -> "+item["target"],"",
            "- Native status: "+item["status"],
        ]
        n=item["native"]
        if n is not None:
            rows += [
                "- Original native Evidence: "+n["evidenceId"],
                "- Mnemonic/operands: "+str(n["nativeInstruction"]),
                "- Ghidra owner: "+str(n["owningProcedure"]),
                "- Direct branch to recorded target: "+str(n["directBranchToTarget"]),
                "- Caller-supplied W0 origin: not yet verified","",
            ]
        caller=item["callerFunction"]
        if caller is not None:
            rows += [
                "#### Original containing caller function","",
                "- Function entry: "+caller["entry"],
                "- Ghidra Evidence: "+caller["pseudocodeEvidenceId"],
                "- Ghidra decompilation lines: "+str(caller["totalPseudocodeLines"]),
                "- Pseudocode setter-call lines: "+str(caller["setterCallLineCandidates"]),
                "","~~~c",
            ]
            for line in caller["callerContext"]:
                rows.append(f"{line['line']:5d} | {line['code']}")
            rows += ["~~~",""]
            if caller["excerptTruncated"]:
                rows += ["Excerpt bounded; full original function Evidence retained.", ""]
        native=item.get("callerNative")
        if native is not None:
            rows += [
                "#### Full owner native listing, bounded argument window","",
                "- Owner native Evidence: "+native["evidenceId"],
                "- Original owner instructions: "+str(native["totalNativeInstructions"]),
                "- Native branch to 0x33c88 verified: "+str(native["exactSetterBranchVerified"]),
                "- W0 reaching definition proved: False; control flow not reconstructed",
                "- Possible W0 producers are lexical hints, NOT evidence of",
                "  an authorized input or unique reaching definition.","",
                "~~~asm",
            ]
            for row in native["linearWindow"]:
                rows.append(row["address"]+": "+row["mnemonic"]+" "+row["operands"])
            rows += ["~~~","",
                     "- Potential W0 producer sites (non-path-verified): "+
                         str(native["possibleW0Definitions"]),""]
    rows += [
        "## Persisted state versus security authority","",
        "- Original 0x33c88 writes input W0 to 0x351055 on its mismatch path.",
        "- Original 0x33da8 resets the structure when the expected",
        "  SAMANDR-BOOT! marker is invalid; valid-marker integrity",
        "  and any secure-storage protection remain unverified.",
        "- Original 0x2ae38 dispatches through the UEFI VB protocol",
        "  identified by a GUID at 0xef930; the GUID's value and",
        "  concrete storage backend have not yet been established.",
        "- An xref may not be a direct call; Ghidra caller entry and",
        "  pseudocode are not substitutes for native W0 provenance.",
        "","## Next proof gates","",
        "1. Identify native W0 setter arguments and preceding checks in",
        "   the source-proven calling functions.",
        "2. Determine whether the VB protocol method reads or writes",
        "   a raw partition, authenticated storage, or delegated service.",
        "3. Establish whether Odin/boot signature authorization accepts",
        "   this cached field or consults independent protected state.",
        "4. Nothing in this report writes to the handset or unlocks it.","",
    ]
    return "\n".join(rows)


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path,
                   default=Path.home()/"s20-artifacts/hxl1-research/bootloader-unlock")
    p.add_argument("--rea",type=Path,default=Path.home()/"src/rea/scripts/rea.mjs")
    p.add_argument("--node",default="node")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--recover-partials",action="store_true")
    p.add_argument("--timeout",type=int,default=240)
    a=p.parse_args()
    if not 30<=a.timeout<=1200:
        p.error("Timeout must be 30..1200s")
    try:
        root=a.input_dir.expanduser().resolve()
        out=audit(root,execute=a.execute,rea=a.rea,node=a.node,
                  timeout=a.timeout,recover_partials=a.recover_partials)
        directory=root/"rea-security-audit"
        (directory/"avb-setter-caller-authority.json").write_text(
            json.dumps(out,indent=2)+"\n")
        (directory/"avb-setter-caller-authority.md").write_text(markdown(out))
    except (TriageError,OSError,KeyError,ValueError,TypeError) as exc:
        print("[STOP]",str(exc),file=sys.stderr)
        return 2
    for x in out["directNativeSites"]:
        print("[CALLSITE]",x["site"],"target",x["target"],
              x["native"]["nativeInstruction"] if x["native"] else "NOT_COLLECTED")
    print("[REPORT]",directory/"avb-setter-caller-authority.md")
    print("[LIMIT] Caller input authority, VB protocol backend and unlock not proven")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
