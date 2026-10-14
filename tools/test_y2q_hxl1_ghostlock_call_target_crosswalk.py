"""Synthetic, fail-closed GhostLock HXL1 static call-target label resolution tests."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_ghostlock_call_target_crosswalk as m

BASE=m.stock.IMAGE_VA
TARGETS=[f"0x{BASE+0x2000+i*0x100:016x}" for i in range(17)]+[
    "0xffffff800966f2a4","0xffffff800967357c",
    "0xffffff80082df814","0xffffff8008305c0c"]
REQUIRED=list(sorted(m.REQUIRED_EDGES))

def fixture():
    names=list(m.windows.NAMES)
    counts=m.EXPECTED_COUNTS
    functions=[]
    ctr=0
    for name in names:
        calls=[]
        for j in range(counts[name]):
            target=TARGETS[ctr%len(TARGETS)]
            addr=f"0x{BASE+0x9000+ctr*4:016x}"
            calls.append({"staticImageVA":addr,"opcode":"bl",
                          "directTargetText":target,
                          "calleeArgumentIdentityProved":False,
                          "pointerEscapeProved":False,
                          "nearbySpConstructionTextualOnly":
                          ([{"syntacticSpConstruction":"mov x2, sp"}] if ctr<19 else [])})
            ctr+=1
        if calls:
            functions.append({"symbol":name,"status":"ORIGINAL_CALLSITES_REVIEWED",
                "callsiteInventory":{"calls":calls,"totalCalls":len(calls),
                    "directCalls":len(calls),"indirectCalls":0,
                    "sourceLocalVariableAttributionVerified":False,
                    "interproceduralDataflowVerified":False,
                    "runtimeCarrierWindowVerified":False}})
        else:
            functions.append({"symbol":name,"status":"NAME_NOT_RECOVERED",
                              "compilerEmittedFunctionAbsent":False})
    # Preserve known original static edges in their corresponding callers.
    for name,origin,target in REQUIRED:
        row=next(f for f in functions if f["symbol"]==name)
        index=sum(1 for a,b,c in REQUIRED if a==name and b<origin)
        row["callsiteInventory"]["calls"][index]["staticImageVA"]=origin
        row["callsiteInventory"]["calls"][index]["directTargetText"]=target
    # Recalculate distinct destinations in synthetic fixture after edits.
    all_calls=[c for f in functions for c in f.get("callsiteInventory",{}).get("calls",[])]
    distinct={c["directTargetText"] for c in all_calls}
    for i in range(len(all_calls)):
        if len(distinct)>=21:break
        all_calls[i]["directTargetText"]=TARGETS[i]
        distinct={c["directTargetText"] for c in all_calls}
    # Validate synthetic 41/21 uniqueness, else remove excess unique targets
    # from non-required rows.
    req={(n,a,t) for n,a,t in REQUIRED}
    for f in functions:
        for c in f.get("callsiteInventory",{}).get("calls",[]):
            if len(distinct)<=21:break
            if (f["symbol"],c["staticImageVA"],c["directTargetText"]) in req:continue
            old=c["directTargetText"]
            if sum(y["directTargetText"]==old for y in all_calls)==1:
                c["directTargetText"]=TARGETS[0]
                distinct={y["directTargetText"] for y in all_calls}
    assert len(all_calls)==41 and len(distinct)==21
    return {
        "schemaVersion":1,
        "target":"SM-G986U1/G986U1UESCHXL1",
        "scope":"STATIC_ORIGINAL_AARCH64_CALLSITES_AND_SP_PROXIMITY_ONLY",
        "verifiedOriginalInstructionSlots":746,
        "frameReportSha256":m.FRAME_SHA,
        "originalWindowsManifestSha256":m.WINDOWS_SHA,
        "originalKernelImageHashReportedAndVerifiedByPriorTool":m.stock.STOCK_SHA,
        "recoveredNmSha256":m.ORIGINAL_NM_SHA,
        "functions":functions}

def nm():
    rows=[f"{BASE:x} T _text"]
    for i,t in enumerate(TARGETS):
        rows.append(f"{int(t,16):x} t symbol_{i}")
    return ("\n".join(rows)+"\n").encode()

class CallTargetTests(unittest.TestCase):
    def test_valid_pinned_structure(self):
        self.assertEqual(len(m.validate_owner_report(fixture())),41)

    def test_false_pointer_flow_claim_fails(self):
        d=fixture()
        d["functions"][0]["callsiteInventory"]["calls"][0]["pointerEscapeProved"]=True
        with self.assertRaisesRegex(m.CrosswalkError,"dataflow"):
            m.validate_owner_report(d)

    def test_missing_known_internal_call_fails(self):
        d=fixture()
        caller=next(x for x in d["functions"] if x["symbol"]=="__sys_sendmsg")
        entry=next(x for x in caller["callsiteInventory"]["calls"]
                   if x["staticImageVA"]=="0xffffff800966f248")
        entry["directTargetText"]=TARGETS[0]
        with self.assertRaisesRegex(m.CrosswalkError,"provenance"):
            m.validate_owner_report(d)

    def test_bad_instruction_count_fails(self):
        d=fixture();d["verifiedOriginalInstructionSlots"]=745
        with self.assertRaisesRegex(m.CrosswalkError,"fingerprint"):
            m.validate_owner_report(d)

    def test_forged_missing_function_absence_fails(self):
        d=fixture()
        row=next(x for x in d["functions"] if x["symbol"]=="futex_wait_requeue_pi")
        row["compilerEmittedFunctionAbsent"]=True
        with self.assertRaisesRegex(m.CrosswalkError,"absent"):
            m.validate_owner_report(d)

    def test_modified_nm_hash_fails_closed(self):
        with self.assertRaisesRegex(m.CrosswalkError,"SHA256"):
            m.read_symbols(nm())

    def test_exact_label_match_reports_only_recovered_label(self):
        src=nm()
        with patch.object(m,"ORIGINAL_NM_SHA",hashlib.sha256(src).hexdigest()):
            by,addr=m.read_symbols(src,hashlib.sha256(src).hexdigest())
        o=m.symbol_match(TARGETS[0],by,addr)
        self.assertEqual(o["status"],"EXACT_RECOVERED_TEXT_LABEL")
        self.assertEqual(o["labels"],["symbol_0"])
        self.assertFalse(o["calleeCompilerFunctionIdentityVerified"])

    def test_interior_code_address_is_not_exact_symbol(self):
        by={BASE:["lower"],BASE+0x100:["upper"]}
        o=m.symbol_match(hex(BASE+0x40),by,sorted(by))
        self.assertEqual(o["status"],"INTERIOR_OF_RECOVERED_TEXT_INTERVAL_UNPROVEN")
        self.assertEqual(o["offsetFromLowerLabel"],64)
        self.assertFalse(o["calleeCompilerFunctionIdentityVerified"])

    def test_lack_of_bracketing_symbol_has_no_candidate(self):
        by={BASE:["_text"]}
        o=m.symbol_match(hex(BASE+0x400),by,sorted(by))
        self.assertEqual(o["status"],"NO_SAFE_TEXT_SYMBOL_BOUND")

    def test_exact_aliases_are_not_arbitrarily_discarded(self):
        by={BASE:["same","alias"]}
        o=m.symbol_match(hex(BASE),by,[BASE])
        self.assertEqual(o["labels"],["same","alias"])

    def test_full_summary_preserves_uncertainty(self):
        d=fixture()
        raw=nm()
        with patch.object(m,"ORIGINAL_NM_SHA",hashlib.sha256(raw).hexdigest()):
            d["recoveredNmSha256"]=m.ORIGINAL_NM_SHA
            r=m.crosswalk(d,raw)
        self.assertEqual(r["callsites"],41)
        self.assertEqual(r["uniqueDestinations"],21)
        self.assertFalse(r["callArgumentPointerDataflowVerified"])
        self.assertFalse(r["rootOrKernelSuVerified"])

    def test_cli_imports_from_external_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            x=subprocess.run([sys.executable,"-I",str(Path(m.__file__).resolve()),"--help"],
                             cwd=d,text=True,capture_output=True,timeout=15)
        self.assertEqual(x.returncode,0,x.stderr)
        self.assertIn("--report",x.stdout)

if __name__=="__main__":
    unittest.main()
