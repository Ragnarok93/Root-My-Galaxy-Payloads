#!/usr/bin/env python3
"""Synthetic regression gates for original HXL1 direct vs OEM-checked unlock routes."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_oem_unlock_routes as routes
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


FUNCTION_TEXT={
    "0x2f538": """void FUN_0002f538(longlong param_1) {
        lVar3 = FUN_0000f44c(0x9a0);
        lVar4 = FUN_0002ae38(0,lVar3,0x9a0);
        mode = *(int*)(&DAT_000c08a0 + param_1*0x10);
        result = FUN_00033928(mode,1);
        return;
        }""",
    "0x34238": """longlong FUN_00034238(void) {
        x = DAT_00351055;
        if (x == 0) {
           result = FUN_00033928(0,1);
           log = "flash unlock Success..!!";
        }
        return result;
        }""",
    "0x34370": """longlong FUN_00034370(void) {
        x = DAT_00351055;
        if (x != 0) {
           result = FUN_00033928(0,0);
           log = "flash lock Success..!!";
        }
        return result;
        }""",
    "0x674d8": """void FUN_000674d8(void) {
        while (status) { status = FUN_0002cae8(); }
        flag = FUN_000608c8();
        if (flag == 0) {
           log = "Warning..!! OEM_UNLOCK flag is NOT set.";
        } else {
           result = FUN_00033928(0,1);
        }
        result2 = FUN_00033928(0,0);
        return;
        }""",
}


def function_ev(entry,site):
    return evidence_obj("a"*64,"analyze_function","procedure",site,{
        "procedure":{"address":entry,"name":"FUN_"+entry[2:].zfill(8),
                     "body":{"available":True,"ranges":[
                         {"start":entry,"end":hex(int(entry,16)+0x400)}]}},
        "pseudocode":FUNCTION_TEXT[entry]+"\n"+("\n".join("/* synthetic Ghidra context */" for _ in range(14))),
        "native_value_flow":{"available":True},
    })


def native_ev(entry):
    required=routes.NATIVE_PINS[entry]
    lines=[a+": "+m+" "+o for a,m,o in required]
    # Synthetic model keeps gaps outside the strict contiguous windows.
    for i in range(8):
        lines.append(hex(int(entry,16)+4*i)+": nop")
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        entry,lines)


def prior():
    rows=[]
    for site,entry in routes.OWNER_BY_SITE.items():
        ev=function_ev(entry,site)
        ni=native_ev(entry)
        rows.append({
            "site":site,"directBLToParent":True,
            "native":{"nativeInstruction":"bl 0x00033928"},
            "containingFunction":{
                "containingFunction":entry,"originalEvidenceId":ev["evidence_id"]},
            "ownerNative":{"owner":entry,"nativeBLVerified":True,
                           "evidenceId":ni["evidence_id"]},
        })
    return {"sourceAttested":True,"originalXrefCount":5,"sites":rows}


def write_provenance(folder:Path):
    for site,entry in routes.OWNER_BY_SITE.items():
        (folder/("function-upstream-"+site+".json")).write_text(
            json.dumps(function_ev(entry,site)))
    for entry in routes.OWNERS:
        (folder/("instructions-upstream-owner-"+entry+".json")).write_text(
            json.dumps(native_ev(entry)))


class Hxl1OemRoutesTests(unittest.TestCase):
    def test_five_sites_four_verified_owners(self):
        got=routes.attested_owner_inventory(prior())
        self.assertEqual(len(got),5)
        changed=prior()
        changed["sites"][0]["containingFunction"]["containingFunction"]="0x2f540"
        with self.assertRaisesRegex(TriageError,"owner not verified|owning function"):
            routes.attested_owner_inventory(changed)
        changed=prior()
        changed["sites"][1]["directBLToParent"]=False
        with self.assertRaisesRegex(TriageError,"Unexpected original mode-dispatcher caller|BL not verified"):
            routes.attested_owner_inventory(changed)

    def test_four_original_route_native_argument_sequences(self):
        for entry in routes.OWNERS:
            p=routes.NATIVE_PINS[entry]
            obj=native_ev(entry)
            ins=routes.parse_instructions(obj,entry)
            for addr,m,o in p:
                routes.exact_instruction(ins,addr,m,o)

    def test_modified_oem_gate_and_direct_call_rejected(self):
        ev=native_ev("0x674d8")
        ev["normalized_result"]=[
            x.replace("0x67634: cbz w0,0x000676f4",
                      "0x67634: cbnz w0,0x000676f4")
            for x in ev["normalized_result"]]
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            write_provenance(folder)
            (folder/"instructions-upstream-owner-0x674d8.json").write_text(
                json.dumps(ev))
            p=prior()
            # Pin modified evidence ID, not the original, to reach opcode gate.
            for item in p["sites"]:
                if item["containingFunction"]["containingFunction"]=="0x674d8":
                    item["ownerNative"]["evidenceId"]=ev["evidence_id"]
            with self.assertRaisesRegex(TriageError,"0x67634"):
                routes.verify_cached_routes(p,folder,"a"*64)
        ev=native_ev("0x34238")
        ev["normalized_result"]=[
            x.replace("0x342e0: bl 0x00033928",
                      "0x342e0: bl 0x00033920")
            for x in ev["normalized_result"]]
        with self.assertRaisesRegex(TriageError,"0x342e0"):
            ins=routes.parse_instructions(ev,"0x34238")
            routes.exact_instruction(ins,"0x342e0","bl","0x00033928")

    def test_unproven_caller_reachability_never_elevated(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            write_provenance(folder)
            good=routes.verify_cached_routes(prior(),folder,"a"*64)
        self.assertEqual(len(good),4)
        self.assertEqual(good[1]["owner"],"0x34238")
        self.assertEqual(good[2]["owner"],"0x34370")
        self.assertTrue(all(not x["callerAuthorizationEstablished"]
                            and not x["allPathDominanceEstablished"] for x in good))

    def test_helper_pseudocode_keeps_trust_unknown(self):
        ev=evidence_obj("a"*64,"analyze_function","procedure","0x608c8",{
            "procedure":{"address":"0x608c8","name":"FUN_000608c8",
                         "body":{"available":True,"ranges":[
                             {"start":"0x608c8","end":"0x60920"}]}},
            "pseudocode":"int FUN_000608c8(void) { return DAT_00090801; }",
            "native_value_flow":{"available":True},
        })
        f=routes.original_oem_predicate(ev)
        self.assertEqual(f["globalRefs"],["DAT_00090801"])
        self.assertFalse(f["secureAuthorityProven"])
        bad=dict(ev)
        bad["normalized_result"]=dict(ev["normalized_result"])
        bad["normalized_result"]["procedure"]=dict(
            ev["normalized_result"]["procedure"])
        bad["normalized_result"]["procedure"]["address"]="0x608cc"
        with self.assertRaisesRegex(TriageError,"does not own|owner mismatch"):
            routes.original_oem_predicate(bad)

    def test_four_xref_and_three_predicate_queries_plan_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            write_provenance(folder)
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi",
                               "a"*64,{})
            with mock.patch.object(routes,"verify_upstream",return_value=prior()),\
                 mock.patch.object(routes,"choose_targets",return_value=[target]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No host process")):
                report=routes.audit(root)
        self.assertEqual(report["newQueries"],7)
        self.assertEqual(len(report["routeCallerXrefs"]),4)
        self.assertIsNone(report["oemPredicate"])
        self.assertFalse(report["unrestrictedDirectUnlockReachableProven"])
        self.assertFalse(report["protectedOemAuthorizationProven"])
        self.assertFalse(report["secureBootOrFlashPolicyBypassProven"])
        self.assertFalse(report["deviceModified"])

    def test_cached_one_reference_reduces_planned_work(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            write_provenance(folder)
            ref=evidence_obj("a"*64,"xrefs","address","0x34238",
                             ["0x40010","0x40020"])
            (folder/"xrefs-route-0x34238.json").write_text(json.dumps(ref))
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi",
                               "a"*64,{})
            with mock.patch.object(routes,"verify_upstream",return_value=prior()),\
                 mock.patch.object(routes,"choose_targets",return_value=[target]):
                report=routes.audit(root)
        self.assertEqual(report["newQueries"],6)
        self.assertEqual(report["routeCallerXrefs"][1]["total"],2)

    def test_scripts_contain_no_phone_flash_commands(self):
        src=Path(routes.__file__).read_text()
        for fragment in ("fastboot flash","heimdall flash","adb shell",
                         "subprocess.Popen(", "os.system("):
            self.assertNotIn(fragment,src)


if __name__=="__main__":
    unittest.main()
