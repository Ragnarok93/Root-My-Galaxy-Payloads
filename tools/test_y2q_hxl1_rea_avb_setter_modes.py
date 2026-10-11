#!/usr/bin/env python3
"""Synthetic regression of HXL1 original 0x33928 two-setter mode/byte paths."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_setter_modes as modes
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


PSEUDO = "\n".join([
    "longlong FUN_00033928(int param_1,uint param_2)",
    "{",
    "  if (param_1 == 0) {",
    "    FUN_00033c88(param_2);",
    "  }",
    "  if (param_1 == 1) {",
    '    FUN_00039818("IsUnlockCritical",DAT_00351056);',
    "    if (param_2 != 0) {",
    "      DAT_00351056._0_1_ = (byte)param_2;",
    "      FUN_0002ae38(1,&DAT_00351048,0x9a0);",
    "    }",
    "  }",
    '  msg = "recovery\\n--wipe_data\\n--reason=MasterClearConfirm";',
    "  bVar1 = (param_2 & 0xff) == 0;",
    "  FUN_00033c88(bVar1);",
    *("  if (param_1) { z = 1; }" for _ in range(24)),
    "  return 0;",
    "}",
])


def parent_function(site="0x33a08",pseudo=PSEUDO):
    return evidence_obj("a"*64,"analyze_function","procedure",site,{
        "procedure":{
            "address":"0x33928","name":"FUN_00033928",
            "body":{"available":True,"ranges":[{
                "start":"0x33928","end":"0x33b5c"
            }]},
        },
        "pseudocode":pseudo,"native_value_flow":{"available":True},
    })


def native_owner():
    lines = [
        f"{a}: {op} {args}".rstrip()
        for a,op,args in modes.REQUIRED_NATIVE
    ]
    extra = [
        f"{hex(0x33b24+4*i)}: nop" for i in range(60)
    ]
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        "0x33928",lines+extra)


def prior():
    return {
        "sourceAttested":True,
        "directNativeSites":[{
            "site":site,
            "native":{"directBranchToTarget":True,"directBranchMnemonic":"bl"},
            "callerFunction":{"entry":"0x33928"},
            "callerNative":{"owner":"0x33928","exactSetterBranchVerified":True},
        } for site in modes.CALLS],
    }


class Hxl1SetterModesTests(unittest.TestCase):
    def test_native_argument_modes_and_critical_byte_are_separated(self):
        n=modes.verify_two_setter_paths(native_owner())
        self.assertEqual(n["firstCallSite"],"0x33a08")
        self.assertEqual(n["secondCallSite"],"0x33b20")
        self.assertEqual(n["criticalByte"],"0x351056")
        self.assertEqual(n["normalByte"],"0x351055")
        self.assertTrue(n["callerSuppliedW1InputObserved"])
        self.assertFalse(n["interproceduralX21PreservationVerified"])
        self.assertFalse(n["upstreamCommandAuthorizationVerified"])

    def test_modified_critical_byte_store_or_cset_fails_closed(self):
        ev=native_owner()
        ev["normalized_result"]=[
            line.replace("0x33a24: cset w21, eq","0x33a24: cset w21, ne")
            for line in ev["normalized_result"]
        ]
        with self.assertRaisesRegex(TriageError,"0x33a24"):
            modes.verify_two_setter_paths(ev)
        ev=native_owner()
        ev["normalized_result"]=[
            line.replace("0x339c8: strb w21, [x1,#0xe]",
                         "0x339c8: strb w21, [x1,#0xd]")
            for line in ev["normalized_result"]
        ]
        with self.assertRaisesRegex(TriageError,"0x339c8"):
            modes.verify_two_setter_paths(ev)

    def test_local_argument_chain_rejects_unknown_instruction(self):
        ev=native_owner()
        ev["normalized_result"].append("0x33a06: mov w0, wzr")
        with self.assertRaisesRegex(TriageError,"inserted"):
            modes.verify_two_setter_paths(ev)

    def test_pseudocode_attests_distinct_critical_flag_and_wipe_string(self):
        p=modes.verified_parent_function(parent_function(),"0x33a08")
        self.assertEqual(p["entry"],"0x33928")
        self.assertTrue(p["pseudocodeSha256"])
        self.assertFalse(p["authorizationVerified"])
        ev=parent_function(pseudo=PSEUDO.replace("IsUnlockCritical","FakeFlag"))
        with self.assertRaisesRegex(TriageError,"setter, critical byte or wipe"):
            modes.verified_parent_function(ev,"0x33a08")

    def test_wrong_parent_function_rejected(self):
        ev=parent_function()
        ev["normalized_result"]["procedure"]["address"]="0x33800"
        with self.assertRaisesRegex(TriageError,"not function 0x33928"):
            modes.verified_parent_function(ev,"0x33a08")

    def test_bounded_plan_adds_one_original_xrefs_query(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            for site in modes.CALLS:
                (folder/("function-caller-"+site+".json")).write_text(
                    json.dumps(parent_function(site)))
            (folder/modes.NATIVE_EVIDENCE).write_text(json.dumps(native_owner()))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(modes,"verify_setter_callers",return_value=prior()),\
                 mock.patch.object(modes,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("REA must not run")):
                result=modes.audit(root)
        self.assertEqual(result["newQueries"],1)
        self.assertEqual(result["parentXrefCount"],0)
        self.assertFalse(result["callerOwnersAndSourceArgumentsVerified"])
        self.assertFalse(result["criticalUnlockAuthorizationProven"])
        self.assertFalse(result["bootloaderUnlockDemonstrated"])
        self.assertIn("mode-zero",modes.markdown(result))

    def test_cache_preserves_provenance_and_no_new_rea_query(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            for site in modes.CALLS:
                (folder/("function-caller-"+site+".json")).write_text(
                    json.dumps(parent_function(site)))
            (folder/modes.NATIVE_EVIDENCE).write_text(json.dumps(native_owner()))
            refs=evidence_obj("a"*64,"xrefs","address","0x33928",
                              ["0x1010","0x2020"])
            (folder/"xrefs-parent-0x33928.json").write_text(json.dumps(refs))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(modes,"verify_setter_callers",return_value=prior()),\
                 mock.patch.object(modes,"choose_targets",return_value=[t]):
                result=modes.audit(root)
        self.assertEqual(result["newQueries"],0)
        self.assertEqual(result["parentXrefSites"],["0x1010","0x2020"])

    def test_inconsistent_synthetic_caller_pseudocode_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            (folder/"function-caller-0x33a08.json").write_text(
                json.dumps(parent_function("0x33a08")))
            changed=PSEUDO.replace("int param_1,uint param_2",
                                    "int param_1, uint param_2")
            (folder/"function-caller-0x33b20.json").write_text(
                json.dumps(parent_function("0x33b20",changed)))
            (folder/modes.NATIVE_EVIDENCE).write_text(json.dumps(native_owner()))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(modes,"verify_setter_callers",return_value=prior()),\
                 mock.patch.object(modes,"choose_targets",return_value=[t]):
                with self.assertRaises(TriageError):
                    modes.audit(root)

    def test_no_device_flash_or_phone_actions(self):
        s=Path(modes.__file__).read_text()
        for forbidden in ("fastboot flash","heimdall flash","adb shell",
                          "os.system(", "subprocess.Popen("):
            self.assertNotIn(forbidden,s)


if __name__=="__main__":
    unittest.main()
