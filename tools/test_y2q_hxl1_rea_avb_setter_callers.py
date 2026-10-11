#!/usr/bin/env python3
"""Synthetic, fail-closed AVB state-setter callsite provenance tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_setter_callers as caller
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def prior():
    return {
        "sourceAttested":True,"globalAddress":"0x351055",
        "storageHelperPseudocode":{"entry":"0x2ae38"},
        "storageHelperNative":{"instructionCount":50},
        "functionXrefs":[
            {"function":fn,"sites":list(sites),"evidenceId":"ev_test"}
            for fn,sites in caller.SITES.items()
        ],
    }


def instruction(site, target, asm=None, *, status="decoded", mnemonic="bl"):
    if asm is None:
        asm="bl "+target
    return evidence_obj("a"*64,"inspect_native_instruction","address",site,{
        "address":site,"status":status,"mnemonic":mnemonic,
        "raw_disassembly":asm,"procedure":"0x33900",
    })


def containing(site, entry="0x33900"):
    return evidence_obj("a"*64,"analyze_function","procedure",site,{
        "procedure":{"address":entry,"name":"FUN_original",
                     "body":{"available":True,"ranges":[{
                         "start":entry,"end":"0x33bd0",
                     }]}},
        "pseudocode":"\n".join([
            "void FUN_original(void) {",
            "  int desired=FUN_0001a000();",
            "  if (desired != 0) {",
            "    FUN_00033c88(1);",
            "  } else { FUN_00033c88(0); }",
            "}",
        ]),
        "native_value_flow":{"available":True},
    })


class CallerAttributionTests(unittest.TestCase):
    def test_exact_two_setter_and_three_initializer_site_inventory(self):
        caller.verified_original_xrefs(prior())
        p=prior()
        p["functionXrefs"][0]["sites"].append("0x33b28")
        with self.assertRaisesRegex(TriageError,"inventory changed"):
            caller.verified_original_xrefs(p)
        p=prior()
        p["functionXrefs"][0]["evidenceId"]=None
        with self.assertRaisesRegex(TriageError,"Evidence ID"):
            caller.verified_original_xrefs(p)

    def test_native_direct_branch_classified_not_authorized(self):
        site="0x33a08"
        a=caller.inspect_xref(instruction(site,"0x33c88"),site,"0x33c88")
        self.assertTrue(a["directBranchToTarget"])
        self.assertEqual(a["directBranchMnemonic"],"bl")
        self.assertFalse(a["setterCallerAuthorizationProven"])
        self.assertFalse(a["observedSourceW0Value"])
        b=caller.inspect_xref(
            instruction(site,"0x33c88","adrp x8,0x33000",mnemonic="adrp"),
            site,"0x33c88")
        self.assertFalse(b["directBranchToTarget"])
        self.assertIsNone(b["directBranchMnemonic"])

    def test_invalid_mnemonic_or_wrong_instruction_address_rejected(self):
        ev=instruction("0x33a08","0x33c88")
        with self.assertRaisesRegex(TriageError,"coordinate"):
            caller.inspect_xref(ev,"0x33a0c","0x33c88")
        ev["normalized_result"]["mnemonic"]="b"
        with self.assertRaisesRegex(TriageError,"mnemonic differs"):
            caller.inspect_xref(ev,"0x33a08","0x33c88")

    def test_false_other_direct_call_stays_unknown(self):
        ev=instruction("0x33b20","0x33c88",
                       "bl 0x0001e81c")
        out=caller.inspect_xref(ev,"0x33b20","0x33c88")
        self.assertFalse(out["directBranchToTarget"])
        self.assertEqual(out["otherBranchDestination"],"0x1e81c")

    def test_caller_source_preserves_unresolved_W0_value(self):
        got=caller.source_caller(containing("0x33a08"),"0x33a08")
        self.assertEqual(got["entry"],"0x33900")
        self.assertEqual(len(got["setterCallLineCandidates"]),2)
        self.assertFalse(got["argumentW0NativeDefinitionVerified"])
        with self.assertRaisesRegex(TriageError,"does not own"):
            caller.source_caller(containing("0x33a08"),"0x33c88")

    def test_plan_mode_has_five_bounded_queries_and_no_ghidra_launch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(caller,"verify_persistence",return_value=prior()),\
                 mock.patch.object(caller,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("Not an execute request")):
                report=caller.audit(root)
        self.assertEqual(report["requestedQueries"],5)
        self.assertEqual(report["originalStorageDispatcher"],"0x2ae38")
        self.assertEqual(len(report["directNativeSites"]),5)
        self.assertFalse(report["setterW0InputAuthorityVerified"])
        self.assertFalse(report["bootloaderUnlockProven"])
        self.assertFalse(report["deviceModified"])

    def test_cached_direct_setter_calls_collect_only_matching_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            for fn,sites in caller.SITES.items():
                for site in sites:
                    if site=="0x33a08":
                        ev=instruction(site,fn,"bl 0x00033c88")
                    elif site=="0x33b20":
                        ev=instruction(site,fn,"ldr x8,[x20,#0x8]",mnemonic="ldr")
                    else:
                        ev=instruction(site,fn,"bl 0x00033da8")
                    (folder/("instruction-caller-"+site+".json")).write_text(
                        json.dumps(ev))
            (folder/"function-caller-0x33a08.json").write_text(
                json.dumps(containing("0x33a08")))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(caller,"verify_persistence",return_value=prior()),\
                 mock.patch.object(caller,"choose_targets",return_value=[t]):
                report=caller.audit(root)
        self.assertEqual(report["requestedQueries"],0)
        self.assertTrue(report["directNativeSites"][0]["native"]["directBranchToTarget"])
        self.assertIsNotNone(report["directNativeSites"][0]["callerFunction"])
        self.assertFalse(report["directNativeSites"][1]["native"]["directBranchToTarget"])
        self.assertIsNone(report["directNativeSites"][1]["callerFunction"])

    def test_source_contains_no_firmware_execution_device_tools(self):
        text=Path(caller.__file__).read_text()
        for unsafe in ("fastboot flash","heimdall flash","adb shell",
                       "subprocess.Popen(","os.system("):
            self.assertNotIn(unsafe,text)


if __name__=="__main__":
    unittest.main()
