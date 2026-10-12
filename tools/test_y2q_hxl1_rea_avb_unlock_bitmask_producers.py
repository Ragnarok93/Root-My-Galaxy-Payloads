#!/usr/bin/env python3
"""Synthetic original HXL1 0x67dd8 bitmask, root xrefs, and read-only query gates."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_unlock_bitmask_producers as mod
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def ins(entry,count,pins=()):
    all_ops={hex(int(entry,16)+4*i):("nop","") for i in range(count)}
    for a,m,o in pins:
        assert a in all_ops,(entry,a)
        all_ops[a]=(m,o)
    return evidence_obj("a"*64,"read_function_instructions","procedure",entry,[
        addr+": "+m+(" "+ops if ops else "")
        for addr,(m,ops) in all_ops.items()
    ])


def selector():
    return ins(mod.DECISION,18,mod.DECISION_PINS)


def main():
    return ins(mod.MAIN,569,mod.ENTRY_PINS)


BOOT_PSEUDO="""ulonglong FUN_000182d0(void) {
 i=FUN_0002cae8(&local_34);
 if (FUN_00060bd8() != 0) {
   FUN_000674d8();
 }
 return 0;
}"""


def source(entry,pseudo=None):
    return evidence_obj("a"*64,"analyze_function","procedure",entry,{
        "procedure":{
            "address":entry,"name":"FUN_"+entry[2:].zfill(8),
            "body":{"available":True,"ranges":[
                {"start":entry,"end":hex(int(entry,16)+0x1000)}
            ]},
        },
        "pseudocode":pseudo if pseudo is not None else
          ("int FUN_test(void) {\n  int r=FUN_00012340();\n  return r;\n}"),
        "native_value_flow":{"available":True},
    })


def prior():
    return {
        "sourceAttested":True,
        "mainUnlockSelection":{
            "entry":"0x17d8","selectorFunction":"0x67dd8",
            "inputToSelector":"0x4","nativeSelectorBranchVerified":True,
            "nonzeroResultDirectTarget":"0x34238",
            "zeroResultDirectTarget":"0x34370",
            "nativeEvidenceId":main()["evidence_id"],
        },
        "boundaryHelpers":[
            {
                "entry":entry,
                "function":{"sourceEvidenceId": source(
                    entry,BOOT_PSEUDO if entry=="0x182d0" else None)["evidence_id"]},
                "native":{"nativeEvidenceId": selector()["evidence_id"]
                          if entry==mod.DECISION else "ev_dummy"},
            }
            for entry in ("0x67dd8","0x1e5f0","0x182d0")
        ],
    }


def write_original(folder):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/"instructions-state-boundary-0x67dd8.json").write_text(json.dumps(selector()))
    (folder/"instructions-route-owner-0x17d8.json").write_text(json.dumps(main()))
    (folder/"function-state-boundary-0x182d0.json").write_text(
        json.dumps(source("0x182d0",BOOT_PSEUDO)))


class BitmaskSourceTests(unittest.TestCase):
    def test_original_boolean_return_and_mask4(self):
        x=mod.bitmask_native(selector(),mod.assert_prior(prior())["0x67dd8"])
        self.assertEqual(x["globalAddress"],"0x3651ec")
        self.assertEqual(x["globalWidthBits"],32)
        self.assertEqual(x["specificResult"],"(uint32_at_0x3651ec & 4) != 0")
        self.assertTrue(x["normalReturnFlowVerified"])
        self.assertFalse(x["originOfGlobalBitsProven"])
        self.assertFalse(x["secureStatePolicyProven"])

    def test_modified_native_adrp_load_or_CSET_rejected(self):
        for old,new in (
            ("0x67de4: adrp x9,0x365000","0x67de4: adrp x9,0x364000"),
            ("0x67df8: ldr w8,[x9,#0x1ec]","0x67df8: ldr w8,[x9,#0x1e8]"),
            ("0x67e04: cset w0,ne","0x67e04: cset w0,eq"),
            ("0x67e18: ret","0x67e18: nop"),
        ):
            ev=selector()
            ev["normalized_result"]=[s.replace(old,new) for s in ev["normalized_result"]]
            with self.subTest(old=old),self.assertRaises(TriageError):
                mod.bitmask_native(ev,mod.assert_prior(prior())["0x67dd8"])

    def test_main_preselector_and_unlocked_route_verified_not_authority(self):
        x=mod.verify_entry_native(main(),prior())
        self.assertEqual(x["preSelectionFunction"],"0x68f18")
        self.assertEqual(x["maskValue"],4)
        self.assertFalse(x["preSelectionWriterOfGlobalVerified"])
        self.assertFalse(x["entryAuthorizationVerified"])
        ev=main()
        ev["normalized_result"]=[s.replace(
            "0x1b44: b.eq 0x00001db0","0x1b44: b.ne 0x00001db0")
            for s in ev["normalized_result"]]
        with self.assertRaisesRegex(TriageError,"0x1b44"):
            mod.verify_entry_native(ev,prior())

    def test_interactive_different_boot_selection_path(self):
        p=mod.assert_prior(prior())
        out=mod.verify_interactive_link(source("0x182d0",BOOT_PSEUDO),p["0x182d0"])
        self.assertEqual(out["bootModeCallsUnlockConfirmation"],"0x674d8")
        self.assertFalse(out["interactiveEntryPermissionEstablished"])
        ev=source("0x182d0",BOOT_PSEUDO.replace("FUN_00060bd8","FUN_00060bdc"))
        with self.assertRaisesRegex(TriageError,"interactive source marker"):
            mod.verify_interactive_link(ev,p["0x182d0"])

    def test_inconsistent_prior_rejected_early(self):
        p=prior()
        p["mainUnlockSelection"]["nonzeroResultDirectTarget"]="0x34370"
        with self.assertRaisesRegex(TriageError,"main unlock/relock selector changed"):
            mod.assert_prior(p)
        p=prior()
        p["boundaryHelpers"].pop()
        with self.assertRaisesRegex(TriageError,"helper evidence incomplete"):
            mod.assert_prior(p)

    def test_six_queries_planned_no_original_ghidra(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            write_original(root/"rea-security-audit"/"LinuxLoader")
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_boundary",return_value=prior()),\
                 mock.patch.object(mod,"choose_targets",return_value=[target]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("Ghidra executed in plan mode")):
                r=mod.audit(root)
        self.assertEqual(r["newQueries"],6)
        self.assertEqual(len(r["sourceXrefs"]),2)
        self.assertEqual(len(r["investigationHelpers"]),2)
        self.assertFalse(r["bit2SecurityAuthorizationVerified"])
        self.assertFalse(r["deviceModified"])

    def test_cached_queries_keep_original_evidence_and_zero_new_runs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            write_original(folder)
            for addr,_ in mod.SITES:
                x=evidence_obj("a"*64,"xrefs","address",addr,
                               ["0x1b34","0x1b48"])
                (folder/("xrefs-selector-root-"+addr+".json")).write_text(json.dumps(x))
            for entry,_ in mod.FUNCTIONS:
                f=source(entry)
                n=ins(entry,10)
                (folder/("function-selector-root-"+entry+".json")).write_text(json.dumps(f))
                (folder/("instructions-selector-root-"+entry+".json")).write_text(json.dumps(n))
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_boundary",return_value=prior()),\
                 mock.patch.object(mod,"choose_targets",return_value=[target]):
                r=mod.audit(root)
        self.assertEqual(r["newQueries"],0)
        self.assertEqual(r["sourceXrefs"][0]["xrefCount"],2)
        self.assertTrue(all(x["function"] and x["native"]
                            for x in r["investigationHelpers"]))
        self.assertFalse(r["trustedBootOrOdinSignatureAcceptanceVerified"])

    def test_no_device_flash_or_untrusted_execution(self):
        s=Path(mod.__file__).read_text()
        for unsafe in ("fastboot flash","heimdall flash","adb shell",
                       "subprocess.Popen(","os.system("):
            self.assertNotIn(unsafe,s)


if __name__=="__main__":
    unittest.main()
