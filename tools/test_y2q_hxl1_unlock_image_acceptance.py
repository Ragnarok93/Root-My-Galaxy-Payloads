#!/usr/bin/env python3
"""Synthetic HXL1 Odin/LinuxLoader image acceptance original-Ghidra evidence gates."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_unlock_image_acceptance as mod
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def function(name,site,entry,text):
    pseudo=(
        f"int FUN_{entry[2:].zfill(8)}(void) {{\n"
        " int result = FUN_00001234();\n"
        " if (result != 0) {\n"
        f'  Print("{text}");\n'
        "  result=1;\n"
        " }\n"
        " return result;\n"
        "}\n"
    )
    return evidence_obj(
        "a"*64,"analyze_function","procedure",site,{
            "procedure":{"address":entry,"name":"FUN_"+entry[2:].zfill(8),
                         "body":{"available":True,"ranges":[{
                             "start":min(site,entry,key=lambda x:int(x,16)),
                             "end":hex(max(int(site,16),int(entry,16))+0x500),
                         }]}},
            "pseudocode":pseudo,"native_value_flow":{"available":True},
        },
    )


def ins(entry,name):
    rows=[f"{hex(int(entry,16)+i*4)}: nop" for i in range(125)]
    if name=="LinuxLoader":
        rows[5]=f"{hex(int(entry,16)+20)}: bl 0x000039dc"
    return evidence_obj("a"*64,"read_function_instructions","procedure",entry,rows)


def cached(root,with_native=False):
    top=root/"rea-security-audit"
    for name,_,site,entry,word in mod.TARGETS:
        folder=top/name
        folder.mkdir(parents=True,exist_ok=True)
        (folder/("function-"+site+".json")).write_text(
            json.dumps(function(name,site,entry,word)))
        if with_native:
            (folder/("instructions-unlock-acceptance-"+entry+".json")).write_text(
                json.dumps(ins(entry,name)))


class Hxl1AcceptanceRootTests(unittest.TestCase):
    def test_saved_original_source_requires_correct_owner_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cached(root)
            for name,seed,site,entry,word in mod.TARGETS:
                target=base.Target(name,root/"fake.efi","a"*64,{})
                case=mod.exact_saved_case(root,target,seed,site,entry,word)
                self.assertEqual(case["nativeEntry"],entry)
                self.assertTrue(case["verifiedDiagnosticReference"])
                self.assertFalse(case["actualImageSignatureAuthorizationProven"])
            name,seed,site,entry,word=mod.TARGETS[0]
            folder=root/"rea-security-audit"/name
            path=folder/("function-"+site+".json")
            altered=function(name,site,entry,word.replace("Skipping","Not skipping"))
            path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(TriageError,"diagnostic disappeared"):
                mod.exact_saved_case(
                    root,base.Target(name,root/"fake.efi","a"*64,{}),
                    seed,site,entry,word)

    def test_native_context_is_not_dominance_or_signature_bypass(self):
        entry="0x3f54"
        native=mod.native_case(ins(entry,"LinuxLoader"),entry,"0x40f0")
        self.assertTrue(native["referencedStringInstructionPresent"])
        self.assertFalse(native["exactOwnerStringBranchProven"])
        self.assertFalse(native["imageSignatureAcceptanceFromNativeProven"])
        entry="0x1b6a8"
        out=mod.native_case(ins(entry,"Odin"),entry,"0x1b3d4")
        self.assertFalse(out["referencedStringInstructionPresent"])
        self.assertEqual(out["nativeInstructionCount"],125)

    def test_plan_only_does_not_run_ghidra_and_emits_two_queries(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cached(root)
            targets=[base.Target(name,root/("fake-"+name+".efi"),"a"*64,{})
                     for name,_,_,_,_ in mod.TARGETS]
            with mock.patch.object(mod,"verify_strings_and_xrefs",return_value={
                  "allFiveReferencesVerified":True,"qualifiedFunctionReferences":5,
                 }),\
                 mock.patch.object(mod,"choose_targets",return_value=targets),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("Host Ghidra executed")):
                out=mod.audit(root)
            self.assertEqual(out["newQueries"],2)
            self.assertTrue(out["sourceAttested"])
            self.assertTrue(all(x["originalNative"] is None for x in out["acceptanceRoots"]))
            self.assertFalse(out["imageExecutionAuthorizationControlledByWritableFlagProven"])
            self.assertFalse(out["bootloaderUnlockProven"])
            self.assertFalse(out["deviceModified"])

    def test_complete_caches_reuse_without_new_queries(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cached(root,with_native=True)
            targets=[base.Target(name,root/("fake-"+name+".efi"),"a"*64,{})
                     for name,_,_,_,_ in mod.TARGETS]
            with mock.patch.object(mod,"verify_strings_and_xrefs",return_value={
                  "allFiveReferencesVerified":True,"qualifiedFunctionReferences":5,
                 }),\
                 mock.patch.object(mod,"choose_targets",return_value=targets):
                out=mod.audit(root)
            self.assertEqual(out["newQueries"],0)
            self.assertEqual(len(out["acceptanceRoots"]),2)
            self.assertTrue(all(x["originalNative"] for x in out["acceptanceRoots"]))
            self.assertIn("LinuxLoader",mod.markdown(out))
            self.assertIn("Odin",mod.markdown(out))

    def test_bad_upstream_security_seed_chain_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cached(root)
            with mock.patch.object(mod,"verify_strings_and_xrefs",return_value={
                 "allFiveReferencesVerified":False,"qualifiedFunctionReferences":4,
                }):
                with self.assertRaisesRegex(TriageError,"five literal"):
                    mod.audit(root)

    def test_wrong_native_ghidra_query_stops(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cached(root,with_native=True)
            f=root/"rea-security-audit"/"Odin"/"instructions-unlock-acceptance-0x1b6a8.json"
            ev=json.loads(f.read_text())
            ev["parameters"]["procedure"]="0x1b6ac"
            f.write_text(json.dumps(ev))
            targets=[base.Target(name,root/("fake-"+name+".efi"),"a"*64,{})
                     for name,_,_,_,_ in mod.TARGETS]
            with mock.patch.object(mod,"verify_strings_and_xrefs",return_value={
                  "allFiveReferencesVerified":True,"qualifiedFunctionReferences":5,
                 }),\
                 mock.patch.object(mod,"choose_targets",return_value=targets):
                with self.assertRaisesRegex(TriageError,"provenance mismatch"):
                    mod.audit(root)

    def test_no_device_write_flash_or_firmware_patch_commands(self):
        src=Path(mod.__file__).read_text()
        for s in ("adb shell","fastboot flashing unlock",
                  "heimdall flash","subprocess.Popen(","os.system("):
            self.assertNotIn(s,src)


if __name__=="__main__":
    unittest.main()
