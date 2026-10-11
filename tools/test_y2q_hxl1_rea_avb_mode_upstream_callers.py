#!/usr/bin/env python3
"""Synthetic tests for exact original HXL1 mode-dispatcher upstream callsites."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_mode_upstream_callers as upstream
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def prior():
    return {
        "sourceAttested":True,"parentXrefEvidenceId":"ev_parent",
        "parentXrefCount":5,"parentXrefsTruncated":False,
        "parentXrefSites":list(upstream.ORIGINAL_XREF_SITES),
        "originalNativeArgumentPaths":{"entry":"0x33928"},
    }


def original_ref(site, opcode="bl 0x00033928", mnemonic="bl"):
    return evidence_obj("a"*64,"inspect_native_instruction","address",site,{
        "address":site, "status":"decoded","mnemonic":mnemonic,
        "raw_disassembly":opcode,"procedure":"0x2f580",
    })


def function_at_site(site="0x2f604",entry="0x2f580"):
    return evidence_obj("a"*64,"analyze_function","procedure",site,{
        "procedure":{
            "address":entry,"name":"FUN_"+entry[2:].zfill(8),
            "body":{"available":True,"ranges":[
                {"start":entry,"end":hex(int(entry,16)+0x130)},
            ]},
        },
        "pseudocode":"\n".join([
            "void FUN_0002f580(int mode, int value) {",
            "  uVar1 = FUN_00012340();",
            "  if (uVar1 != 0) {",
            "    FUN_00033928(mode,value);",
            "  }",
            "  return;",
            "}",
        ]),
        "native_value_flow":{"available":True},
    })


def owner_native(site="0x2f604",entry="0x2f580"):
    addr=int(site,16)
    return evidence_obj("a"*64,"read_function_instructions","procedure",entry,[
        f"{hex(addr-24)}: mov w19, w0",
        f"{hex(addr-20)}: mov w20, w1",
        f"{hex(addr-16)}: bl 0x0001e123",
        f"{hex(addr-12)}: cbz w0, {hex(addr+4)}",
        f"{hex(addr-8)}: mov w0, w19",
        f"{hex(addr-4)}: mov w1, w20",
        f"{site}: bl 0x00033928",
        f"{hex(addr+4)}: ret",
    ])


class Hxl1UpstreamTests(unittest.TestCase):
    def test_exact_five_original_reference_inventory(self):
        v=upstream.verify_original_inventory(prior())
        self.assertEqual(v["sitesCount"],5)
        self.assertTrue(v["originalXrefsVerified"])
        modified=prior()
        modified["parentXrefSites"][4]="0x67644"
        with self.assertRaisesRegex(TriageError,"inventory inconsistent"):
            upstream.verify_original_inventory(modified)
        modified=prior()
        modified["parentXrefSites"].append("0x67640")
        with self.assertRaisesRegex(TriageError,"inventory inconsistent"):
            upstream.verify_original_inventory(modified)

    def test_native_BL_must_target_exact_parent(self):
        t=upstream.verify_native_reference(
            original_ref("0x2f604"),"0x2f604")
        self.assertTrue(t["directBLToParent"])
        self.assertFalse(t["upstreamAuthorityProven"])
        t=upstream.verify_native_reference(
            original_ref("0x2f604","bl 0x00033c88"),"0x2f604")
        self.assertFalse(t["directBLToParent"])
        self.assertEqual(t["observedBranchDestination"],"0x33c88")
        ev=original_ref("0x2f604")
        ev["normalized_result"]["mnemonic"]="b"
        with self.assertRaisesRegex(TriageError,"mnemonic"):
            upstream.verify_native_reference(ev,"0x2f604")

    def test_non_branch_never_claimed_as_call(self):
        ev=original_ref("0x342e0","ldr x0, [x19,#0x8]",mnemonic="ldr")
        t=upstream.verify_native_reference(ev,"0x342e0")
        self.assertFalse(t["directBLToParent"])
        self.assertIsNone(t["observedBranchDestination"])
        with self.assertRaisesRegex(TriageError,"coordinate mismatch"):
            upstream.verify_native_reference(ev,"0x343dc")

    def test_source_owner_and_native_argument_windows(self):
        f=upstream.analyze_owner_source(function_at_site(),"0x2f604")
        self.assertEqual(f["containingFunction"],"0x2f580")
        self.assertEqual(f["possibleParentCalls"],[4])
        self.assertFalse(f["sourceInputTrustVerified"])
        w=upstream.native_argument_window(
            owner_native(),"0x2f604","0x2f580")
        self.assertTrue(w["nativeBLVerified"])
        self.assertTrue(w["noControlFlowPathOrInterproceduralClobberProof"])
        self.assertFalse(w["nativeModeValueReachingDefinitionsProven"])
        self.assertEqual(w["potentialW0Writes"][-1]["address"],"0x2f5fc")
        self.assertEqual(w["potentialW1Writes"][-1]["address"],"0x2f600")

    def test_changed_native_call_target_fails_closed(self):
        ev=owner_native()
        ev["normalized_result"]=[
            x.replace("0x2f604: bl 0x00033928","0x2f604: bl 0x00033920")
            for x in ev["normalized_result"]
        ]
        with self.assertRaisesRegex(TriageError,"does not contain exact BL"):
            upstream.native_argument_window(ev,"0x2f604","0x2f580")

    def test_wrong_containing_function_rejected(self):
        ev=function_at_site()
        ev["normalized_result"]["procedure"]["address"]="0x2f900"
        with self.assertRaisesRegex(TriageError,"does not own"):
            upstream.analyze_owner_source(ev,"0x2f604")

    def test_plan_cannot_issue_unbounded_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            xrefs=evidence_obj("a"*64,"xrefs","address","0x33928",
                               list(upstream.ORIGINAL_XREF_SITES))
            (folder/"xrefs-parent-0x33928.json").write_text(json.dumps(xrefs))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            p=prior()
            p["parentXrefEvidenceId"]=xrefs["evidence_id"]
            with mock.patch.object(upstream,"verify_setter_modes",return_value=p),\
                 mock.patch.object(upstream,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No host process in plan")):
                result=upstream.audit(root)
        self.assertEqual(result["queriesRequested"],5)
        self.assertEqual(len(result["sites"]),5)
        self.assertTrue(all(not x["directBLToParent"] for x in result["sites"]))
        self.assertFalse(result["modeAndValueTrustedSourcesProven"])
        self.assertFalse(result["signatureOrOdinPolicyBypassProven"])
        self.assertFalse(result["deviceModified"])

    def test_cached_sites_add_only_two_dossiers_for_native_BL(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            xrefs=evidence_obj("a"*64,"xrefs","address","0x33928",
                               list(upstream.ORIGINAL_XREF_SITES))
            (folder/"xrefs-parent-0x33928.json").write_text(json.dumps(xrefs))
            for site in upstream.ORIGINAL_XREF_SITES:
                op="bl 0x00033928" if site=="0x2f604" else "ldr x8,[x0,#0x8]"
                mn="bl" if site=="0x2f604" else "ldr"
                ev=original_ref(site,op,mn)
                (folder/("instruction-upstream-"+site+".json")).write_text(json.dumps(ev))
            (folder/"function-upstream-0x2f604.json").write_text(
                json.dumps(function_at_site()))
            (folder/"instructions-upstream-owner-0x2f580.json").write_text(
                json.dumps(owner_native()))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            p=prior()
            p["parentXrefEvidenceId"]=xrefs["evidence_id"]
            with mock.patch.object(upstream,"verify_setter_modes",return_value=p),\
                 mock.patch.object(upstream,"choose_targets",return_value=[t]):
                result=upstream.audit(root)
        self.assertEqual(result["queriesRequested"],0)
        self.assertEqual(result["sites"][0]["containingFunction"]["containingFunction"],"0x2f580")
        self.assertTrue(result["sites"][0]["ownerNative"]["nativeBLVerified"])
        self.assertIsNone(result["sites"][1]["containingFunction"])
        self.assertFalse(result["allCallersReachableProven"])

    def test_incorrect_original_cached_xrefs_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            xrefs=evidence_obj("a"*64,"xrefs","address","0x33928",
                               ["0x2f604"])
            (folder/"xrefs-parent-0x33928.json").write_text(json.dumps(xrefs))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(upstream,"verify_setter_modes",return_value=prior()),\
                 mock.patch.object(upstream,"choose_targets",return_value=[t]):
                with self.assertRaisesRegex(TriageError,"Original saved Ghidra"):
                    upstream.audit(root)

    def test_source_contains_no_device_or_flash_commands(self):
        source=Path(upstream.__file__).read_text()
        for dangerous in ("fastboot flash","heimdall flash","adb shell",
                          "subprocess.Popen(", "os.system("):
            self.assertNotIn(dangerous,source)


if __name__=="__main__":
    unittest.main()
