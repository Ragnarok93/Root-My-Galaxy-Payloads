#!/usr/bin/env python3
"""Synthetic-only HXL1 original EMC BLGetStatus request/response source gates."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_emc_blgetstatus_provenance as mod
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


ORIGINAL_TEXT="""int FUN_00068810(int param_1,int param_2) {
 local_50 = param_2;
 iStack_4c = param_1;
 FUN_00067e20();
 FUN_000712b8(6,&DAT_00365210,&DAT_00365230);
 FUN_000715e8(DAT_00365228,1,&iStack_4c,2);
 FUN_000715e8(DAT_00365228,0x15,&local_50,4);
 FUN_0006d820(&DAT_00365210,0x20,&DAT_00365230);
 iVar4 = DAT_00365234;
 if (DAT_00365234 == 0) {
     iVar4 = 1;
 }
 return iVar4;
 /* synthetic local Ghidra context 1 */
 /* synthetic local Ghidra context 2 */
 /* synthetic local Ghidra context 3 */
 /* synthetic local Ghidra context 4 */
 /* synthetic local Ghidra context 5 */
 /* synthetic local Ghidra context 6 */
 /* synthetic local Ghidra context 7 */
 /* synthetic local Ghidra context 8 */
 /* synthetic local Ghidra context 9 */
 /* synthetic local Ghidra context 10 */
 /* synthetic local Ghidra context 11 */
 /* synthetic local Ghidra context 12 */
 /* synthetic local Ghidra context 13 */
 /* synthetic local Ghidra context 14 */
 /* synthetic local Ghidra context 15 */
 /* synthetic local Ghidra context 16 */
}"""


def fn(entry,source=None):
    return evidence_obj("a"*64,"analyze_function","procedure",entry,{
        "procedure":{"address":entry,"name":"FUN_"+entry[2:].zfill(8),
                     "body":{"available":True,"ranges":[{
                         "start":entry,"end":hex(int(entry,16)+0x900)}]}},
        "pseudocode":source if source is not None else
           "int FUN_test(int a) {\n  int b=FUN_00012340(a);\n  DAT_00365234=b;\n  return b;\n}",
        "native_value_flow":{"available":True},
    })


def native(entry):
    count=318 if entry==mod.ROOT else 45
    base_addr=int(entry,16)
    lines={hex(base_addr+4*i):"nop" for i in range(count)}
    if entry==mod.ROOT:
        for a,m,o in mod.BL_NATIVE:
            assert a in lines
            lines[a]=m+(" "+o if o else "")
    return evidence_obj("a"*64,"read_function_instructions","procedure",entry,
                        [a+": "+v for a,v in lines.items()])


def prior():
    rows=[]
    for site,owner in ((mod.ROOT,mod.ROOT),
                       ("0x68160","0x68148"),("0x69834","0x69780")):
        rows.append({
            "site":site,"source":{"owner":owner,"evidenceId":fn(
                site,ORIGINAL_TEXT if site==mod.ROOT else None)["evidence_id"]},
            "native":{"owner":owner,"nativeEvidenceId":native(
                mod.ROOT if site==mod.ROOT else owner)["evidence_id"]},
        })
    return {
        "sourceAttested":True,
        "bit2NativeMerge":{"exactLocalBit2AndBit3MergeVerified":True,
                           "effectiveAddressFromPinnedX19":"0x3651ec"},
        "remainingAndProvider":rows,
    }


def place(folder,all_cached=False):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/"function-bitmask-bit2-0x68810.json").write_text(
        json.dumps(fn(mod.ROOT,ORIGINAL_TEXT)))
    (folder/"instructions-bitmask-bit2-owner-0x68810.json").write_text(
        json.dumps(native(mod.ROOT)))
    if all_cached:
        status=evidence_obj("a"*64,"xrefs","address",mod.STATUS,
                            ["0x68a70","0x6d858"])
        (folder/"xrefs-emc-status-0x365234.json").write_text(json.dumps(status))
        for entry,_ in mod.FUNCTIONS:
            (folder/("function-emc-status-"+entry+".json")).write_text(
                json.dumps(fn(entry)))
            (folder/("instructions-emc-status-"+entry+".json")).write_text(
                json.dumps(native(entry)))


class Hxl1EmcStatusTests(unittest.TestCase):
    def test_prior_requires_source_proven_bit2_and_all_three_owners(self):
        mod.verify_prior(prior())
        changed=prior()
        changed["remainingAndProvider"][1]["source"]["owner"]="0x68144"
        with self.assertRaisesRegex(TriageError,"source-owner"):
            mod.verify_prior(changed)
        changed=prior()
        changed["bit2NativeMerge"]["exactLocalBit2AndBit3MergeVerified"]=False
        with self.assertRaisesRegex(TriageError,"merge provenance"):
            mod.verify_prior(changed)

    def test_BLGetStatus_exact_native_request_and_data_argument_provenance(self):
        known=mod.verify_prior(prior())[mod.ROOT]
        result=mod.verify_original_BLGetStatus(
            fn(mod.ROOT,ORIGINAL_TEXT),native(mod.ROOT),known)
        self.assertEqual(result["nativeInstructionCount"],318)
        self.assertTrue(result["requestArgumentSourcesPinned"])
        self.assertEqual(result["originalStatusGlobal"],"0x365234")
        self.assertFalse(result["authenticatedResponseOrSecureAuthorizationProven"])
        self.assertFalse(result["returnedStatusNativeW0Proof"])

    def test_modified_status_return_or_native_helpers_fail_closed(self):
        k=mod.verify_prior(prior())[mod.ROOT]
        f=fn(mod.ROOT,ORIGINAL_TEXT.replace("DAT_00365234 == 0","DAT_00365234 == 1"))
        with self.assertRaisesRegex(TriageError,"source marker differs"):
            mod.verify_original_BLGetStatus(f,native(mod.ROOT),k)
        for old,new in (
            ("0x68a24: bl 0x000715e8","0x68a24: bl 0x000714b0"),
            ("0x68a40: mov w3,#0x4","0x68a40: mov w3,#0x8"),
            ("0x68a68: bl 0x0006d820","0x68a68: bl 0x0006d824"),
        ):
            ev=native(mod.ROOT)
            ev["normalized_result"]=[x.replace(old,new) for x in ev["normalized_result"]]
            with self.subTest(addr=old),self.assertRaises(TriageError):
                mod.verify_original_BLGetStatus(fn(mod.ROOT,ORIGINAL_TEXT),ev,
                                                {"source":k["source"],
                                                 "native":{"nativeEvidenceId":ev["evidence_id"]}})

    def test_unknown_native_gap_between_request_arguments_fails(self):
        ev=native(mod.ROOT)
        ev["normalized_result"]=[
            s.replace("0x68a1c: add x2,sp,#0x4","0x68a1c: mov x2,x8")
            for s in ev["normalized_result"]]
        known=mod.verify_prior(prior())[mod.ROOT]
        # Force expected identity to modified source for semantic opcode test.
        known["native"]["nativeEvidenceId"]=ev["evidence_id"]
        with self.assertRaisesRegex(TriageError,"0x68a1c"):
            mod.verify_original_BLGetStatus(fn(mod.ROOT,ORIGINAL_TEXT),ev,known)

    def test_original_helper_dossiers_not_trust_claims(self):
        entry="0x6d820"
        f=mod.bounded_function(fn(entry),entry,"emc-status-response-transfer")
        n=mod.bounded_native(native(entry),entry)
        self.assertIn("DAT_00365234",f["globalRefs"])
        self.assertFalse(f["trustedResponseSourceVerified"])
        self.assertFalse(n["secureMessageIntegrityEstablished"])

    def test_plan_seven_original_readonly_queries(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            place(root/"rea-security-audit"/"LinuxLoader")
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_bit2",return_value=prior()),\
                 mock.patch.object(mod,"choose_targets",return_value=[target]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No Ghidra execution in plan mode")):
                result=mod.audit(root)
        self.assertEqual(result["newQueries"],7)
        self.assertIsNone(result["statusReferences"]["sourceEvidenceId"])
        self.assertTrue(all(x["native"] is None and x["source"] is None
                            for x in result["helpers"]))
        self.assertFalse(result["deviceModified"])
        self.assertFalse(result["responseAuthenticationProven"])
        self.assertFalse(result["bit2OEMAuthorizationProven"])

    def test_cached_queries_return_no_new_ghidra_calls(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            place(root/"rea-security-audit"/"LinuxLoader",all_cached=True)
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_bit2",return_value=prior()),\
                 mock.patch.object(mod,"choose_targets",return_value=[target]):
                result=mod.audit(root)
        self.assertEqual(result["newQueries"],0)
        self.assertEqual(result["statusReferences"]["total"],2)
        self.assertTrue(all(h["source"] and h["native"] for h in result["helpers"]))
        self.assertFalse(result["signedImageOrOdinBypassProven"])

    def test_original_gate_never_issues_phone_flash_commands(self):
        s=Path(mod.__file__).read_text()
        for forbidden in ("fastboot flash","heimdall flash","adb shell",
                          "subprocess.Popen(","os.system("):
            self.assertNotIn(forbidden,s)


if __name__=="__main__":
    unittest.main()
