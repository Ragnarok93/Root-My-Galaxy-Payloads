#!/usr/bin/env python3
"""Synthetic, fail-closed HXL1 persistent-OEM and selector source tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_oem_persistent_boundary as stage
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


OEM_PSEUDO="""undefined4 FUN_00060790(void) {
 local_4c = 0;
 uVar4 = 0x10001;
 iVar2 = FUN_0001e5f0("persistent",&local_40,&local_48);
 if (iVar2 == 0) {
   FUN_0000f9d8(&local_4c,lVar3 + lVar5 + -1,1);
   uVar4 = local_4c;
 }
 return uVar4;
}"""
FRP_PSEUDO="""uint FUN_00060918(void) {
 iVar2 = FUN_0001e5f0("persistent",&local_30,&local_38);
 if (iVar2 == 0) {
   FUN_0000f9d8(&DAT_0035cb14,lVar3 + 0x24,4);
   uVar5 = (DAT_0035cb14 & 0xff00ff00) >> 8;
   DAT_0035cb14 = uVar5 >> 0x10 | uVar5 << 0x10;
 }
 return uVar5;
}"""


def fun_ev(entry,pseudocode=None):
    text=pseudocode if pseudocode is not None else (
        OEM_PSEUDO if entry==stage.OEM else FRP_PSEUDO if entry==stage.FRP else
        "int FUN_original(void) {\n r=FUN_00011234();\n return r;\n}")
    return evidence_obj("a"*64,"analyze_function","procedure",entry,{
        "procedure":{"address":entry,"name":"FUN_original",
                     "body":{"available":True,"ranges":[{
                        "start":entry,"end":hex(int(entry,16)+0x900)}]}},
        "pseudocode":text,"native_value_flow":{"available":True},
    })


def ins_ev(entry):
    if entry==stage.OEM:
        count,pins=78,stage.OEM_NATIVE_PINS
    elif entry==stage.FRP:
        count,pins=92,stage.FRP_NATIVE_PINS
    elif entry==stage.MAIN:
        count,pins=569,stage.MAIN_NATIVE_PINS
    else:
        count,pins=8,()
    instructions={hex(int(entry,16)+4*i):("nop","") for i in range(count)}
    for addr,mnemonic,operands in pins:
        if addr not in instructions:
            raise AssertionError("fixture pin outside code region "+addr)
        instructions[addr]=(mnemonic,operands)
    rows=[address+": "+mnemonic+(" "+operand if operand else "")
          for address,(mnemonic,operand) in instructions.items()]
    return evidence_obj("a"*64,"read_function_instructions",
                        "procedure",entry,rows)


def source_prior():
    return {
        "sourceAttested":True,
        "mainNative":{"entry":stage.MAIN,"evidenceId":ins_ev(stage.MAIN)["evidence_id"]},
        "stateProviders":[{
            "entry":entry,
            "function":{"evidenceId":fun_ev(entry)["evidence_id"]},
            "native":{"evidenceId":ins_ev(entry)["evidence_id"]},
        } for entry in (stage.OEM,stage.FRP)],
    }


def write_input(folder):
    folder.mkdir(parents=True,exist_ok=True)
    for entry in (stage.OEM,stage.FRP):
        (folder/("function-oem-provider-"+entry+".json")).write_text(json.dumps(fun_ev(entry)))
        (folder/("instructions-oem-provider-"+entry+".json")).write_text(json.dumps(ins_ev(entry)))
    (folder/"instructions-route-owner-0x17d8.json").write_text(
        json.dumps(ins_ev(stage.MAIN)))


class Hxl1PersistentBoundaryTests(unittest.TestCase):
    def test_both_partition_providers_attest_fixed_offsets(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target_folder=root/"rea-security-audit"/"LinuxLoader"
            write_input(target_folder)
            p=stage.saved_provider_evidence(root,"a"*64,
                                            stage.validated_prior(source_prior()))
        self.assertEqual(p[stage.OEM]["sourceDataLocation"],
                         "last byte of allocated partition buffer")
        self.assertEqual(p[stage.FRP]["sourceDataLocation"],"4 bytes at buffer+0x24")
        self.assertFalse(p[stage.OEM]["partitionContentsCryptographicallyAuthenticatedProven"])
        self.assertFalse(p[stage.FRP]["samePartitionDeviceAsVBDeviceProven"])

    def test_main_exact_selector_and_zero_branch(self):
        x=stage.verify_main_selection(ins_ev(stage.MAIN),
                                      ins_ev(stage.MAIN)["evidence_id"])
        self.assertEqual(x["inputToSelector"],"0x4")
        self.assertEqual(x["zeroResultDirectTarget"],"0x34370")
        self.assertEqual(x["nonzeroResultDirectTarget"],"0x34238")
        self.assertFalse(x["selectorSemanticsOrAuthorityProven"])

    def test_modified_selector_route_and_persistent_offsets_fail_closed(self):
        ev=ins_ev(stage.MAIN)
        ev["normalized_result"]=[s.replace("0x1b44: b.eq 0x00001db0",
                                           "0x1b44: b.ne 0x00001db0")
                                 for s in ev["normalized_result"]]
        with self.assertRaisesRegex(TriageError,"0x1b44"):
            stage.verify_main_selection(ev,ev["evidence_id"])
        ev=ins_ev(stage.OEM)
        ev["normalized_result"]=[s.replace("0x6081c: sub x1,x8,#0x1",
                                           "0x6081c: sub x1,x8,#0x2")
                                 for s in ev["normalized_result"]]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            write_input(folder)
            (folder/"instructions-oem-provider-0x60790.json").write_text(json.dumps(ev))
            p=source_prior()
            p["stateProviders"][0]["native"]["evidenceId"]=ev["evidence_id"]
            with self.assertRaisesRegex(TriageError,"0x6081c"):
                stage.saved_provider_evidence(root,"a"*64,stage.validated_prior(p))

    def test_unverified_source_pseudocode_rejected(self):
        changed=fun_ev(stage.FRP,FRP_PSEUDO.replace("lVar3 + 0x24","lVar3 + 0x20"))
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            write_input(folder)
            (folder/"function-oem-provider-0x60918.json").write_text(json.dumps(changed))
            p=source_prior()
            p["stateProviders"][1]["function"]["evidenceId"]=changed["evidence_id"]
            with self.assertRaisesRegex(TriageError,"partition source semantics"):
                stage.saved_provider_evidence(root,"a"*64,stage.validated_prior(p))

    def test_incomplete_or_duplicate_prior_rejected(self):
        stage.validated_prior(source_prior())
        p=source_prior()
        p["stateProviders"][1]["entry"]=stage.OEM
        with self.assertRaisesRegex(TriageError,"inventory changed"):
            stage.validated_prior(p)
        p=source_prior()
        p["mainNative"]["entry"]="0x17dc"
        with self.assertRaisesRegex(TriageError,"entry dossier absent"):
            stage.validated_prior(p)

    def test_six_readonly_queries_without_ghidra_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            write_input(root/"rea-security-audit"/"LinuxLoader")
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(stage,"verify_providers",
                                   return_value=source_prior()),\
                 mock.patch.object(stage,"choose_targets",return_value=[target]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("REA called in plan-only mode")):
                result=stage.audit(root)
        self.assertEqual(result["newQueries"],6)
        self.assertEqual(len(result["boundaryHelpers"]),3)
        self.assertTrue(all(x["native"] is None and x["function"] is None
                            for x in result["boundaryHelpers"]))
        self.assertFalse(result["onDeviceUnlockAuthorizationOrImageBypassProven"])
        self.assertFalse(result["deviceModified"])

    def test_cached_boundary_dossiers_reduce_new_queries_to_zero(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            write_input(folder)
            for entry,kind in stage.QUERY:
                (folder/("function-state-boundary-"+entry+".json")).write_text(
                    json.dumps(fun_ev(entry)))
                (folder/("instructions-state-boundary-"+entry+".json")).write_text(
                    json.dumps(ins_ev(entry)))
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(stage,"verify_providers",
                                   return_value=source_prior()),\
                 mock.patch.object(stage,"choose_targets",return_value=[target]):
                result=stage.audit(root)
        self.assertEqual(result["newQueries"],0)
        self.assertEqual([x["entry"] for x in result["boundaryHelpers"]],
                         [x[0] for x in stage.QUERY])
        self.assertTrue(all(x["native"] and x["function"] for x in result["boundaryHelpers"]))
        self.assertFalse(result["persistentPartitionTrustedAndAuthenticatedProven"])

    def test_source_has_no_phone_or_flash_action(self):
        source=Path(stage.__file__).read_text()
        for unsafe in ("fastboot flash","heimdall flash","adb shell",
                       "subprocess.Popen(", "os.system("):
            self.assertNotIn(unsafe,source)


if __name__=="__main__":
    unittest.main()
