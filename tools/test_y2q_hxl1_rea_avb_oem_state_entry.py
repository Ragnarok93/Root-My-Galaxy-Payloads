#!/usr/bin/env python3
"""Synthetic-only HXL1 original OEM flag W0 and direct-entry provenance tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_oem_state_entry as stage
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


OEM_NATIVE_LINES = (
    "0x608c8: sub sp,sp,#0x20",
    "0x608cc: str x30,[sp,#0x10]",
    "0x608d0: adrp x8,0x32a000",
    "0x608d4: adrp x9,0x35c000",
    "0x608d8: ldr x8,[x8,#0x4b8]",
    "0x608dc: str x8,[sp,#0x8]",
    "0x608e0: ldr w8,[x9,#0xb1c]",
    "0x608e4: cbnz w8,0x000608ec",
    "0x608e8: bl 0x00060af8",
    "0x608ec: adrp x8,0x35c000",
    "0x608f0: adrp x9,0x32a000",
    "0x608f4: ldr w0,[x8,#0xb18]",
    "0x608f8: ldr x8,[sp,#0x8]",
    "0x608fc: ldr x9,[x9,#0x4b8]",
    "0x60900: cmp x9,x8",
    "0x60904: b.ne 0x00060914",
    "0x60908: ldr x30,[sp,#0x10]",
    "0x6090c: add sp,sp,#0x20",
    "0x60910: ret",
    "0x60914: bl 0x0001e81c",
)


def native_predicate():
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        "0x608c8",list(OEM_NATIVE_LINES))


def previous(native=None):
    ev=native or native_predicate()
    return {
        "sourceAttested":True,
        "verifiedRoutes":[{"owner":e} for e in ("0x2f538","0x34238","0x34370","0x674d8")],
        "routeCallerXrefs":[{
            "function":target,"total":1,"referenceSites":[site],
            "evidenceId":"ev_"+target,
        } for site,target in stage.ROUTE_SITES],
        "oemPredicate":{"entry":"0x608c8"},
        "oemNative":{"count":20,"evidenceId":ev["evidence_id"]},
        "oemXrefSites":["0x67630"],
    }


def ins_at(site,target,*,raw=None,mnemonic="bl"):
    return evidence_obj("a"*64,"inspect_native_instruction","address",site,{
        "address":site,"status":"decoded","mnemonic":mnemonic,
        "raw_disassembly":raw or "bl "+target,
        "procedure":"0x1900",
    })


def caller(site,entry="0x1900"):
    return evidence_obj("a"*64,"analyze_function","procedure",site,{
        "procedure":{"address":entry,"name":"FUN_00001900",
                     "body":{"available":True,"ranges":[
                         {"start":entry,"end":"0x1eff"}]}},
        "pseudocode":"\n".join([
            "void FUN_00001900(void) {",
            "  int permission=FUN_00011111();",
            "  if (permission != 0) {",
            "    FUN_00034238();",
            "  }",
            "  return;",
            "}",
        ]),
        "native_value_flow":{"available":True},
    })


def initializer_fn():
    return evidence_obj("a"*64,"analyze_function","procedure","0x60af8",{
        "procedure":{"address":"0x60af8","name":"FUN_00060af8",
                     "body":{"available":True,"ranges":[
                         {"start":"0x60af8","end":"0x60b90"}]}},
        "pseudocode":"void FUN_00060af8(void) {\n  DAT_0035cb18 = FUN_00010000();\n}\n",
        "native_value_flow":{"available":True},
    })


def initializer_native():
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        "0x60af8",[
        "0x60af8: stp x19,x30,[sp,#-0x10]!",
        "0x60afc: bl 0x00010000",
        "0x60b00: mov w19, w0",
        "0x60b04: cbz w19, 0x00060b10",
        "0x60b08: mov w0, wzr",
        "0x60b0c: ret",
    ])


class Hxl1OemEntryTests(unittest.TestCase):
    def test_original_native_W0_32bit_return_and_init_gate(self):
        got=stage.verify_saved_native_return(native_predicate())
        self.assertEqual(got["normalReturnW0ReadFrom"],"0x35cb18")
        self.assertEqual(got["initializationGuardReadFrom"],"0x35cb1c")
        self.assertTrue(got["normalEpiloguePreservesW0"])
        self.assertEqual(got["whenGuardZeroCalls"],"0x60af8")
        self.assertFalse(got["flagIntegrityOrAuthorizationVerified"])

    def test_modified_return_register_guard_or_tail_fails_closed(self):
        for old,new in (
            ("0x608f4: ldr w0","0x608f4: ldr w1"),
            ("0x608e4: cbnz","0x608e4: cbz"),
            ("0x608e8: bl 0x00060af8","0x608e8: bl 0x00060a00"),
            ("0x60910: ret","0x60910: nop"),
        ):
            ev=native_predicate()
            ev["normalized_result"]=[s.replace(old,new) for s in ev["normalized_result"]]
            with self.subTest(old=old),self.assertRaises(TriageError):
                stage.verify_saved_native_return(ev)

    def test_changed_upstream_owner_count_or_oem_xref_fails(self):
        stage.verify_prior_sources(previous())
        bad=previous()
        bad["routeCallerXrefs"][1]["referenceSites"]=["0x1b4c"]
        with self.assertRaisesRegex(TriageError,"four entry-route"):
            stage.verify_prior_sources(bad)
        bad=previous()
        bad["oemXrefSites"]=["0x67630","0x67634"]
        with self.assertRaisesRegex(TriageError,"sole known xref"):
            stage.verify_prior_sources(bad)

    def test_native_entry_bl_precise_and_noncall_stays_unknown(self):
        item=stage.classify_native_xref(ins_at("0x1b48","0x34238"),
                                        "0x1b48","0x34238")
        self.assertTrue(item["directBLToTarget"])
        self.assertFalse(item["authorizedAndReachableProven"])
        item=stage.classify_native_xref(
            ins_at("0x1b48","0x34238",raw="adrp x8,0x34000",mnemonic="adrp"),
            "0x1b48","0x34238")
        self.assertFalse(item["directBLToTarget"])
        with self.assertRaisesRegex(TriageError,"not original requested"):
            stage.classify_native_xref(ins_at("0x1b48","0x34238"),
                                       "0x1b4c","0x34238")

    def test_original_initializer_dossiers_do_not_infer_integrity(self):
        got=stage.init_function(initializer_fn())
        self.assertIn("DAT_0035cb18",got["globalRefs"])
        self.assertFalse(got["trustedOEMSourceProven"])
        native=stage.init_native(initializer_native())
        self.assertEqual(native["nativeCount"],6)
        self.assertFalse(native["globalWriterVerified"])

    def test_plan_mode_is_exactly_eight_readonly_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            (folder/"instructions-oem-flag-0x608c8.json").write_text(
                json.dumps(native_predicate()))
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(stage,"verify_oem_routes",
                                   return_value=previous()),\
                 mock.patch.object(stage,"choose_targets",return_value=[target]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No Ghidra in plan mode")):
                result=stage.audit(root)
        self.assertEqual(result["newQueries"],8)
        self.assertEqual(len(result["routeEntries"]),4)
        self.assertTrue(all(x["caller"] is None for x in result["routeEntries"]))
        self.assertEqual(len(result["oemGlobalXrefs"]),2)
        self.assertFalse(result["directUnlockWithoutAuthorizationProven"])
        self.assertFalse(result["signedBootOrFlashBypassProven"])
        self.assertFalse(result["deviceModified"])

    def test_direct_call_conditional_function_is_attested_from_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            (folder/"instructions-oem-flag-0x608c8.json").write_text(
                json.dumps(native_predicate()))
            for site,target_name in stage.ROUTE_SITES:
                item=ins_at(site,target_name)
                (folder/("instruction-route-entry-"+site+".json")).write_text(json.dumps(item))
                if site in ("0x1b48","0x1db0"):
                    (folder/("function-route-entry-"+site+".json")).write_text(
                        json.dumps(caller(site)))
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(stage,"verify_oem_routes",return_value=previous()),\
                 mock.patch.object(stage,"choose_targets",return_value=[target]):
                result=stage.audit(root)
        self.assertEqual(result["newQueries"],4)
        self.assertTrue(all(r["native"]["directBLToTarget"]
                            for r in result["routeEntries"]))
        self.assertIsNotNone(result["routeEntries"][1]["caller"])
        self.assertIsNotNone(result["routeEntries"][2]["caller"])
        self.assertFalse(result["directUnlockWithoutAuthorizationProven"])

    def test_unsupported_original_device_actions_absent(self):
        src=Path(stage.__file__).read_text()
        for forbidden in ("fastboot flash","heimdall flash","adb shell",
                          "subprocess.Popen(", "os.system("):
            self.assertNotIn(forbidden,src)


if __name__=="__main__":
    unittest.main()
