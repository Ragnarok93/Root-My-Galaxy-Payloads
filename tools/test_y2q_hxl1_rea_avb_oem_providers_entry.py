#!/usr/bin/env python3
"""Synthetic HXL1 OEM/FRP value-provider and LinuxLoader entry dispatch tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_oem_providers_entry as mod
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def fn(entry,pseudo,query=None):
    return evidence_obj("a"*64,"analyze_function","procedure",query or entry,{
        "procedure":{"address":entry,"name":"FUN_"+entry[2:].zfill(8),
                     "body":{"available":True,"ranges":[{
                        "start":entry,"end":hex(int(entry,16)+0x800)}]}},
        "pseudocode":pseudo,"native_value_flow":{"available":True},
    })


INIT_SOURCE="""void FUN_00060af8(void) {
 DAT_0035cb14 = FUN_00060918();
 iVar4 = FUN_00060790();
 iVar2 = DAT_0035cb14;
 DAT_0035cb18 = iVar4;
 if ((iVar4 == 0x10001) || (iVar2 == 0x10001)) {
   DAT_0035cb18 = 0;
 } else {
   DAT_0035cb1c = 1;
 }
}"""


def native(entry,lines):
    return evidence_obj("a"*64,"read_function_instructions","procedure",entry,
                        list(lines))


def initializer_native():
    lines=[a+": "+m+" "+o for a,m,o in mod.INIT_PINS]
    lines.extend(f"{hex(0x60bd4+4*i)}: nop" for i in range(55-len(lines)))
    return native("0x60af8",lines)


MAIN_PSEUDO="\n".join([
    "ulonglong FUN_000017d8(void) {",
    "   FUN_00033da8();",
    *("   if (g_"+str(i)+") { FUN_00011111(); }" for i in range(60)),
    '   if (device_status == 1) FUN_00034238();',
    '   if (device_status == 2) FUN_00034370();',
    "   return 0;",
    "}",
])


def main_ev(site):
    return fn("0x17d8",MAIN_PSEUDO,site)


def main_native():
    return native("0x17d8",[
        "0x1ae0: cmp w19,#0x1",
        "0x1ae4: b.ne 0x00001b60",
        "0x1b40: mov w0,#0x1",
        "0x1b44: cbz w0,0x00001b50",
        "0x1b48: bl 0x00034238",
        "0x1b4c: mov w19,#0x2",
        "0x1d9c: cmp w19,#0x2",
        "0x1da0: b.ne 0x00001dc0",
        "0x1dac: mov w0,wzr",
        "0x1db0: bl 0x00034370",
        "0x1db4: mov w20,w0",
        *[f"{hex(0x1dc4+4*i)}: nop" for i in range(45)],
    ])


def provider_ev(entry):
    return fn(entry,"""longlong FUN_original(void) {
   int status = FUN_00010204();
   if (status != 0) {
     DAT_00350000 = status;
   }
   return status;
}""")


def provider_ins(entry):
    base_addr=int(entry,16)
    return native(entry,[
        f"{hex(base_addr)}: stp x19,x30,[sp,#-0x10]!",
        f"{hex(base_addr+4)}: bl 0x00010204",
        f"{hex(base_addr+8)}: mov w19,w0",
        f"{hex(base_addr+12)}: cbz w19,{hex(base_addr+24)}",
        f"{hex(base_addr+16)}: mov w0,w19",
        f"{hex(base_addr+20)}: nop",
        f"{hex(base_addr+24)}: ret",
    ])


def prior():
    initn=initializer_native()
    initf=fn("0x60af8",INIT_SOURCE)
    return {
        "sourceAttested":True,
        "predicateNative":{"normalReturnW0ReadFrom":"0x35cb18",
                           "initializationGuardReadFrom":"0x35cb1c"},
        "routeEntries":[
            {"site":site,"target":target,
             "native":{"directBLToTarget":True,
                       "instruction":f"bl 0x{int(target,16):08x}"},
             "caller":{"owner":"0x17d8","sourceEvidence":main_ev(site)["evidence_id"]}}
            if site in ("0x1b48","0x1db0") else
            {"site":site,"target":target}
            for site,target in (("0x2f1f0","0x2f538"),
                                ("0x1b48","0x34238"),
                                ("0x1db0","0x34370"),
                                ("0x185a4","0x674d8"))
        ],
        "initializerFunction":{"entry":"0x60af8","evidenceId":initf["evidence_id"]},
        "initializerNative":{"nativeCount":55,"evidenceId":initn["evidence_id"]},
    }


def stored(root):
    folder=root/"rea-security-audit"/"LinuxLoader"
    folder.mkdir(parents=True)
    data={
        "function-oem-initializer-0x60af8.json":fn("0x60af8",INIT_SOURCE),
        "instructions-oem-initializer-0x60af8.json":initializer_native(),
        "function-route-entry-0x1b48.json":main_ev("0x1b48"),
        "function-route-entry-0x1db0.json":main_ev("0x1db0"),
    }
    for name,obj in data.items():
        (folder/name).write_text(json.dumps(obj))
    return folder


class Hxl1OemProvidersTests(unittest.TestCase):
    def test_original_initializer_proves_cache_assignments_not_secure_trust(self):
        p=prior()
        fn_result=mod.verify_source_initializer(fn("0x60af8",INIT_SOURCE),p)
        n_result=mod.verify_native_initializer(initializer_native(),p)
        self.assertEqual(fn_result["sourceStatementCount"],7)
        self.assertTrue(n_result["originalNativeAssignmentsVerified"])
        self.assertEqual(n_result["oemSource"],"0x60790")
        self.assertEqual(n_result["frpSource"],"0x60918")
        self.assertFalse(n_result["secureSourceTrustVerified"])

    def test_wrong_provider_call_or_error_sentinel_rejected(self):
        p=prior()
        ev=initializer_native()
        ev["normalized_result"]=[x.replace("0x60b1c: bl 0x00060790",
                                           "0x60b1c: bl 0x00060794")
                                for x in ev["normalized_result"]]
        with self.assertRaisesRegex(TriageError,"0x60b1c"):
            mod.verify_native_initializer(ev,p)
        ev=fn("0x60af8",INIT_SOURCE.replace("0x10001","0x10000"))
        with self.assertRaisesRegex(TriageError,"statement changed"):
            mod.verify_source_initializer(ev,p)

    def test_parent_source_attestation_and_both_site_contexts(self):
        p=prior()
        result=mod.verify_main_pseudocode(
            {"0x1b48":main_ev("0x1b48"),"0x1db0":main_ev("0x1db0")},p)
        self.assertEqual(result["entry"],"0x17d8")
        self.assertEqual(len(result["directCalls"]),2)
        self.assertFalse(result["branchAuthorizationVerified"])
        bad=main_ev("0x1db0")
        bad["normalized_result"]["pseudocode"]=MAIN_PSEUDO.replace(
            "FUN_00034370()","FUN_00034374()")
        with self.assertRaises(TriageError):
            mod.verify_main_pseudocode(
                {"0x1b48":main_ev("0x1b48"),"0x1db0":bad},p)

    def test_parent_native_windows_contain_exact_native_BL_sites(self):
        n=mod.main_native_context(main_native())
        self.assertEqual(n["entry"],"0x17d8")
        self.assertEqual(len(n["callWindows"]),2)
        self.assertFalse(n["callWindows"]["0x1b48"]["controlFlowDominanceVerified"])
        ev=main_native()
        ev["normalized_result"]=[x.replace(
            "0x1db0: bl 0x00034370","0x1db0: bl 0x00034374")
            for x in ev["normalized_result"]]
        with self.assertRaisesRegex(TriageError,"0x1db0"):
            mod.main_native_context(ev)

    def test_helpers_have_read_only_evidence_not_verified_return(self):
        result=mod.provider_source(provider_ev("0x60790"),"0x60790","OEM-value")
        self.assertIn("FUN_00010204",result["functionRefs"])
        self.assertFalse(result["trustedSecureStorageVerified"])
        native_data=mod.provider_native(provider_ins("0x60918"),"0x60918")
        self.assertEqual(native_data["instructionCount"],7)
        self.assertFalse(native_data["returnRegisterSourceProven"])

    def test_plan_mode_requires_only_five_original_read_only_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            stored(root)
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_oem_state",return_value=prior()),\
                 mock.patch.object(mod,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No REA in plan mode")):
                report=mod.audit(root)
        self.assertEqual(report["newQueries"],5)
        self.assertIsNone(report["mainNative"])
        self.assertTrue(all(x["native"] is None for x in report["stateProviders"]))
        self.assertFalse(report["directUnlockEntryAuthorizedProven"])
        self.assertFalse(report["deviceModified"])

    def test_cached_original_provider_and_parent_reuses_all_five(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=stored(root)
            (folder/"instructions-route-owner-0x17d8.json").write_text(
                json.dumps(main_native()))
            for entry,_ in mod.PROVIDERS:
                (folder/("function-oem-provider-"+entry+".json")).write_text(
                    json.dumps(provider_ev(entry)))
                (folder/("instructions-oem-provider-"+entry+".json")).write_text(
                    json.dumps(provider_ins(entry)))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_oem_state",return_value=prior()),\
                 mock.patch.object(mod,"choose_targets",return_value=[t]):
                result=mod.audit(root)
        self.assertEqual(result["newQueries"],0)
        self.assertEqual(len(result["stateProviders"]),2)
        self.assertIsNotNone(result["mainNative"])
        self.assertFalse(result["oemFrpProtectedSourceProven"])

    def test_never_calls_phone_tools_or_flash(self):
        source=Path(mod.__file__).read_text()
        for unsafe in ("fastboot flash","heimdall flash","adb shell",
                       "subprocess.Popen(", "os.system("):
            self.assertNotIn(unsafe,source)


if __name__=="__main__":
    unittest.main()
