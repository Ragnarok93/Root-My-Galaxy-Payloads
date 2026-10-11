#!/usr/bin/env python3
"""Synthetic-only regression gates for HXL1 AVB byte persistence analysis."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_state_persistence as pers
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def ghidra_function(entry, pseudo):
    return evidence_obj("a"*64,"analyze_function","procedure",entry,{
        "procedure":{
            "address":entry,"name":"FUN_"+entry[2:].zfill(8),
            "body":{"available":True,"ranges":[
                {"start":entry,"end":hex(int(entry,16)+0x3a0)}]},
        },
        "pseudocode":pseudo,"native_value_flow":{"available":True},
    })


STORE_PSEUDO = """longlong FUN_00033c88(char param_1)
{
 if (DAT_00351055 == param_1) return 0;
 DAT_00351055 = param_1;
 lVar4 = FUN_0002ae38(1,&DAT_00351048,0x9a0);
 return lVar4;
}"""
INIT_PSEUDO = """longlong FUN_00033da8(void)
{
 lVar3 = FUN_0002ae38(0,&DAT_00351048,0x9a0);
 lVar3 = FUN_0000f7e4(&DAT_00351048,"SAMANDR-BOOT!",0xd);
 if (lVar3 != 0) {
   DAT_00351055 = 0;
   lVar3 = FUN_0002ae38(1,&DAT_00351048,0x9a0);
 }
 return lVar3;
}"""

STORE_ASM = [
    "0x33c90: adrp x8, 0x32a000",
    "0x33c94: mov w19, w0",
    "0x33ce0: adrp x8, 0x351000",
    "0x33ce4: add x8, x8, #0x48",
    "0x33ce8: ldrb w9, [x8, #0xd]",
    "0x33cec: cmp w9, w19, uxtb",
    "0x33cf0: b.ne 0x00033cfc",
    "0x33cf4: mov x19, xzr",
    "0x33cf8: b 0x00033d7c",
    "0x33cfc: ldr w9, [x8, #0x998]",
    "0x33d00: tst w19, #0xff",
    "0x33d04: and w10, w19, #0xff",
    "0x33d08: strb w19, [x8, #0xd]",
    "0x33d0c: cinc w9, w9, ne",
]
RESET_ASM = [
    "0x33da8: stp x29, x30, [sp, #-0x20]!",
    "0x33db0: adrp x19, 0x351000",
    "0x33db4: add x19, x19, #0x48",
    "0x33dbc: bl 0x0002ae38",
    "0x33ec8: mov w2, wzr",
    "0x33ed8: bl 0x0002b520",
    "0x33ee0: strb wzr, [x19, #0xd]",
    "0x33ee4: mov w0, #0x1",
    "0x33ef8: bl 0x0002ae38",
]


def asm_ev(entry, lines):
    return evidence_obj("a"*64,"read_function_instructions",
                        "procedure",entry,list(lines))


def minimal_prior():
    return {
        "sourceAttested":True,
        "storeCandidates":[
            {"ownerEntry":"0x33c88","site":"0x33d08"},
            {"ownerEntry":"0x33da8","site":"0x33ee0"},
        ],
    }


class PersistenceTests(unittest.TestCase):
    def test_exact_original_pseudo_update_and_magic_initialization(self):
        x=pers.validate_pseudocode(
            ghidra_function("0x33c88",STORE_PSEUDO),
            "0x33c88",pers.PSEUDO_STORE)
        self.assertEqual(len(x["observedStatements"]),2)
        y=pers.validate_pseudocode(
            ghidra_function("0x33da8",INIT_PSEUDO),
            "0x33da8",pers.PSEUDO_INIT)
        self.assertEqual(len(y["observedStatements"]),4)
        self.assertFalse(y["nativeMemoryAliasOrPersistentIntegrityProven"])

    def test_pseudo_changed_global_magic_or_helper_fails_closed(self):
        a=ghidra_function("0x33c88",
                          STORE_PSEUDO.replace("DAT_00351055","DAT_00351056"))
        with self.assertRaisesRegex(TriageError,"write/storage sequence"):
            pers.validate_pseudocode(a,"0x33c88",pers.PSEUDO_STORE)
        a=ghidra_function("0x33da8",
                          INIT_PSEUDO.replace("SAMANDR-BOOT!","ANOTHER-MAGIC"))
        with self.assertRaisesRegex(TriageError,"write/storage sequence"):
            pers.validate_pseudocode(a,"0x33da8",pers.PSEUDO_INIT)

    def test_native_source_store_local_address_and_value(self):
        x=pers.exact_33c88_local_store(asm_ev("0x33c88",STORE_ASM))
        self.assertEqual(x["effectiveByteAddress"],"0x351055")
        self.assertTrue(x["nativeStoreTargetVerifiedOnSourceAddressPath"])
        self.assertFalse(x["sourceCallerAuthorizationVerified"])

    def test_native_source_store_modified_branch_or_address_rejected(self):
        changed=[row.replace("add x8, x8, #0x48","add x8, x8, #0x50")
                 for row in STORE_ASM]
        with self.assertRaises(TriageError):
            pers.exact_33c88_local_store(asm_ev("0x33c88",changed))
        changed=[row.replace("b.ne 0x00033cfc","b.eq 0x00033cfc")
                 for row in STORE_ASM]
        with self.assertRaises(TriageError):
            pers.exact_33c88_local_store(asm_ev("0x33c88",changed))

    def test_reset_base_is_only_conditional_static_candidate(self):
        x=pers.x19_33da8_provenance(asm_ev("0x33da8",RESET_ASM))
        self.assertEqual(x["staticAddressCandidate"],"0x351055")
        self.assertFalse(x["effectiveAddressProvedOnAllControlFlowPaths"])
        changed=[row.replace("add x19, x19, #0x48","add x19, x19, #0x50")
                 for row in RESET_ASM]
        x=pers.x19_33da8_provenance(asm_ev("0x33da8",changed))
        self.assertIsNone(x["staticAddressCandidate"])

    def test_storage_helper_preserves_original_calls_as_leads(self):
        fn=ghidra_function("0x2ae38", """longlong FUN_0002ae38(int mode,char *buf,int len) {
          x = FUN_00022222(mode);
          if (x != 0) return x;
          return FUN_00033333(buf,len);
        }""")
        got=pers.storage_helper_dossier(fn)
        self.assertEqual(got["entry"],"0x2ae38")
        self.assertFalse(got["readWriteFlagSemanticsProven"])
        self.assertTrue(any(x["address"]=="0x22222"
                            for x in got["directLexicalCallees"]))

    def test_plan_requests_four_ghidra_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            data=[
                ("function-0x33c88.json",ghidra_function("0x33c88",STORE_PSEUDO)),
                ("function-0x33da8.json",ghidra_function("0x33da8",INIT_PSEUDO)),
                ("instructions-0x33c88.json",asm_ev("0x33c88",STORE_ASM)),
                ("instructions-0x33da8.json",asm_ev("0x33da8",RESET_ASM)),
            ]
            for name,obj in data:
                (folder/name).write_text(json.dumps(obj))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(pers,"verify_byte_producers",
                                   return_value=minimal_prior()),\
                 mock.patch.object(pers,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No REA in plan mode")):
                r=pers.audit(root)
        self.assertEqual(r["newQueries"],4)
        self.assertEqual(r["variableStoreNative"]["effectiveByteAddress"],"0x351055")
        self.assertEqual(len(r["functionXrefs"]),2)
        self.assertIsNone(r["storageHelperPseudocode"])
        self.assertFalse(r["trustedUnlockAuthorizationProven"])
        self.assertFalse(r["onDiskIntegrityOrCryptoProven"])
        self.assertFalse(r["unlockBypassProven"])

    def test_cached_source_dossiers_keep_no_new_query(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            data=[
                ("function-0x33c88.json",ghidra_function("0x33c88",STORE_PSEUDO)),
                ("function-0x33da8.json",ghidra_function("0x33da8",INIT_PSEUDO)),
                ("instructions-0x33c88.json",asm_ev("0x33c88",STORE_ASM)),
                ("instructions-0x33da8.json",asm_ev("0x33da8",RESET_ASM)),
                ("function-0x2ae38.json",
                 ghidra_function("0x2ae38","int FUN_0002ae38(){return 0;}")),
                ("instructions-0x2ae38.json",asm_ev("0x2ae38",STORE_ASM)),
                ("xrefs-function-0x33c88.json",
                 evidence_obj("a"*64,"xrefs","address","0x33c88",
                              ["0x100","0x200"])),
                ("xrefs-function-0x33da8.json",
                 evidence_obj("a"*64,"xrefs","address","0x33da8",
                              ["0x300"])),
            ]
            for name,obj in data: (folder/name).write_text(json.dumps(obj))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(pers,"verify_byte_producers",
                                   return_value=minimal_prior()),\
                 mock.patch.object(pers,"choose_targets",return_value=[t]):
                r=pers.audit(root)
        self.assertEqual(r["newQueries"],0)
        self.assertEqual(r["functionXrefs"][0]["count"],2)
        self.assertEqual(r["storageHelperPseudocode"]["entry"],"0x2ae38")

    def test_source_has_no_firmware_or_device_action(self):
        raw=Path(pers.__file__).read_text()
        for forbidden in ("fastboot flash","heimdall flash","adb shell",
                          "subprocess.Popen(", "os.system("):
            self.assertNotIn(forbidden,raw)


if __name__=="__main__":
    unittest.main()
