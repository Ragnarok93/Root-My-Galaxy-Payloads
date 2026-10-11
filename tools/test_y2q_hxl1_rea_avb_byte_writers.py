#!/usr/bin/env python3
"""Synthetic-only original HXL1 verified native returned-byte & xrefs tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_byte_writers as writers
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def native_cb():
    lines = (
        "0xb2bc: stp x19, x30, [sp, #-0x10]!",
        "0xb2c0: cbz x1, 0x0000b2dc",
        "0xb2c4: mov x19, x1",
        "0xb2c8: bl 0x00033770",
        "0xb2cc: mov w8, w0",
        "0xb2d0: mov w0, wzr",
        "0xb2d4: strb w8, [x19]",
        "0xb2d8: b 0x0000b304",
        "0xb300: mov w0, #0x2",
        "0xb308: ret",
    )
    return evidence_obj("a"*64, "read_function_instructions",
                        "procedure", "0xb2bc", list(lines))


def native_source():
    lines = (
        "0x3378c: b.eq 0x000337c4",
        "0x3379c: b.eq 0x000337c4",
        "0x337a0: adrp x8, 0x351000",
        "0x337a4: add x8, x8, #0x48",
        "0x337b0: ldrb w3, [x8, #0xd]",
        "0x337c4: adrp x8, 0x351000",
        "0x337c8: add x8, x8, #0x48",
        "0x337d0: ldrb w0, [x8, #0xd]",
        "0x337d4: ldr x8, [sp, #0x8]",
        "0x337d8: ldr x9, [x9, #0x4b8]",
        "0x337dc: cmp x9, x8",
        "0x337e0: b.ne 0x000337f0",
        "0x337e4: ldr x30, [sp, #0x10]",
        "0x337e8: add sp, sp, #0x20",
        "0x337ec: ret",
        "0x337f0: bl 0x0001e81c",
    )
    return evidence_obj("a"*64, "read_function_instructions",
                        "procedure", "0x33770", list(lines))


def prior():
    return {
        "originalSourceVerified":True,
        "instructions":[{"entry":"0xb2bc"},{"entry":"0x33770"}],
        "globalReferences":[{"address":"0x351055"},{"address":"0x32a4b8"}]
    }


class ByteWriterTests(unittest.TestCase):
    def test_byte_return_normal_path_and_callback_status_verified(self):
        x=writers.native_byte_contract(native_cb(),native_source())
        self.assertEqual(x["returnedByteAddress"],"0x351055")
        self.assertTrue(x["normalPathReturnsLoadedW0"])
        self.assertEqual(x["callbackStoresByteAt"],"0xb2d4")
        self.assertEqual(x["callbackStatusSuccessW0SetAt"],"0xb2d0")
        self.assertFalse(x["stateOriginOrTrustProven"])

    def test_modified_W0_or_offset_fails_before_query(self):
        ev=native_source()
        ev["normalized_result"]=[
            x.replace("0x337d0: ldrb w0","0x337d0: ldrb w1")
            for x in ev["normalized_result"]
        ]
        with self.assertRaisesRegex(TriageError,"0x337d0"):
            writers.native_byte_contract(native_cb(),ev)
        ev=native_source()
        ev["normalized_result"]=[
            x.replace("#0xd]", "#0xe]")
            for x in ev["normalized_result"]
        ]
        with self.assertRaises(TriageError):
            writers.native_byte_contract(native_cb(),ev)

    def test_modified_callback_transfer_is_not_promoted(self):
        ev=native_cb()
        ev["normalized_result"]=[
            x.replace("0xb2d4: strb w8", "0xb2d4: strb w0")
            for x in ev["normalized_result"]
        ]
        with self.assertRaisesRegex(TriageError,"0xb2d4"):
            writers.native_byte_contract(ev,native_source())
        ev=native_source()
        ev["normalized_result"].insert(-1,"0x337e6: mov w0, wzr")
        with self.assertRaisesRegex(TriageError,"Unknown native instruction"):
            writers.native_byte_contract(native_cb(),ev)

    def test_xref_instruction_is_only_opcode_level(self):
        ev=evidence_obj("a"*64,"inspect_native_instruction","address","0x33ccc",{
            "address":"0x33ccc","procedure":"0x33c10",
            "status":"decoded","mnemonic":"strb",
            "raw_disassembly":"strb w9, [x8,#0xd]",
        })
        result=writers.classify_xref_instruction(ev,"0x33ccc")
        self.assertEqual(result["instructionKind"],"store-instruction")
        self.assertFalse(result["writesGlobalAt0x351055Proven"])
        ev["normalized_result"]["mnemonic"]="adrp"
        result=writers.classify_xref_instruction(ev,"0x33ccc")
        self.assertEqual(result["instructionKind"],"address-formation")
        ev["normalized_result"]["address"]="0x33cd0"
        with self.assertRaisesRegex(TriageError,"xref-instruction mismatch"):
            writers.classify_xref_instruction(ev,"0x33ccc")

    def test_exact_xref_inventory_and_eight_query_limit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            (folder/"instructions-0xb2bc.json").write_text(json.dumps(native_cb()))
            (folder/"instructions-0x33770.json").write_text(json.dumps(native_source()))
            ev=evidence_obj("a"*64,"xrefs","address","0x351055",
                            list(writers.KNOWN_READS+writers.REMAINING_REFS))
            (folder/"xrefs-global-0x351055.json").write_text(json.dumps(ev))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(writers,"verify_global_abi",return_value=prior()),\
                 mock.patch.object(writers,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No subprocess")):
                report=writers.audit(root)
            self.assertEqual(report["newQueries"],8)
            self.assertEqual(report["globalReferenceCount"],10)
            self.assertEqual(len(report["remainingSites"]),8)
            self.assertEqual(report["remainingSites"][0]["address"],"0x33ccc")
            self.assertFalse(report["globalWriterVerified"])
            self.assertFalse(report["secureStateOriginVerified"])
            self.assertFalse(report["oemAuthorizationBypassVerified"])

    def test_changed_original_xref_inventory_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            (folder/"instructions-0xb2bc.json").write_text(json.dumps(native_cb()))
            (folder/"instructions-0x33770.json").write_text(json.dumps(native_source()))
            ev=evidence_obj("a"*64,"xrefs","address","0x351055",["0x337b0"])
            (folder/"xrefs-global-0x351055.json").write_text(json.dumps(ev))
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(writers,"verify_global_abi",return_value=prior()),\
                 mock.patch.object(writers,"choose_targets",return_value=[t]):
                with self.assertRaisesRegex(TriageError,"xref inventory differs"):
                    writers.audit(root)

    def test_source_has_no_flash_or_phone_actions(self):
        raw=Path(writers.__file__).read_text()
        for forbidden in ("fastboot flash","heimdall flash","adb shell",
                          "os.system(","subprocess.Popen"):
            self.assertNotIn(forbidden,raw)


if __name__=="__main__":
    unittest.main()
