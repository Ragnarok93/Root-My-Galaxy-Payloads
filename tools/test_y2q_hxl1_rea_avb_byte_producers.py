#!/usr/bin/env python3
"""Synthetic tests for original HXL1 candidate IsUnlocked byte writers."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_byte_producers as producers
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def previous():
    labels = {
        "0x33d08": ("0x33c88", "strb w19,[x8, #0xd]", "store-instruction"),
        "0x33ee0": ("0x33da8", "strb wzr,[x19, #0xd]", "store-instruction"),
    }
    out = []
    for address in producers.REMAINING_REFS:
        parent, inst, kind = labels.get(
            address, ("0x34238", "ldrb w8,[x8, #0xd]", "load-instruction"))
        out.append({
            "address": address, "status": "SOURCE_ATTESTED",
            "observation": {
                "evidenceId": "ev_"+address[2:],
                "owningProcedure": parent,
                "nativeInstruction": inst, "instructionKind": kind,
            },
        })
    return {
        "originalSourcesVerified": True,
        "byteReturnPath": {"returnedByteAddress": "0x351055"},
        "remainingSites": out,
    }


def function_evidence(entry: str, address: str, sha="a"*64):
    end = hex(int(entry, 16)+0x1f0)
    pseudo = "\n".join((
        "void FUN_original(void) {",
        "  undefined1 value;",
        "  value = DAT_00351055;",
        "  if (value != 0) {",
        "    DAT_00351055 = value;",
        "  }",
        "  return;",
        "}",
    ))
    return evidence_obj(sha, "analyze_function", "procedure", entry, {
        "procedure": {"address": entry, "name": "FUN_original",
                      "body": {"available": True, "ranges": [
                          {"start": entry, "end": end}]}},
        "pseudocode": pseudo, "native_value_flow": {"available": True},
    })


def instructions(entry: str, site: str, operands: str, sha="a"*64):
    first = int(site,16)-16
    rows = [
        f"{hex(first)}: adrp x8, 0x351000",
        f"{hex(first+4)}: add x8, x8, #0x48",
        f"{hex(first+8)}: nop",
        f"{hex(first+12)}: mov w19, w0",
        f"{site}: strb {operands.replace('w19,','w19, ').replace('wzr,','wzr, ')}",
        f"{hex(first+20)}: nop",
        f"{hex(first+24)}: ret",
    ]
    return evidence_obj(sha,"read_function_instructions","procedure",entry,rows)


class Hxl1ByteProducersTests(unittest.TestCase):
    def test_precise_two_original_candidate_stores(self):
        got = producers.verified_xref_candidates(previous())
        self.assertEqual([(c["ownerEntry"],c["site"]) for c in got], [
            ("0x33c88","0x33d08"),("0x33da8","0x33ee0")
        ])
        self.assertTrue(all(not c["actualMemoryWriteProven"] for c in got))
        self.assertFalse(any(c["effectiveAddressVerified"] for c in got))

    def test_wrong_parent_or_store_operand_rejected(self):
        snapshot = previous()
        snapshot["remainingSites"][2]["observation"]["owningProcedure"] = "0x33c80"
        with self.assertRaisesRegex(TriageError,"candidate store mismatched"):
            producers.verified_xref_candidates(snapshot)
        snapshot = previous()
        snapshot["remainingSites"][2]["observation"]["nativeInstruction"] = (
            "strb w20,[x8,#0xd]")
        with self.assertRaisesRegex(TriageError,"candidate store mismatched"):
            producers.verified_xref_candidates(snapshot)

    def test_rejects_unverified_missing_or_new_xrefs(self):
        snapshot = previous()
        snapshot["remainingSites"].pop()
        with self.assertRaisesRegex(TriageError,"8-site"):
            producers.verified_xref_candidates(snapshot)
        snapshot = previous()
        snapshot["remainingSites"][0]["observation"]["instructionKind"] = "store-instruction"
        with self.assertRaisesRegex(TriageError,"instruction kind"):
            producers.verified_xref_candidates(snapshot)

    def test_function_owner_contains_original_store(self):
        ev = function_evidence("0x33c88","0x33d08")
        got = producers.function_context(ev,entry="0x33c88",site="0x33d08")
        self.assertEqual(got["entry"],"0x33c88")
        self.assertFalse(got["producerOrAliasVerified"])
        self.assertTrue(got["selectedCode"])
        with self.assertRaisesRegex(TriageError,"owning function differs"):
            producers.function_context(ev,entry="0x33da8",site="0x33d08")

    def test_native_listing_requires_exact_store(self):
        ev = instructions("0x33c88","0x33d08","w19,[x8,#0xd]")
        got = producers.native_context(
            ev,entry="0x33c88",site="0x33d08",
            opcode="strb",operands="w19,[x8,#0xd]")
        self.assertTrue(got["nativeStoreOpcodeVerified"])
        self.assertFalse(got["nativeStoreAddressAliasVerified"])
        self.assertEqual(got["instructionCount"],7)
        with self.assertRaisesRegex(TriageError,"STRB instruction differs"):
            producers.native_context(
                ev,entry="0x33c88",site="0x33d08",
                opcode="strb",operands="w19,[x19,#0xd]")

    def test_plan_exactly_four_readonly_requests(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(producers,"verify_prior_writers",
                                   return_value=previous()),\
                 mock.patch.object(producers,"choose_targets",
                                   return_value=[target]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("No Ghidra in plan mode")):
                result=producers.audit(root)
        self.assertEqual(result["queryCount"],4)
        self.assertEqual(len(result["storeCandidates"]),2)
        self.assertEqual(result["storeCandidates"][0]["ownerEntry"],"0x33c88")
        self.assertIsNone(result["storeCandidates"][0]["functionDossier"])
        self.assertIsNone(result["storeCandidates"][0]["nativeDossier"])
        self.assertFalse(result["actualWriterIdentified"])
        self.assertFalse(result["trustedBootStateSourceIdentified"])
        self.assertFalse(result["deviceModified"])
        self.assertIn("0x33c88 store 0x33d08",producers.markdown(result))

    def test_cached_dossiers_reduce_number_of_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            folder=root/"rea-security-audit"/"LinuxLoader"
            folder.mkdir(parents=True)
            for owner, site, op, operands, _ in producers.CANDIDATES:
                (folder/f"function-{owner}.json").write_text(
                    json.dumps(function_evidence(owner,site)))
                (folder/f"instructions-{owner}.json").write_text(
                    json.dumps(instructions(owner,site,operands)))
            target=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(producers,"verify_prior_writers",
                                   return_value=previous()),\
                 mock.patch.object(producers,"choose_targets",
                                   return_value=[target]):
                result=producers.audit(root)
        self.assertEqual(result["queryCount"],0)
        self.assertEqual(len(result["storeCandidates"]),2)
        self.assertTrue(all(x["functionDossier"] and x["nativeDossier"]
                            for x in result["storeCandidates"]))
        self.assertFalse(result["actualWriterIdentified"])

    def test_no_phone_or_firmware_execution(self):
        raw=Path(producers.__file__).read_text()
        for forbidden in ("fastboot flash","adb shell","heimdall flash",
                          "subprocess.Popen(", "os.system("):
            self.assertNotIn(forbidden,raw)


if __name__=="__main__":
    unittest.main()
