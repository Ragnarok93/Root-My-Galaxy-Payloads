#!/usr/bin/env python3
"""Synthetic regressions for real-HXL1 handoff and fallback-byte provenance."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_linuxloader_rea_stage4_handoff as handoff
from tools.y2q_linuxloader_rea_stage4_xrefs import AuditError

ORIGINAL_STYLE_CODE = """
local_190 = (code *)(local_1c0 | *puVar1);
local_190 = local_190 + uVar14;
lVar13 = FUN_0001e868();
if (lVar13 < 0) {
  FUN_00039818(0x80000000,"ERROR: Can not shutdown UEFI boot services.");
}
else {
  FUN_0001e9b8();
  FUN_0002d878(1);
  if (local_130 == '\\0') {
    (*local_190)(local_178,local_1c0,(longlong)local_190 - local_1c0,0);
  }
  else if (uVar23 == 0) {
    (*local_190)(0,0,local_178);
  }
  else {
    lVar13 = (*pcVar24)(local_108);
  }
}
"""


class HandoffEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.sources = {
            "oem-offset-words": ("0xb2210", 16, "00000800000060050000c00300800000"),
            "kaslr-static-word": ("0x32a4c8", 4, "40000000"),
        }
        self.write_rea()

    def write_rea(self):
        for label, (addr, count, hx) in self.sources.items():
            report = {
                "operation": "read_bytes",
                "provider": {"id": "ghidra"},
                "subject": {"digest": {"sha256": handoff.LOADER_SHA256},
                            "architecture": "arm64"},
                "parameters": {"address": addr, "length": count},
                "normalized_result": {
                    "address": addr, "requested_bytes": count,
                    "returned_bytes": count, "complete": True, "bytes_hex": hx,
                },
                "evidence_id": "ev_" + label,
            }
            (self.folder / ("rea-stage4-" + label + ".json")).write_text(json.dumps(report))

    def run_audit(self, code=ORIGINAL_STYLE_CODE):
        auth = {"loaderSha256": handoff.LOADER_SHA256}
        with patch.object(handoff, "authenticate_placement", return_value=auth):
            with patch.object(handoff, "original_dossier", return_value={"pseudocode": code}):
                return handoff.evaluate(self.folder)

    def test_real_fallback_values_and_static_handoff(self):
        report = self.run_audit()
        vals = report["fallbackConstants"]
        self.assertEqual(vals["arm64Offset"], 0x80000)
        self.assertEqual(vals["arm64RegionBytes"], 0x05600000)
        self.assertEqual(vals["alternateRegionBytes"], 0x03c00000)
        self.assertEqual(vals["alternateOffset"], 0x8000)
        self.assertEqual(report["kaslrState"]["imageInitializer"], 0x40)
        self.assertFalse(report["kernelRuntimePhysicalBaseMeasured"])
        self.assertFalse(report["kernelEntryExecutedObserved"])
        self.assertFalse(report["deviceModified"])

    def test_exact_arm64_abi_arguments_in_static_source(self):
        report = self.run_audit()
        self.assertEqual(report["staticHandoff"]["arm64DirectKernelEntry"], "local_190")
        self.assertEqual(report["staticHandoff"]["arm64ArgumentExpressions"],
                         ["local_178", "local_1c0", "(longlong)local_190 - local_1c0", "0"])

    def test_no_claim_of_running_boot_device(self):
        report = self.run_audit()
        md = handoff.render(report)
        self.assertIn("NOT proven", md)
        self.assertIn("runtime BaseMemory", md)
        self.assertFalse(report["actualDtbSelected"])

    def test_little_endian_data_tamper_fails(self):
        self.sources["oem-offset-words"] = (
            "0xb2210", 16, "00000800000060050000c00300080000")
        self.write_rea()
        with self.assertRaisesRegex(AuditError, "fallback constants differ"):
            self.run_audit()

    def test_static_sentinel_is_not_runtime_kaslr(self):
        self.sources["kaslr-static-word"] = ("0x32a4c8", 4, "00000000")
        self.write_rea()
        with self.assertRaisesRegex(AuditError, "sentinel"):
            self.run_audit()

    def test_incomplete_ghidra_bytes_rejected(self):
        path = self.folder/"rea-stage4-oem-offset-words.json"
        obj = json.loads(path.read_text())
        obj["normalized_result"]["complete"] = False
        path.write_text(json.dumps(obj))
        with self.assertRaisesRegex(AuditError, "not complete"):
            self.run_audit()

    def test_foreign_loader_digest_rejected(self):
        path = self.folder/"rea-stage4-oem-offset-words.json"
        obj = json.loads(path.read_text())
        obj["subject"]["digest"]["sha256"] = "0"*64
        path.write_text(json.dumps(obj))
        with self.assertRaisesRegex(AuditError, "not from the original"):
            self.run_audit()

    def test_missing_arm64_indirect_jump_rejected(self):
        with self.assertRaisesRegex(AuditError, "three handoff"):
            self.run_audit(ORIGINAL_STYLE_CODE.replace(
                "(*local_190)(local_178,local_1c0,(longlong)local_190 - local_1c0,0);",
                "unknown_jump();"))

    def test_wrong_exit_order_rejected(self):
        code = ORIGINAL_STYLE_CODE.replace(
            "lVar13 = FUN_0001e868();", "lVar13 = FUN_0001e868_removed();")
        with self.assertRaisesRegex(AuditError, "shutdown precedes"):
            self.run_audit(code)

    def test_static_byte_result_address_mismatch_rejected(self):
        path = self.folder/"rea-stage4-kaslr-static-word.json"
        obj = json.loads(path.read_text())
        obj["normalized_result"]["address"] = "0x1234"
        path.write_text(json.dumps(obj))
        with self.assertRaisesRegex(AuditError, "not complete or not at requested"):
            self.run_audit()


if __name__ == "__main__":
    unittest.main()
