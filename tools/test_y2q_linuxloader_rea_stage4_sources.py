#!/usr/bin/env python3
"""Synthetic fixture tests for source function Ghidra provenance."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_linuxloader_rea_stage4_sources as mod


class SourceFunctionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        (self.folder/"LinuxLoader-HXL1.efi").write_bytes(b"synthetic source test")
        self.sha = mod.digest(self.folder/"LinuxLoader-HXL1.efi")
        for label, address, name in mod.SOURCES:
            doc = {
                "evidence_id": "ev_"+label,
                "operation": "analyze_function",
                "provider": {"id": "ghidra"},
                "subject": {"digest": {"sha256": self.sha}, "architecture": "arm64"},
                "parameters": {"procedure": address},
                "normalized_result": {
                    "procedure": {"name": name, "address": address,
                                  "body": {"available": True,
                                           "provenance": "ghidra-function-body-address-set",
                                           "ranges": [{"start": address, "end": address}]}},
                    "pseudocode": "void function() {}",
                    "native_value_flow": {"available": True, "truncated": False},
                },
            }
            self.write(label, doc)

    def write(self, label, doc):
        (self.folder/("rea-stage4-source-"+label+".json")).write_text(json.dumps(doc))

    def read(self, label):
        return json.loads((self.folder/("rea-stage4-source-"+label+".json")).read_text())

    def run_audit(self):
        with patch.object(mod, "LOADER_SHA256", self.sha):
            return mod.audit(self.folder)

    def test_all_three_source_functions_are_authenticated(self):
        result = self.run_audit()
        self.assertEqual(len(result["functions"]), 3)
        self.assertTrue(all(x["status"] == "VERIFIED_STATIC_FUNCTION"
                            for x in result["functions"]))
        self.assertFalse(result["kernelPhysicalBaseMeasured"])
        self.assertFalse(result["bootTimeKaslrMeasured"])
        self.assertFalse(result["deviceModified"])

    def test_invalid_original_loader_hash_rejected(self):
        (self.folder/"LinuxLoader-HXL1.efi").write_bytes(b"other")
        with self.assertRaisesRegex(mod.AuditError, "digest mismatch"):
            self.run_audit()

    def test_foreign_provider_not_accepted(self):
        label = "base-memory-provider"
        doc = self.read(label)
        doc["provider"]["id"] = "hopper"
        self.write(label, doc)
        result = self.run_audit()
        self.assertEqual(result["functions"][0]["status"], "FUNCTION_NOT_VERIFIED")

    def test_wrong_function_query_not_accepted(self):
        label = "kaslr-initializer"
        doc = self.read(label)
        doc["parameters"]["procedure"] = "0x1111"
        self.write(label, doc)
        result = self.run_audit()
        self.assertEqual(result["functions"][1]["status"], "FUNCTION_NOT_VERIFIED")

    def test_incorrect_containing_function_not_accepted(self):
        label = "exit-boot-services"
        doc = self.read(label)
        doc["normalized_result"]["procedure"]["body"]["ranges"] = [
            {"start": "0x0", "end": "0x100"}]
        self.write(label, doc)
        result = self.run_audit()
        self.assertEqual(result["functions"][2]["status"], "FUNCTION_NOT_VERIFIED")

    def test_highfunction_not_available_is_retained_as_unavailable(self):
        label = "base-memory-provider"
        doc = self.read(label)
        doc["normalized_result"]["native_value_flow"]["available"] = False
        self.write(label, doc)
        result = self.run_audit()
        self.assertEqual(result["functions"][0]["status"], "VERIFIED_STATIC_FUNCTION")
        self.assertFalse(result["functions"][0]["highFunctionAvailable"])

    def test_foreign_original_sha_rejected(self):
        label = "base-memory-provider"
        doc = self.read(label)
        doc["subject"]["digest"]["sha256"] = "0"*64
        self.write(label, doc)
        result = self.run_audit()
        self.assertEqual(result["functions"][0]["status"], "FUNCTION_NOT_VERIFIED")

    def test_no_pseudocode_means_unverified(self):
        label = "kaslr-initializer"
        doc = self.read(label)
        doc["normalized_result"].pop("pseudocode")
        self.write(label, doc)
        result = self.run_audit()
        self.assertEqual(result["functions"][1]["status"], "FUNCTION_NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
