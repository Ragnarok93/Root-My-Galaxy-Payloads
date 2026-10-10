#!/usr/bin/env python3
"""Synthetic REA saved-Evidence tests; never contacts real Ghidra/device."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_linuxloader_rea_stage4_seeds as stage4


class GhidraStage4SeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.loader = self.directory / "LinuxLoader-HXL1.efi"
        self.loader.write_bytes(b"synthetic loader bytes for test only")
        self.fake_sha = stage4.digest(self.loader)
        self.data = {}
        for q in stage4.QUERIES:
            evidence = {
                "evidence_id": "ev_test_" + q,
                "operation": "search_strings",
                "provider": {"id": "ghidra", "name": "Ghidra", "version": "12.1.4"},
                "subject": {"name": "LinuxLoader-HXL1.efi",
                            "digest": {"sha256": self.fake_sha},
                            "architecture": "arm64", "format": "pe"},
                "parameters": {"pattern": q, "mode": "literal",
                               "case_sensitive": False},
                "normalized_result": [{"address": "0x2000", "value": "bootimg kernel dtb"}],
            }
            self.data[q] = evidence
            self.write(q)

    def write(self, query):
        (self.directory / ("rea-ghidra-search-" + query + ".json")).write_text(
            json.dumps(self.data[query]))

    def audit(self):
        with patch.object(stage4, "LOADER_SHA256", self.fake_sha):
            return stage4.analyze(self.directory)

    def test_exact_provenance_and_static_coordinates(self):
        result = self.audit()
        self.assertEqual(result["classification"],
                         "REA_GHIDRA_STATIC_SEARCH_EVIDENCE_ONLY")
        self.assertEqual([p["hitCount"] for p in result["queries"]], [1, 1, 1])
        self.assertFalse(result["physicalKernelLoadVerified"])
        self.assertFalse(result["actualHandoffVerified"])
        self.assertFalse(result["deviceModified"])

    def test_modified_original_loader_refused(self):
        self.loader.write_bytes(b"wrong")
        with self.assertRaisesRegex(stage4.EvidenceError, "hash mismatch"):
            self.audit()

    def test_foreign_target_digest_unverified(self):
        self.data["kernel"]["subject"]["digest"]["sha256"] = "0" * 64
        self.write("kernel")
        result = self.audit()
        self.assertEqual(result["queries"][1]["status"], "UNVERIFIED_EVIDENCE")

    def test_foreign_analysis_provider_rejected(self):
        self.data["dtb"]["provider"]["id"] = "hopper"
        self.write("dtb")
        result = self.audit()
        self.assertEqual(result["queries"][2]["status"], "UNVERIFIED_EVIDENCE")

    def test_no_strict_conclusion_on_zero_string_hits(self):
        self.data["kernel"]["normalized_result"] = []
        self.write("kernel")
        result = self.audit()
        self.assertEqual(result["queries"][1]["status"], "VERIFIED_STATIC_SEARCH")
        self.assertEqual(result["queries"][1]["hitCount"], 0)
        with patch.object(stage4, "LOADER_SHA256", self.fake_sha):
            md = stage4.markdown(result)
        self.assertIn("does not prove there is no loader code", md)

    def test_query_mismatch_is_not_promoted(self):
        self.data["bootimg"]["parameters"]["pattern"] = "ramdisk"
        self.write("bootimg")
        result = self.audit()
        self.assertEqual(result["queries"][0]["status"], "UNVERIFIED_EVIDENCE")

    def test_cea_error_object_is_not_promoted(self):
        self.data["dtb"] = {"error": "Analysis failed", "code": "timeout"}
        self.write("dtb")
        result = self.audit()
        self.assertEqual(result["queries"][2]["status"], "UNVERIFIED_EVIDENCE")

    def test_forged_memory_address_rejected(self):
        self.data["kernel"]["normalized_result"][0]["address"] = "0x2000;rm -rf"
        self.write("kernel")
        with self.assertRaisesRegex(stage4.EvidenceError, "Invalid address"):
            self.audit()


if __name__ == "__main__":
    unittest.main()
