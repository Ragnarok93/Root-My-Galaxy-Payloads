#!/usr/bin/env python3
"""Synthetic tests for REA three-seed Ghidra xrefs, no live Ghidra."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_linuxloader_rea_stage4_xrefs as xrefs


class LinuxLoaderXrefsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.loader = self.folder / "LinuxLoader-HXL1.efi"
        self.loader.write_bytes(b"synthetic PE fixture")
        self.fake_sha = xrefs.digest(self.loader)
        self.seeds = []
        for label, group, address, needle in xrefs.REFS:
            self.seeds.append({
                "query": group, "status": "VERIFIED_STATIC_SEARCH",
                "evidenceId": "ev_search_" + label,
                "hits": [{"address": address, "value": needle + " (test)"}],
            })
            doc = {
                "evidence_id": "ev_xrefs_" + label,
                "operation": "xrefs",
                "subject": {"digest": {"sha256": self.fake_sha},
                            "architecture": "arm64"},
                "provider": {"id": "ghidra"},
                "parameters": {"address": address},
                "normalized_result": ["0x12abc", "0x12ac0"],
            }
            self.save(label, doc)
        self.write_seeds()

    def save(self, label, document):
        (self.folder / ("rea-stage4-xrefs-" + label + ".json")).write_text(
            json.dumps(document))

    def load(self, label):
        return json.loads((self.folder / ("rea-stage4-xrefs-" + label + ".json")).read_text())

    def write_seeds(self):
        groups = {}
        for row in self.seeds:
            if row["query"] not in groups:
                groups[row["query"]] = {
                    "query": row["query"],
                    "status": row["status"],
                    "evidenceId": row["evidenceId"],
                    "hits": [],
                }
            groups[row["query"]]["hits"].extend(row["hits"])
        (self.folder / "rea-stage4-seed-audit.json").write_text(
            json.dumps({"originalLoaderSha256": self.fake_sha,
                        "queries": list(groups.values())}))

    def go(self):
        with patch.object(xrefs, "LOADER_SHA256", self.fake_sha):
            return xrefs.assess(self.folder)

    def test_three_distinct_seed_xrefs_are_authenticated(self):
        report = self.go()
        self.assertEqual(len(report["references"]), 3)
        self.assertTrue(all(p["status"] == "VERIFIED_GHIDRA_XREFS"
                            for p in report["references"]))
        self.assertEqual(report["references"][0]["sourceAddresses"],
                         ["0x12abc", "0x12ac0"])
        self.assertFalse(report["physicalKernelLoadVerified"])
        self.assertFalse(report["kernelHandoffVerified"])
        self.assertFalse(report["deviceModified"])

    def test_zero_xrefs_are_valid_negative_result_not_absence_of_loader(self):
        document = self.load("best-dtb-match")
        document["normalized_result"] = []
        self.save("best-dtb-match", document)
        report = self.go()
        self.assertEqual(report["references"][2]["crossReferenceCount"], 0)
        self.assertIn("does not exclude", xrefs.markdown(report))

    def test_stale_foreign_loader_digest_not_accepted(self):
        document = self.load("kernel-load-print")
        document["subject"]["digest"]["sha256"] = "0"*64
        self.save("kernel-load-print", document)
        report = self.go()
        self.assertEqual(report["references"][0]["status"], "XREFS_NOT_YET_VERIFIED")

    def test_wrong_xrefs_coordinate_rejected(self):
        document = self.load("kernel-dt-boundary")
        document["parameters"]["address"] = "0xdead"
        self.save("kernel-dt-boundary", document)
        report = self.go()
        self.assertEqual(report["references"][1]["status"], "XREFS_NOT_YET_VERIFIED")

    def test_wrong_seed_string_coordinate_is_hard_stop(self):
        self.seeds[0]["hits"][0]["address"] = "0xbaad"
        self.write_seeds()
        with self.assertRaisesRegex(xrefs.AuditError, "not verified"):
            self.go()

    def test_references_are_not_trusted_as_physical_addresses(self):
        document = self.load("kernel-load-print")
        document["normalized_result"] = ["0x1234567;drop", "0x12abc"]
        self.save("kernel-load-print", document)
        report = self.go()
        self.assertEqual(report["references"][0]["status"], "XREFS_NOT_YET_VERIFIED")
        self.assertFalse(report["physicalKernelLoadVerified"])

    def test_genuine_duplicate_xrefs_have_one_reported_source(self):
        document = self.load("kernel-load-print")
        document["normalized_result"] = ["0x12abc", "0x12abc"]
        self.save("kernel-load-print", document)
        report = self.go()
        self.assertEqual(report["references"][0]["crossReferenceCount"], 2)
        self.assertEqual(report["references"][0]["sourceAddresses"], ["0x12abc"])

    def test_wrong_provider_refused(self):
        document = self.load("best-dtb-match")
        document["provider"]["id"] = "hopper"
        self.save("best-dtb-match", document)
        report = self.go()
        self.assertEqual(report["references"][2]["status"], "XREFS_NOT_YET_VERIFIED")

    def test_wrong_original_loader_bytes_refused(self):
        self.loader.write_bytes(b"damaged fixture")
        with self.assertRaisesRegex(xrefs.AuditError, "SHA256"):
            self.go()

    def test_missing_query_file_reported_as_gap(self):
        (self.folder / "rea-stage4-xrefs-best-dtb-match.json").unlink()
        report = self.go()
        self.assertEqual(report["references"][2]["status"], "XREFS_NOT_YET_VERIFIED")


if __name__ == "__main__":
    unittest.main()
