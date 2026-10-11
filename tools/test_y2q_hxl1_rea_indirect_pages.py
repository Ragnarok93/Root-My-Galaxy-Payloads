#!/usr/bin/env python3
"""Synthetic tests for HXL1 original-REA paged indirect-call provenance."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_indirect_pages as paged
from tools import y2q_hxl1_rea_security_audit as base
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError
from tools.test_y2q_hxl1_rea_decision_path_review import make_saved_evidence
from tools.test_y2q_hxl1_rea_trace_evidence import workflow_fixture
from tools.test_y2q_hxl1_rea_graph_forensics import node


def fixture_pages(sha: str, entry: str):
    initial = workflow_fixture(sha, entry)
    g = initial["normalized_result"]
    g["nodes"] = [node(entry, "indirect-1", entry, "CALLIND"),
                  node(entry, "direct", "0x2000", "CALL")]
    g["total_nodes"] = 3
    g["total_edges"] = 0
    g["next_offset"] = 2
    g["truncated"] = True
    g["unknowns"] = [{"procedure": entry, "address": None,
                      "reason": "decompilation budget reached"}]
    page = json.loads(json.dumps(initial))
    pg = page["normalized_result"]
    pg["nodes"] = [node(entry, "indirect-2", "0x5000", "CALLIND")]
    pg["next_offset"] = None
    page["parameters"]["offset"] = 2
    page["parameters"]["limit"] = 1000
    return initial, page


class Hxl1PagedRootTests(unittest.TestCase):
    def test_complete_indirect_inventory_and_budget_warning(self):
        a, b = fixture_pages("c"*64, "0x5950")
        r = paged.inspect_pages(a, b, entry="0x5950")
        self.assertEqual(r["coveredNodes"], 3)
        self.assertEqual(r["totalNodes"], 3)
        self.assertEqual(r["pages"], 2)
        self.assertEqual(len(r["rootIndirectCallsObserved"]), 2)
        self.assertTrue(r["truncatedDespiteAllNodes"])
        self.assertTrue(r["decompilationBudgetReached"])
        self.assertIsNone(r["nextOffset"])
        self.assertFalse(r["indirectCallTargetProven"])
        md = paged.markdown({"originalArchiveSha256": "c"*64,
                             "mode": "SAVED_ONLY_PLAN", "newCommands": 0,
                             "roots": [dict(r, module="LinuxLoader",
                                            pendingSecondPage=False)]})
        self.assertIn("CALLIND", md)
        self.assertIn("Graph truncation flag with all retained nodes: True", md)

    def test_partial_gap_never_infers_target_absent(self):
        a, b = fixture_pages("c"*64, "0x5950")
        r = paged.inspect_pages(a, None, entry="0x5950")
        self.assertEqual(r["coveredNodes"], 2)
        self.assertEqual(r["nextOffset"], 2)
        self.assertEqual(len(r["rootIndirectCallsObserved"]), 1)

    def test_changed_graph_and_duplicate_identity_rejected(self):
        a, b = fixture_pages("c"*64, "0x5950")
        b["normalized_result"]["total_edges"] = 100
        with self.assertRaisesRegex(TriageError, "inconsistent"):
            paged.inspect_pages(a, b, entry="0x5950")
        a, b = fixture_pages("c"*64, "0x5950")
        b["normalized_result"]["nodes"][0]["id"] = a["normalized_result"]["nodes"][0]["id"]
        with self.assertRaisesRegex(TriageError, "Overlapping"):
            paged.inspect_pages(a, b, entry="0x5950")

    def test_page_validation_binds_query_offset_and_limits(self):
        from tools.y2q_hxl1_rea_trace_evidence import validated_trace
        a, b = fixture_pages("c"*64, "0x5950")
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "trace.json"
            dest.write_text(json.dumps(b))
            self.assertEqual(validated_trace(dest, sha="c"*64, entry="0x5950",
                                             offset=2, limit=1000),
                             b)
            with self.assertRaisesRegex(TriageError, "pagination parameters"):
                validated_trace(dest, sha="c"*64, entry="0x5950",
                                offset=1, limit=1000)
            b["normalized_result"]["next_offset"] = 3
            dest.write_text(json.dumps(b))
            with self.assertRaisesRegex(TriageError, "pagination result"):
                validated_trace(dest, sha="c"*64, entry="0x5950",
                                offset=2, limit=1000)

    def test_plan_does_not_launch_ghidra(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)
            for name, entry in paged.TARGETS:
                a, b = fixture_pages(sha[name], entry)
                if name == "Odin":
                    a["normalized_result"]["nodes"] += b["normalized_result"]["nodes"]
                    a["normalized_result"]["total_nodes"] = 3
                    a["normalized_result"]["next_offset"] = None
                dest = root / "rea-security-audit" / name / ("trace-" + entry + ".json")
                dest.write_text(json.dumps(a))
            with mock.patch.dict(base.EXPECTED, sha):
                with mock.patch.object(base.subprocess, "Popen",
                                       side_effect=AssertionError("no subprocess")):
                    result = paged.review(root)
            self.assertEqual(result["mode"], "SAVED_ONLY_PLAN")
            self.assertEqual(result["newCommands"], 1)
            self.assertTrue(result["roots"][1]["pendingSecondPage"])
            self.assertFalse(result["authorizationBypassEstablished"])

    def test_invalid_source_attestation_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)
            for name, entry in paged.TARGETS:
                a, b = fixture_pages(sha[name], entry)
                if name == "Odin":
                    a["normalized_result"]["nodes"] += b["normalized_result"]["nodes"]
                    a["normalized_result"]["next_offset"] = None
                (root / "rea-security-audit" / name / ("trace-" + entry + ".json")).write_text(json.dumps(a))
            with mock.patch.dict(base.EXPECTED, {"Odin": "e"*64}):
                with self.assertRaisesRegex(TriageError, "pinned"):
                    paged.review(root)

    def test_no_live_firmware_or_device_actions(self):
        source = Path(paged.__file__).read_text()
        for forbidden in ("fastboot flash", "adb shell", "heimdall flash", "os.system("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
