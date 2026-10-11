#!/usr/bin/env python3
"""Synthetic-only regression for saved HXL1 REA high-p-code graph inventory."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_graph_forensics as forensic
from tools import y2q_hxl1_rea_security_audit as base
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError
from tools.test_y2q_hxl1_rea_decision_path_review import make_saved_evidence
from tools.test_y2q_hxl1_rea_trace_evidence import workflow_fixture


def node(root, identity, address, opcode):
    return {
        "id": root + "/" + identity, "procedure": root, "kind": "operation",
        "evidence_id": "ev_synthetic", "parameter": None,
        "operation": {
            "id": identity, "address": address, "sequence": 0,
            "opcode": opcode, "block_membership": "member", "is_dead": False,
            "inputs": [{"kind": "constant", "size_bytes": 8,
                        "location": None, "constant_hex": "10"}],
            "output": None,
        },
    }


def sample_trace(sha, entry):
    ev = workflow_fixture(sha, entry)
    g = ev["normalized_result"]
    g["nodes"] = [node(entry, "indirect", entry, "CALLIND"),
                  node(entry, "return", "0x2345", "RETURN"),
                  node("0x2000", "call", "0x2100", "CALL")]
    g["edges"] = [
        {"source": entry+"/indirect", "target": "0x9999",
         "kind": "call", "status": "candidate", "evidence_id": "ev_synthetic",
         "input_index": None},
        {"source": entry+"/return", "target": "0x2000/call",
         "kind": "def-use", "status": "derived", "evidence_id": "ev_synthetic",
         "input_index": 0},
    ]
    g["unknowns"] = [
        {"procedure": entry, "address": entry,
         "reason": "Call target unresolved"},
        {"procedure": entry, "address": None,
         "reason": "Call target unresolved"},
    ]
    g.update({"total_nodes": 8, "total_edges": 7,
              "next_offset": 3, "truncated": True})
    return ev


class SavedGraphForensicsTests(unittest.TestCase):
    def test_root_operations_and_paging_not_overclaimed(self):
        ev = sample_trace("c"*64, "0x1ec00")
        s = forensic.summarize(ev, "Odin", "0x1ec00")
        self.assertEqual(s["rootCalls"], 1)
        self.assertEqual(s["rootCallSample"][0]["opcode"], "CALLIND")
        self.assertEqual(s["rootCallSample"][0]["address"], "0x1ec00")
        self.assertEqual(s["rootCallEdgeCount"], 1)
        self.assertFalse(s["rootCallEdgeSample"][0]["targetPresentOnPage"])
        self.assertEqual(s["unresolvedCount"], 2)
        self.assertEqual(s["unresolvedReasons"][0]["count"], 2)
        self.assertEqual(s["nextOffset"], 3)
        self.assertFalse(s["originalSecureStateProven"])
        self.assertFalse(s["vulnerabilityProven"])
        md = forensic.markdown({"originalArchiveSha256": "c"*64, "results": [s]})
        self.assertIn("COVERAGE WARNING", md)
        self.assertIn("CALLIND", md)
        self.assertIn("not prove exploitability", md)

    def test_full_original_provenance_gate_two_results(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)
            for name, entry in forensic.ROOTS:
                f = root / "rea-security-audit" / name / ("trace-" + entry + ".json")
                f.write_text(json.dumps(sample_trace(sha[name], entry)))
            with mock.patch.dict(base.EXPECTED, sha):
                report = forensic.audit(root)
            self.assertTrue(report["sourcesVerified"])
            self.assertEqual(len(report["results"]), 2)
            self.assertFalse(report["workingUnlockDemonstrated"])

    def test_bad_source_hash_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)
            for name, entry in forensic.ROOTS:
                file = root / "rea-security-audit" / name / ("trace-" + entry + ".json")
                file.write_text(json.dumps(sample_trace(sha[name], entry)))
            file = root / "rea-security-audit" / "Odin" / "trace-0x1ec00.json"
            data = json.loads(file.read_text())
            data["normalized_result"]["target_sha256"] = "f"*64
            file.write_text(json.dumps(data))
            with mock.patch.dict(base.EXPECTED, sha):
                with self.assertRaisesRegex(TriageError, "graph / seed / binary SHA256"):
                    forensic.audit(root)

    def test_duplicate_nodes_rejected(self):
        ev = sample_trace("c"*64, "0x1ec00")
        ev["normalized_result"]["nodes"].append(ev["normalized_result"]["nodes"][0])
        with self.assertRaisesRegex(TriageError, "duplicate"):
            forensic.summarize(ev, "Odin", "0x1ec00")

    def test_invalid_varnodes_and_lengths_rejected(self):
        ev = sample_trace("c"*64, "0x1ec00")
        ev["normalized_result"]["nodes"][0]["operation"]["inputs"][0]["kind"] = "garbage"
        with self.assertRaisesRegex(TriageError, "varnode kind"):
            forensic.summarize(ev, "Odin", "0x1ec00")
        ev = sample_trace("c"*64, "0x1ec00")
        ev["normalized_result"]["total_nodes"] = 1
        with self.assertRaisesRegex(TriageError, "pagination"):
            forensic.summarize(ev, "Odin", "0x1ec00")

    def test_no_reexecution_or_firmware_write(self):
        contents = Path(forensic.__file__).read_text()
        for forbidden in ("subprocess", "os.system(", "fastboot flash",
                          "adb shell", "heimdall flash"):
            self.assertNotIn(forbidden, contents)


if __name__ == "__main__":
    unittest.main()
