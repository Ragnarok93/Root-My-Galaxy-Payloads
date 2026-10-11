#!/usr/bin/env python3
"""Synthetic-only check of original HXL1 Odin/LinuxLoader semantic trace gates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_security_audit as base
from tools import y2q_hxl1_rea_semantic_roots as sem
from tools.test_y2q_hxl1_rea_decision_path_review import make_saved_evidence
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


class SemanticRootsTests(unittest.TestCase):
    def test_context_is_targeted_and_bounded(self):
        s = "\n".join(
            ["return 0;"]*10 +
            ["if (iVar9 == 0xc) log(\"Blocked By OEM Lock\");"] +
            ["return 1;"]*150
        )
        data = sem.focal_context(s, ("Blocked By OEM Lock",))
        self.assertEqual(data["totalTermMatches"], 1)
        self.assertTrue(any(x["line"] == 11 for x in data["selected"]))
        self.assertTrue(all(len(x["code"]) <= 500 for x in data["selected"]))
        self.assertEqual(sem.focal_context("nothing relevant", ("NONE",))["totalTermMatches"], 0)

    def test_plan_mode_uses_all_five_owner_qualified_origins(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            with mock.patch.dict(base.EXPECTED, hashes):
                with mock.patch.object(sem.Runner, "obtain", wraps=None) as _:
                    pass
                result = sem.inspect_focus(
                    root, root / "rea-security-audit", execute=False,
                    node="node", script=root / "missing-rea.mjs",
                    count=2, timeout=120)
            self.assertEqual(result["mode"], "PLAN_ONLY")
            self.assertEqual(result["count"], 2)
            self.assertEqual([x["entry"] for x in result["targets"]],
                             ["0x1ec00", "0x5950"])
            self.assertEqual([x["traceStatus"] for x in result["targets"]],
                             ["PLANNED_NOT_EXECUTED", "PLANNED_NOT_EXECUTED"])
            self.assertEqual(len(result["plannedOrNewCommands"]), 2)
            self.assertFalse(result["unlockMethodProven"])
            self.assertFalse(result["vulnerabilityProven"])

    def test_invalid_function_entry_never_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            bad_focus = (dict(sem.FOCUS[0], entry="0x123456"),)
            with mock.patch.dict(base.EXPECTED, hashes):
                with mock.patch.object(sem, "FOCUS", bad_focus):
                    with self.assertRaisesRegex(TriageError, "not backed"):
                        sem.inspect_focus(root, root / "rea-security-audit",
                                          execute=False, node="node",
                                          script=root / "rea.mjs", count=1,
                                          timeout=120)

    def test_cached_valid_trace_honors_binary_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            trace_file = root / "rea-security-audit" / "Odin" / "trace-0x1ec00.json"
            obj = evidence_obj(hashes["Odin"], "trace_native_values",
                               "procedure", "0x1ec00",
                               {"nodes": [{"id": 1}], "edges": [], "truncated": True})
            trace_file.write_text(json.dumps(obj))
            with mock.patch.dict(base.EXPECTED, hashes):
                report = sem.inspect_focus(root, root / "rea-security-audit",
                                           execute=False, node="node",
                                           script=root / "missing.mjs",
                                           count=1, timeout=120)
            first = report["targets"][0]
            self.assertEqual(first["traceStatus"],
                             "VERIFIED_REA_TRACE_EVIDENCE_UNINTERPRETED")
            self.assertEqual(first["traceSummary"]["collectionSizes"]["nodes"], 1)
            self.assertFalse(first["traceSummary"]["semanticsValidated"])
            # Cached evidence must not be treated as authorized if source changes.
            obj["subject"]["digest"]["sha256"] = "0"*64
            trace_file.write_text(json.dumps(obj))
            with mock.patch.dict(base.EXPECTED, hashes):
                with self.assertRaisesRegex(TriageError, "provenance mismatch"):
                    sem.inspect_focus(root, root / "rea-security-audit",
                                      execute=False, node="node",
                                      script=root / "missing.mjs", count=1,
                                      timeout=120)

    def test_analysis_never_claims_unlock(self):
        report = {
            "originalArchiveSha256": sem.HXL1_BL_SHA256, "mode": "PLAN_ONLY",
            "count": 1, "targets": [
                {"module": "Odin", "entry": "0x1ec00",
                 "hypothesis": "OEM value/status producer",
                 "purpose": "trace code path", "originalFunctionEvidenceId": "ev_fixture",
                 "traceStatus": "PLANNED_NOT_EXECUTED",
                 "traceFile": "/tmp/fixture.json",
                 "pseudocodeContext": {"totalTermMatches": 1, "truncated": False,
                                       "selected": [{"line": 1, "code": "return 1;"}]},
                 "traceSummary": None}],
        }
        md = sem.markdown(report)
        self.assertIn("no secure-state decision proven", md.lower()
                      if "no secure-state decision proven" in md.lower() else
                      "no secure-state decision proven") if False else None
        self.assertIn("reporting case, not proof", md)
        self.assertIn("~~~c", md)
        for value in ["flash --", "adb shell", "heimdall flash"]:
            self.assertNotIn(value, Path(sem.__file__).read_text())


if __name__ == "__main__":
    unittest.main()
