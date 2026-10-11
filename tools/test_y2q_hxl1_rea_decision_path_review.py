#!/usr/bin/env python3
"""Synthetic verification of five saved original-HXL1 REA/Ghidra dossier chains."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_decision_path_review as review
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj, seeded_tree


def make_saved_evidence(root: Path) -> dict[str, str]:
    sha = seeded_tree(root)
    report_dir = root / "rea-security-audit"
    report_dir.mkdir(parents=True)
    (report_dir / "security-paths.json").write_text(json.dumps({
        "mode": "EXECUTE_STATIC_GHIDRA",
        "originalArchiveSha256": review.HXL1_BL_SHA256,
        "sourceAttested": True,
        "bootloaderUnlockDemonstrated": False,
    }))
    for module, label, term, string_addr, source, entry, hypothesis in review.SEEDS:
        directory = report_dir / module
        directory.mkdir(parents=True, exist_ok=True)
        search = evidence_obj(sha[module], "search_strings", "pattern", term, [
            {"address": string_addr, "value": f"{term}: synthetic"}])
        xrefs = evidence_obj(sha[module], "xrefs", "address", string_addr, [source])
        fn = evidence_obj(sha[module], "analyze_function", "procedure", source, {
            "procedure": {
                "address": entry, "name": f"FUN_{entry[2:]}",
                "body": {"available": True,
                         "ranges": [
                             {"start": source, "end": source},
                             {"start": entry, "end": entry},
                         ]},
            },
            "pseudocode": f"if (OEM_UNLOCK) {{\n  // {hypothesis}\n  return 1;\n}}",
            "native_value_flow": {"available": True},
        })
        for path, obj in (
            (directory / f"search-{label}.json", search),
            (directory / f"xrefs-{label}-{base.safe_segment(string_addr)}.json", xrefs),
            (directory / f"function-{base.safe_segment(source)}.json", fn),
        ):
            path.write_text(json.dumps(obj))
    return sha


class GhidraDossierTests(unittest.TestCase):
    def test_five_authentic_original_reference_chains(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            with mock.patch.dict(base.EXPECTED, hashes):
                result = review.audit(root)
            self.assertTrue(result["allFiveReferencesVerified"])
            self.assertEqual(result["qualifiedFunctionReferences"], 5)
            self.assertEqual(result["unresolved"], [])
            self.assertFalse(result["deviceUnlockDemonstrated"])
            self.assertFalse(result["vulnerabilityDemonstrated"])
            self.assertTrue(all(x["verifiedGhidraFunctionBody"] for x in result["references"]))
            self.assertTrue(any(x["disjointBodyPossible"] for x in result["references"]))
            md = review.to_markdown(result)
            self.assertIn("OEM unlock and verified-boot", md)
            self.assertIn("numerically before", md)
            self.assertIn("AUTHENTICATED_STATIC_REFERENCE_ONLY", json.dumps(result))

    def test_ghidra_source_xref_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            module, label, _, addr, _, _, hypothesis = review.SEEDS[0]
            path = root / "rea-security-audit" / module / f"xrefs-{label}-{base.safe_segment(addr)}.json"
            saved = json.loads(path.read_text())
            saved["normalized_result"] = ["0x0"]
            path.write_text(json.dumps(saved))
            with mock.patch.dict(base.EXPECTED, hashes):
                result = review.audit(root)
            self.assertEqual(result["qualifiedFunctionReferences"], 4)
            self.assertFalse(result["allFiveReferencesVerified"])
            self.assertEqual(result["unresolved"][0]["hypothesis"], hypothesis)

    def test_wrong_ghidra_function_entry_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            module, label, _, _, src, _, hypothesis = review.SEEDS[1]
            path = root / "rea-security-audit" / module / f"function-{base.safe_segment(src)}.json"
            saved = json.loads(path.read_text())
            saved["normalized_result"]["procedure"]["address"] = "0x11"
            saved["normalized_result"]["procedure"]["body"]["ranges"].append({
                "start": "0x11", "end": "0x11"})
            path.write_text(json.dumps(saved))
            with mock.patch.dict(base.EXPECTED, hashes):
                result = review.audit(root)
            self.assertFalse(result["allFiveReferencesVerified"])
            self.assertEqual(result["unresolved"][0]["hypothesis"], hypothesis)

    def test_original_binary_change_hard_stop(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            copied = next((root / "comparison-inputs" / "HXL1" /
                           "uefi-modules" / "abl.elf").glob("000-*.efi"))
            copied.write_bytes(b"tamper")
            with mock.patch.dict(base.EXPECTED, hashes):
                with self.assertRaisesRegex(base.TriageError, "SHA256"):
                    review.audit(root)

    def test_context_bounded_without_match(self):
        self.assertEqual(review.candidate_context("return 0;")["matchingLineCount"], 0)
        very_long = "\n".join("if (oem_unlock) return 1;" for _ in range(300))
        sliced = review.candidate_context(very_long)
        self.assertLessEqual(len(sliced["selectedLines"]), review.MAX_SNIPPET_LINES)
        self.assertTrue(sliced["matchingLinesTruncated"])
        self.assertTrue(sliced["excerptTruncated"])

    def test_no_rea_or_firmware_execution(self):
        source = Path(review.__file__).read_text()
        for banned in ("subprocess", "os.system", "adb shell", "fastboot flash"):
            self.assertNotIn(banned, source)
        self.assertIn('"deviceModified": False', source)


if __name__ == "__main__":
    unittest.main()
