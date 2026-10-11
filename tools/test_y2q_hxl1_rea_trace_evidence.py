#!/usr/bin/env python3
"""REA workflow trace tests: original SHA profile, no-clobber partial recovery."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools import y2q_hxl1_rea_trace_evidence as trace
from tools.y2q_hxl1_rea_security_audit import Runner, Target
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def workflow_fixture(sha: str, entry: str) -> dict:
    upstream = {
        "provider": {"id": "ghidra", "name": "Ghidra", "version": "12.1"},
        "digest": "a" * 64, "parameters": {"analysis_mode": "fixture"},
    }
    return {
        "operation": "trace_native_values",
        "provider": {"id": "rea-workflow", "name": "REA", "version": "1"},
        "subject": {"digest": {"sha256": sha}, "architecture": "arm64"},
        "parameters": {"procedure": entry},
        "analysis_profile": {
            "provider": {"id": "rea-workflow", "name": "REA", "version": "1"},
            "digest": "b" * 64,
            "parameters": {"upstream_analysis_profile": upstream},
        },
        "normalized_result": {
            "seed": entry, "target_sha256": sha,
            "nodes": [], "edges": [], "unknowns": [],
            "procedures": [
                {"address": entry, "depth": 0, "provider": "ghidra",
                 "analysis_profile_digest": "a" * 64, "evidence_id": "ev_synthetic"}
            ],
            "total_nodes": 0, "total_edges": 0, "decompilations": 1,
            "next_offset": None, "truncated": False, "limitations": [],
        },
        "evidence_id": "ev_synthetic_workflow",
    }


class TraceEvidenceTests(unittest.TestCase):
    def test_rea_workflow_with_original_upstream_ghidra_is_accepted(self):
        sha, entry = "c" * 64, "0x1ec00"
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "trace.json"
            data = workflow_fixture(sha, entry)
            f.write_text(json.dumps(data))
            validated = trace.validated_trace(f, sha=sha, entry=entry)
            self.assertEqual(validated["provider"]["id"], "rea-workflow")
            self.assertEqual(validated["normalized_result"]["seed"], entry)

    def test_only_original_sha_seed_and_ghidra_profile_accepted(self):
        sha, entry = "c" * 64, "0x1ec00"
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "trace.json"
            def check(blob, expected):
                f.write_text(json.dumps(blob))
                with self.assertRaisesRegex(TriageError, expected):
                    trace.validated_trace(f, sha=sha, entry=entry)
            good = workflow_fixture(sha, entry)
            for field, bad in (("provider", "ghidra"), ("subject", "no"),
                               ("seed", "0x222"), ("upstream", "fixture"),
                               ("upstream_sha", "f" * 64), ("procedure", "0x222")):
                obj = json.loads(json.dumps(good))
                if field == "provider":
                    obj["provider"]["id"] = bad
                elif field == "subject":
                    obj["subject"]["digest"]["sha256"] = bad
                elif field == "seed":
                    obj["normalized_result"]["seed"] = bad
                elif field == "upstream":
                    obj["analysis_profile"]["parameters"]["upstream_analysis_profile"]["provider"]["id"] = bad
                elif field == "upstream_sha":
                    obj["normalized_result"]["target_sha256"] = bad
                else:
                    obj["parameters"]["procedure"] = bad
                check(obj, "mismatch|profile")
            obj = json.loads(json.dumps(good))
            obj["normalized_result"]["procedures"][0]["analysis_profile_digest"] = "f"*64
            check(obj, "procedure without original Ghidra profile")
            obj = json.loads(json.dumps(good))
            obj["normalized_result"]["procedures"][0]["address"] = "0x1234"
            check(obj, "no exact original Ghidra seed")

    def test_no_clobber_recovery_of_completed_partial(self):
        sha, entry = "c" * 64, "0x1ec00"
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            final = folder / "trace-0x1ec00.json"
            partial = final.with_suffix(".json.partial")
            content = json.dumps(workflow_fixture(sha, entry))
            partial.write_text(content)
            (folder / "trace-0x1ec00.json.stderr.txt").write_text("")
            target = Target("Odin", folder / "original.efi", sha, {})
            runner = Runner(folder, folder / "rea.mjs", run_commands=True,
                            recover_partials=True)
            observed = runner.obtain(
                target, ["trace-native-values", str(target.path), entry], final,
                operation="trace_native_values", parameter="procedure", value=entry)
            self.assertEqual(observed["normalized_result"]["seed"], entry)
            self.assertTrue(final.is_file())
            self.assertEqual(final.read_text(), content)
            self.assertEqual(partial.read_text(), content)
            self.assertEqual(runner.planned, [])

    def test_reject_malformed_and_tampered_partial_unchanged(self):
        sha, entry = "c" * 64, "0x1ec00"
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            final = folder / "trace-0x1ec00.json"
            partial = final.with_suffix(".json.partial")
            partial.write_text('{"operation":')
            before = partial.read_text()
            with self.assertRaisesRegex(TriageError, "Incomplete or malformed"):
                trace.recover_partial_trace(final, sha=sha, entry=entry)
            self.assertFalse(final.exists())
            self.assertEqual(partial.read_text(), before)
            bad = workflow_fixture(sha, entry)
            bad["subject"]["digest"]["sha256"] = "f" * 64
            partial.write_text(json.dumps(bad))
            with self.assertRaisesRegex(TriageError, "identity mismatch"):
                trace.recover_partial_trace(final, sha=sha, entry=entry)
            self.assertFalse(final.exists())

    def test_never_overwrite_completed_trace_or_follow_symlink(self):
        sha, entry = "c" * 64, "0x1ec00"
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            final = folder / "trace-0x1ec00.json"
            partial = final.with_suffix(".json.partial")
            final.write_text("existing retained original")
            partial.write_text(json.dumps(workflow_fixture(sha, entry)))
            self.assertIsNone(trace.recover_partial_trace(final, sha=sha, entry=entry))
            self.assertEqual(final.read_text(), "existing retained original")
            final.unlink()
            partial.unlink()
            partial.symlink_to(folder / "target")
            with self.assertRaisesRegex(TriageError, "symlinked"):
                trace.recover_partial_trace(final, sha=sha, entry=entry)


if __name__ == "__main__":
    unittest.main()
