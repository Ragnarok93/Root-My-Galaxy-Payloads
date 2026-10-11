#!/usr/bin/env python3
"""Host-only synthetic tests of original HXL1 SSA backward-slice conservatism."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_indirect_value_slices as slices
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_decision_path_review import make_saved_evidence
from tools.test_y2q_hxl1_rea_trace_evidence import workflow_fixture
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def operation(entry, name, address, opcode, input_count=2):
    operands = [
        {"kind": "register", "size_bytes": 8,
         "location": "register:0x4048", "constant_hex": None}
        for _ in range(input_count)
    ]
    return {
        "id": entry + "/" + name, "procedure": entry, "kind": "operation",
        "evidence_id": "ev_fixture", "parameter": None,
        "operation": {
            "id": name, "address": address, "sequence": 0, "opcode": opcode,
            "is_dead": False, "block_membership": "member",
            "inputs": operands, "output": None,
        },
    }


def connection(source, target, index):
    return {"source": source, "target": target, "input_index": index,
            "kind": "def-use", "status": "derived", "evidence_id": "ev_fixture"}


class IndirectValueSliceTests(unittest.TestCase):
    def test_pointer_operand_zero_follows_actual_static_producers_only(self):
        entry = "0x5950"
        call = operation(entry, "indirect", "0x5dc4", "CALLIND")
        load = operation(entry, "load", "0x5db8", "LOAD")
        add = operation(entry, "ptrsub", "0x5db0", "PTRSUB")
        unrelated = operation(entry, "irrelevant", "0x5dac", "COPY")
        g = {
            "nodes": [call, load, add, unrelated],
            "edges": [
                connection(load["id"], call["id"], 0),
                connection(add["id"], load["id"], 1),
                connection(unrelated["id"], call["id"], 1),
            ],
        }
        result = slices.backward_slice(g, entry=entry, site="0x5dc4")
        self.assertEqual(result["chainNodeCount"], 3)
        self.assertEqual([x["opcode"] for x in result["chain"]],
                         ["CALLIND", "LOAD", "PTRSUB"])
        self.assertTrue(result["loadRequiresAliasResolution"])
        self.assertFalse(result["indirectTargetResolved"])
        self.assertFalse(result["securityStateSourceEstablished"])
        self.assertEqual(result["targetOperand"]["kind"], "register")

    def test_missing_memory_alias_and_missing_edges_are_not_forged(self):
        entry = "0x1ec00"
        call = operation(entry, "indirect", "0x1ec84", "CALLIND")
        result = slices.backward_slice({"nodes": [call], "edges": []},
                                       entry=entry, site="0x1ec84")
        self.assertEqual(result["chainNodeCount"], 1)
        self.assertFalse(result["indirectTargetResolved"])
        g = {"nodes": [call], "edges": [connection(
            "0x1ec00/missing", call["id"], 0)]}
        result = slices.backward_slice(g, entry=entry, site="0x1ec84")
        self.assertEqual(result["unseenSourceReferences"], ["0x1ec00/missing"])

    def test_wrong_ghidra_block_and_duplicate_call_rejected(self):
        call = operation("0x5950", "c", "0x5dc4", "CALLIND")
        call["operation"]["block_membership"] = "detached"
        with self.assertRaisesRegex(TriageError, "not part"):
            slices.backward_slice({"nodes": [call], "edges": []},
                                  entry="0x5950", site="0x5dc4")
        call["operation"]["block_membership"] = "member"
        other = operation("0x5950", "d", "0x5dc4", "CALLIND")
        with self.assertRaisesRegex(TriageError, "exactly one"):
            slices.backward_slice({"nodes": [call, other], "edges": []},
                                  entry="0x5950", site="0x5dc4")

    def test_bounded_code_window_reports_exact_matched_lines(self):
        code = "\n".join(["intro"]*15 + [
            "x = (**(code **)(param_1 + 0x40))(param_1, flag);",
            'write("androidboot.vbmeta.device_state", state);'
        ] + ["tail"]*100)
        snippet = slices.code_window(code,
                                     (r"\(param_1 \+ 0x40\)",
                                      r"androidboot\.vbmeta\.device_state"),
                                     window=2, max_lines=7)
        self.assertEqual(snippet["matchedLineNumbers"], [16, 17])
        self.assertEqual(snippet["selected"][0]["line"], 14)
        self.assertLessEqual(len(snippet["selected"]), 7)

    def test_second_page_retains_all_nodes_and_dependency_edges(self):
        entry, sha = "0x5950", "f"*64
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "rea-security-audit" / "LinuxLoader"
            directory.mkdir(parents=True)
            first = workflow_fixture(sha, entry)
            g = first["normalized_result"]
            g["nodes"] = [
                operation(entry, f"node-{i}", f"0x{0x6000+i*4:x}", "COPY")
                for i in range(999)
            ] + [operation(entry, "call", "0x5dc4", "CALLIND")]
            g["total_nodes"] = 1002
            g["total_edges"] = 1
            g["next_offset"] = 1000
            g["truncated"] = True
            g["edges"] = []
            (directory / "trace-0x5950.json").write_text(json.dumps(first))
            second = json.loads(json.dumps(first))
            second["parameters"].update({"offset": 1000, "limit": 1000})
            second["normalized_result"]["nodes"] = [
                operation(entry, "load", "0x5dbc", "LOAD"),
                operation(entry, "ptrsub", "0x5db0", "PTRSUB"),
            ]
            second["normalized_result"]["edges"] = [connection(
                entry + "/load", entry + "/call", 0)]
            second["normalized_result"]["next_offset"] = None
            (directory / "trace-0x5950-offset1000-limit1000.json").write_text(
                json.dumps(second))
            merged, pages = slices.graph_for(Path(td), "LinuxLoader", entry, sha)
            self.assertEqual(merged["totalNodes"], 1002)
            self.assertEqual(merged["totalEdges"], 1)
            self.assertEqual(pages["nextOffset"], None)
            picked = slices.backward_slice(merged, entry=entry, site="0x5dc4")
            self.assertEqual(picked["chainNodeCount"], 2)
            self.assertTrue(picked["loadRequiresAliasResolution"])

    def test_original_dossier_full_copy_and_separate_avb_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = make_saved_evidence(root)
            out = root / "rea-security-audit"
            original = ["void persistent_lookup(void)", "{"] + [
                "  local = 0;" for _ in range(53)
            ] + ["  return;", "}"]
            self.assertEqual(len(original), 57)
            dossier = evidence_obj(
                hashes["Odin"], "analyze_function", "procedure", "0x10e58",
                {"procedure": {
                    "address": "0x10e58", "name": "FUN_00010e58",
                    "body": {"available": True, "ranges": [
                        {"start": "0x10e58", "end": "0x10ef0"}]}},
                 "pseudocode": "\n".join(original),
                 "native_value_flow": {"available": True}})
            (out / "Odin" / "function-0x10e58.json").write_text(json.dumps(dossier))
            with mock.patch.dict(base.EXPECTED, hashes):
                targets = {x.name: x for x in base.choose_targets(root)}
                result = slices.original_dossiers(root, targets)
            self.assertEqual(len(result["odinStorageLookup"]["fullLines"]), 57)
            self.assertEqual(result["odinStorageLookup"]["fullLines"][0]["line"], 1)
            self.assertIn("linuxLoaderAvbImage", result)
            self.assertIn("linuxLoaderUnlockCallbackUser", result)

    def test_audit_respects_saved_evidence_plan_only(self):
        root = Path("/tmp/synthetic-HXL1-slice")
        detail = {
            "selectedCalls": [{
                "module": module, "callsite": addr,
                "observed": {"rawDisassembly": "blr x8",
                             "providerResolutionStatus": "unresolved",
                             "instructionEvidenceId": "e1",
                             "resolverEvidenceId": "e2"},
            } for module, _, addr, _ in slices.SITES],
            "allCallsiteFactsObserved": True,
        }
        entry = {"Odin": "0x1ec00", "LinuxLoader": "0x5950"}
        def graph(module):
            nodes = [operation(entry[module], addr, addr, "CALLIND")
                     for m, _, addr, _ in slices.SITES if m == module]
            return {
                "nodes": nodes, "edges": [], "unknowns": [],
                "truncated": True, "totalNodes": len(nodes),
                "totalEdges": 0, "decompilations": 16,
            }, None
        with mock.patch.object(slices, "validate_callsite_evidence",
                               return_value=detail), mock.patch.object(
                                   slices, "choose_targets", return_value=[
                                       base.Target(k, root / k, "a"*64, {})
                                       for k in entry]), mock.patch.object(
                                           slices, "graph_for",
                                           side_effect=lambda root, module, e, sha:
                                               graph(module)), mock.patch.object(
                                                   slices, "original_dossiers",
                                                   return_value={"mocked": True}):
            result = slices.audit(root)
        self.assertEqual(len(result["callSlices"]), 4)
        self.assertEqual(result["mode"], "SAVED_ONLY_NO_NEW_REA")
        self.assertFalse(result["callbackInitializerVerified"])
        self.assertFalse(result["vulnerabilityDemonstrated"])

    def test_no_firmware_execution_or_device_api(self):
        text = Path(slices.__file__).read_text()
        for forbidden in ("subprocess", "os.system(", "fastboot flash",
                          "adb shell", "heimdall flash"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
