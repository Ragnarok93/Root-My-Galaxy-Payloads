"""Offline regression tests for the HXL1 source-derived ABI parity report."""
import tempfile
import unittest
from pathlib import Path

from tools import y2q_hxl1_stage3_abi_crosscheck as a


class Stage3AbiCrosscheckTest(unittest.TestCase):
    def test_nested_member_offsets_match_canonical_examples(self):
        layouts = {
            "task_struct": {
                "pi_lock": {"type": "raw_spinlock_t", "offset": 2248, "size": 16},
                "pi_waiters": {"type": "struct rb_root_cached", "offset": 2272, "size": 16},
                "pi_blocked_on": {"type": "struct rt_mutex_waiter *", "offset": 2296, "size": 8}},
            "rt_mutex": {"waiters": {"type": "struct rb_root_cached", "offset": 16, "size": 16},
                         "owner": {"type": "struct task_struct *", "offset": 32, "size": 8}},
            "rt_mutex_waiter": {name: {"type": "int", "offset": off, "size": 4}
                                for name, off in (("tree_entry", 0), ("pi_tree_entry", 24),
                                                  ("task", 48), ("lock", 56), ("prio", 64),
                                                  ("deadline", 72))},
            "rb_root_cached": {"rb_root": {"type": "struct rb_root", "offset": 0, "size": 8},
                               "rb_leftmost": {"type": "struct rb_node *", "offset": 8, "size": 8}},
            "rb_root": {"rb_node": {"type": "struct rb_node *", "offset": 0, "size": 8}}
        }
        expected = {("task_struct", "pi_lock"): "0x8c8",
                    ("task_struct", "pi_waiters.rb_root.rb_node"): "0x8e0",
                    ("task_struct", "pi_waiters.rb_leftmost"): "0x8e8",
                    ("task_struct", "pi_blocked_on"): "0x8f8",
                    ("rt_mutex", "waiters.rb_root.rb_node"): "0x10",
                    ("rt_mutex", "waiters.rb_leftmost"): "0x18",
                    ("rt_mutex", "owner"): "0x20"}
        for (root, path), off in expected.items():
            self.assertEqual(a.resolve_nested(layouts, root, path)["offset"], off)

    def test_pahole_parser_rejects_duplicate_member(self):
        raw = """struct task_struct {
            raw_spinlock_t pi_lock; /* 2248 16 */
            raw_spinlock_t pi_lock; /* 2256 16 */
        };"""
        with self.assertRaisesRegex(a.AuditError, "duplicate"):
            a.parse_layout(raw, "task_struct")

    def test_pahole_parser_handles_ptr_member(self):
        raw = """struct rt_mutex_waiter {
            struct task_struct * task; /* 48 8 */
            struct rb_node tree_entry __attribute__((__aligned__(8))); /* 0 24 */
            int prio; /* 64 4 */
        };"""
        parsed = a.parse_layout(raw, "rt_mutex_waiter")
        self.assertEqual(parsed["task"]["offset"], 48)
        self.assertEqual(parsed["prio"]["offset"], 64)
        self.assertEqual(parsed["tree_entry"]["size"], 24)

    def test_nested_ptr_not_a_value_type(self):
        layout = {"task_struct": {"pi_waiters": {"type": "struct rb_root_cached *",
                                                "offset": 16, "size": 8}},
                  "rb_root_cached": {"rb_leftmost": {"type": "struct rb_node *",
                                                   "offset": 8, "size": 8}}}
        with self.assertRaisesRegex(a.AuditError, "value-type"):
            a.resolve_nested(layout, "task_struct", "pi_waiters.rb_leftmost")

    def test_config_metadata_only_is_not_an_abi_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            shared = ("CONFIG_ARM64_VA_BITS=39\nCONFIG_DEBUG_INFO=y\n"
                      "CONFIG_RT_GROUP_SCHED=y\nCONFIG_SCHED_DEBUG=y\n")
            stock = base / "stock"
            stock.write_text(shared + "CONFIG_CLANG_VERSION=100006\n# CONFIG_SEC_X1Q_PROJECT is not set\n")
            model = base / "model"
            model.write_text(shared + "CONFIG_CLANG_VERSION=180103\n")
            status = a.validate_configuration(stock, model)
            self.assertEqual(status["unexpectedSemanticChanges"], {})
            model.write_text(shared.replace("CONFIG_ARM64_VA_BITS=39", "CONFIG_ARM64_VA_BITS=48"))
            with self.assertRaisesRegex(a.AuditError, "Critical"):
                a.validate_configuration(stock, model)

    def test_registry_reads_data_without_importing_code(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            (repo / "tools").mkdir()
            (repo / "tools/y2q_hxl1_rtmutex_displacement_attest.py").write_text(
                'FIELDS = {"rt_mutex":{"waiters.rb_root.rb_node":"0x10","waiters.rb_leftmost":"0x18","owner":"0x20"},'
                '"rt_mutex_waiter":{"tree_entry":"0x0","pi_tree_entry":"0x18","task":"0x30","lock":"0x38","prio":"0x40","deadline":"0x48"},'
                '"task_struct":{"pi_lock":"0x8c8","pi_waiters.rb_root.rb_node":"0x8e0","pi_waiters.rb_leftmost":"0x8e8","pi_blocked_on":"0x8f8"}}\n'
                'raise RuntimeError("this must not execute")\n')
            self.assertEqual(a.read_comparison_registry(repo)["rt_mutex"]["owner"], "0x20")

    def test_report_keeps_oem_gate_false(self):
        sample = {"members":[{"type":"task_struct","memberPath":"pi_lock",
                  "existingClang10Candidate":"0x8c8","clang18SourceDerived":"0x8c8",
                  "crossCompilerOffsetAgreement":True,"savedOriginalRegisterChainStatus":"MATCHED_STATIC_CHAIN"}],
                  "matchedOffsets":1,"candidateCount":1}
        md = a.markdown(sample)
        self.assertIn("PARTIAL", md)
        self.assertIn("not OEM factory DWARF", md)


if __name__ == "__main__":
    unittest.main()
