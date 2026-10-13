"""Synthetic-only checks for original HXL1 ARM64 static CFG evidence."""
import unittest
from tools import y2q_hxl1_static_cfg_audit as m

def windows():
    result = {name: {"start": 0x10000 + i * 0x10000,
                      "instructions": {0x10000 + i*0x10000: ("ret", "")}}
              for i, name in enumerate(m.NAMES)}
    base = result["do_futex"]["start"]
    data = {base + 4*i: ("nop", "") for i in range(0xb24//4)}
    data[base + 0xb14] = ("cmp", "w8, #0xb")
    data[base + 0xb18] = ("b.eq", hex(base + 0xb1c))
    data[base + 0xb20] = ("ret", "")
    result["do_futex"]["instructions"] = data
    return result

class Hxl1StaticCfgTests(unittest.TestCase):
    def test_direct_conditional_branch_has_two_potential_edges(self):
        code = {0x1000: ("cmp", "w8, #0xb"),
                0x1004: ("b.eq", "0x1010"),
                0x1008: ("bl", "0x2000"),
                0x100c: ("ret", ""),
                0x1010: ("b", "0x100c")}
        edges, count, external, unknown = m.edges_for(code)
        self.assertEqual(edges[0x1004], [0x1010, 0x1008])
        self.assertEqual(m.reachable(edges, 0x1000), set(code))
        self.assertEqual((count, external, unknown), (2, 0, 0))

    def test_unknown_indirect_and_outside_branches_reported(self):
        _, _, outside, unknown = m.edges_for(
            {0x1000: ("b", "0x3000"), 0x1004: ("br", "x9")})
        self.assertEqual((outside, unknown), (1, 1))

    def test_malformed_disassembly_gap_is_rejected(self):
        data = b"0000000000001000: d503201f nop\n0000000000001008: d503201f nop\n"
        with self.assertRaisesRegex(m.AuditError, "not contiguous"):
            m.parse_disassembly(data, 0x1000, 8)

    def test_original_operation_11_static_graph_remains_no_root_proof(self):
        result = m.analyze(windows())
        self.assertTrue(result["operation11Branch"]["canReachBranchFromEntry"])
        self.assertTrue(result["operation11Branch"]["branchMayReachDispatcherReturn"])
        self.assertFalse(result["sourceHelperInliningProven"])
        self.assertFalse(result["crossSyscallStackReuseProven"])
        self.assertFalse(result["liveRuntimeOrRootVerified"])

    def test_modified_original_command_fails_closed(self):
        w = windows()
        base = w["do_futex"]["start"]
        w["do_futex"]["instructions"][base + 0xb14] = ("cmp", "w8, #0x8")
        with self.assertRaisesRegex(m.AuditError, "comparison missing"):
            m.analyze(w)

if __name__ == "__main__":
    unittest.main()
