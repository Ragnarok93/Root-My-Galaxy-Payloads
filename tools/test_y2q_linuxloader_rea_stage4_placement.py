#!/usr/bin/env python3
"""Tests for HXL1 Ghidra placement evidence; no firmware or Ghidra required."""
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import y2q_linuxloader_rea_stage4_placement as placement
from tools.y2q_linuxloader_rea_stage4_xrefs import AuditError

REAL_EXCERPT = """
lVar13 = (**(code **)(DAT_00351a40 + 0x48))(L"KernelBaseAddr",&DAT_000ef6d0,0,local_b8,&local_118);
lVar16 = (**(code **)(DAT_00351a40 + 0x48))(L"KernelSize",&DAT_000ef6d0,0,local_b8,local_108);
lVar13 = 0x80000;
if (local_130 != '\\0') {
  lVar13 = 0x8000;
}
local_190 = (code *)(lVar13 + local_118);
local_190 = (code *)(local_1c0 | *puVar1);
lVar13 = FUN_0001f018(&local_1c0);
_DAT_a0001004 = DAT_0032a4c8 << 0xf;
local_190 = local_190 + uVar14;
local_180 = local_188 - (ulonglong)0x400000;
local_178 = (code *)(local_180 - (ulonglong)(local_164 + 0x200000));
if (local_178 <= local_190) {
  FUN_00039818(0x80000000,"Not Enough space left to load kernel image");
}
iVar9 = FUN_00023730(local_1b8 + local_164,local_160,local_190,0x100000,&local_14c,local_b8);
(**(code **)(DAT_00351a38 + 0x160))(local_190,pcVar24,local_160);
FUN_00039818(0x400000,"Kernel Load Address: 0x%x\\n",local_190);
lVar13 = FUN_00023bc8(uVar14,uVar23,local_14c,local_178);
void unrelated_last_150_lines(void) { }
"""
DTB_EXCERPT = """
FUN_00037658(puVar50,iVar18,"model",&local_6c);
FUN_00037658(puVar50,iVar18,"qcom,board-id",&local_70);
FUN_00037658(puVar50,iVar18,"qcom,msm-id",&local_74);
FUN_00037658(puVar50,iVar18,"qcom,pmic-id",&local_78);
"""


def verified_funcs():
    return {
        "functions": [
            {"label": "kernel-load-print", "status": "VERIFIED_FUNCTION", "entry": "0x20a60"},
            {"label": "kernel-dt-boundary", "status": "VERIFIED_FUNCTION", "entry": "0x20a60"},
            {"label": "best-dtb-match", "status": "VERIFIED_FUNCTION", "entry": "0x23bc8"},
        ],
        "sharedFunctions": [{
            "entry": "0x20a60",
            "labels": ["kernel-load-print", "kernel-dt-boundary"],
        }],
    }


def dossiers(code=REAL_EXCERPT, dtb=DTB_EXCERPT, flow=None):
    if flow is None:
        flow = {"available": True, "operations": [1, 2], "truncated": False}
    return {
        "kernel-load-print": {"pseudocode": code, "native_value_flow": flow},
        "kernel-dt-boundary": {"pseudocode": code, "native_value_flow": flow},
        "best-dtb-match": {"pseudocode": dtb, "native_value_flow": {"available": True}},
    }


class PlacementAnalysisTests(unittest.TestCase):
    def check(self, dossier=None, functions=None):
        if dossier is None:
            dossier = dossiers()
        if functions is None:
            functions = verified_funcs()
        with patch.object(placement, "validate_functions", return_value=functions):
            with patch.object(placement, "original_dossier", side_effect=lambda _folder,label:dossier[label]):
                return placement.trace(Path("/synthetic"))

    def test_exact_original_static_placement_anchors(self):
        result=self.check()
        self.assertTrue(all(v["observed"] for v in result["placementStatements"].values()))
        self.assertTrue(all(v["observed"] for v in result["dtbProperties"].values()))
        self.assertEqual(result["bootLinuxFunction"], "0x20a60")
        self.assertFalse(result["numericPhysicalLoadVerified"])
        self.assertFalse(result["kernelHandoffVerified"])
        self.assertFalse(result["deviceModified"])

    def test_tail_preserves_original_not_invented_jump(self):
        result=self.check()
        self.assertTrue(any("unrelated_last_150_lines" in line for line in result["bootLinuxTail"]))
        self.assertNotIn("physicalKernelAddress", result)

    def test_different_bootlinux_dossiers_rejected(self):
        different=dossiers()
        different["kernel-dt-boundary"]["pseudocode"]="Not same pseudocode"
        with self.assertRaisesRegex(AuditError,"differs"):
            self.check(different)

    def test_wrong_function_identity_is_hard_stop(self):
        broken=verified_funcs()
        broken["functions"][2]["entry"]="0x25000"
        with self.assertRaisesRegex(AuditError,"identity"):
            self.check(functions=broken)

    def test_no_highfunction_status_is_rejected(self):
        wrong=dossiers(flow={"operations":[]})
        with self.assertRaisesRegex(AuditError,"p-code status"):
            self.check(wrong)

    def test_unobserved_expression_is_not_fabricated(self):
        changed=dossiers(code=REAL_EXCERPT.replace("DAT_0032a4c8 << 0xf", "unknown_input"))
        result=self.check(changed)
        self.assertFalse(result["placementStatements"]["kaslr_shift"]["observed"])
        self.assertTrue(result["placementStatements"]["kernel_load_log"]["observed"])

    def test_highfunction_counts_not_raw_pcode_dumped(self):
        result=self.check()
        self.assertEqual(result["highFunctionMetadata"]["operations"]["count"],2)
        self.assertNotIn("operations",str(result["bootLinuxTail"]))

    def test_report_explicitly_disclaims_actual_physical_address(self):
        result=self.check()
        md=placement.render(result)
        self.assertIn("Neither the exact runtime physical base", md)
        self.assertIn("KernelBaseAddr",md)
        self.assertIn("Previously omitted",md)


if __name__ == "__main__":
    unittest.main()
