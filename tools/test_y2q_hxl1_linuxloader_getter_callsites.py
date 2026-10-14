"""No-provider tests of the authenticated HXL1 formatter getter-callsite audit."""
import copy
import json
from pathlib import Path
import unittest

from tools import y2q_hxl1_linuxloader_getter_callsites as m

def fixture():
    excerpt=[
        (250,"  cVar6 = FUN_000235b0();"),
        (251,"  if (cVar6 == '\\0') {"),
        (252,"    iVar8 = FUN_00023b00();"),
        (253,"    if (iVar8 != -1) {"),
        (254,'      FUN_0000ddc4(&local_f0,0x40,&DAT_000bfbf6," androidboot.dtbo_idx=",iVar8);'),
        (261,"    iVar8 = FUN_00023b40();"),
        (262,"    if (iVar8 != -1) {"),
        (263,'      FUN_0000ddc4(&local_130,0x40,&DAT_000bfbf6," androidboot.dtb_idx=",iVar8);'),
    ]
    return {
      "target":"SM-G986U1/G986U1UESCHXL1",
      "classification":"VERIFIED_CACHED_ORIGINAL_CMDLINE_FUNCTION_NO_VALUE_FLOW",
      "originalLinuxLoaderSha256":m.LOADER_SHA256,
      "sharedFunctionAnalysisEntry":"0x2bdf8",
      "cachedFunctionPseudocodeConsistent":True,
      "xrefEvidence":[
          {"label":"dtb-index","xrefSource":"0x2c350","pcodeAvailable":True,
           "functionEvidenceId":"ev_123"},
          {"label":"dtbo-index","xrefSource":"0x2c308","pcodeAvailable":True,
           "functionEvidenceId":"ev_456"}
      ],
      "formatterContext":{
          "pseudocodeSha256":m.ORIGINAL_PSEUDOCODE_SHA256,
          "indexLiteralLines":[254,263],
          "pseudocodeLineCount":398,
          "snippetTruncated":False,
          "boundedPseudocodeExcerpt":[{"line":n,"text":s} for n,s in excerpt],
      },
      "savedNativeTrace":{"state":"SAVED_TRACE_FAILURE","code":"cancelled",
                          "verifiedValueFlow":False},
    }

class GetterCallsiteTests(unittest.TestCase):
    def test_both_getters_and_sentinel_branches_proven_by_cached_excerpt(self):
        r=m.analyze(fixture())
        self.assertTrue(r["allImmediateGetterCallsitesCorroborated"])
        self.assertEqual(r["suggestedBoundedNextTargets"],["0x23b00","0x23b40"])
        self.assertEqual([x["skipFormattingWhenReturnEquals"] for x in
                          r["callsiteEvidence"]],[-1,-1])
        self.assertFalse(r["getterInternalsOrSelectionAlgorithmVerified"])

    def test_wrong_original_loader_digest_is_rejected(self):
        d=fixture();d["originalLinuxLoaderSha256"]="0"*64
        with self.assertRaisesRegex(m.ProvenanceError,"provenance"):
            m.analyze(d)

    def test_wrong_pseudocode_hash_is_rejected(self):
        d=fixture();d["formatterContext"]["pseudocodeSha256"]="0"*64
        with self.assertRaisesRegex(m.ProvenanceError,"identity"):
            m.analyze(d)

    def test_wrong_xref_is_rejected(self):
        d=fixture();d["xrefEvidence"][0]["xrefSource"]="0x23b40"
        with self.assertRaisesRegex(m.ProvenanceError,"xref"):
            m.analyze(d)

    def test_stale_dtbo_callee_is_rejected(self):
        d=fixture();d["formatterContext"]["boundedPseudocodeExcerpt"][2]["text"]=" iVar8 = FUN_00023b40();"
        with self.assertRaisesRegex(m.ProvenanceError,"call"):
            m.analyze(d)

    def test_removed_dtb_sentinel_is_rejected(self):
        d=fixture();d["formatterContext"]["boundedPseudocodeExcerpt"][6]["text"]=" if (iVar8 != 0) {"
        with self.assertRaisesRegex(m.ProvenanceError,"call"):
            m.analyze(d)

    def test_swapped_formatter_literature_is_rejected(self):
        d=fixture();d["formatterContext"]["boundedPseudocodeExcerpt"][7]["text"]=' FUN_0000ddc4("androidboot.dtbo_idx=",iVar8);'
        with self.assertRaisesRegex(m.ProvenanceError,"call"):
            m.analyze(d)

    def test_cancelled_trace_cannot_be_promoted_to_native_values(self):
        d=fixture();d["savedNativeTrace"]["verifiedValueFlow"]=True
        with self.assertRaisesRegex(m.ProvenanceError,"trace"):
            m.analyze(d)

    def test_missing_gate_is_rejected(self):
        d=fixture();d["formatterContext"]["boundedPseudocodeExcerpt"][1]["text"]=" if (cVar6 != '\\0') {"
        with self.assertRaisesRegex(m.ProvenanceError,"gate"):
            m.analyze(d)

    def test_untrusted_duplicate_excerpt_lines_are_rejected(self):
        d=fixture()
        d["formatterContext"]["boundedPseudocodeExcerpt"].append({"line":252,"text":"fake"})
        with self.assertRaisesRegex(m.ProvenanceError,"Repeated"):
            m.analyze(d)

if __name__=="__main__":
    unittest.main()
