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

    def test_duplicate_ref_label_is_rejected(self):
        d=fixture()
        d["xrefEvidence"][1]["label"]="dtb-index"
        d["xrefEvidence"][1]["xrefSource"]="0x2c350"
        with self.assertRaisesRegex(m.ProvenanceError,"duplicate"):
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

class GetterProviderDossierTests(unittest.TestCase):
    def result(self, address="0x23b00"):
        return {
            "operation": "analyze_function",
            "provider": {"id": "ghidra"},
            "subject": {"digest": {"sha256": m.LOADER_SHA256}},
            "parameters": {"procedure": "0x23b00"},
            "normalized_result": {
                "procedure": {"address": address},
                "pseudocode": "int FUN_00023b00(void) { return -1; }",
            },
        }

    def test_requested_getter_entry_is_actually_returned(self):
        a = m.verify_getter_dossier(self.result("0x00023b00"), "0x23b00")
        self.assertTrue(a["functionEntryMatchesRequested"])
        self.assertFalse(a["getterIndexAlgorithmVerified"])

    def test_neighboring_getter_cannot_be_accepted(self):
        with self.assertRaisesRegex(m.ProvenanceError, "different Ghidra function entry"):
            m.verify_getter_dossier(self.result("0x23b40"), "0x23b00")

    def test_echoed_different_parameter_rejected(self):
        d = self.result()
        d["parameters"]["procedure"] = "0x23b40"
        with self.assertRaisesRegex(m.ProvenanceError, "different procedure"):
            m.verify_getter_dossier(d, "0x23b00")

    def test_untrusted_loader_digest_stops(self):
        d = self.result()
        d["subject"]["digest"]["sha256"] = "0"*64
        with self.assertRaisesRegex(m.ProvenanceError, "digest mismatch"):
            m.verify_getter_dossier(d, "0x23b00")

    def test_empty_decompilation_does_not_pass(self):
        d = self.result()
        d["normalized_result"]["pseudocode"] = " "
        with self.assertRaisesRegex(m.ProvenanceError, "missing or empty"):
            m.verify_getter_dossier(d, "0x23b00")

    def test_rea_error_envelope_rejected(self):
        d = self.result()
        d["error"] = "cancelled"
        with self.assertRaisesRegex(m.ProvenanceError, "error or non-object"):
            m.verify_getter_dossier(d, "0x23b00")

    def test_portable_packet_contains_both_only_and_retains_semantic_unknown(self):
        dtbo=self.result("0x23b00")
        dtb=self.result("0x23b40")
        dtb["parameters"]["procedure"]="0x23b40"
        dtb["normalized_result"]["pseudocode"]="int FUN_00023b40(void) { return -1; }"
        packet=m.package_verified_getter_dossiers({"dtbo":dtbo, "dtb":dtb})
        self.assertTrue(packet["bothGetterEntriesAuthenticated"])
        self.assertFalse(packet["indexSelectionSemanticsInterpreted"])
        self.assertEqual([x["kind"] for x in packet["dossiers"]],["dtbo","dtb"])
        self.assertEqual(len(packet["dossiers"]),2)

    def test_portable_packet_cannot_omit_one_getter(self):
        with self.assertRaisesRegex(m.ProvenanceError,"Exactly the dtb and dtbo"):
            m.package_verified_getter_dossiers({"dtbo":self.result()})

    def test_portable_packet_cannot_swap_function_dossiers(self):
        swapped=self.result("0x23b40")
        with self.assertRaisesRegex(m.ProvenanceError,"different Ghidra function entry"):
            m.package_verified_getter_dossiers({"dtbo":swapped,"dtb":swapped})

    def test_portable_packet_rejects_oversized_pseudocode(self):
        dtbo=self.result()
        dtb=self.result("0x23b40")
        dtb["parameters"]["procedure"]="0x23b40"
        dtb["normalized_result"]["pseudocode"]="abc"*170_000
        with self.assertRaisesRegex(m.ProvenanceError,"Oversized getter"):
            m.package_verified_getter_dossiers({"dtbo":dtbo,"dtb":dtb})

    def test_unsafe_request_target_rejected(self):
        with self.assertRaisesRegex(m.ProvenanceError, "Unexpected getter target"):
            m.verify_getter_dossier(self.result(), "0x2bdf8")


if __name__=="__main__":
    unittest.main()
