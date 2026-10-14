"""No-phone unit tests for the HXL1 read-only runtime FDT identity crosswalk."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_runtime_dtb_identity as m

EVIDENCE=Path(__file__).resolve().parents[1]/"research/y2q-G986U1UESCHXL1/evidence.json"

def fixture():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))

def props():
    return {"ro.product.model":"SM-G986U1",
            "ro.build.display.id":"TP1A.220624.014.G986U1UESCHXL1",
            "uname -r":"4.19.113-27095354"}

class DtbIdentityTests(unittest.TestCase):
    def test_exact_repo_stock_fdt_semantic_inventory(self):
        d=fixture()
        self.assertEqual(len(m.candidate_models(d)),4)
        self.assertEqual(m.candidate_models(d)[0]["rootCompatible"],["qcom,kona"])

    def test_owner_original_config_pin_is_unchanged(self):
        self.assertEqual(hashlib.sha256(EVIDENCE.read_bytes()).hexdigest(),m.EVIDENCE_SHA)

    def test_first_candidate_model_match_does_not_prove_dtb_selection(self):
        d=fixture();first=m.candidate_models(d)[0]
        r=m.analyze(d,first["rootModel"].encode()+b"\0",b"qcom,kona\0",props())
        self.assertTrue(r["candidateRootMatchUnambiguous"])
        self.assertEqual(r["matchingOriginalRootModelCandidateIndices"],[1])
        self.assertFalse(r["candidateRootMatchProvesExactRuntimeDtb"])
        self.assertFalse(r["bootloaderSelectedDtbProven"])
        self.assertFalse(r["physicalLinuxLoadBaseVerified"])

    def test_all_three_stock_root_models_correlate_individually(self):
        d=fixture()
        for candidate in m.candidate_models(d)[:3]:
            r=m.analyze(d,candidate["rootModel"].encode("utf-8")+b"\0",
                        b"qcom,kona\0",props())
            self.assertEqual(r["matchingOriginalRootModelCandidateIndices"],
                             [candidate["index"]])

    def test_unknown_root_model_does_not_fabricate_identity(self):
        r=m.analyze(fixture(),b"Qualcomm unexpected\0",b"qcom,kona\0",props())
        self.assertEqual(r["matchingOriginalRootModelCandidateIndices"],[])
        self.assertFalse(r["candidateRootMatchUnambiguous"])

    def test_wrong_live_firmware_must_not_certify_candidate(self):
        p=props();p["ro.build.display.id"]="other release"
        r=m.analyze(fixture(),m.candidate_models(fixture())[1]["rootModel"].encode(),
                    b"qcom,kona\0",p)
        self.assertFalse(r["liveIdentityMatchesPinnedHxl1"])
        self.assertFalse(r["candidateRootMatchUnambiguous"])

    def test_missing_kona_compatible_no_match(self):
        r=m.analyze(fixture(),m.candidate_models(fixture())[2]["rootModel"].encode(),
                    b"qcom,other\0",props())
        self.assertEqual(r["matchingOriginalRootModelCandidateIndices"],[])

    def test_invalid_nonprintable_root_rejected(self):
        with self.assertRaisesRegex(m.GateError,"nonprintable"):
            m.parse_root(b"\x01\x02\0")

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(m.GateError,"Non-UTF8"):
            m.parse_root(b"\xff\0")

    def test_changed_stock_candidate_model_rejected(self):
        d=fixture();d["hxl1Stage4BootloaderDiscovery"][
            "followupFdtStructureAndRootIdentity"]["candidates"][0]["rootCompatible"]=[]
        with self.assertRaisesRegex(m.GateError,"root identities"):
            m.candidate_models(d)

    def test_adb_process_is_read_only_exec_and_bounded(self):
        from subprocess import CompletedProcess
        with patch.object(m.subprocess,"run",
             return_value=CompletedProcess(args=[],returncode=0,stdout=b"qcom,kona\x00",stderr=b"")) as fn:
            result=m.adb_read("adb","test-transport",["exec-out","cat","/proc/device-tree/compatible"])
        self.assertEqual(result,b"qcom,kona\x00")
        args,kw=fn.call_args
        self.assertEqual(args[0],["adb","-s","test-transport","exec-out",
                                  "cat","/proc/device-tree/compatible"])
        self.assertEqual(kw["timeout"],15)

    def test_adb_denial_does_not_promote_evidence(self):
        from subprocess import CompletedProcess
        with patch.object(m.subprocess,"run",
             return_value=CompletedProcess(args=[],returncode=1,stdout=b"",stderr=b"permission denied")):
            with self.assertRaisesRegex(m.GateError,"unavailable"):
                m.adb_read("adb",None,["exec-out","cat","/proc/device-tree/model"])


    def test_malformed_live_model_creates_bounded_nonroot_diagnostics(self):
        raw=b"Qualcomm Technologies, Inc. kona v2.1 SoC\n\0"
        result=m.diagnose(fixture(),raw,b"qcom,kona\0",props())
        self.assertEqual(result["status"],"ROOT_PROPERTY_PARSE_REQUIRES_REVIEW")
        self.assertIn("model",result["parseError"])
        self.assertEqual(result["rawPropertyDiagnostics"]["model"]
                         ["firstControlByteExcludingNul"],{"offset":41,"hex":"0a"})
        self.assertEqual(result["rawPropertyDiagnostics"]["model"]["first128Hex"],
                         raw.hex())
        self.assertFalse(result["candidateRootMatchUnambiguous"])
        self.assertFalse(result["bootloaderSelectedDtbProven"])
        self.assertFalse(result["physicalLinuxLoadBaseVerified"])

    def test_malformed_live_compatible_is_diagnosed_by_property(self):
        raw=b"qcom,kona\0qcom,other\r\0"
        good=m.candidate_models(fixture())[0]["rootModel"].encode()+b"\0"
        result=m.diagnose(fixture(),good,raw,props())
        self.assertIn("compatible",result["parseError"])
        self.assertTrue(result["rawPropertyDiagnostics"]["compatible"]["nulTerminated"])
        self.assertEqual(result["matchingOriginalRootModelCandidateIndices"],[])
        self.assertFalse(result["candidateRootMatchProvesExactRuntimeDtb"])

    def test_clean_live_properties_remain_unchanged(self):
        selected=m.candidate_models(fixture())[1]
        result=m.diagnose(fixture(),selected["rootModel"].encode()+b"\0",
                          b"qcom,kona\0qcom,example\0",props())
        self.assertEqual(result["status"],"ROOT_PROPERTY_PARSED")
        self.assertEqual(result["matchingOriginalRootModelCandidateIndices"],[2])
        self.assertTrue(result["candidateRootMatchUnambiguous"])
        self.assertFalse(result["bootloaderSelectedDtbProven"])

    def test_invalid_utf8_never_silently_replaced(self):
        raw=b"qcom,kona\0bad\xff\0"
        good=m.candidate_models(fixture())[0]["rootModel"].encode()+b"\0"
        result=m.diagnose(fixture(),good,raw,props())
        self.assertIn("Non-UTF8",result["parseError"])
        self.assertFalse(result["candidateRootMatchUnambiguous"])

    def test_live_malformed_property_still_saves_diagnostic_json_and_returns_error(self):
        import io
        import sys
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"dtb-diagnostic.json"
            bad=(b"unexpected\x01\0",b"qcom,kona\0",props())
            argv=["probe","--output",str(path)]
            with patch.object(sys,"argv",argv),patch.object(m,"capture",return_value=bad):
                with patch("sys.stderr",new_callable=io.StringIO) as err:
                    code=m.main()
            self.assertEqual(code,2)
            self.assertTrue(path.is_file())
            out=json.loads(path.read_text())
            self.assertEqual(out["status"],"ROOT_PROPERTY_PARSE_REQUIRES_REVIEW")
            self.assertEqual(out["rawPropertyDiagnostics"]["model"]
                             ["firstControlByteExcludingNul"],{"offset":10,"hex":"01"})
            self.assertIn("model",err.getvalue())

    def test_evidence_drift_is_not_masked_as_live_format_error(self):
        d=fixture()
        d["identity"]["firmware"]="OTHER"
        with self.assertRaisesRegex(m.GateError,"Wrong original"):
            m.diagnose(d,b"bad\n\0",b"qcom,kona\0",props())


if __name__=="__main__":
    unittest.main()
