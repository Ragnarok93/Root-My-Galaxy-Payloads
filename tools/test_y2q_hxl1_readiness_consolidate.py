"""Read-only repository fixture tests for the HXL1 stage reconciliation gate."""
import copy
import json
from pathlib import Path
import unittest

from tools import y2q_hxl1_readiness_consolidate as m

EVIDENCE = (Path(__file__).resolve().parents[1] /
    "research/y2q-G986U1UESCHXL1/evidence.json")

def fixture():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))

class ReconcileTests(unittest.TestCase):
    def test_real_checked_in_research_manifest(self):
        report=m.audit(fixture())
        self.assertEqual([x["state"] for x in report["nineStages"]],m.STAGES)
        self.assertFalse(report["kernelSuLoaded"])
        self.assertFalse(report["productionFeedAllowed"])
        self.assertFalse(report["livePrivilegeEscalationVerified"])

    def test_wrong_firmware_rejected(self):
        f=fixture();f["identity"]["firmware"]="G986U1OTHER"
        with self.assertRaisesRegex(m.EvidenceError,"Wrong model"):
            m.audit(f)

    def test_modified_kernel_digest_rejected(self):
        f=fixture();f["artifacts"]["kernel.bin"]["sha256"]="f"*64
        with self.assertRaisesRegex(m.EvidenceError,"SHA pins"):
            m.audit(f)

    def test_changed_module_trust_config_rejected(self):
        f=fixture();f["kernelConfig"]["CONFIG_MODULE_SIG_FORCE"]="n"
        with self.assertRaisesRegex(m.EvidenceError,"security config"):
            m.audit(f)

    def test_premature_stage_three_upgrade_rejected(self):
        f=fixture()
        f["hxl1NineStagePortReadiness"]["nineStages"][2]["state"]="COMPLETE"
        with self.assertRaisesRegex(m.EvidenceError,"Stage promotion"):
            m.audit(f)

    def test_production_feed_claim_rejected(self):
        f=fixture();f["publishInSupportFeed"]=True
        with self.assertRaisesRegex(m.EvidenceError,"Unsafe root"):
            m.audit(f)

    def test_physical_handoff_claim_rejected(self):
        f=fixture();f["hxl1Stage4BootloaderDiscovery"]["physicalKernelLoadAddressVerified"]=True
        with self.assertRaisesRegex(m.EvidenceError,"Physical handoff"):
            m.audit(f)

    def test_signed_kernel_su_module_claim_rejected(self):
        f=fixture();f["hxl1KernelSuReadiness"]["moduleLoadVerified"]=True
        with self.assertRaisesRegex(m.EvidenceError,"KernelSU trust"):
            m.audit(f)

    def test_authoritative_stage_report_contradiction(self):
        r={"gates":[{"stage":i,"state":s} for i,s in enumerate(m.STAGES,1)],
           "payloadPortCompleted":False,"ghostLockRuntimeValidated":False,
           "temporaryRootVerified":False,"kernelSuLoaded":False}
        self.assertEqual(m.audit(fixture(),readiness=r)["checks"]
                         ["portingReadinessReport"],"AGREES_ALL_NINE_STAGES")
        r["gates"][6]["state"]="COMPLETE"
        with self.assertRaisesRegex(m.EvidenceError,"Authoritative porting"):
            m.audit(fixture(),readiness=r)

    def test_incomplete_debug_scan_rejected(self):
        inventory={"scanRoots":["/home/main/s20-artifacts"],
                   "truncated":True,"errorCount":0,
                   "scopeCompleteAtRequestedDepth":False,
                   "candidateFiles":1,"classificationCounts":{"x":1},
                   "oemSymbolsAuthenticated":False}
        with self.assertRaisesRegex(m.EvidenceError,"Debug-symbol inventory"):
            m.audit(fixture(),inventory=inventory)

    def test_no_research_outputs_can_be_written_inside_repository(self):
        import io
        import sys
        from unittest.mock import patch
        destination=EVIDENCE.parents[2] / "tools" / "should-not-create-readiness.json"
        arguments=["readiness", "--evidence", str(EVIDENCE),
                   "--output", str(destination)]
        with patch.object(sys, "argv", arguments), patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(m.main(), 2)
            self.assertIn("outside the repository", err.getvalue())
        self.assertFalse(destination.exists())

if __name__=="__main__":
    unittest.main()
