"""Purely offline test harness for the HXL1 cleanup ownership model."""
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_cleanup_regression as m

class CleanupRegressionTests(unittest.TestCase):
    def test_compiled_ownership_divergence(self):
        if not shutil.which('cc'):self.skipTest('No compiler')
        rows=m.run_model()
        a={(r['variant'],r['scenario']):r for r in rows}
        self.assertEqual(a['stock','different_negative']['touched'],1)
        self.assertEqual(a['fixed','different_negative']['touched'],2)
        self.assertTrue(a['stock','different_negative']['waiterTaskBlocked'])
        self.assertFalse(a['fixed','different_negative']['waiterTaskBlocked'])
    def test_validated_source_required(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(m.stock,'validate_original',return_value={'rtmutex.c':'pin'}) as verify, \
                 patch.object(m.stock,'inspect_source',return_value={k:{'found':True} for k in m.MOTIFS}):
                result=m.verify_source(Path(d))
            verify.assert_called_once();self.assertEqual(len(result['verifiedMotifs']),6)
    def test_bad_source_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(m.stock,'validate_original',side_effect=m.stock.AuditError('bad pin')):
                with self.assertRaisesRegex(m.stock.AuditError,'bad pin'):
                    m.verify_source(Path(d))
    def test_missing_motif_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(m.stock,'validate_original',return_value={}), \
                 patch.object(m.stock,'inspect_source',return_value={}):
                with self.assertRaisesRegex(ValueError,'pattern mismatch'):
                    m.verify_source(Path(d))
    def test_output_anomaly_rejected(self):
        if not shutil.which('cc'):self.skipTest('No compiler')
        rows=m.run_model();rows[1]['waiterTaskBlocked']=False
        with self.assertRaises(ValueError):m.verify_rows(rows)
    def test_user_space_only_and_gate_stays_closed(self):
        if not shutil.which('cc'):self.skipTest('No compiler')
        with tempfile.TemporaryDirectory() as d:
            with patch.object(m,'verify_source',return_value={'verifiedMotifs':list(m.MOTIFS)}):
                report=m.analyze(Path(d))
        for name in ('originalSamsungKernelExecuted','sourceExactKernelGuestReproduced',
                     'hxl1RuntimeReachabilityProven','rootPrimitiveVerified','kernelSuInstallable','deviceModified'):
            self.assertIs(report[name],False)
        self.assertEqual(report['gate'],'USERSPACE_SEMANTIC_MODEL_ONLY')
    def test_model_does_not_trigger_kernel_race(self):
        for forbidden in ('syscall(', 'futex(', 'mmap(', 'ioctl(', 'ptrace('):
            self.assertNotIn(forbidden,m.C)
    def test_all_scenario_names_present(self):
        if not shutil.which('cc'):self.skipTest('No compiler')
        data=m.run_model()
        self.assertEqual(set(x['scenario'] for x in data),set(m.SCENARIOS))
if __name__=='__main__':unittest.main()
