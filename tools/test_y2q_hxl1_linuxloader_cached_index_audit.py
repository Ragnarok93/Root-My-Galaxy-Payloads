"""Offline no-REA-provider tests for index function cache analysis."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

PATH=Path(__file__).with_name('y2q_hxl1_linuxloader_cached_index_audit.py')
spec=importlib.util.spec_from_file_location('y2q_hxl1_linuxloader_cached_index_audit',PATH)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CachedIndexAuditTests(unittest.TestCase):
    def test_exact_cancelled_partial_is_not_a_completed_trace(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'partial.json'
            p.write_text(json.dumps({'error':'Analysis failed','code':'cancelled',
                                     'category':'cancelled',
                                     'details':{'operation':'analyze_function','cleanup':'complete'}}))
            item=m.trace_status(p)
        self.assertEqual(item['state'],'SAVED_TRACE_FAILURE')
        self.assertEqual(item['code'],'cancelled')
        self.assertEqual(item['operation'],'analyze_function')
        self.assertFalse(item['verifiedValueFlow'])

    def test_missing_trace_is_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            r=m.trace_status(Path(d)/'nothing.json')
            self.assertEqual(r['state'],'NO_SAVED_TRACE')
            self.assertFalse(r['verifiedValueFlow'])

    def test_nonerror_trace_still_needs_independent_schema(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'result.json';path.write_text('{"operation":"trace-native-values"}')
            r=m.trace_status(path)
            self.assertEqual(r['state'],'SAVED_NONERROR_REPORT_NOT_INDEPENDENTLY_VERIFIED')
            self.assertFalse(r['verifiedValueFlow'])

    def test_snippet_matches_both_literals_without_proving_producers(self):
        fake='\n'.join(['start', 'x = "androidboot.dtb_idx="',
                        'format(cmd,x,value)', 'y = "androidboot.dtbo_idx="',
                        'format(cmd,y,other)', 'end'])
        r=m.snippet(fake)
        self.assertEqual(r['indexLiteralLineCount'],2)
        self.assertFalse(r['producerValueFlowProved'])
        self.assertIn('androidboot.dtb_idx',r['boundedPseudocodeExcerpt'][1]['text'])

    def test_missing_literal_is_not_proof_of_absence(self):
        r=m.snippet('proc_FUN_0002bdf8(arg0)')
        self.assertEqual(r['indexLiteralLineCount'],0)
        self.assertEqual(r['boundedPseudocodeExcerpt'],[])
        self.assertFalse(r['producerValueFlowProved'])

    def test_excerpt_has_strict_line_and_character_bounds(self):
        s='\n'.join(['androidboot.dtb_idx='+('A'*1000) for _ in range(30)])
        r=m.snippet(s)
        self.assertLessEqual(len(r['boundedPseudocodeExcerpt']),m.MAX_SNIPPET_LINES)
        self.assertTrue(all(len(x['text'])<=240 for x in r['boundedPseudocodeExcerpt']))
        self.assertTrue(r['snippetTruncated'])

    def test_modified_unsafe_partial_json_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'partial.json';p.write_text('{broken')
            with self.assertRaises(ValueError):m.trace_status(p)

    def test_reject_symlink_partial(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source.json';p.write_text('{}')
            link=Path(d)/'partial.json';link.symlink_to(p)
            with self.assertRaisesRegex(m.AuditError,'Unsafe'):
                m.trace_status(link)

    def test_missing_run_no_fake_cache(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(m.AuditError,'Missing/symlink'):
                m.review_cached(Path(d)/'missing',Path(d)/'loader',Path(d)/'partial')

    def test_loader_hash_mismatch_fails_before_provider_import(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);p=r/'loader';p.write_bytes(b'not a real loader')
            with self.assertRaisesRegex(m.AuditError,'SHA mismatch'):
                m.review_cached(r,p,r/'partial')

if __name__=='__main__':unittest.main()
