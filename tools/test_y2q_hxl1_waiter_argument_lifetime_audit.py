"""Fail-closed tests for original HXL1 stack-derived waiter-helper arguments."""
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from tools import y2q_hxl1_waiter_argument_lifetime_audit as m

def fake_rows():
    rows={}
    for site in m.SITES:
        for offset,word,op,args in site['expected']:
            rows[m.BASE+offset]=(word,op,args)
    return rows

def fake_c():
    return b'''static int futex_wait_requeue_pi(void) {
struct rt_mutex_waiter rt_waiter;
/* The waiter is allocated on our stack, manipulated by the requeue */
rt_mutex_init_waiter(&rt_waiter);
q.rt_waiter = &rt_waiter;
futex_wait_setup(uaddr, val, flags, &q, &hb);
futex_wait_queue_me(hb, &q, to);
if (!q.rt_waiter)
rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);
if (ret && !rt_mutex_cleanup_proxy_lock(pi_mutex, &rt_waiter))
debug_rt_mutex_free_waiter(&rt_waiter);
unqueue_me_pi(&q);
return ret;
}
'''

class OriginalWaiterArgumentTests(unittest.TestCase):
    def test_expected_original_sites_identified(self):
        sites=m.compiled_argument_ledger(fake_rows())
        self.assertEqual([s['role'] for s in sites],['initialize','proxy_wait','proxy_cleanup'])
        self.assertEqual([s['argumentRegister'] for s in sites],['x0','x2','x1'])
        self.assertTrue(all(s['literalArgumentExpression']=='sp + 0xc0' for s in sites))
        self.assertTrue(all(s['stackPointerEqualityAcrossDistinctCallPathsProven'] is False for s in sites))

    def test_changed_register_operand_rejected(self):
        rows=fake_rows()
        rows[m.BASE+0x12fc]=('910303e2','add','x3, sp, #0xc0')
        with self.assertRaisesRegex(m.AuditError,'provenance drift'):
            m.compiled_argument_ledger(rows)

    def test_changed_register_word_rejected(self):
        rows=fake_rows()
        rows[m.BASE+0x1320]=('910303ff','add','x1, sp, #0xc0')
        with self.assertRaisesRegex(m.AuditError,'provenance drift'):
            m.compiled_argument_ledger(rows)

    def test_overwrite_between_creation_and_call_rejected(self):
        rows=fake_rows()
        rows[m.BASE+0x1304]=('aa1403e2','mov','x2, x20')
        with self.assertRaisesRegex(m.AuditError,'provenance drift'):
            m.compiled_argument_ledger(rows)

    def test_changed_callee_address_rejected(self):
        rows=fake_rows()
        rows[m.BASE+0x1328]=('97fee218','bl','0xffffff80081474fc')
        with self.assertRaisesRegex(m.AuditError,'provenance drift'):
            m.compiled_argument_ledger(rows)

    def test_ordered_source_markers(self):
        rows=m.source_markers(fake_c())
        self.assertEqual(len(rows),12)
        self.assertEqual(rows[0]['role'],'declaration')
        self.assertEqual(rows[-1]['role'],'return')

    def test_source_cleanup_not_unconditional(self):
        src=fake_c().replace(b'if (ret && !rt_mutex_cleanup_proxy_lock',
                             b'if (!rt_mutex_cleanup_proxy_lock')
        with self.assertRaisesRegex(m.AuditError,'conditional_cleanup'):
            m.source_markers(src)

    def test_source_missing_queue_pointer_rejected(self):
        src=fake_c().replace(b'q.rt_waiter = &rt_waiter;',b'q.rt_waiter = 0;')
        with self.assertRaisesRegex(m.AuditError,'queue_pointer'):
            m.source_markers(src)

    def test_repeated_source_initializer_rejected(self):
        src=fake_c().replace(b'q.rt_waiter = &rt_waiter;',
                b'rt_mutex_init_waiter(&rt_waiter);\nq.rt_waiter = &rt_waiter;')
        with self.assertRaisesRegex(m.AuditError,'initializer'):
            m.source_markers(src)

    def test_fake_nm_fails_strict_digest(self):
        with self.assertRaisesRegex(m.AuditError,'Original recovered nm SHA mismatch'):
            m.exact_nm_labels(b'anything')

    def test_original_binary_member_exact_sha_required(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source.tar.gz'
            with tarfile.open(p,'w:gz') as t:
                b=b'altered'
                ti=tarfile.TarInfo('kernel/futex.c')
                ti.size=len(b)
                t.addfile(ti,io.BytesIO(b))
            with self.assertRaisesRegex(m.AuditError,'SHA mismatch'):
                m.tar_part(p,m.PINS['source_archive'],'kernel/futex.c',
                           m.PINS['futex_source'])

    def test_cli_import_in_isolated_interpreter(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,'-I',str(Path(m.__file__).resolve()),
                              '--help'],cwd=d,text=True,capture_output=True,timeout=12)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('--source-archive',r.stdout)

if __name__=='__main__':unittest.main()
