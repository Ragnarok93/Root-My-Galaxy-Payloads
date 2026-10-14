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

def fake_sp_frame_rows():
    rows=fake_rows()
    rows[m.BASE]=('d10783ff','sub','sp, sp, #0x1e0')
    rows[m.BASE+0xb78]=('910783ff','add','sp, sp, #0x1e0')
    rows[m.BASE+0xb7c]=('d65f03c0','ret','')
    present=sum(bool(m.SP_OPERAND.search(args)) for _,op,args in rows.values())
    count=158-present
    for i in range(count):
        addr=m.BASE+0x200+4*i
        assert addr not in rows
        rows[addr]=('910023e9','add','x9, sp, #0x8')
    return rows

class OriginalWaiterArgumentTests(unittest.TestCase):
    def test_original_frame_has_only_entry_and_return_sp_writes(self):
        r=m.compiled_sp_integrity(fake_sp_frame_rows())
        self.assertEqual(r['observedInstructionsReferencingSp'],158)
        self.assertEqual(r['observedSpWriteOffsets'],['0x0','0xb78'])
        self.assertEqual(r['frameAllocationBytes'],480)
        self.assertTrue(r['frameBaseSpHasNoOtherSyntacticWrites'])
        self.assertFalse(r['allPathCallSequenceAndObjectLifetimeProven'])

    def test_third_sp_write_refused(self):
        rows=fake_sp_frame_rows()
        rows[m.BASE+0x200]=('910043ff','add','sp, sp, #0x10')
        with self.assertRaisesRegex(m.AuditError,'SP-write instruction inventory drift'):
            m.compiled_sp_integrity(rows)

    def test_sp_memory_writeback_refused(self):
        rows=fake_sp_frame_rows()
        rows[m.BASE+0x200]=('f84087e9','ldr','x9, [sp], #8')
        with self.assertRaisesRegex(m.AuditError,'implicit memory writeback'):
            m.compiled_sp_integrity(rows)

    def test_unexpected_sp_opcode_refused(self):
        rows=fake_sp_frame_rows()
        rows[m.BASE+0x200]=('910003e9','mov','x9, sp')
        with self.assertRaisesRegex(m.AuditError,'Unexpected SP instruction'):
            m.compiled_sp_integrity(rows)

    def test_modified_epilogue_word_refused(self):
        rows=fake_sp_frame_rows()
        rows[m.BASE+0xb78]=('910683ff','add','sp, sp, #0x1e0')
        with self.assertRaisesRegex(m.AuditError,'SP-write instruction inventory drift'):
            m.compiled_sp_integrity(rows)

    def test_early_missing_ret_refused(self):
        rows=fake_sp_frame_rows()
        rows[m.BASE+0xb7c]=('d503201f','nop','')
        with self.assertRaisesRegex(m.AuditError,'not immediately followed by ret'):
            m.compiled_sp_integrity(rows)

    def test_extra_sp_reference_detected(self):
        rows=fake_sp_frame_rows()
        rows[m.BASE+0x500]=('910023ea','add','x10, sp, #0x8')
        with self.assertRaisesRegex(m.AuditError,'SP reference count drift'):
            m.compiled_sp_integrity(rows)

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
