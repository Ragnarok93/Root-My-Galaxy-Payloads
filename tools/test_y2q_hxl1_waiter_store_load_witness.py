"""Synthetic regressions: no original archive or device required."""
import unittest
from tools import y2q_hxl1_waiter_store_load_witness as m
from tools import y2q_hxl1_waiter_store_load_cfg as cfg

OFFS=[0x11d0,0x11d4,0x11d8,0x11dc,0x1224,0x1228,0x122c,0x1230,
      0x1294,0x1298,0x129c,0x12a0,0x12a4,0x12a8,0x12ac,0x12b0,
      0x12b4,0x12b8,0x12bc,0x12c0,0x12c4,0x12c8,0x12cc,0x12d0,
      0x12d4,0x12d8,0x12dc,0x12e0,0x12e4,0x12e8,0x12ec]

def fixture():
    r={cfg.BASE+v:('d503201f','nop','') for v in OFFS}
    r.update({cfg.BASE+v:row for v,row in cfg.REQUIRED.items()})
    for o in m.CALLS:
        r[cfg.BASE+o]=('94000000','bl',hex(cfg.BASE+0x300))
    for o in m.BRANCHES:
        idx=OFFS.index(o)
        nxt=OFFS[idx+1]
        if nxt!=o+4:
            r[cfg.BASE+o]=('54000000','b.ne',hex(cfg.BASE+nxt))
        else:
            r[cfg.BASE+o]=('54000000','b.ne',hex(cfg.BASE+0x1be0))
    return r

class WitnessTests(unittest.TestCase):
    def test_five_branches_four_calls_and_one_store(self):
        x=m.witness(fixture())
        self.assertEqual(x['staticInstructionCount'],31)
        self.assertEqual(len(x['conditionalBranches']),5)
        self.assertEqual(len(x['directCalls']),4)
        self.assertEqual(len(x['explicitStores']),1)
        self.assertFalse(x['interproceduralMemoryAliasEffectsExcluded'])

    def test_taken_and_fallthrough_edges_recorded(self):
        c=m.witness(fixture())['conditionalBranches']
        self.assertEqual([x['selected'] for x in c],
                         ['taken','taken','fallthrough','fallthrough','fallthrough'])
        self.assertTrue(all(x['predicateFeasibleProven'] is False for x in c))

    def test_extra_explicit_store_rejected(self):
        r=fixture();r[cfg.BASE+0x12c4]=('f90003e9','str','x9, [sp]')
        with self.assertRaisesRegex(cfg.AuditError,'Explicit store census changed'):
            m.witness(r)

    def test_changed_direct_call_rejected(self):
        r=fixture();r[cfg.BASE+0x12a4]=('d503201f','nop','')
        with self.assertRaisesRegex(cfg.AuditError,'Four-call witness drift'):
            m.witness(r)

    def test_changed_branch_rejected(self):
        r=fixture();r[cfg.BASE+0x12c0]=('d503201f','nop','')
        with self.assertRaisesRegex(cfg.AuditError,'Five-condition witness drift'):
            m.witness(r)

    def test_original_store_fingerprint_is_required(self):
        r=fixture();r[cfg.BASE+0x11d0]=('d503201f','nop','')
        with self.assertRaisesRegex(cfg.AuditError,'drift'):
            m.witness(r)

    def test_cfg_does_not_claim_runtime_lifetime(self):
        x=m.witness(fixture())
        self.assertFalse(x['pointerLifetimeAcrossWaitVerified'])
        self.assertFalse(x['crossSyscallStackReuseOrRootVerified'])
        self.assertFalse(x['sourceFutexQFieldExactFactoryIdentityVerified'])

if __name__=='__main__': unittest.main()
