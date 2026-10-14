"""Regression for one previously missing HXL1 function: GNU objdump VA syntax."""
import unittest
from tools import y2q_hxl1_task_blocks_original_compiled_gap as gap

E=gap.EXPECTED_ENTRY
CHAIN=0xffffff8008146ca4

def example():
    sequence=[
      (0x0,'cmp','x20, x19'),
      (0x4,'b.eq',hex(E+0x18)),
      (0x8,'mov','x20, x2'),
      (0xc,'str','x21, [x20, #2296]'),
      (0x10,'bl',hex(CHAIN)),
      (0x14,'b',hex(E+0x18)),
      (0x18,'ret',''),
    ]
    return {E+off:{'relative':hex(off),'pc':hex(E+off),
                    'word':'d503201f','op':op,'args':args}
            for off,op,args in sequence}

class NewFunctionBranchSyntaxTests(unittest.TestCase):
    def test_gnu_no_prefix_branch_and_call_addresses_normalized(self):
        n=gap.normalize_objdump_control_target
        self.assertEqual(n('bl','ffffff8008146ca4'),hex(CHAIN))
        self.assertEqual(n('b.eq',f'{E+0x18:016x}'),hex(E+0x18))
        self.assertEqual(n('cbnz',f'w0, {E+0x18:016x}'),
                         f'w0, {hex(E+0x18)}')

    def test_non_control_offsets_and_unknown_forms_not_fabricated(self):
        n=gap.normalize_objdump_control_target
        self.assertEqual(n('str','x21, [x20, #2296]'),
                         'x21, [x20, #2296]')
        self.assertEqual(n('blr','x8'),'x8')
        self.assertEqual(n('b','unexpected_symbol'),'unexpected_symbol')

    def test_publication_then_chainwalk_then_return_and_early_return(self):
        labels={CHAIN:['rt_mutex_adjust_prio_chain']}
        out=gap.inspect(example(),labels,sorted(labels))
        self.assertEqual(out['candidateStoresCount'],1)
        self.assertEqual(out['exactRtMutexAdjustPrioChainCallCount'],1)
        store=out['candidatePiBlockedOnStoreDisplacements'][0]
        self.assertTrue(store['staticEntryMayReachPublication'])
        self.assertTrue(store['possibleReturnReachableAfterStoreUnderConservativeGraph'])
        self.assertTrue(store['possibleEarlyReturnAvoidingThisStoreUnderConservativeGraph'])
        flow=store['chainwalkCandidatesFromPublication'][0]
        self.assertTrue(flow['staticPublicationMayReachChainwalk'])
        self.assertTrue(flow['staticChainwalkMayReachReturn'])
        self.assertFalse(flow['postPublicationErrorResultProven'])
        self.assertFalse(out['lateErrorPostPublicationObservedAtRuntime'])

if __name__=='__main__':
    unittest.main()
