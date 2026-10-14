"""Regression for one previously missing HXL1 function: GNU objdump VA syntax."""
import unittest
from tools import y2q_hxl1_task_blocks_original_compiled_gap as gap

E=gap.EXPECTED_ENTRY
CHAIN=0xffffff8008146ca4

def example():
    sequence=[
      (0x0,'cmp','x20, x19'),
      (0x4,'b.eq',hex(E+0x1a4)),
      (0x8,'mov','x20, x2'),
      (0xc,'str','x21, [x20, #2296]'),
      (0x10,'b',hex(E+0x18c)),
      (0x18c,'bl',hex(CHAIN)),
      (0x190,'mov','w20, w0'),
      (0x194,'mov','w0, w20'),
      (0x198,'b',hex(E+0x1a4)),
      (0x1a4,'ret',''),
    ]
    return {E+off:{'relative':hex(off),'pc':hex(E+off),
                    'word':'2a0003f4' if off==0x190 else 'd503201f',
                    'op':op,'args':args}
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
        captured=out['compiledChainwalkReturnCapture']
        self.assertEqual(captured['captureInstruction'],'mov w20, w0')
        self.assertEqual(captured['candidateCopiesFound'],1)
        self.assertTrue(captured['compiledReturnCopyCandidates'][0][
            'w20NotSyntacticallyOverwrittenAlongAConservativePath'])
        self.assertFalse(captured['runtimeNonzeroChainwalkErrorProven'])

    def test_post_copy_to_return_can_preserve_w0(self):
        output=gap.inspect(example(),{CHAIN:['rt_mutex_adjust_prio_chain']},[CHAIN])
        candidate=output['compiledChainwalkReturnCapture']['compiledReturnCopyCandidates'][0]
        self.assertTrue(candidate['existsNoSyntacticW0ClobberCandidatePathToReturn'])
        self.assertEqual(candidate['postCopyReturnPaths'][0]['conservativePath'],
                         ['0x198','0x1a4'])
        self.assertFalse(candidate['returnValueMustBeNonzeroProven'])

    def test_post_copy_call_is_a_return_register_clobber_barrier(self):
        rows=example()
        va=E+0x198
        rows[va]={'relative':'0x198','pc':hex(va),
                  'word':'94000000','op':'bl','args':hex(CHAIN)}
        va=E+0x19c
        rows[va]={'relative':'0x19c','pc':hex(va),
                  'word':'14000000','op':'b','args':hex(E+0x1a4)}
        result=gap.inspect(rows,{CHAIN:['rt_mutex_adjust_prio_chain']},[CHAIN])
        item=result['compiledChainwalkReturnCapture']['compiledReturnCopyCandidates'][0]
        self.assertTrue(item['returnStaticReachableAfterCopy'])
        self.assertFalse(item['existsNoSyntacticW0ClobberCandidatePathToReturn'])
        self.assertTrue(item['interveningCallsTreatedAsW0Clobber'])
        self.assertFalse(item['runtimeLateErrorOrPostReturnDanglingWaiterProven'])

    def test_post_copy_w0_overwrite_blocks_return_register_witness(self):
        rows=example()
        va=E+0x198
        rows[va]={'relative':'0x198','pc':hex(va),
                  'word':'52800000','op':'mov','args':'w0, #0x0'}
        va=E+0x19c
        rows[va]={'relative':'0x19c','pc':hex(va),
                  'word':'14000000','op':'b','args':hex(E+0x1a4)}
        result=gap.inspect(rows,{CHAIN:['rt_mutex_adjust_prio_chain']},[CHAIN])
        item=result['compiledChainwalkReturnCapture']['compiledReturnCopyCandidates'][0]
        self.assertTrue(item['returnStaticReachableAfterCopy'])
        self.assertFalse(item['existsNoSyntacticW0ClobberCandidatePathToReturn'])

    def test_intermediate_w20_clobber_blocks_return_copy_witness(self):
        rows=example()
        pc=E+0x194
        rows[pc]={'relative':'0x194','pc':hex(pc),
                  'word':'d503201f','op':'mov','args':'w20, w7'}
        copy=E+0x198
        rows[copy]={'relative':'0x198','pc':hex(copy),
                    'word':'d503201f','op':'mov','args':'w0, w20'}
        rows[E+0x19c]={'relative':'0x19c','pc':hex(E+0x19c),
                        'word':'d503201f','op':'b','args':hex(E+0x1a4)}
        out=gap.inspect(rows,{CHAIN:['rt_mutex_adjust_prio_chain']},[CHAIN])
        copies=out['compiledChainwalkReturnCapture']['compiledReturnCopyCandidates']
        self.assertEqual(len(copies),1)
        self.assertFalse(copies[0]['w20NotSyntacticallyOverwrittenAlongAConservativePath'])
        self.assertFalse(out['actualRuntimeLateErrorConditionProven'])

if __name__=='__main__':
    unittest.main()
