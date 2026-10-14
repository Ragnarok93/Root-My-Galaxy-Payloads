"""Synthetic regression tests for missing stock HXL1 chainwalk W20 origins."""
import unittest
from tools import y2q_hxl1_chainwalk_w20_origins as m

P=m.ENTRY
COPY=P+m.COPY_OFFSET

def row(off, op, args, word='d503201f'):
    return {'relative':hex(off),'op':op,'args':args,'word':word}

def sample(insns):
    r={P+off:row(off,*item) for off,item in insns.items()}
    r[COPY]=row(m.COPY_OFFSET,'mov','w0, w20',m.COPY_WORD)
    return r

def link(*nodes):
    return {nodes[i]:[nodes[i+1]] for i in range(len(nodes)-1)}

class CarrierTests(unittest.TestCase):
    def test_negative_w20_literal_reaches_copy(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('b',hex(COPY))})
        report=m.analyze(r,{P+4:[COPY]})
        self.assertEqual(report['deadlockLiteralOriginsCount'],1)
        self.assertEqual(report['negativeLiteralOriginsWithConservativeWitness'][0]['signed32Literal'],-35)
        self.assertFalse(report['branchPredicateFeasibilityProven'])

    def test_movn_negative_immediate(self):
        r=sample({0:('movn','w20, #0x22'),4:('b',hex(COPY))})
        self.assertEqual(m.analyze(r,{P+4:[COPY]})['negativeLiteralOriginsCount'],1)

    def test_overwrite_blocks_path(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('mov','w20, #0')})
        report=m.analyze(r,link(P,P+4,COPY))
        self.assertEqual(report['negativeLiteralOriginsCount'],0)
        self.assertEqual(report['definitionsCount'],2)

    def test_x20_alias_clobber(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('mov','x20, x6')})
        self.assertEqual(m.analyze(r,link(P,P+4,COPY))['negativeLiteralOriginsCount'],0)

    def test_abi_callee_saved_register(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('bl','0xffffff80080abc00')})
        self.assertEqual(m.analyze(r,link(P,P+4,COPY))['negativeLiteralOriginsCount'],1)

    def test_unknown_load_cancels_constant(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('ldr','w20, [x5]')})
        self.assertEqual(m.analyze(r,link(P,P+4,COPY))['negativeLiteralOriginsCount'],0)

    def test_store_using_w20_does_not_clobber(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('str','w20, [x5]')})
        self.assertEqual(m.analyze(r,link(P,P+4,COPY))['negativeLiteralOriginsCount'],1)

    def test_status_store_destination_clobber(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('stxr','w20, w9, [x5]')})
        self.assertEqual(m.analyze(r,link(P,P+4,COPY))['negativeLiteralOriginsCount'],0)

    def test_second_register_in_ldp_clobbers(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('ldp','x1, x20, [sp]')})
        self.assertEqual(m.analyze(r,link(P,P+4,COPY))['negativeLiteralOriginsCount'],0)

    def test_partial_movk_not_complete_literal(self):
        r=sample({0:('movk','w20, #0xffdd')})
        self.assertIsNone(m.analyze(r,{P:[COPY]})['definitions'][0]['signed32Literal'])

    def test_nonliteral_dataflow_unknown(self):
        r=sample({0:('mov','w20, w17')})
        self.assertEqual(m.analyze(r,{P:[COPY]})['negativeLiteralOriginsCount'],0)

    def test_copy_word_must_match(self):
        r=sample({0:('mov','w20, #0xffffffdd')})
        r[COPY]['word']='00000000'
        with self.assertRaisesRegex(m.GapError,'fingerprint'):
            m.analyze(r,{P:[COPY]})

    def test_branch_can_bypass_overwrite_is_only_possible(self):
        r=sample({0:('mov','w20, #0xffffffdd'),4:('b.cond',hex(COPY)),8:('mov','w20, #0')})
        result=m.analyze(r,{P+4:[P+8,COPY],P+8:[COPY]})
        self.assertEqual(result['negativeLiteralOriginsCount'],1)
        self.assertFalse(result['branchPredicateFeasibilityProven'])

if __name__=='__main__':
    unittest.main()
