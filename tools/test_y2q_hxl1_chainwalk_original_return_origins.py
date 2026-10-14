"""New-function-only tests: original PI-chain return-origin inventory."""
import unittest
from tools import y2q_hxl1_chainwalk_original_return_origins as walk

P=walk.ENTRY
def row(off,op,args):
    return {"relative":hex(off),"word":"d503201f","op":op,"args":args}
class ChainwalkReturnOriginTests(unittest.TestCase):
    def test_negative_literal_may_reach_ret_in_static_model(self):
        rows={P:row(0,"mov","w0, #0xffffffdd"),
              P+4:row(4,"b",hex(P+12)),
              P+8:row(8,"mov","w0, #0x0"),
              P+12:row(12,"ret","")}
        report=walk.inspect(rows,{},[])
        neg=report["syntacticNegativeImmediateReturnCandidates"]
        self.assertEqual(len(neg),1)
        self.assertEqual(neg[0]["immediateSigned32"],-35)
        self.assertTrue(neg[0]["possibleUnclobberedReturnPaths"])
        self.assertFalse(report["negativeErrorFromPublishedWaiterPathFeasibleVerified"])

    def test_intervening_bl_blocks_preserved_w0_witness(self):
        rows={P:row(0,"mov","w0, #0xffffffdd"),
              P+4:row(4,"bl",hex(P+100)),
              P+8:row(8,"ret","")}
        report=walk.inspect(rows,{P+100:["dummy"]},[P+100])
        candidate=report["syntacticNegativeImmediateReturnCandidates"][0]
        self.assertEqual(candidate["possibleUnclobberedReturnPaths"],[])
        self.assertFalse(report["postReturnDanglingReferenceVerified"])

    def test_nonreturn_register_or_zero_not_negative_candidate(self):
        rows={P:row(0,"mov","w8, #0xffffffdd"),
              P+4:row(4,"mov","w0, #0x0"),
              P+8:row(8,"ret","")}
        report=walk.inspect(rows,{},[])
        self.assertEqual(len(report["syntacticNegativeImmediateReturnCandidates"]),0)
        self.assertEqual(len(report["returnRegisterWriteCandidates"]),1)
        self.assertEqual(report["returnRegisterWriteCandidates"][0]["immediateSigned32"],0)

if __name__=="__main__":
    unittest.main()
