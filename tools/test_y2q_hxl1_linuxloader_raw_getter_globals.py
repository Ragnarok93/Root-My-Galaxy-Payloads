"""No-provider synthetic tests of original HXL1 LinuxLoader getter RVA decoding."""
import unittest
from tools import y2q_hxl1_linuxloader_raw_getter_globals as m

# Fixed 16-word original HXL1 getter windows, independent of owner WSL files.
WORDS = {
    "dtbo": (
        "ff8300d1 fe0b00f9 281800f0 291800f0 "
        "085d42f9 e80700f9 20cd44b9 291800f0 "
        "e80740f9 295d42f9 3f0108eb 81000054 "
        "fe0b40f9 ff830091 c0035fd6 38ebff97"
    ),
    "dtb": (
        "ff8300d1 fe0b00f9 281800f0 291800f0 "
        "085d42f9 e80700f9 20d144b9 291800f0 "
        "e80740f9 295d42f9 3f0108eb 81000054 "
        "fe0b40f9 ff830091 c0035fd6 28ebff97"
    ),
}

def fixture():
    targets=[]
    for name,start in (("dtbo",0x23b00),("dtb",0x23b40)):
        words=[]
        for i,le in enumerate(WORDS[name].split()):
            word=int.from_bytes(bytes.fromhex(le),'little')
            words.append({"rva":hex(start+i*4),
                          "wordUnsignedHex":hex(word),
                          "wordLittleEndianHex":le})
        targets.append({"kind":name,"candidatePeRva":hex(start),
            "peFileOffset":hex(start),"peSection":".text","nativeWords":words})
    return {
        "schemaVersion":1,
        "classification":"SHA_PINNED_PE_RVA_WINDOWS_NO_GHIDRA_OR_SELECTOR_CLAIM",
        "device":"SM-G986U1","firmware":"G986U1UESCHXL1",
        "loaderSha256":m.LOADER_SHA,"peMachine":"0xaa64",
        "pePreferredImageBase":"0x0","targets":targets,
        "sections":[
            {"name":".text","rva":0x1000,"fileBytes":0xef000,"executable":True},
            {"name":".data","rva":0xf0000,"virtualBytes":0x276000,"executable":False},
        ],
    }

class GetterTests(unittest.TestCase):
    def test_stock_read_relationship_is_conservative(self):
        data=m.analyze(fixture())
        self.assertEqual(data['getterFindings']['dtbo']['nativeGetterReturnsGlobalU32AtRva'],'0x32a4cc')
        self.assertEqual(data['getterFindings']['dtb']['nativeGetterReturnsGlobalU32AtRva'],'0x32a4d0')
        self.assertEqual(data['adjacentGlobalsDistanceBytes'],4)
        self.assertEqual(data['getterFindings']['dtbo']['sharedSavedAndComparedCheckwordRva'],'0x32a4b8')
        self.assertFalse(data['selectedDtbOrDtboOverlayAuthenticated'])

    def test_wrong_identity_rejected(self):
        d=fixture();d['loaderSha256']='0'*64
        with self.assertRaisesRegex(m.AuditError,'identity'):m.analyze(d)

    def test_opcode_change_rejected(self):
        d=fixture();d['targets'][0]['nativeWords'][6]['wordUnsignedHex']='0xb944cd21'
        d['targets'][0]['nativeWords'][6]['wordLittleEndianHex']='21cd44b9'
        with self.assertRaisesRegex(m.AuditError,'LDR W0'):m.analyze(d)

    def test_word_endianness_rejected(self):
        d=fixture();d['targets'][0]['nativeWords'][0]['wordLittleEndianHex']='00000000'
        with self.assertRaisesRegex(m.AuditError,'endian'):m.analyze(d)

    def test_missing_function_rejected(self):
        d=fixture();d['targets']=d['targets'][:1]
        with self.assertRaisesRegex(m.AuditError,'exactly one'):m.analyze(d)

    def test_globals_out_of_data_rejected(self):
        d=fixture();d['sections'][1]['virtualBytes']=100
        with self.assertRaisesRegex(m.AuditError,'outside original PE'):m.analyze(d)

if __name__=='__main__':
    unittest.main()
