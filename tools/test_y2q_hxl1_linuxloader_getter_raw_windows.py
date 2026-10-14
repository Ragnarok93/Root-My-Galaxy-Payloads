"""Synthetic PE32+ fixtures verify offline HXL1 getter window mapping and fail-closed handling."""
import hashlib
import struct
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_linuxloader_getter_raw_windows as m

def image():
    # Original PE e_lfanew=0xe58; DOS stubs need not be 0x80 bytes.
    p=0xe58
    blob=bytearray(0x6000)
    blob[:2]=b'MZ'
    struct.pack_into('<I',blob,0x3c,p)
    blob[p:p+4]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',blob,p+4,0xaa64,1,0,0,0,0xf0,0)
    op=p+24
    struct.pack_into('<H',blob,op,0x20b)
    struct.pack_into('<Q',blob,op+0x18,0x400000)
    struct.pack_into('<I',blob,op+0x38,0x50000)
    sec=op+0xf0
    blob[sec:sec+5]=b'.text'
    struct.pack_into('<IIII',blob,sec+8,0x2000,0x23000,0x2000,0x2000)
    struct.pack_into('<I',blob,sec+36,0x60000020)
    blob[0x2b00:0x2b04]=bytes.fromhex('20008052')
    blob[0x2b40:0x2b44]=bytes.fromhex('c0035fd6')
    return bytes(blob)

def calls():
    return {'target':'SM-G986U1/G986U1UESCHXL1',
            'originalLinuxLoaderSha256':m.ORIGINAL_SHA,
            'classification':m.EXPECTED_CALLSITE_CLASS,
            'allImmediateGetterCallsitesCorroborated':True,
            'getterInternalsOrSelectionAlgorithmVerified':False,
            'callsiteEvidence':[{'indexKind':k,'ghidraStaticAnalysisTarget':hex(a)}
                                for k,a,_ in m.TARGETS]}

class OfflineWindowTests(unittest.TestCase):
    def test_pe_nonstandard_header_parse(self):
        base,size,sections=m.sections_for_image(image())
        self.assertEqual((base,size),(0x400000,0x50000))
        self.assertEqual(sections[0]['rva'],0x23000)
        self.assertTrue(sections[0]['executable'])

    def test_2_raw_function_windows_with_no_selector_claim(self):
        img=image()
        with patch.object(m,'ORIGINAL_SHA',hashlib.sha256(img).hexdigest()):
            evidence=calls();evidence['originalLinuxLoaderSha256']=m.ORIGINAL_SHA
            out=m.emit(img,evidence)
        self.assertEqual(len(out['targets']),2)
        self.assertEqual(out['targets'][0]['peFileOffset'],'0x2b00')
        self.assertEqual(out['targets'][1]['peFileOffset'],'0x2b40')
        self.assertEqual(out['targets'][0]['nativeWords'][0]['wordUnsignedHex'],'0x52800020')
        self.assertEqual(out['targets'][1]['nativeWords'][0]['decodedControlTransferOnly']['mnemonic'],'ret')
        self.assertFalse(out['ghidraAddressToPeRvaEqualityVerified'])
        self.assertFalse(out['dtbOrOverlaySelectionVerified'])

    def test_stock_sha_mismatch_rejected(self):
        with self.assertRaisesRegex(m.FailClosed,'SHA mismatch'):
            m.emit(image(),calls())

    def test_wrong_architecture_rejected(self):
        b=bytearray(image());struct.pack_into('<H',b,0xe58+4,0x8664)
        with self.assertRaisesRegex(m.FailClosed,'ARM64'):
            m.sections_for_image(bytes(b))

    def test_truncated_pe_section_rejected(self):
        with self.assertRaisesRegex(m.FailClosed,'Truncated'):
            m.sections_for_image(image()[:0xf40])

    def test_nonexecutable_section_rejected(self):
        img=bytearray(image());section=0xe58+24+0xf0
        struct.pack_into('<I',img,section+36,0x40000040)
        raw=bytes(img)
        with patch.object(m,'ORIGINAL_SHA',hashlib.sha256(raw).hexdigest()):
            evidence=calls();evidence['originalLinuxLoaderSha256']=m.ORIGINAL_SHA
            with self.assertRaisesRegex(m.FailClosed,'executable section'):
                m.emit(raw,evidence)

    def test_swapped_getters_rejected(self):
        img=image()
        with patch.object(m,'ORIGINAL_SHA',hashlib.sha256(img).hexdigest()):
            evidence=calls();evidence['originalLinuxLoaderSha256']=m.ORIGINAL_SHA
            evidence['callsiteEvidence'][0]['ghidraStaticAnalysisTarget']='0x23b40'
            with self.assertRaisesRegex(m.FailClosed,'Ambiguous/missing'):
                m.emit(img,evidence)

    def test_branch_and_negative_sign_extension(self):
        self.assertEqual(m.decode_control(0x14000001,0x1000)['targetRva'],'0x1004')
        self.assertEqual(m.decode_control(0x17ffffff,0x1000)['targetRva'],'0xffc')
        self.assertEqual(m.decode_control(0x94000002,0x1000)['targetRva'],'0x1008')
        self.assertEqual(m.decode_control(0x54000040,0x1000)['targetRva'],'0x1008')

    def test_unmapped_requested_windows_fail_closed(self):
        img=bytearray(image());sec=0xe58+24+0xf0
        struct.pack_into('<I',img,sec+12,0x1000)
        raw=bytes(img)
        with patch.object(m,'ORIGINAL_SHA',hashlib.sha256(raw).hexdigest()):
            evidence=calls();evidence['originalLinuxLoaderSha256']=m.ORIGINAL_SHA
            with self.assertRaisesRegex(m.FailClosed,'executable section'):
                m.emit(raw,evidence)

if __name__=='__main__':unittest.main()
