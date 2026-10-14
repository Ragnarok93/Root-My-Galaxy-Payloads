"""Focused synthetic tests for original LinuxLoader direct global reference scan."""
import struct
import unittest
from tools import y2q_hxl1_linuxloader_index_global_refs as m
from tools import y2q_hxl1_linuxloader_raw_getter_globals as getter
from tools.test_y2q_hxl1_linuxloader_raw_getter_globals import fixture, WORDS

def make_text(extra=None):
    body=bytearray(0x400)
    for name,start in [('dtbo',0x23b00),('dtb',0x23b40)]:
        for i,token in enumerate(WORDS[name].split()):
            pos=start-0x23b00+i*4
            body[pos:pos+4]=bytes.fromhex(token)
    if extra:
        for off,word in extra.items():
            struct.pack_into('<I',body,off,word)
    return bytes(body)

class XrefTests(unittest.TestCase):
    def test_two_original_getters_read_adjacent_globals(self):
        rows=m.scan_words(make_text(),0x23b00)
        reads={(x['indexKind'],x['accessRva'],x['mode']) for x in rows}
        self.assertIn(('dtbo','0x23b18','READ'),reads)
        self.assertIn(('dtb','0x23b58','READ'),reads)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def test_added_str_w_indicates_only_candidate_writer(self):
        extra={0x100:0xf0001829,
               0x104:0xb9000000 | ((0x4cc//4)<<10) | (9<<5),
               0x108:0xd65f03c0}
        rows=m.scan_words(make_text(extra),0x23b00)
        writes=[x for x in rows if x['mode']=='WRITE']
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0]['indexKind'],'dtbo')
        self.assertEqual(writes[0]['accessRva'],'0x23c04')
        self.assertTrue(writes[0]['isExact32BitAccess'])
        self.assertFalse(writes[0]['readWriteRegisterValueProven'])

    def test_nonmatching_page_cannot_create_writer_candidate(self):
        extra={0x100:0x90000009,
               0x104:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def test_intervening_ret_excludes_separate_writer(self):
        extra={0x100:0xf0001829,0x104:0xd65f03c0,
               0x108:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def test_no_match_cannot_be_presented_as_writer_absence_proof(self):
        words=bytes.fromhex('c0035fd6')*10
        self.assertEqual(m.scan_words(words,0x1000),[])

    def test_unaligned_scan_refused(self):
        with self.assertRaisesRegex(m.Stop,'aligned'):
            m.scan_words(b'abc',0x1000)

    def test_actual_window_reference_is_consistent(self):
        decoded=getter.analyze(fixture())
        self.assertEqual(decoded['getterFindings']['dtb']['nativeGetterReturnsGlobalU32AtRva'],'0x32a4d0')
        self.assertEqual(decoded['getterFindings']['dtbo']['nativeGetterReturnsGlobalU32AtRva'],'0x32a4cc')

if __name__=='__main__':unittest.main()
