"""Focused synthetic tests for original LinuxLoader direct global reference scan."""
import struct
import hashlib
import unittest
from unittest import mock
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

    def test_mov_of_page_base_prevents_false_writer(self):
        extra={0x100:0xf0001829,  # adrp x9, original global page
               0x104:0xaa0003e9,  # mov x9, x0 (clobber)
               0x108:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def test_load_of_page_base_prevents_false_writer(self):
        extra={0x100:0xf0001829,
               0x104:0xf9400009,  # ldr x9, [x0] replaces the ADRP base
               0x108:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def test_pair_load_second_register_clobbers_page_base(self):
        extra={0x100:0xf0001829,
               0x104:0xa9400000 | (9<<10) | 1,  # ldp x1, x9, [x0]
               0x108:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def test_store_of_page_base_does_not_invalidate_it(self):
        extra={0x100:0xf0001829,
               0x104:0xf9000009,  # str x9, [x0] does not change x9
               0x108:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertEqual(len([x for x in rows if x['mode']=='WRITE']),1)

    def test_move_wide_clobber_prevents_false_writer(self):
        extra={0x100:0xf0001829,
               0x104:0xd2800009,  # movz x9, #0
               0x108:0xb9000000 | ((0x4cc//4)<<10) | (9<<5)}
        rows=m.scan_words(make_text(extra),0x23b00)
        self.assertFalse(any(x['mode']=='WRITE' for x in rows))

    def _context_fixture(self):
        text=make_text({0x100:0xf0001829,
                        0x104:0xb9000000 | ((0x4d0//4)<<10) | (9<<5) | 8,
                        0x108:0xd65f03c0})
        reads=m.scan_words(text,0x23b00)
        counters={kind:{'readCandidates':0,'writeCandidates':0}
                  for kind in m.TARGETS}
        for row in reads:
            k='readCandidates' if row['mode']=='READ' else 'writeCandidates'
            counters[row['indexKind']][k]+=1
        cfg={'schemaVersion':1,'target':'SM-G986U1/G986U1UESCHXL1',
             'classification':'EXACT_HASH_ORIGINAL_LOADER_DIRECT_GLOBAL_REFERENCES_ONLY',
             'nativeGetterWindowsReconciledAgainstHashedOriginalLoader':True,
             'originalLinuxLoaderSha256':hashlib.sha256(text).hexdigest(),
             'originalPeImageSize':0x4000000,
             'textSectionRva':'0x23b00','textBytesScanned':len(text),
             'getterGlobalAddresses':{k:hex(v) for k,v in m.TARGETS.items()},
             'directScalarReferences':reads,
             'summaryByKind':counters}
        section={'name':'.text','rva':0x23b00,'fileOffset':0,
                 'fileBytes':len(text),'executable':True}
        return text,cfg,section

    def _evaluate_context(self,text,report,section):
        with mock.patch.object(m.pe,'ORIGINAL_SHA',hashlib.sha256(text).hexdigest()),\
             mock.patch.object(m.pe,'sections_for_image',
                               return_value=(0,0x4000000,[section])):
            return m.report_writer_window(text,report)

    def test_existing_reference_report_yields_one_bounded_original_writer_packet(self):
        text,report,section=self._context_fixture()
        result=self._evaluate_context(text,report,section)
        self.assertEqual(result['classification'],
                         'EXACT_ORIGINAL_LOADER_BOUNDED_DTB_WRITER_CODE_CONTEXT')
        self.assertEqual(len(result['writerWindows']),1)
        writer=result['writerWindows'][0]
        self.assertEqual(writer['indexKind'],'dtb')
        self.assertEqual(writer['writerCandidateRva'],'0x23c04')
        self.assertEqual(writer['writerBaseRegister'],'x9')
        self.assertEqual(writer['writerValueRegister'],'w8')
        self.assertTrue(writer['originalWords'])
        self.assertFalse(writer['valueDefinitionAndBranchFeasibilityEstablished'])

    def test_existing_report_cannot_reinterpret_mutated_original_store_word(self):
        text,report,section=self._context_fixture()
        corrupted=bytearray(text)
        struct.pack_into('<I',corrupted,0x104,0xd503201f)
        with self.assertRaisesRegex(m.Stop,'Original loader SHA mismatch'):
            self._evaluate_context(bytes(corrupted),report,section)

    def test_existing_report_rejects_modified_global_summary(self):
        text,report,section=self._context_fixture()
        report['summaryByKind']['dtb']['writeCandidates']=2
        with self.assertRaisesRegex(m.Stop,'summary is inconsistent'):
            self._evaluate_context(text,report,section)

    def test_existing_report_rejects_stale_adrp_base(self):
        text,report,section=self._context_fixture()
        corrupted=bytearray(text)
        struct.pack_into('<I',corrupted,0x100,0x90000009) # different page
        report['originalLinuxLoaderSha256']=hashlib.sha256(corrupted).hexdigest()
        with self.assertRaisesRegex(m.Stop,'Reference not confirmed'):
            self._evaluate_context(bytes(corrupted),report,section)

    def test_existing_report_rejects_intervening_base_overwrite(self):
        text,report,section=self._context_fixture()
        # Move the recorded store four bytes later, with a register clobber
        # after the ADRP: never infer this as a writer of the original global.
        corrupted=bytearray(text)
        struct.pack_into('<I',corrupted,0x104,0xaa0003e9) # mov x9,x0
        struct.pack_into('<I',corrupted,0x108,
                         0xb9000000 | ((0x4d0//4)<<10) | (9<<5) | 8)
        row=next(x for x in report['directScalarReferences'] if x['mode']=='WRITE')
        row['accessRva']='0x23c08'
        report['originalLinuxLoaderSha256']=hashlib.sha256(corrupted).hexdigest()
        with self.assertRaisesRegex(m.Stop,'base clobber'):
            self._evaluate_context(bytes(corrupted),report,section)

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
