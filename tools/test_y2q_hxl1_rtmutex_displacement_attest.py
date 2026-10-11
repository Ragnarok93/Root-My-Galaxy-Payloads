"""Offline attestation regression tests; require exported HXL1 evidence archives."""
import io
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZIP_DEFLATED
from tools import y2q_hxl1_rtmutex_displacement_attest as a

REA=Path(os.environ.get('HXL1_REA_ZIP','/mnt/data/HXL1-Stage3-REA-Evidence.zip'))
ELF=Path(os.environ.get('HXL1_SLICES_ZIP','/mnt/data/HXL1-Stage3-Code-Slices.zip'))

class OriginalSliceAttestation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not REA.is_file() or not ELF.is_file():
            raise unittest.SkipTest('Original HXL1 evidence files not available in CI')
    def test_31_verified_words(self):
        r=a.attest(ELF,REA)
        self.assertEqual(r['witnessCount'],31)
        self.assertEqual(r['compiledWordWitnesses']['remove_waiter']['0x13c']['arm64Word'],'f9400d01')
    def test_stays_research_only(self):
        r=a.attest(ELF,REA)
        for k in ('sourceHeaderHashesAuthenticatedByThisTool','fullFactoryStructLayoutsAuthenticated','rootOrKernelSuVerified'):
            self.assertFalse(r[k])
    def test_source_requires_original_exact_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'Samsung C source SHA'):
                a.attest(ELF,REA,source=Path(d))
    def test_source_member_declarations_and_conditional_reporting(self):
        contents={
          'kernel/locking/rtmutex.c':'// test pinned rtmutex',
          'kernel/futex.c':'// test pinned futex',
          'include/linux/rtmutex.h':'struct rt_mutex {\nint wait_lock;\nint waiters;\nint owner;\n};\n',
          'kernel/locking/rtmutex_common.h':(
            'struct rt_mutex_waiter {\nint tree_entry;\nint pi_tree_entry;\nint task;\n'
            'int lock;\n#ifdef TEST\nint optional;\n#endif\nint prio;\nint deadline;\n};\n'),
        }
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for rel,body in contents.items():
                p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body)
            mocked={key:hashlib.sha256(contents[key].encode()).hexdigest()
                    for key in a.SOURCE_PINS}
            with patch.dict(a.SOURCE_PINS,mocked):
                r=a.attest(ELF,REA,source=root)
                self.assertTrue(r['sourceHeaderHashesAuthenticatedByThisTool'])
                self.assertFalse(r['sourceProvenance']['fullOriginalFactoryCompiledLayoutProven'])
                self.assertTrue(r['sourceProvenance']['originalSamsungHeaderDeclarationsFound']
                               ['kernel/locking/rtmutex_common.h']['conditionalMembersPossible'])
    def test_modified_word_pin_rejected(self):
        with patch.dict(a.WORDS['remove_waiter'],{0x28:'f9401ec9'}):
            with self.assertRaisesRegex(ValueError,'compiled instruction changed'):
                a.attest(ELF,REA)
    def test_wrong_elf_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'bad.zip'
            with ZipFile(ELF) as zin, ZipFile(output,'w',ZIP_DEFLATED) as zout:
                for f in zin.namelist():
                    b=zin.read(f)
                    if 'remove_waiter' in f:
                        b=b[:-1]+bytes([b[-1]^1])
                    zout.writestr(f,b)
            with self.assertRaisesRegex(ValueError,'whole ELF digest changed'):
                a.attest(output,REA)
    def test_manifest_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'bad.zip'
            with ZipFile(REA) as zin, ZipFile(output,'w',ZIP_DEFLATED) as zout:
                for f in zin.namelist():
                    b=zin.read(f)
                    if f=='stage3-rea-correlation.json':
                        data=json.loads(b);data['firmware']='WRONG';b=json.dumps(data).encode()
                    zout.writestr(f,b)
            with self.assertRaisesRegex(ValueError,'stock image identity'):
                a.attest(ELF,output)

if __name__=='__main__':unittest.main()
