"""Self-contained negative tests for HXL1 factory debug evidence gate."""
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_factory_debug_ceiling as m

GOOD_CONFIG = ('CONFIG_CC_IS_CLANG=y\nCONFIG_CLANG_VERSION=100006\n'
               'CONFIG_LTO_NONE=y\nCONFIG_DEBUG_INFO=y\nCONFIG_FRAME_POINTER=y\n'
               'CONFIG_STACKPROTECTOR_STRONG=y\nCONFIG_MODULE_SIG_FORCE=y\n'
               '# CONFIG_KPROBES is not set\n').encode()
GOOD_FILES = {
    'stock-sections.txt': b' [ 1] .kernel PROGBITS 0000\n [ 4] .symtab SYMTAB 0000\n',
    'qemu-lab-sections.txt': b' [12] .debug_info PROGBITS 0000\n',
    'qemu-lab-kasan-sections.txt': b' [12] .debug_info PROGBITS 0000\n',
    'stock-task_struct-errors.txt': b"libbpf: failed to find '.BTF' ELF section\npahole: Invalid argument\n",
    'stock-rt_mutex_waiter-errors.txt': b"libbpf: failed to find '.BTF' ELF section\npahole: Invalid argument\n",
}

def make_archive(path, parts, repeat=False, symlink=False):
    with tarfile.open(path, 'w:gz') as ar:
        for name, data in parts.items():
            for _ in range(2 if repeat and name == 'stock-sections.txt' else 1):
                info = tarfile.TarInfo('./' + name)
                if symlink and name == 'stock-sections.txt':
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/etc/passwd'
                    ar.addfile(info)
                else:
                    info.size = len(data)
                    ar.addfile(info, io.BytesIO(data))

class Hxl1FactoryDebugCeilingTests(unittest.TestCase):
    def test_real_owner_bundle(self):
        config = os.environ.get('HXL1_STOCK_CONFIG')
        archive = os.environ.get('HXL1_DWARF_ARCHIVE')
        if not config or not archive:
            self.skipTest('Owner stock config and DWARF report archive not supplied')
        result = m.audit(Path(config), Path(archive))
        self.assertTrue(result['debugInfoConfiguredButAbsentFromReconstructedElf'])
        self.assertFalse(result['compilerLocalIdentityProven'])
        self.assertFalse(result['workingGhostLockOrKernelSu'])

    def test_config_is_pinned(self):
        with self.assertRaisesRegex(m.AuditError, 'SHA256 mismatch'):
            m.parse_config(GOOD_CONFIG)

    def test_synthetic_config_and_clang_flags(self):
        with patch.object(m, 'CONFIG_SHA', hashlib.sha256(GOOD_CONFIG).hexdigest()):
            flags = m.parse_config(GOOD_CONFIG)
        self.assertEqual(flags['CONFIG_LTO_NONE'], 'y')
        self.assertEqual(flags['CONFIG_CLANG_VERSION'], '100006')

    def test_config_ambiguity_rejected(self):
        duplicate = GOOD_CONFIG + b'CONFIG_LTO_NONE=n\n'
        with patch.object(m, 'CONFIG_SHA', hashlib.sha256(duplicate).hexdigest()):
            with self.assertRaisesRegex(m.AuditError, 'ambiguous'):
                m.parse_config(duplicate)

    def test_report_archive_regular_members_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'r.tar.gz';make_archive(dest,GOOD_FILES)
            data, digest = m.read_reports(dest)
            self.assertEqual(set(m.ARTIFACTS), set(data))
            self.assertEqual(len(digest), 64)

    def test_duplicate_member_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'r.tar.gz';make_archive(dest,GOOD_FILES,repeat=True)
            with self.assertRaisesRegex(m.AuditError, 'Duplicate'):
                m.read_reports(dest)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'r.tar.gz';make_archive(dest,GOOD_FILES,symlink=True)
            with self.assertRaisesRegex(m.AuditError, 'Unexpected symlink'):
                m.read_reports(dest)

    def test_debug_sections_recognized_only_as_sections(self):
        self.assertNotIn('.debug_info',m.sections(GOOD_FILES['stock-sections.txt']))
        self.assertIn('.debug_info',m.sections(GOOD_FILES['qemu-lab-sections.txt']))

    def test_malformed_section_dump_rejected(self):
        with self.assertRaisesRegex(m.AuditError, 'section inventory'):
            m.sections(b'no ELF section table here')

    def test_no_original_compiler_object_claim(self):
        with patch.object(m, 'CONFIG_SHA', hashlib.sha256(GOOD_CONFIG).hexdigest()):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); config=root/'stock.config'; archive=root/'reports.tar.gz'
                config.write_bytes(GOOD_CONFIG);make_archive(archive,GOOD_FILES)
                result=m.audit(config, archive)
        self.assertFalse(result['recoveredNmProvidesFactoryCVariableLocationLists'])
        self.assertFalse(result['stockReconstructedElf']['originalUnstrippedOEMVmlinuxAvailableInSuppliedEvidence'])
        self.assertFalse(result['qemuNormalComparison']['factoryEquivalent'])

if __name__ == '__main__':
    unittest.main()
