"""Synthetic read-only tests for HXL1 OEM debug candidate discovery."""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_oem_debug_discovery as m

def elf64(section_name='.debug_info', machine=183):
    # Self-contained synthetic ELF64 Little Endian with a string table and one section.
    names = b'\x00.shstrtab\x00' + section_name.encode() + b'\x00'
    table = bytearray(64 * 3)
    struct.pack_into('<IIQQQQIIQQ',table,64,1,3,0,0,64,len(names),0,0,1,0)
    struct.pack_into('<IIQQQQIIQQ',table,128,11,1,0,0,64+len(names),4,0,0,1,0)
    ehdr=bytearray(64)
    ehdr[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H',ehdr,16,2)
    struct.pack_into('<H',ehdr,18,machine)
    struct.pack_into('<Q',ehdr,40,64+len(names)+4)
    struct.pack_into('<H',ehdr,58,64)
    struct.pack_into('<H',ehdr,60,3)
    struct.pack_into('<H',ehdr,62,1)
    return bytes(ehdr)+names+b'\x00'*4+bytes(table)

class DiscoveryTests(unittest.TestCase):
    def test_debug_elf_is_candidate_not_authenticated(self):
        with tempfile.TemporaryDirectory() as d:
            x = Path(d)/'vmlinux.debug'
            x.write_bytes(elf64())
            meta=m.inspect_elf(x)
            self.assertEqual(meta['debugSections'],['.debug_info'])
            self.assertEqual(m.classify(x,meta),'DEBUG_BEARING_CANDIDATE_REQUIRES_OEM_PROVENANCE')

    def test_comparison_debug_elf_cannot_count_as_factory(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d)/'qemu-lab'
            parent.mkdir()
            x=parent/'vmlinux'
            x.write_bytes(elf64())
            self.assertEqual(m.classify(x,m.inspect_elf(x)),'COMPARISON_BUILD_NOT_FACTORY')

    def test_reconstructed_stock_is_not_factory_debug(self):
        with tempfile.TemporaryDirectory() as d:
            x=Path(d)/'stock-vmlinux.elf'
            x.write_bytes(elf64())
            self.assertEqual(m.classify(x,m.inspect_elf(x)),'STOCK_RECONSTRUCTED_NOT_ORIGINAL_DEBUG_ELF')

    def test_non_aarch64_debug_not_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            x=Path(d)/'vmlinux'
            x.write_bytes(elf64(machine=62))
            self.assertEqual(m.classify(x,m.inspect_elf(x)),'NON_AARCH64_OR_NON_ELF_CANDIDATE')

    def test_symlink_ignored_and_depth_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'vmlinux.debug').write_bytes(elf64())
            (root/'linked.elf').symlink_to(root/'vmlinux.debug')
            deeper=root/'nested'; deeper.mkdir()
            (deeper/'vmlinux.debug').write_bytes(elf64())
            result=m.inventory([root],max_depth=0)
            self.assertEqual(result['candidateFiles'],1)
            self.assertFalse(result['oemSymbolsAuthenticated'])

    def test_exact_original_config_must_be_pinned(self):
        with self.assertRaisesRegex(m.DiscoveryError,'hash mismatch'):
            m.config_flags(b'CONFIG_DEBUG_INFO=y\n')

    def test_source_config_demotes_split_dwarf_hypothesis(self):
        data=(b'CONFIG_DEBUG_INFO=y\n# CONFIG_DEBUG_INFO_SPLIT is not set\n'
              b'CONFIG_LTO_NONE=y\nCONFIG_CLANG_VERSION=100006\n')
        with patch.object(m,'STOCK_CONFIG_SHA',hashlib.sha256(data).hexdigest()):
            out=m.config_flags(data)
        self.assertEqual(out['CONFIG_DEBUG_INFO_SPLIT'],'n')

    def test_wrong_split_dwarf_config_fails(self):
        data=(b'CONFIG_DEBUG_INFO=y\nCONFIG_DEBUG_INFO_SPLIT=y\n'
              b'CONFIG_LTO_NONE=y\nCONFIG_CLANG_VERSION=100006\n')
        with patch.object(m,'STOCK_CONFIG_SHA',hashlib.sha256(data).hexdigest()):
            with self.assertRaisesRegex(m.DiscoveryError,'flag disagreement'):
                m.config_flags(data)

    def test_inventory_limit_is_signaled(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for i in range(5): (root/('vmlinux'+str(i))).write_bytes(elf64())
            report=m.inventory([root],max_entries=2)
            self.assertTrue(report['truncated'])
            self.assertEqual(report['filesExamined'],2)
            self.assertFalse(report['oemSymbolsAuthenticated'])

if __name__ == '__main__': unittest.main()
