"""Regression tests for offline original-image function slice gating."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_ghostlock_stack_gate as m


def fake_image():
    content = bytearray(0x1000)
    content[0x38:0x3c] = b'ARM\x64'
    return bytes(content)


def syms():
    return {
        '_text': (m.IMAGE_VA, 'T'),
        'core_sys_select': (m.IMAGE_VA + 0x100, 'T'),
        'do_select': (m.IMAGE_VA + 0x200, 't'),
        'futex_wait_requeue_pi': (m.IMAGE_VA + 0x300, 'T'),
        'next': (m.IMAGE_VA + 0x400, 't'),
    }


class StackGateTests(unittest.TestCase):
    def test_recovered_nm_text_only(self):
        listing = (f'{m.IMAGE_VA:x} T _text\n'
                   f'{m.IMAGE_VA + 0x100:x} t do_select\n'
                   f'{m.IMAGE_VA + 0x200:x} D private_data\n'
                   'invalid line\n')
        result = m.parse_nm(listing)
        self.assertIn('do_select', result)
        self.assertNotIn('private_data', result)
        self.assertEqual(result['_text'], (m.IMAGE_VA, 'T'))

    def test_duplicate_symbol_different_va_rejected(self):
        with self.assertRaisesRegex(m.GateError, 'Conflicting'):
            m.parse_nm(f'{m.IMAGE_VA:x} T foo\n{m.IMAGE_VA+8:x} t foo')

    def test_pinned_kernel_mismatch_rejected(self):
        with self.assertRaisesRegex(m.GateError, 'SHA256 mismatch'):
            m.collect(fake_image(), syms())

    def test_bounded_functions_and_missing_symbols_no_fake_feasibility(self):
        raw = fake_image()
        with patch.object(m, 'STOCK_SHA', hashlib.sha256(raw).hexdigest()):
            result, slices = m.collect(raw, syms())
        self.assertEqual(result['originalFunctionsWithBoundedCode'], 3)
        self.assertEqual(len(slices['core_sys_select']), 0x100)
        self.assertEqual(len(slices['do_select']), 0x100)
        self.assertEqual(len(slices['futex_wait_requeue_pi']), 0x100)
        self.assertFalse(result['validGhostLockStackReclamationEstablished'])
        self.assertFalse(result['workingRootEstablished'])
        self.assertTrue(any(x['status'] == 'NOT_FOUND_IN_RECOVERED_NM'
                            for x in result['functions']))

    def test_image_slice_rejects_invalid_range(self):
        raw = fake_image()
        with self.assertRaisesRegex(m.GateError, 'Unaligned'):
            m.image_slice(raw, m.IMAGE_VA + 1, m.IMAGE_VA + 200)
        with self.assertRaisesRegex(m.GateError, 'Nonpositive'):
            m.image_slice(raw, m.IMAGE_VA + 0x100, m.IMAGE_VA + 0x100)
        with self.assertRaisesRegex(m.GateError, 'beyond'):
            m.image_slice(raw, m.IMAGE_VA + 0x100, m.IMAGE_VA + 0x2000)

    def test_no_next_symbol_is_not_guessed(self):
        code, item = m.image_slice(fake_image(), m.IMAGE_VA + 0x100, None)
        self.assertEqual(code, b'')
        self.assertEqual(item['status'], 'NO_NEXT_BOUND')

    def test_gnu_binutils_invocation_does_not_execute_image(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            outfile = Path(folder) / 'func.disasm.txt'
            with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='hello disasm', stderr='')) as mocked:
                result = m.disassemble(b'\x1f\x20\x03\xd5', m.IMAGE_VA,
                                       outfile, '/usr/bin/aarch64-linux-gnu-objdump')
            cmd = mocked.call_args.args[0]
            self.assertIn('-D', cmd)
            self.assertIn('-b', cmd)
            self.assertNotIn('adb', ' '.join(cmd))
            self.assertTrue(outfile.is_file())
            self.assertEqual(result['status'], 'DISASSEMBLED')


if __name__ == '__main__':
    unittest.main()
