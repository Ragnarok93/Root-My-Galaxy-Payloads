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

    def test_duplicate_unrelated_symbol_names_preserve_both_addresses(self):
        first = m.IMAGE_VA + 0x180
        second = m.IMAGE_VA + 0x380
        listing = (f'{m.IMAGE_VA:x} T _text\n'
                   f'{first:x} T gic_handle_irq\n'
                   f'{second:x} t gic_handle_irq\n')
        parsed = m.parse_nm(listing)
        self.assertEqual(parsed['gic_handle_irq'], (first, 'T'))
        self.assertEqual(parsed.duplicate_unrelated_names['gic_handle_irq'],
                         {first, second})
        self.assertTrue({first, second}.issubset(parsed.all_text_addresses))

    def test_duplicate_required_symbol_different_va_rejected(self):
        with self.assertRaisesRegex(m.GateError, 'Ambiguous required text symbol'):
            m.parse_nm(
                f'{m.IMAGE_VA+0x100:x} T core_sys_select\n'
                f'{m.IMAGE_VA+0x120:x} t core_sys_select\n')
        with self.assertRaisesRegex(m.GateError, 'Ambiguous required text symbol'):
            m.parse_nm(
                f'{m.IMAGE_VA:x} T _text\n'
                f'{m.IMAGE_VA+0x10:x} T _text\n')

    def test_unrelated_duplicate_creates_correct_nearest_code_boundary(self):
        raw = fake_image()
        lines = [f'{va:x} {kind} {name}'
                 for name, (va, kind) in syms().items()]
        lines.extend([
            f'{m.IMAGE_VA+0x180:x} T gic_handle_irq',
            f'{m.IMAGE_VA+0x380:x} t gic_handle_irq'])
        parsed = m.parse_nm('\n'.join(lines))
        with patch.object(m, 'STOCK_SHA', hashlib.sha256(raw).hexdigest()):
            result, slices = m.collect(raw, parsed)
        self.assertEqual(len(slices['core_sys_select']), 0x80)
        self.assertEqual(len(slices['futex_wait_requeue_pi']), 0x80)
        self.assertEqual(result['recoveredNmDuplicateUnrelatedTextNames'], 1)
        self.assertEqual(result['recoveredNmDuplicateUnrelatedExamples'],
                         ['gic_handle_irq'])
        self.assertFalse(result['validGhostLockStackReclamationEstablished'])

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
