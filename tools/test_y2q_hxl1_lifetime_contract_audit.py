"""Synthetic source-lifetime evidence tests: no payload, device or exploit."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_lifetime_contract_audit as m


def fixture():
    futex = '''static int futex_wait_requeue_pi(
{
struct rt_mutex_waiter rt_waiter;
struct futex_q q = futex_q_init;
if (uaddr == uaddr2)
rt_mutex_init_waiter(&rt_waiter);
q.rt_waiter = &rt_waiter;
futex_wait_setup(
futex_wait_queue_me(
if (!q.rt_waiter)
rt_mutex_wait_proxy_lock(
rt_mutex_cleanup_proxy_lock(
debug_rt_mutex_free_waiter(
unqueue_me_pi(
put_futex_key(&q.key);
return ret;
}
'''
    shared = '''long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];
bits = stack_fds;
if (size > sizeof(stack_fds) / 6)
'''
    tail = '''ret = do_select(
if (bits != stack_fds)
'''
    select = ('int core_sys_select(\n{\n' + shared +
              'bits = kvmalloc(\n' + tail + 'kvfree(bits);\nreturn ret;\n}\n' +
              'static int compat_core_sys_select(\n{\n' + shared +
              'bits = kmalloc_array(\n' + tail + 'kfree(bits);\nreturn ret;\n}\n')
    return {'kernel/futex.c': futex, 'fs/select.c': select}


def create_archive(path, source, duplicate=False, link=False):
    with tarfile.open(path, 'w:gz') as t:
        for name in (['kernel/futex.c'] if duplicate else []) + list(source):
            raw = source[name].encode()
            member = tarfile.TarInfo(name)
            if link and name == 'fs/select.c':
                member.type = tarfile.SYMTYPE
                member.linkname = '/etc/passwd'
                t.addfile(member)
            else:
                member.size = len(raw)
                t.addfile(member, io.BytesIO(raw))


class LifetimeContractTests(unittest.TestCase):
    def test_30_ordered_source_landmarks(self):
        result = m.analyze_source(fixture())
        self.assertEqual(result['landmarksVerified'], 30)
        self.assertEqual(len(result['stages']['futex_wait_requeue_pi']), 14)
        self.assertFalse(result['factoryCompiledObjectSlotsVerified'])
        self.assertFalse(result['crossSyscallStackReuseVerified'])

    def test_futex_lifetimes_not_promoted_to_compiled_offsets(self):
        result = m.analyze_source(fixture())
        self.assertTrue(all(not item['factoryCompiledLocalVerified']
            for group in result['stages'].values() for item in group))

    def test_missing_cleanup_fails_closed(self):
        source = fixture()
        source['kernel/futex.c'] = source['kernel/futex.c'].replace(
            'rt_mutex_cleanup_proxy_lock(', 'missing_cleanup(')
        with self.assertRaisesRegex(m.AuditError, 'Missing/reordered'):
            m.analyze_source(source)

    def test_reordered_wait_fails_closed(self):
        source = fixture()
        source['kernel/futex.c'] = source['kernel/futex.c'].replace(
            'futex_wait_setup(\nfutex_wait_queue_me(',
            'futex_wait_queue_me(\nfutex_wait_setup(')
        with self.assertRaisesRegex(m.AuditError, 'Missing/reordered'):
            m.analyze_source(source)

    def test_bad_stock_hash_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'source.tar.gz'
            create_archive(path, fixture())
            with self.assertRaisesRegex(m.AuditError, 'SHA mismatch'):
                m.source_archive(path)

    def test_good_synthetic_hashes_accepted(self):
        data = fixture()
        pins = {name: hashlib.sha256(body.encode()).hexdigest()
                for name, body in data.items()}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'source.tar.gz'
            create_archive(path, data)
            with patch.object(m, 'PINS', pins):
                self.assertEqual(m.source_archive(path), data)

    def test_duplicate_source_archive_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'source.tar.gz'
            create_archive(path, fixture(), duplicate=True)
            with self.assertRaisesRegex(m.AuditError, 'Unsafe'):
                m.source_archive(path)

    def test_symlink_source_archive_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'source.tar.gz'
            create_archive(path, fixture(), link=True)
            with self.assertRaisesRegex(m.AuditError, 'Unsafe'):
                m.source_archive(path)

    def test_select_macro_not_assumed_to_be_defined_here(self):
        result = m.analyze_source(fixture())
        self.assertFalse(result['selectStackAllocationMacroDefinedInProvidedSource'])
        self.assertFalse(result['numericSelectThresholdValidated'])

    def test_markdown_explicitly_disclaims_root(self):
        body = m.markdown({'sourceLifetimeContract': {'stages': {}}})
        self.assertIn('temporary root', body)
        self.assertIn('NOT VERIFIED', body)


if __name__ == '__main__':
    unittest.main()
