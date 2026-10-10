#!/usr/bin/env python3
"""Host-only tests for disposable, boot-only Linux 4.19 ARM64 QEMU lab."""
from __future__ import annotations

import argparse
import gzip
import importlib.util
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

LAB_FILE = Path(__file__).resolve().with_name("y2q_qemu_lab.py")
spec = importlib.util.spec_from_file_location("y2q_qemu_lab", LAB_FILE)
lab = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(lab)


def args_for(td: Path, action="initramfs"):
    return argparse.Namespace(
        action=action,
        source=td / "source", vendor=td / "vendor",
        output=td / "build", kasan=False,
        jobs=1, memory=1024, timeout=240
    )


def make_dummy_source(path: Path):
    (path / "arch/arm64/configs").mkdir(parents=True)
    (path / "kernel/locking").mkdir(parents=True)
    (path / "arch/arm64/configs/defconfig").write_text("")
    (path / "kernel/locking/rtmutex.c").write_text("upstream")
    (path / "kernel/futex.c").write_text("upstream")
    (path / "Makefile").write_text(
        "VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 325\nEXTRAVERSION =\n"
    )


class LabTests(unittest.TestCase):
    def test_newc_cpio_entries_have_correct_header_and_alignment(self):
        data = lab.write_cpio([
            ("dev", b"", stat.S_IFDIR | 0o755, 0, 0),
            ("dev/console", b"", stat.S_IFCHR | 0o600, 5, 1),
            ("init", b"arm64-program", stat.S_IFREG | 0o755, 0, 0),
            ("TRAILER!!!", b"", 0, 0, 0),
        ])
        pos = 0
        seen = []
        while pos < len(data):
            self.assertEqual(data[pos:pos+6], b"070701")
            fields = [int(data[pos+6+i*8:pos+14+i*8], 16)
                      for i in range(13)]
            self.assertEqual(len(fields), 13)
            mode = fields[1]
            size = fields[6]
            name_len = fields[11]
            name_off = pos + 110
            name = data[name_off:name_off+name_len].rstrip(b"\x00").decode()
            seen.append(name)
            if name == "dev/console":
                self.assertEqual(mode, stat.S_IFCHR | 0o600)
                self.assertEqual(fields[9:11], [5, 1])
            pos = (name_off + name_len + 3) & ~3
            if name == "init":
                self.assertEqual(data[pos:pos+size], b"arm64-program")
            pos = (pos + size + 3) & ~3
        self.assertEqual(seen, ["dev", "dev/console", "init", "TRAILER!!!"])

    def test_cpio_rejects_unsafe_paths(self):
        for name in ("/device", "../etc/passwd", "a/../b"):
            with self.assertRaises(lab.LabError):
                lab.write_cpio([(name, b"", stat.S_IFREG, 0, 0)])

    def test_source_guard_only_allows_upstream_4_19(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            upstream, vendor = root / "source", root / "vendor"
            make_dummy_source(upstream)
            lab.check_kernel_source(upstream, vendor)
            with self.assertRaisesRegex(lab.LabError, "Refusing"):
                lab.check_kernel_source(upstream, upstream)
            (upstream / "Makefile").write_text("VERSION = 5\nPATCHLEVEL = 10\n")
            with self.assertRaisesRegex(lab.LabError, "Linux 4.19"):
                lab.check_kernel_source(upstream, vendor)

    def test_initramfs_packs_arm64_static_init_without_mknod(self):
        with tempfile.TemporaryDirectory() as td:
            args = args_for(Path(td))
            def gcc_mock(argv, **kwargs):
                binary = Path(argv[argv.index("-o") + 1])
                header = bytearray(128)
                header[:6] = b"\x7fELF\x02\x01"
                header[18:20] = (183).to_bytes(2, "little")
                binary.write_bytes(header)
                return subprocess.CompletedProcess(argv, 0, "", "")
            with mock.patch.object(lab.shutil, "which", return_value="/usr/bin/aarch64-linux-gnu-gcc"), \
                 mock.patch.object(lab.subprocess, "run", side_effect=gcc_mock):
                path = lab.make_initramfs(args)
            self.assertTrue(path.is_file())
            raw = gzip.decompress(path.read_bytes())
            self.assertIn(b"070701", raw)
            self.assertIn(b"dev/console\x00", raw)
            self.assertIn(b"init\x00", raw)
            self.assertIn(b"TRAILER!!!\x00", raw)

    def test_boot_marks_only_exact_guest_sentinel_success(self):
        with tempfile.TemporaryDirectory() as td:
            args = args_for(Path(td), action="boot")
            output = args.output / "kernel-build/arch/arm64/boot"
            output.mkdir(parents=True)
            (output / "Image").write_bytes(b"dummy kernel")
            (args.output / "initramfs.cpio.gz").write_bytes(b"dummy archive")
            good = subprocess.CompletedProcess(["qemu"], 0,
                   "RMG_QEMU_LAB_COMPLETE=PASS_BOOT_ONLY_NOT_GHOSTLOCK\n", "")
            with mock.patch.object(lab.shutil, "which", return_value="/usr/bin/qemu-system-aarch64"), \
                 mock.patch.object(lab.subprocess, "run", return_value=good):
                self.assertEqual(lab.boot(args), 0)
            self.assertTrue(list(args.output.glob("qemu-boot-*.json")))
            bad = subprocess.CompletedProcess(["qemu"], 1,
                   "Kernel panic", "")
            with mock.patch.object(lab.shutil, "which", return_value="/usr/bin/qemu-system-aarch64"), \
                 mock.patch.object(lab.subprocess, "run", return_value=bad):
                self.assertEqual(lab.boot(args), 3)

    def test_build_status_reads_latest_compiler_line(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "kernel-build.log"
            log.write_text("  CC      kernel/sched/core.o\n"
                           "  CC      mm/memory.o\n")
            with mock.patch.object(lab.time, "monotonic", return_value=150.0):
                line = lab.build_progress_line(log, 95.0)
                self.assertIn("elapsed=55s", line)
                self.assertIn("mm/memory.o", line)
                self.assertNotIn("kernel/sched/core.o", line)
                missing = lab.build_progress_line(Path(td) / "absent.log", 95.0)
                self.assertIn("not yet readable", missing)

    def test_build_status_heartbeat_does_not_touch_build(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "kernel-build.log"
            log.write_text("  CC      kernel/locking/rtmutex.o\n")
            stop = lab.threading.Event()
            with mock.patch("builtins.print") as output:
                monitor = lab.threading.Thread(
                    target=lab.report_build_progress,
                    args=(log, stop, 0.0, 0.025),
                    daemon=True)
                monitor.start()
                # Bounded wait for the thread's 25ms heartbeat to execute.
                for _ in range(30):
                    if output.called:
                        break
                    lab.time.sleep(0.01)
                stop.set()
                monitor.join(timeout=1)
                self.assertTrue(output.called)
                self.assertIn("rtmutex.o", output.call_args.args[0])
            self.assertEqual(
                log.read_text(), "  CC      kernel/locking/rtmutex.o\n")

    def test_no_phone_or_exploit_calls_in_lab(self):
        script = LAB_FILE.read_text()
        guest = lab.GUEST_SOURCE.read_text()
        for forbidden in (
            "adb push", "adb shell", "fastboot", "init_module(",
            "FUTEX_CMP_REQUEUE_PI", "FUTEX_WAIT_REQUEUE_PI",
            "ptrace(", "setresuid(", "CAP_SYS_ADMIN"
        ):
            self.assertNotIn(forbidden, script)
            self.assertNotIn(forbidden, guest)
        self.assertIn("panic=-1", script)
        self.assertIn('"cortex-a57"', script)
        self.assertIn("RMG_QEMU_LAB_COMPLETE=PASS_BOOT_ONLY_NOT_GHOSTLOCK", guest)


if __name__ == "__main__":
    unittest.main()
