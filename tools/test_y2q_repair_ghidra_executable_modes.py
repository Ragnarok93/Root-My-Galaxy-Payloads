#!/usr/bin/env python3
"""Offline fixture tests for official-ZIP-verified Ghidra chmod repair."""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from tools import y2q_repair_ghidra_executable_modes as mod


class GhidraExecutableModeRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.install = self.base / mod.ZIP_ROOT
        self.install.mkdir()
        self.archive = self.base / mod.ZIP_NAME
        self.entries = {
            "support/analyzeHeadless": b"#!/bin/sh\nexit 0\n",
            "support/launch.sh": b"#!/bin/sh\nexit 0\n",
            "Ghidra/Features/Decompiler/os/linux_x86_64/decompile":
                b"\x7fELF\x02\x01\x01" + bytes(120),
            "Ghidra/application.properties": b"application.version=12.1.4\n",
        }
        self.make_zip()
        for name, content in self.entries.items():
            target = self.install / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o644)
        self.pin = mod.sha256_path(self.archive)

    def make_zip(self):
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_DEFLATED) as z:
            for path, payload in self.entries.items():
                item = zipfile.ZipInfo(mod.ZIP_ROOT + "/" + path)
                item.create_system = 3
                executable = path in mod.REQUIRED_EXECUTABLES
                item.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
                z.writestr(item, payload)

    def go(self, *, apply=True):
        return mod.restore(self.archive, self.install,
                           expected_sha=self.pin, apply=apply)

    def test_recover_three_expected_exec_modes(self):
        report = self.go()
        self.assertEqual(report["verifiedExecutableFiles"], 3)
        self.assertEqual(report["changedFiles"], 3)
        self.assertFalse(report["firmwareModified"])
        for name in mod.REQUIRED_EXECUTABLES:
            self.assertEqual(stat.S_IMODE((self.install / name).stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(
            (self.install / "Ghidra/application.properties").stat().st_mode), 0o644)

    def test_dry_run_does_not_modify(self):
        report = self.go(apply=False)
        self.assertEqual(report["status"], "DRY_RUN")
        for name in mod.REQUIRED_EXECUTABLES:
            self.assertEqual(stat.S_IMODE((self.install / name).stat().st_mode), 0o644)

    def test_idempotent_second_pass(self):
        self.go()
        again = self.go()
        self.assertEqual(again["changedFiles"], 0)

    def test_wrong_archive_digest_refused(self):
        with self.assertRaisesRegex(mod.ModeRepairError, "SHA256 mismatch"):
            mod.restore(self.archive, self.install, expected_sha="0" * 64)

    def test_modified_extracted_script_refused_without_partial_chmod(self):
        self.install.joinpath("support/launch.sh").write_bytes(b"tampered")
        with self.assertRaisesRegex(mod.ModeRepairError, "Installed"):
            self.go()
        for name in mod.REQUIRED_EXECUTABLES:
            self.assertEqual(stat.S_IMODE((self.install / name).stat().st_mode), 0o644)

    def test_executable_symlink_refused(self):
        target = self.install / "support/analyzeHeadless"
        target.unlink()
        target.symlink_to(self.install / "support/launch.sh")
        with self.assertRaisesRegex(mod.ModeRepairError, "symlinked"):
            self.go()

    def test_missing_required_release_member_rejected(self):
        self.entries.pop("support/launch.sh")
        self.make_zip()
        self.pin = mod.sha256_path(self.archive)
        with self.assertRaisesRegex(mod.ModeRepairError, "missing expected Linux executable"):
            self.go()


if __name__ == "__main__":
    unittest.main()
