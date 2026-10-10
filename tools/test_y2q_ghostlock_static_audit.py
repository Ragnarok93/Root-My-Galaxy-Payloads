#!/usr/bin/env python3
"""Offline fail-closed tests for pinned HXL1 GhostLock static corroboration."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools import y2q_ghostlock_static_audit as mod

ROOT_VA = 0xFFFFFF8008080000
REL = 0x40
SAMPLE = 64


def analysis(phys="unset (no xbl_config.img; pass --phys or let the runtime derive it)",
             primitive="remove_waiter@0x40 unpatched"):
    return f"""== GhostLock kernel analysis ==
release                 4.19.113-27095354
kernel_major            4.19
kernel_family           unverified (no family layout will be emitted)
kernel_phys_load        {phys}
rt_mutex_waiter         (no rt_mutex_waiter type in BTF)
mm_struct size          (unavailable)
primitive               {primitive}
pselect chain           not attempted (no embedded BTF)
path multicast_waiter   available (ip_mc_msfadd=absent ip_mc_source@0xffffff800978367c)
path select_stack       available (core_sys_select@0xffffff80082f8d64 futex_wait@0xffffff80081900c4)
path tcp_zerocopy       missing (tcp_zerocopy_receive=absent)
suggested route         none (low)
"""


def make_fixture(root: Path):
    raw = bytearray(range(128))
    raw[0x38:0x3C] = b"ARM\x64"
    paths = {name: root / name for name in ("kernel.bin", "vmlinux-stock.nm", "analysis.txt", "diagnostics.txt")}
    paths["kernel.bin"].write_bytes(raw)
    paths["vmlinux-stock.nm"].write_text(f"{ROOT_VA:016x} T _text\n{ROOT_VA+REL:016x} t remove_waiter\n")
    paths["analysis.txt"].write_text(analysis())
    paths["diagnostics.txt"].write_text("warning: embedded BTF not found\n")
    kwargs = {
        "expected_kernel_sha": mod.sha256(raw),
        "expected_kernel_bytes": len(raw),
        "expected_text": ROOT_VA,
        "expected_relative": REL,
        "expected_sample_sha": mod.sha256(raw[REL:REL+SAMPLE]),
    }
    return paths, kwargs


def do_audit(paths, opts):
    return mod.audit(paths["kernel.bin"], paths["vmlinux-stock.nm"],
                     paths["analysis.txt"], paths["diagnostics.txt"], **opts)


class StaticCrosscheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths, self.opts = make_fixture(self.root)

    def test_good_fixture_passes_without_physical_or_runtime_promotion(self):
        result = do_audit(self.paths, self.opts)
        self.assertEqual(result["relativeImageOffset"], "0x40")
        self.assertEqual(result["classification"], "PASS_STATIC_SYMBOL_AND_IMAGE_CORRELATION_ONLY")
        for claim in ("physicalKernelLoadVerified", "runtimeVulnerabilityVerified",
                      "executableGhostlockProfileVerified", "kernelSuVerified", "phoneModified"):
            self.assertFalse(result[claim])

    def test_invalid_original_hash_rejected(self):
        self.paths["kernel.bin"].write_bytes(self.paths["kernel.bin"].read_bytes() + b"X")
        with self.assertRaisesRegex(mod.AuditError, "size/hash mismatch"):
            do_audit(self.paths, self.opts)

    def test_sample_diff_rejected_even_with_current_kernel_hash(self):
        self.opts["expected_sample_sha"] = "0"*64
        with self.assertRaisesRegex(mod.AuditError, "function bytes mismatch"):
            do_audit(self.paths, self.opts)

    def test_missing_nm_symbol_rejected(self):
        self.paths["vmlinux-stock.nm"].write_text(f"{ROOT_VA:016x} T _text\n")
        with self.assertRaisesRegex(mod.AuditError, "remove_waiter: missing/ambiguous"):
            do_audit(self.paths, self.opts)

    def test_ambiguous_nm_rejected(self):
        with self.paths["vmlinux-stock.nm"].open("a") as stream:
            stream.write(f"{ROOT_VA + REL + 4:016x} t remove_waiter\n")
        with self.assertRaisesRegex(mod.AuditError, "remove_waiter: missing/ambiguous"):
            do_audit(self.paths, self.opts)

    def test_wrong_symbol_delta_rejected(self):
        self.paths["vmlinux-stock.nm"].write_text(
            f"{ROOT_VA:016x} T _text\n{ROOT_VA+REL+4:016x} t remove_waiter\n")
        with self.assertRaisesRegex(mod.AuditError, "offset mismatch"):
            do_audit(self.paths, self.opts)

    def test_host_iomem_contamination_rejected(self):
        self.paths["analysis.txt"].write_text(analysis(phys="0xfffff800 (iomem)"))
        with self.assertRaisesRegex(mod.AuditError, "not unset"):
            do_audit(self.paths, self.opts)

    def test_host_iomem_diagnostic_rejected(self):
        self.paths["diagnostics.txt"].write_text("info: iomem source /proc/iomem\n")
        with self.assertRaisesRegex(mod.AuditError, "physical-load inference"):
            do_audit(self.paths, self.opts)

    def test_no_measured_abi_cannot_be_promoted(self):
        original = analysis()
        self.paths["analysis.txt"].write_text(original.replace(
            "unverified (no family layout will be emitted)", "STRUCT_OFFSETS_6_1 (verified Android family)"))
        with self.assertRaisesRegex(mod.AuditError, "kernel_family"):
            do_audit(self.paths, self.opts)

    def test_wrong_primitive_offset_rejected(self):
        self.paths["analysis.txt"].write_text(analysis(primitive="remove_waiter@0x44 unpatched"))
        with self.assertRaisesRegex(mod.AuditError, "function offset"):
            do_audit(self.paths, self.opts)

    def test_nonstandard_arm64_header_rejected(self):
        raw = bytearray(self.paths["kernel.bin"].read_bytes())
        raw[0x38:0x3C] = b"XXXX"
        self.paths["kernel.bin"].write_bytes(raw)
        self.opts["expected_kernel_sha"] = mod.sha256(raw)
        with self.assertRaisesRegex(mod.AuditError, "ARM64 header"):
            do_audit(self.paths, self.opts)

    def test_report_is_text_only_read_only_no_phone(self):
        source = Path(mod.__file__).read_text()
        self.assertNotIn("import subprocess", source)
        for term in ("adb shell", "fastboot", "CVE-2026-43499-popsicle", "setresuid("):
            self.assertNotIn(term, source)
        self.assertIn('"physicalKernelLoadVerified": False', source)


if __name__ == "__main__":
    unittest.main()
