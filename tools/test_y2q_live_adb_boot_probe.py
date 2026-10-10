#!/usr/bin/env python3
"""Unit checks for read-only identity-gated HXL1 ADB probe (no device)."""
import subprocess
import unittest
from unittest.mock import patch

from tools import y2q_live_adb_boot_probe as p


def completed(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(["adb"], rc, stdout, stderr)


class LiveAdbBootProbeTests(unittest.TestCase):
    def test_sensitive_boot_parameters_redacted(self):
        original = ("console=ttyMSM0 androidboot.serialno=ABC123 "
                    "androidboot.imei=01234567 kaslr-seed:ABCDEF "
                    "androidboot.hardware=qcom")
        sanitized = p.redact(original)
        for secret in ("ABC123","01234567","ABCDEF"):
            self.assertNotIn(secret,sanitized)
        self.assertIn("androidboot.hardware=qcom",sanitized)

    def test_sole_authorized_adb_device_selected(self):
        devices="List of devices attached\nSECRET_SERIAL\tdevice\n"
        with patch.object(p,"command",return_value=completed(devices)):
            self.assertEqual(p.choose(None),"SECRET_SERIAL")

    def test_unauthorized_device_refused(self):
        devices="List of devices attached\nSECRET_SERIAL\tunauthorized\n"
        with patch.object(p,"command",return_value=completed(devices)):
            with self.assertRaisesRegex(p.Stop,"Expected one authorized"):
                p.choose(None)

    def test_multiple_devices_require_serial(self):
        devices="List of devices attached\nA\tdevice\nB\tdevice\n"
        with patch.object(p,"command",return_value=completed(devices)):
            with self.assertRaisesRegex(p.Stop,"Expected one authorized"):
                p.choose(None)
            self.assertEqual(p.choose("B"),"B")

    def test_wrong_exact_firmware_fails_before_other_reads(self):
        seen=[]
        def response(argv):
            seen.append(argv)
            prop=argv[-1]
            return completed("SOME_OTHER_FIRMWARE\n" if prop=="ro.boot.bootloader"
                             else p.EXPECTED.get(prop,"")+"\n")
        with patch.object(p,"command",side_effect=response):
            with self.assertRaisesRegex(p.Stop,"identity mismatch"):
                p.collect("safe-serial")
        self.assertTrue(all("cat" not in x for x in seen))

    def test_exact_identity_and_unprivileged_shell_admitted(self):
        def response(argv):
            cmd=argv[-2:]
            if cmd[0]=="getprop":
                return completed(p.EXPECTED[cmd[1]]+"\n")
            if cmd==["uname","-r"]:
                return completed(p.KERNEL+"\n")
            if cmd==["id","-u"]:
                return completed("2000\n")
            raise AssertionError("Unexpected read: "+str(argv))
        with patch.object(p,"command",side_effect=response):
            data=p.identity("nonlogged-serial")
        self.assertEqual(data["adbShellUid"],"2000")
        self.assertEqual(data["kernelRelease"],p.KERNEL)

    def test_unprivileged_identity_required(self):
        def response(argv):
            cmd=argv[-2:]
            if cmd[0]=="getprop":
                return completed(p.EXPECTED[cmd[1]]+"\n")
            if cmd==["uname","-r"]:
                return completed(p.KERNEL+"\n")
            return completed("0\n")
        with patch.object(p,"command",side_effect=response):
            with self.assertRaisesRegex(p.Stop,"uid 2000"):
                p.identity("nonlogged-serial")

    def test_permission_failure_preserved_as_status(self):
        with patch.object(p,"command",return_value=completed(
                stderr="cat: /proc/iomem: Permission denied",rc=1)):
            got=p.optional_file("test","/proc/iomem")
        self.assertEqual(got["status"],"PERMISSION_DENIED")
        self.assertNotIn("text",got)

    def test_zeroed_iomem_not_a_physical_load(self):
        got=p.iomem_classification({
            "status":"READ_OK","text":"00000000-00000000 : System RAM\n"
                 "00000000-00000000 : Kernel code\n"
        })
        self.assertEqual(got["status"],"ALL_ZERO_RANGES_NOT_USABLE")
        self.assertFalse(got["kernelEntryVerified"])

    def test_nonzero_iomem_also_not_bootloader_proof(self):
        got=p.iomem_classification({
            "status":"READ_OK","text":"80000000-8fffffff : System RAM\n"
                 "80001000-800fffff : Kernel code\n"
        })
        self.assertEqual(got["status"],
                         "NONZERO_RANGES_VISIBLE_BUT_NOT_KERNEL_HANDOFF_PROOF")
        self.assertFalse(got["kernelEntryVerified"])

    def test_failed_optional_read_not_replaced_by_zero(self):
        got=p.iomem_classification({"status":"PERMISSION_DENIED"})
        self.assertEqual(got["status"],"UNAVAILABLE")

    def test_collector_has_no_firmware_or_device_write_commands(self):
        forbidden=("push","pull","install","root","reboot","flash","remount",
                   "disable-verity","shell su","setprop","dd")
        import inspect
        source=inspect.getsource(p)
        for command in forbidden:
            # Safety terms in the docstring do not imply command execution;
            # only check the actual subprocess callsite + admission gate.
            self.assertNotIn('["adb", "'+command+'"',source)
        self.assertFalse(p.collect.__doc__ and "privilege escalation" in p.collect.__doc__)


if __name__ == "__main__":
    unittest.main()
