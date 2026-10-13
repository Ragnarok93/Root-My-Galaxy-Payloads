"""Tests for read-only HXL1 device-identity collection (no real ADB calls)."""
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from tools import y2q_hxl1_live_identity_snapshot as m

class SnapshotTests(unittest.TestCase):
    def test_select_one_authorized_device(self):
        self.assertEqual(m.select_device(
            "List of devices attached\nF00 device product:y2q model:SM-G986U1\n", None), "F00")

    def test_unauthorized_or_ambiguous_rejected(self):
        with self.assertRaisesRegex(m.SnapshotError, "exactly one"):
            m.select_device("List of devices attached\nA unauthorized\n", None)
        with self.assertRaisesRegex(m.SnapshotError, "exactly one"):
            m.select_device("List of devices attached\nA device\nB device\n", None)
        self.assertEqual(m.select_device(
            "List of devices attached\nA device\nB device\n", "B"), "B")
        with self.assertRaisesRegex(m.SnapshotError, "not authorized"):
            m.select_device("List of devices attached\nB offline\n", "B")

    def test_decode_device_tree_nul_compatible(self):
        self.assertEqual(m.decode_value("dtCompatible", b"qcom,kona\0qcom,sm8250\0"),
                         ["qcom,kona", "qcom,sm8250"])
        self.assertEqual(m.decode_value("dtModel", b"Samsung S20+\0"),
                         "Samsung S20+")

    def test_adb_cat_permission_denied_stdout_even_when_exit_zero(self):
        for name in ("dtModel", "dtCompatible"):
            target = m.READS[name][-1]
            output = f"cat: {target}: Permission denied\\n".encode()
            record = m.read_result(name, 0, output, b"")
            self.assertEqual(record["state"], "PERMISSION_DENIED")
            self.assertIsNone(record["value"])
            self.assertIn("Permission denied", record["error"])

    def test_adb_cat_missing_file_and_regular_read_are_distinct(self):
        key = "dtModel"
        path = m.READS[key][-1]
        missing = m.read_result(
            key, 0, f"cat: {path}: No such file or directory\\n".encode(), b"")
        self.assertEqual(missing["state"], "UNAVAILABLE")
        self.assertIsNone(missing["value"])
        self.assertEqual(
            m.read_result("dtCompatible", 0, b"qcom,kona\\0", b"")["value"],
            ["qcom,kona"])

    def test_unrelated_permission_text_does_not_mask_valid_dt_model(self):
        model = b"Samsung Permission denied test product\\0"
        value = m.read_result("dtModel", 0, model, b"")
        self.assertEqual(value["state"], "READ")
        self.assertEqual(value["value"], "Samsung Permission denied test product")

    def test_require_exact_hxl1_identity(self):
        props = {
            "ro.product.model": "SM-G986U1",
            "ro.build.fingerprint": "samsung/y2qxxx/G986U1:13/TP1A/G986U1UESCHXL1:user/release-keys",
            "ro.build.display.id": "G986U1UESCHXL1"
        }
        reads = {"kernelRelease":{"value":"4.19.113-27095354"},
                 "kernelArchitecture":{"value":"aarch64"}}
        result = m.check_identity(props, reads)
        self.assertTrue(result["identityConsistentWithTarget"])
        self.assertFalse(result["bootloaderPhysicalKernelHandoffProven"])
        self.assertFalse(result["kernelRootOrKernelSuProven"])
        changed = {**props, "ro.product.model":"SM-G988U1"}
        self.assertFalse(m.check_identity(changed,reads)["identityConsistentWithTarget"])

    def test_full_collection_does_not_need_root_or_modify_device(self):
        commands = []
        def fake_run(cmd, **kwargs):
            commands.append(tuple(cmd))
            if cmd[-2:] == ["devices", "-l"]:
                return SimpleNamespace(returncode=0,
                    stdout=b"List of devices attached\nSERIAL device product:y2q\n",
                    stderr=b"")
            if "getprop" in cmd:
                k = cmd[-1]
                value = {
                    "ro.product.model":"SM-G986U1",
                    "ro.build.fingerprint":"G986U1UESCHXL1",
                }.get(k,"")
                return SimpleNamespace(returncode=0,stdout=value.encode(),stderr=b"")
            if cmd[-2:]==["uname","-r"]:
                val=b"4.19.113-27095354\n"
            elif cmd[-2:]==["uname","-m"]:
                val=b"aarch64\n"
            elif cmd[-1]=="/proc/device-tree/compatible":
                val=b"qcom,kona\0qcom,sm8250\0"
            elif cmd[-1]=="/proc/device-tree/model":
                val=b"Samsung\0"
            else:
                val=b"Linux version 4.19.113\n"
            return SimpleNamespace(returncode=0,stdout=val,stderr=b"")
        with patch.object(m.subprocess,"run",side_effect=fake_run):
            snap = m.collect("adb",timeout=4)
        self.assertTrue(snap["checks"]["identityConsistentWithTarget"])
        self.assertEqual(snap["deviceReads"]["dtCompatible"]["value"],
                         ["qcom,kona","qcom,sm8250"])
        self.assertFalse(snap["stage4Complete"])
        self.assertFalse(snap["rootVerified"])
        # Validate exact ADB command argument sequences. Looking for "flash"
        # as a substring incorrectly rejects the read-only property
        # "ro.boot.flash.locked".
        allowed = {("adb", "devices", "-l")}
        allowed.update(("adb", "-s", "SERIAL", "shell", "getprop", prop)
                       for prop in m.PROPS)
        allowed.update(("adb", "-s", "SERIAL", *args)
                       for args in m.READS.values())
        self.assertEqual(set(commands), allowed)
        self.assertEqual(len(commands), len(allowed))

    def test_wsl_fallback_prefers_online_linux_adb(self):
        found = {"adb.exe": "/mnt/c/platform-tools/adb.exe",
                 "adb": "/usr/bin/adb"}
        invocations = []
        def fake_run(cmd, **kwargs):
            invocations.append(tuple(cmd))
            listing = (b"List of devices attached\n"
                       if cmd[0].endswith("adb.exe") else
                       b"List of devices attached\nPHONE device product:y2q\n")
            return SimpleNamespace(returncode=0, stdout=listing, stderr=b"")
        with patch.object(m.shutil, "which", side_effect=found.get), \
             patch.object(m.subprocess, "run", side_effect=fake_run):
            self.assertEqual(m.resolve_adb(None, timeout=4), "/usr/bin/adb")
        self.assertEqual(len(invocations), 2)
        self.assertTrue(all(cmd[1:] == ("devices", "-l") for cmd in invocations))

    def test_wsl_no_connected_device_explains_both_backends(self):
        found = {"adb.exe": "/mnt/c/platform-tools/adb.exe",
                 "adb": "/usr/bin/adb"}
        listings = [
            b"List of devices attached\n",
            b"List of devices attached\nPHONE unauthorized\n"
        ]
        def fake_run(cmd, **kwargs):
            item = 0 if cmd[0].endswith("adb.exe") else 1
            return SimpleNamespace(returncode=0, stdout=listings[item], stderr=b"")
        with patch.object(m.shutil, "which", side_effect=found.get), \
             patch.object(m.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(m.SnapshotError, "unauthorized=1"):
                m.resolve_adb(None, timeout=4)

    def test_explicit_adb_does_not_probe_other_clients(self):
        with patch.object(m.shutil, "which", return_value="/usr/bin/adb"), \
             patch.object(m.subprocess, "run") as runner:
            self.assertEqual(m.resolve_adb("adb", timeout=4), "/usr/bin/adb")
            runner.assert_not_called()

    def test_adb_error_does_not_claim_identity(self):
        with patch.object(m.subprocess,"run",return_value=SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"no devices")):
            with self.assertRaisesRegex(m.SnapshotError, "adb devices failed"):
                m.collect("adb")

    def test_output_requires_fresh_directory(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("sys.argv",["snapshot","--output-dir",d]):
                self.assertEqual(m.main(),2)

if __name__ == "__main__":
    unittest.main()
