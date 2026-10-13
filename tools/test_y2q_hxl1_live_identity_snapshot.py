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
        for cmd in commands:
            joined = " ".join(cmd)
            self.assertNotIn("root", joined)
            self.assertNotIn("su -c", joined)
            self.assertNotIn("push", joined)
            self.assertNotIn("remount", joined)
            self.assertNotIn("flash", joined)
            self.assertNotIn("reboot", joined)
        self.assertEqual(len(commands), 1 + len(m.PROPS) + len(m.READS))

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
