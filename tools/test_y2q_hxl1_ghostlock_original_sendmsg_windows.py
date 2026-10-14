"""Original-image GhostLock sendmsg/iovec bounded-code collector tests."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest
from tools import y2q_hxl1_ghostlock_original_sendmsg_windows as m

def input_image():
    data=bytearray(0x1000)
    data[0x38:0x3c]=b"ARM\x64"
    return bytes(data)

def table():
    base=m.gate.IMAGE_VA
    rows=[
        (0,"_text"),(0x100,"__sys_sendmsg"),
        (0x180,"unrelated_between"),
        (0x200,"____sys_sendmsg"),
        (0x280,"rw_copy_check_uvector"),
        (0x320,"futex_wait_requeue_pi"),
        (0x3a0,"next_bound")
    ]
    return "\n".join(f"{base+off:x} t {name}" for off,name in rows)

class OriginalWindowsTests(unittest.TestCase):
    def collect(self,image=None,listing=None):
        data=image if image is not None else input_image()
        with patch.object(m.gate,"STOCK_SHA",hashlib.sha256(data).hexdigest()):
            return m.inventory(data,listing if listing is not None else table())

    def test_bounded_original_code_intervals(self):
        report,slices=self.collect()
        self.assertEqual(report["status"],
            "BOUNDED_STOCK_NATIVE_CODE_WINDOWS_NOT_STACK_GEOMETRY")
        self.assertEqual(len(slices["__sys_sendmsg"]),0x80)
        self.assertEqual(len(slices["rw_copy_check_uvector"]),0xa0)
        self.assertEqual(report["boundedCodeWindows"],4)
        self.assertFalse(report["sendmsgFrameAliasVerified"])
        self.assertFalse(report["actualGhostLockPrimitiveOrRootVerified"])

    def test_missing_symbol_name_does_not_prove_emission_absent(self):
        report,_=self.collect()
        target=next(x for x in report["functions"] if x["symbol"]=="__sys_sendto")
        self.assertEqual(target["status"],"NOT_FOUND_IN_RECOVERED_NM")
        self.assertFalse(target["compiledFunctionAbsenceProven"])

    def test_wrong_image_digest_fails_closed(self):
        data=input_image()
        with patch.object(m.gate,"STOCK_SHA","0"*64):
            with self.assertRaisesRegex(m.WindowStop,"SHA256 mismatch"):
                m.inventory(data,table())

    def test_bad_image_header_fails_closed_after_hash(self):
        data=b"\0"*0x1000
        with patch.object(m.gate,"STOCK_SHA",hashlib.sha256(data).hexdigest()):
            with self.assertRaisesRegex(m.WindowStop,"magic"):
                m.inventory(data,table())

    def test_unexpected_text_base_fails(self):
        base=m.gate.IMAGE_VA+0x100
        listing=f"{base:x} t _text\n{base+0x100:x} t __sys_sendmsg"
        with self.assertRaisesRegex(m.WindowStop,"text base"):
            self.collect(listing=listing)

    def test_unrelated_next_symbol_is_true_upper_bound(self):
        report,slices=self.collect()
        record=next(x for x in report["functions"] if x["symbol"]=="__sys_sendmsg")
        self.assertEqual(record["originalFullTextIntervalBytes"],0x80)
        self.assertEqual(record["nextRecoveredTextVA"],hex(m.gate.IMAGE_VA+0x180))

    def test_missing_next_symbol_cannot_imply_function_size(self):
        base=m.gate.IMAGE_VA
        listing=f"{base:x} T _text\n{base+0x100:x} t __sys_sendmsg"
        report,slices=self.collect(listing=listing)
        record=next(x for x in report["functions"] if x["symbol"]=="__sys_sendmsg")
        self.assertEqual(record["status"],"NO_NEXT_TEXT_SYMBOL_BOUND")
        self.assertNotIn("__sys_sendmsg",slices)

    def test_duplicate_requested_symbol_address_is_rejected(self):
        base=m.gate.IMAGE_VA
        listing=table()+"\n"+f"{base+0x120:x} t __sys_sendmsg"
        with self.assertRaisesRegex(ValueError,"Ambiguous"):
            self.collect(listing=listing)

    def test_cli_direct_standalone_help_from_isolated_python(self):
        with tempfile.TemporaryDirectory() as other:
            proc=subprocess.run(
                [sys.executable,"-I",str(Path(m.__file__).resolve()),"--help"],
                cwd=other,capture_output=True,text=True,timeout=15)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn("--no-disassembly",proc.stdout)
        self.assertNotIn("ModuleNotFoundError",proc.stderr)

if __name__=="__main__":
    unittest.main()
