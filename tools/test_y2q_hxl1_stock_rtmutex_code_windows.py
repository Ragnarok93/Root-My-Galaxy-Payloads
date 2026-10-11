#!/usr/bin/env python3
"""Offline synthetic stock-HXL1 code-window provenance tests, no device."""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from tools import y2q_hxl1_stock_rtmutex_code_windows as audit

def fixture_bytes():
    raw=bytearray(1024)
    raw[0x38:0x3c]=b"ARM\x64"
    # Exact AArch64 RET instructions in fixture, not device firmware.
    for i in range(64,1024,4):
        struct.pack_into("<I",raw,i,0xd65f03c0)
    return bytes(raw)

def map_text(first=0x80,second=0xc0,include_second=True):
    base=audit.TEXT_VA
    lines=[f"{base:016x} T _text",
           f"{base+first:016x} T rt_mutex_start_proxy_lock"]
    if include_second:
        lines.append(f"{base+second:016x} t remove_waiter")
    return "\n".join(lines)

def source():
    return {"model":audit.MODEL,
            "firmware":audit.FIRMWARE,
            "originalFileHashChecksPassed":True,
            "offsetsVerified":False}

class OriginalStockCodeWindows(unittest.TestCase):
    def setUp(self):
        self.raw=fixture_bytes()
        self.pin=hashlib.sha256(self.raw).hexdigest()

    def report(self,map_data=None,command=None):
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            return audit.analyze(self.raw,
                map_data if map_data is not None else map_text(),
                source(),command)

    def test_original_kernel_digest_is_independent_of_nm(self):
        x=self.report()
        self.assertEqual(x["originalKernelSha256"],self.pin)
        self.assertFalse(x["symbolBindingIndependentlyVerified"])

    def test_two_original_candidates_and_digest(self):
        x=self.report()
        values=x["originalCandidateCodeWindows"]
        self.assertEqual(set(values),{
            "rt_mutex_start_proxy_lock","remove_waiter"})
        self.assertEqual(values["rt_mutex_start_proxy_lock"]["byteCount"],64)
        self.assertEqual(values["rt_mutex_start_proxy_lock"]["relativeImageByteOffset"],"0x80")
        self.assertEqual(len(values["remove_waiter"]["originalStockBytesSha256"]),64)

    def test_no_dwarf_factory_or_runtime_claim(self):
        x=self.report()
        for key in ("stockCompiledFieldOffsetsEstablished",
                    "recoveredBtfOrDwarfStructureLayout",
                    "symbolBindingIndependentlyVerified",
                    "liveKernelLoadAddressKnown","rootExploitVerified",
                    "kernelSuInstalled","phoneModified"):
            self.assertIs(x[key],False,key)

    def test_all_missing_code_labels_are_represented(self):
        x=self.report()
        self.assertEqual(len(x["missingSymbolLabels"]),len(audit.NAMES)-2)

    def test_static_code_window_never_goes_beyond_next_name(self):
        x=self.report()
        self.assertEqual(x["originalCandidateCodeWindows"]
                         ["rt_mutex_start_proxy_lock"]["byteCount"],64)

    def test_lone_candidate_has_192byte_bound(self):
        x=self.report(map_text(include_second=False))
        self.assertEqual(x["originalCandidateCodeWindows"]
                         ["rt_mutex_start_proxy_lock"]["byteCount"],audit.MAX_WINDOW)

    def test_duplicate_equal_nm_label_accepted(self):
        text=map_text()
        text+="\n"+text.splitlines()[1]
        x=self.report(text)
        self.assertEqual(len(x["originalCandidateCodeWindows"]),2)

    def test_duplicate_different_nm_symbol_refused(self):
        text=map_text()+f"\n{audit.TEXT_VA+0xe0:016x} T remove_waiter"
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"Ambiguous"):
                audit.analyze(self.raw,text,source())

    def test_patched_original_kernel_refused(self):
        changed=bytearray(self.raw)
        changed[0x88]^=1
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"SHA mismatch"):
                audit.analyze(bytes(changed),map_text(),source())

    def test_wrong_base_refused(self):
        text=map_text().replace(f"{audit.TEXT_VA:016x} T _text",
                                f"{audit.TEXT_VA+0x1000:016x} T _text")
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"_text base"):
                audit.analyze(self.raw,text,source())

    def test_wrong_misaligned_symbol_refused(self):
        text=map_text(first=0x81)
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"not AArch64 aligned"):
                audit.analyze(self.raw,text,source())

    def test_out_of_bounds_symbol_refused(self):
        text=map_text(first=4096)
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"not within original Image"):
                audit.analyze(self.raw,text,source())

    def test_non_text_symbol_refused(self):
        text=map_text().replace(" T rt_mutex_start_proxy_lock",
                                " D rt_mutex_start_proxy_lock")
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"not a text"):
                audit.analyze(self.raw,text,source())

    def test_one_symbol_too_close_to_next_refused(self):
        with self.assertRaisesRegex(audit.WindowError,"less than one"):
            audit.windows(self.raw,
                          audit.parse_nm(map_text(first=0x80,second=0x82)),
                          max_bytes=192)

    def test_zero_selected_symbol_names_fail_closed(self):
        with patch.dict(audit.stock.PINNED,{"kernel.bin":self.pin}):
            with self.assertRaisesRegex(audit.WindowError,"no expected RT-mutex"):
                audit.analyze(self.raw,f"{audit.TEXT_VA:016x} T _text",source())

    def test_no_disassembler_is_diagnostic_only(self):
        x=self.report()
        self.assertEqual(x["originalCandidateCodeWindows"]
                         ["remove_waiter"]["disassembly"]["status"],
                         "NO_AARCH64_OBJDUMP")

    def test_bounded_objdump_original_bytes_and_static_address(self):
        result=SimpleNamespace(returncode=0,
            stdout="\n".join([
                f"{audit.TEXT_VA+0x80:x}: d65f03c0 ret"
                for _ in range(2)
            ]))
        with patch.object(audit.subprocess,"run",return_value=result) as invoke:
            x=audit.disassemble(b"\xc0\x03\x5f\xd6"*2,
                                audit.TEXT_VA+0x80,"aarch64-linux-gnu-objdump")
        self.assertEqual(x["status"],"ORIGINAL_IMAGE_WINDOW_DISASSEMBLED")
        self.assertEqual(len(x["instructions"]),2)
        self.assertFalse(x["instructions"][0]["fieldAccessProven"])
        self.assertIn("--adjust-vma=",str(invoke.call_args.args))

    def test_disassembler_partial_code_rejected(self):
        result=SimpleNamespace(returncode=0,
                               stdout=f"{audit.TEXT_VA+0x80:x}: d65f03c0 ret\n")
        with patch.object(audit.subprocess,"run",return_value=result):
            x=audit.disassemble(b"\xc0\x03\x5f\xd6"*2,
                                audit.TEXT_VA+0x80,"binutils")
        self.assertEqual(x["status"],"INCOMPLETE_DISASSEMBLY")

    def test_disassembler_failure_keeps_provenance_unclaimed(self):
        with patch.object(audit.subprocess,"run",side_effect=OSError("not found")):
            x=audit.disassemble(b"\xc0\x03\x5f\xd6",audit.TEXT_VA,"binutils")
        self.assertEqual(x["status"],"OBJDUMP_ERROR")

    def test_report_no_factory_offset_claim(self):
        md=audit.markdown(self.report())
        self.assertIn("not an independently verified factory",md)
        self.assertIn("No live memory address",md)
        self.assertIn("rt_mutex_start_proxy_lock",md)


if __name__=="__main__":
    unittest.main()
