#!/usr/bin/env python3
"""Read-only synthetic HXL1 stock source/code association regressions.

These tests use fabricated C and AArch64 RET instructions. They never claim
factory structure layouts, Android root, physical addresses or CVE reachability.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import contextlib
import sys
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_stock_rtmutex_source_code_review as review
from tools import y2q_hxl1_stock_rtmutex_code_windows as original
from tools import y2q_stage3_layout_inventory as stock


C_RT='''/* A fake comment: void remove_waiter(int ignored) { } */
static void remove_waiter(struct fake *lock, struct fake *waiter)
{
    const char *literal="a { brace } should not close this body";
    if (waiter->task) {
        waiter->task = 0;
    }
    return;
}
int rt_mutex_start_proxy_lock(
    struct fake *lock,
    struct fake *waiter)
{
    lock->pi_lock = 0;
    return 0;
}
'''
C_FUTEX='''static int futex_lock_pi(
    int a,
    int b
) {
    if (a) { b++; }
    return b;
}
'''

def image_and_names():
    raw=bytearray(4096)
    raw[0x38:0x3c]=b"ARM\x64"
    for i in range(0x100,len(raw),4):
        struct.pack_into("<I",raw,i,0xd65f03c0)
    labels=list(original.NAMES[:-1])
    nm=[f"{original.TEXT_VA:016x} T _text"]
    for i,label in enumerate(labels):
        nm.append(f"{original.TEXT_VA+0x100+i*0x80:016x} t {label}")
    return bytes(raw),"\n".join(nm)

def fake_v2(raw,names):
    windows=original.windows(raw,original.parse_nm(names))
    report={}
    for name,item in windows.items():
        item=item.copy()
        code=item.pop("_raw")
        va=item.pop("_va")
        item["disassembly"]={
            "status":"ORIGINAL_IMAGE_WINDOW_DISASSEMBLED",
            "instructions":[{
                "staticVA":hex(va+i*4),
                "word":f"{int.from_bytes(code[i*4:i*4+4],'little'):08x}",
                "assembly":"ret",
                "fieldAccessProven":False
            } for i in range(item["byteCount"]//4)]
        }
        report[name]=item
    return {
        "model":original.MODEL,
        "firmware":original.FIRMWARE,
        "originalKernelSha256":hashlib.sha256(raw).hexdigest(),
        "stockCompiledFieldOffsetsEstablished":False,
        "symbolBindingIndependentlyVerified":False,
        "liveKernelLoadAddressKnown":False,
        "rootExploitVerified":False,
        "originalCandidateCodeWindows":report,
    }

class SourceCodeReviewTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name)
        self.stock=self.base/"src"
        self.arts=self.base/"artifacts"
        (self.stock/"kernel/locking").mkdir(parents=True)
        (self.arts/"hxl1-research").mkdir(parents=True)
        (self.stock/"kernel/locking/rtmutex.c").write_text(C_RT)
        (self.stock/"kernel/futex.c").write_text(C_FUTEX)
        self.raw,self.nm=image_and_names()
        (self.arts/"kernel.bin").write_bytes(self.raw)
        (self.arts/"config.gz").write_bytes(gzip.compress(
            b"CONFIG_ARM64=y\nCONFIG_DEBUG_INFO=y\n"
        ))
        (self.arts/"hxl1-research/vmlinux-stock.nm").write_text(self.nm)
        self.v2=fake_v2(self.raw,self.nm)
        self.path=self.arts/"hxl1-research/hxl1-stock-rtmutex-code-windows-v2.json"
        self.path.write_text(json.dumps(self.v2))
        self.pins={
            "kernel.bin":hashlib.sha256(self.raw).hexdigest(),
            "config.gz":stock.digest(self.arts/"config.gz"),
        }
        self.srcpins={
            name:stock.digest(self.stock/name)
            for name in set(review.TARGETS.values())
        }

    def attest(self):
        with patch.dict(stock.PINNED,self.pins):
            with patch.dict(stock.SOURCE_PINNED,self.srcpins):
                return review.analyze(self.stock,self.arts,self.path)

    def windows(self):
        with patch.dict(stock.PINNED,self.pins):
            return review.verify_v2(self.v2,self.raw,self.nm)

    def test_unoccupied_default_report_path_stays_exact(self):
        wanted=self.arts/"hxl1-research/hxl1-stock-rtmutex-source-code-01.json"
        got=review.resolve_report_path(wanted,self.stock,explicit=False)
        self.assertEqual(got,wanted)
        self.assertFalse(got.exists())

    def test_existing_default_json_automatically_allocates_next_number(self):
        root=self.arts/"hxl1-research"
        wanted=root/"hxl1-stock-rtmutex-source-code-01.json"
        wanted.write_text("ORIGINAL MUST STAY")
        chosen=review.resolve_report_path(wanted,self.stock,explicit=False)
        self.assertEqual(chosen,root/"hxl1-stock-rtmutex-source-code-02.json")
        self.assertEqual(wanted.read_text(),"ORIGINAL MUST STAY")

    def test_existing_default_markdown_automatically_allocates_next_number(self):
        root=self.arts/"hxl1-research"
        wanted=root/"hxl1-stock-rtmutex-source-code-01.json"
        wanted.with_suffix(".md").write_text("ORIGINAL MD")
        chosen=review.resolve_report_path(wanted,self.stock,explicit=False)
        self.assertEqual(chosen,root/"hxl1-stock-rtmutex-source-code-02.json")
        self.assertEqual(wanted.with_suffix(".md").read_text(),"ORIGINAL MD")

    def test_numbering_skips_occupied_json_and_markdown_pairs(self):
        root=self.arts/"hxl1-research"
        wanted=root/"hxl1-stock-rtmutex-source-code-01.json"
        wanted.write_text("first")
        (root/"hxl1-stock-rtmutex-source-code-02.md").write_text("second")
        (root/"hxl1-stock-rtmutex-source-code-03.json").write_text("third")
        chosen=review.resolve_report_path(wanted,self.stock,explicit=False)
        self.assertEqual(chosen,root/"hxl1-stock-rtmutex-source-code-04.json")

    def test_explicit_existing_output_is_refused_and_named(self):
        wanted=self.arts/"hxl1-research/explicit.json"
        wanted.write_text("DON'T CHANGE ME")
        with self.assertRaisesRegex(review.CorrelationError,"Explicit --out destination already exists"):
            review.resolve_report_path(wanted,self.stock,explicit=True)
        self.assertEqual(wanted.read_text(),"DON'T CHANGE ME")

    def test_explicit_existing_markdown_is_refused(self):
        wanted=self.arts/"hxl1-research/explicit.json"
        wanted.with_suffix(".md").write_text("SAVED")
        with self.assertRaisesRegex(review.CorrelationError,"explicit.json.md|explicit.md"):
            review.resolve_report_path(wanted,self.stock,explicit=True)
        self.assertEqual(wanted.with_suffix(".md").read_text(),"SAVED")

    def test_default_does_not_follow_symlinked_output_file(self):
        wanted=self.arts/"hxl1-research/hxl1-stock-rtmutex-source-code-01.json"
        wanted.symlink_to(self.stock/"kernel/futex.c")
        chosen=review.resolve_report_path(wanted,self.stock,explicit=False)
        self.assertEqual(chosen,wanted.with_name("hxl1-stock-rtmutex-source-code-02.json"))
        self.assertTrue(wanted.is_symlink())

    def test_output_dir_under_original_source_is_rejected(self):
        wanted=self.stock/"kernel/report.json"
        with self.assertRaisesRegex(review.CorrelationError,"outside original Samsung source"):
            review.resolve_report_path(wanted,self.stock,explicit=False)

    def test_non_json_output_is_rejected(self):
        wanted=self.arts/"hxl1-research/any.txt"
        with self.assertRaisesRegex(review.CorrelationError,".json suffix"):
            review.resolve_report_path(wanted,self.stock,explicit=False)

    def test_cli_show_review_prints_saved_original_source_and_instructions(self):
        """Regression: 'a' originalCode previously clobbered argparse args."""
        attested=self.attest()
        destination=self.arts/"hxl1-research/cli-source-code-review.json"
        stdout=io.StringIO()
        with patch.object(review,"analyze",return_value=attested):
            with patch.object(sys,"argv",[
                "y2q_hxl1_stock_rtmutex_source_code_review.py",
                "--source",str(self.stock),"--artifacts",str(self.arts),
                "--v2",str(self.path),"--out",str(destination),"--show-review"
            ]):
                with contextlib.redirect_stdout(stdout):
                    result=review.main()
        self.assertEqual(result,0)
        output=stdout.getvalue()
        self.assertIn("COMPLETE BOUNDED ORIGINAL SOURCE AND DISASSEMBLY REVIEW",output)
        self.assertIn("Original stock AArch64 instructions",output)
        self.assertIn("rt_mutex_start_proxy_lock",output)
        self.assertIn("futex_lock_pi",output)
        self.assertIn("[LIMIT]",output)
        self.assertTrue(destination.is_file())
        self.assertTrue(destination.with_suffix(".md").is_file())

    def test_cli_without_show_review_keeps_summary_and_saved_markdown(self):
        attested=self.attest()
        destination=self.arts/"hxl1-research/cli-summary-only.json"
        stdout=io.StringIO()
        with patch.object(review,"analyze",return_value=attested):
            with patch.object(sys,"argv",[
                "y2q_hxl1_stock_rtmutex_source_code_review.py",
                "--source",str(self.stock),"--out",str(destination)
            ]):
                with contextlib.redirect_stdout(stdout):
                    result=review.main()
        self.assertEqual(result,0)
        output=stdout.getvalue()
        self.assertIn("[CORRELATION CANDIDATE] remove_waiter",output)
        self.assertIn("[REPORT]",output)
        self.assertNotIn("COMPLETE BOUNDED ORIGINAL SOURCE AND DISASSEMBLY REVIEW",output)
        self.assertIn("## futex_lock_pi",destination.with_suffix(".md").read_text())

    def test_both_synthetic_sources_extracted(self):
        r=self.attest()
        self.assertEqual(set(r["focus"]),set(review.TARGETS))
        self.assertTrue(r["full11WindowByteAndDisassemblyWordChecksPassed"])
        self.assertTrue(r["allOriginalSourceHashesVerified"])

    def test_exact_source_file_paths_pinned(self):
        r=self.attest()
        for name,body in r["focus"].items():
            self.assertEqual(body["originalCFile"],review.TARGETS[name])
            self.assertEqual(body["originalCFileSha256"],
                             self.srcpins[review.TARGETS[name]])

    def test_original_bytes_double_checked(self):
        ws=self.windows()
        self.assertEqual(len(ws),11)
        self.assertTrue(all(x["allDecodedWordsAgreeWithStock"]
                            for x in ws.values()))

    def test_fake_comment_does_not_produce_second_definition(self):
        d=review.find_definition(C_RT,"remove_waiter")
        self.assertEqual(d["startLine"],2)
        self.assertTrue(d["sourceLinesTotal"]>2)

    def test_fake_braces_in_strings_ignored(self):
        d=review.find_definition(C_RT,"remove_waiter")
        self.assertIn("return;",C_RT.splitlines()[d["endLine"]-2])

    def test_multiline_declarator_supported(self):
        d=review.find_definition(C_RT,"rt_mutex_start_proxy_lock")
        self.assertGreater(d["endLine"],d["startLine"])
        self.assertTrue(any("pi_lock" in line["source"]
                            for line in d["relevantSourceLines"]))

    def test_source_extract_does_not_identify_fields_from_machine_code(self):
        r=self.attest()
        for entry in r["focus"].values():
            self.assertFalse(entry["symbolToSourceBindingProvenByDebugInfo"])
            self.assertFalse(entry["instructionToSourceMemberMappingProven"])
            self.assertFalse(entry["originalCode"]
                             ["factorySourceMemberOffsetsIdentified"])

    def test_fail_closed_with_duplicate_function_definitions(self):
        with self.assertRaisesRegex(review.CorrelationError,"got 2"):
            review.find_definition(C_FUTEX+"\n"+C_FUTEX,"futex_lock_pi")

    def test_missing_function_body_not_mistaken_for_definition(self):
        with self.assertRaisesRegex(review.CorrelationError,"got 0"):
            review.find_definition("extern int futex_lock_pi(int x);\n",
                                   "futex_lock_pi")

    def test_real_call_not_mistaken_for_function_definition(self):
        c="int other(void) { return futex_lock_pi(1, 2); }\n"+C_FUTEX
        self.assertEqual(review.find_definition(c,"futex_lock_pi")["startLine"],2)

    def test_source_comment_braces_preserved_in_original_line_numbers(self):
        c="/* a multiline\n { pretend definition\n} */\n"+C_FUTEX
        self.assertEqual(review.find_definition(c,"futex_lock_pi")["startLine"],4)

    def test_source_definition_with_nested_braces(self):
        d=review.find_definition(C_FUTEX,"futex_lock_pi")
        self.assertEqual(d["endLine"],7)

    def test_bounded_source_excerpt_truncation(self):
        source="static int futex_lock_pi(int a) {\n"+("    a++;\n"*160)+"}\n"
        d=review.find_definition(source,"futex_lock_pi")
        self.assertTrue(d["sourceExcerptTruncated"])
        self.assertEqual(len(d["sourceExcerpt"]),review.SOURCE_LINES_LIMIT)
        self.assertEqual(d["sourceLinesTotal"],162)

    def test_source_signal_bounds(self):
        body=("static int futex_lock_pi(int a) {\n"+
              ("    rt_mutex_lock(a);\n"*120)+"}\n")
        d=review.find_definition(body,"futex_lock_pi")
        self.assertTrue(d["relevantSourceLinesTruncated"])
        self.assertEqual(len(d["relevantSourceLines"]),review.CONTEXT_MATCHES_LIMIT)

    def test_real_json_corrupted_word_rejected(self):
        key=next(iter(self.v2["originalCandidateCodeWindows"]))
        self.v2["originalCandidateCodeWindows"][key]["disassembly"]["instructions"][0]["word"]="00000000"
        with self.assertRaisesRegex(review.CorrelationError,"word does not match"):
            self.windows()

    def test_static_address_drift_rejected(self):
        key=next(iter(self.v2["originalCandidateCodeWindows"]))
        self.v2["originalCandidateCodeWindows"][key]["disassembly"]["instructions"][0]["staticVA"]="0x1000"
        with self.assertRaisesRegex(review.CorrelationError,"static VA"):
            self.windows()

    def test_stale_pre_v2_larger_code_window_rejected(self):
        key=next(iter(self.v2["originalCandidateCodeWindows"]))
        self.v2["originalCandidateCodeWindows"][key]["byteCount"]=192
        with self.assertRaisesRegex(review.CorrelationError,"full-symbol bounded"):
            self.windows()

    def test_mismatched_original_code_sha_rejected(self):
        key=next(iter(self.v2["originalCandidateCodeWindows"]))
        self.v2["originalCandidateCodeWindows"][key]["originalStockBytesSha256"]="0"*64
        with self.assertRaisesRegex(review.CorrelationError,"full-symbol bounded"):
            self.windows()

    def test_forged_independent_symbol_mapping_rejected(self):
        key=next(iter(self.v2["originalCandidateCodeWindows"]))
        self.v2["originalCandidateCodeWindows"][key]["independentSymbolMappingAuthenticated"]=True
        with self.assertRaisesRegex(review.CorrelationError,"promot"):
            self.windows()

    def test_forged_member_mapping_rejected(self):
        key=next(iter(self.v2["originalCandidateCodeWindows"]))
        self.v2["originalCandidateCodeWindows"][key]["disassembly"]["instructions"][0]["fieldAccessProven"]=True
        with self.assertRaisesRegex(review.CorrelationError,"field attribution"):
            self.windows()

    def test_no_root_or_exploit_evidence(self):
        r=self.attest()
        for attr in ("sourceToDisassemblyMappingIndependentlyProven",
                     "originalFactoryStructOffsetsRecovered",
                     "experimentalClang18OffsetsUsed",
                     "liveKernelAddressKnown",
                     "runtimeVulnerabilityValidated",
                     "rootOrKernelSuInstalled",
                     "phoneContacted"):
            self.assertIs(r[attr],False,attr)

    def test_raw_stock_kernel_mutation_fails(self):
        data=bytearray(self.raw)
        data[0x100]^=0x10
        (self.arts/"kernel.bin").write_bytes(data)
        with self.assertRaisesRegex(stock.InventoryError,"mismatch"):
            self.attest()

    def test_source_changed_fails_preflight(self):
        (self.stock/"kernel/futex.c").write_text(C_FUTEX+"\n")
        with self.assertRaisesRegex(stock.InventoryError,"mismatch"):
            self.attest()

    def test_v2_missing_one_target_rejected(self):
        self.v2["originalCandidateCodeWindows"].pop("futex_lock_pi")
        with self.assertRaisesRegex(review.CorrelationError,"v2 target names differ"):
            self.windows()

    def test_original_config_changed_fails_preflight(self):
        (self.arts/"config.gz").write_bytes(gzip.compress(b"BAD=y\n"))
        with self.assertRaisesRegex(stock.InventoryError,"mismatch"):
            self.attest()

    def test_report_uses_original_source_and_instructions_without_claiming_offsets(self):
        report=review.markdown(self.attest())
        self.assertIn("remove_waiter",report)
        self.assertIn("Stock file: kernel/futex.c",report)
        self.assertIn("AArch64 instructions",report)
        self.assertIn("dataflow",report)
        self.assertIn("No factory Clang10 DWARF/BTF",report)


if __name__=="__main__":
    unittest.main()
