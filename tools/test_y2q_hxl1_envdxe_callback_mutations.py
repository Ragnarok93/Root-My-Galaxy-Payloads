#!/usr/bin/env python3
"""Mutation matrix for original callback PE and Ghidra evidence fail-closed gates.

Each generated unittest method mutates a DISTINCT provenance or ABI field in
the preceding 0x1f74 evidence fixture. These tests are offline and never
probe real hardware or run a Ghidra command.
"""
from __future__ import annotations

import copy
import struct
import unittest

from tools import test_y2q_hxl1_envdxe_callback_raw_proof as fixtures
from tools.y2q_hxl1_extract_envdxe import ExtractionError


class MutationContractTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.OriginalCallbackRawProofTests(
            "test_original_callback_pointer_maps_to_executable_code"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def check_ghidra(self, mutation, expected):
        self.fixture.record=copy.deepcopy(self.fixture.record)
        mutation(self.fixture.record)
        self.fixture.write_read()
        if expected is None:
            result=self.fixture.both()
            self.assertTrue(result["importedBytesEqualOriginal"])
        else:
            with self.assertRaisesRegex(ExtractionError,expected):
                self.fixture.both()

    def check_pe(self, mutation, expected):
        mutation(self.fixture.pe)
        self.fixture.persist()
        with self.assertRaisesRegex(ExtractionError,expected):
            self.fixture.proof()


def ghidra_operation(value):
    return lambda record: record.__setitem__("operation",value)
def ghidra_provider(value):
    return lambda record: record["provider"].__setitem__("id",value)
def ghidra_digest(value):
    return lambda record: record["subject"]["digest"].__setitem__("sha256",value)
def ghidra_arch(value):
    return lambda record: record["subject"].__setitem__("architecture",value)
def ghidra_evidenceid(value):
    return lambda record: record.__setitem__("evidence_id",value)
def ghidra_param(field,value):
    return lambda record: record["parameters"].__setitem__(field,value)
def ghidra_result(field,value):
    return lambda record: record["normalized_result"].__setitem__(field,value)

GHIDRA_CASES=(
    ("wrong_operation_analyze_function",ghidra_operation("analyze_function"),"target mismatch"),
    ("wrong_operation_xrefs",ghidra_operation("xrefs"),"target mismatch"),
    ("wrong_provider_rizin",ghidra_provider("rizin"),"not bound"),
    ("missing_provider_identity",ghidra_provider(None),"not bound"),
    ("foreign_architecture_x64",ghidra_arch("x86_64"),"not bound"),
    ("foreign_architecture_arm32",ghidra_arch("arm"),"not bound"),
    ("mismatched_firmware_sha256",ghidra_digest("f"*64),"not bound"),
    ("missing_firmware_sha256",ghidra_digest(None),"not bound"),
    ("missing_evidence_id",ghidra_evidenceid(None),"not bound"),
    ("empty_evidence_id",ghidra_evidenceid(""),"not bound"),
    ("wrong_query_address",ghidra_param("address","0x1f70"),"target mismatch"),
    ("empty_query_address",ghidra_param("address",""),"target mismatch"),
    ("incorrect_ghidra_query_length_63",ghidra_param("length",63),"target mismatch"),
    ("incorrect_ghidra_query_length_0",ghidra_param("length",0),"target mismatch"),
    ("string_query_length",ghidra_param("length","64"),"target mismatch"),
    ("wrong_return_address",ghidra_result("address","0x1f70"),"incomplete"),
    ("null_return_address",ghidra_result("address",None),"incomplete"),
    ("short_requested_length",ghidra_result("requested_bytes",63),"incomplete"),
    ("short_returned_length",ghidra_result("returned_bytes",63),"incomplete"),
    ("extra_returned_length",ghidra_result("returned_bytes",65),"incomplete"),
    ("complete_false",ghidra_result("complete",False),"incomplete"),
    ("complete_null",ghidra_result("complete",None),"incomplete"),
    ("empty_bytes_hex",ghidra_result("bytes_hex",""),"incomplete"),
    ("nonhex_bytes",ghidra_result("bytes_hex","zz"*64),"incomplete"),
    ("short_hex_bytes",ghidra_result("bytes_hex","aa"*63),"incomplete"),
    ("oversized_hex_bytes",ghidra_result("bytes_hex","aa"*65),"incomplete"),
    ("different_hex_bytes",ghidra_result("bytes_hex","aa"*64),"differ"),
    ("unbounded_result_type",lambda r:r.__setitem__("normalized_result",["malformed"]),"incomplete"),
    ("missing_result",lambda r:r.__setitem__("normalized_result",None),"incomplete"),
    ("case_insensitive_valid_hex",lambda r:r["normalized_result"].__setitem__(
        "bytes_hex",r["normalized_result"]["bytes_hex"].upper()),None),
)


def set_field(pe,offset,fmt,value):
    struct.pack_into(fmt,pe,offset,value)


SEC=0x80+24+0xf0
PE_CASES=(
    ("remove_executable_flag",
        lambda p:set_field(p,SEC+36,"<I",0x40000040),"not in executable"),
    ("make_section_read_only",
        lambda p:set_field(p,SEC+36,"<I",0x40000000),"not in executable"),
    ("make_section_writable_but_nonexec",
        lambda p:set_field(p,SEC+36,"<I",0xC0000040),"not in executable"),
    ("raw_size_zero",
        lambda p:set_field(p,SEC+16,"<I",0),"not uniquely backed"),
    ("raw_size_16_bytes",
        lambda p:set_field(p,SEC+16,"<I",16),"not uniquely backed"),
    ("raw_size_cannot_hold_64_bytes",
        lambda p:set_field(p,SEC+16,"<I",0xfa0),"not uniquely backed"),
    ("raw_section_rva_moved",
        lambda p:set_field(p,SEC+12,"<I",0x3000),"not uniquely backed"),
    ("raw_section_beyond_callback",
        lambda p:set_field(p,SEC+12,"<I",0x2000),"not uniquely backed"),
    ("raw_section_shift_minus_16",
        lambda p:set_field(p,SEC+12,"<I",0x1020),"not uniquely backed"),
    ("raw_section_pointer_near_eof",
        lambda p:set_field(p,SEC+20,"<I",0x1f00),"data truncated"),
    ("no_section_headers",
        lambda p:set_field(p,0x80+6,"<H",0),"not uniquely backed"),
    ("multiple_overlapping_pe_sections",
        lambda p:(set_field(p,0x80+6,"<H",2),
                  p.__setitem__(slice(SEC+40,SEC+80),bytes(p[SEC:SEC+40]))),
        "not uniquely backed"),
)


for suffix,action,expected in GHIDRA_CASES:
    def make_action(perform,match):
        def test(self):
            self.check_ghidra(perform,match)
        return test
    setattr(MutationContractTests,"test_ghidra_"+suffix,
            make_action(action,expected))

for suffix,action,expected in PE_CASES:
    def make_action(perform,match):
        def test(self):
            self.check_pe(perform,match)
        return test
    setattr(MutationContractTests,"test_original_pe_"+suffix,
            make_action(action,expected))


if __name__=="__main__":
    unittest.main()
