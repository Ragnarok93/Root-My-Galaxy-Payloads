#!/usr/bin/env python3
"""Synthetic exact-HXL1 EnvDxe extraction and PE GUID offset mapping tests.

Original XBL is never required for CI; fixtures remain separate from real SHA
pins, and no extracted executable is run on any host or phone.
"""
from __future__ import annotations
import gzip
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_extract_envdxe as extract
from tools.test_y2q_abl_linuxloader_extract import section, pack_sections, ffs, volume, pe
from tools.test_y2q_hxl1_xbl_envdxe_fv_probe import stock_like_elf

SYN_FFS="eaf4d036-8df6-450a-a23a-2b5f56132686"


def synthetic_pe(*, mapped=True, with_guid=True):
    image=bytearray(pe())
    # One declared PE section, with a 16-byte raw 0x300 GUID-bearing tail.
    image.extend(extract.GUID_LE if with_guid else b"N" * 16)
    if mapped:
        section_table=0x80+24+0xf0
        image[section_table:section_table+8]=b".rdata\x00\x00"
        struct.pack_into("<IIII",image,section_table+8,
                         16,0x2000,16,0x300)
    return bytes(image)


def synthetic_original(*, mapped=True, with_guid=True):
    image=synthetic_pe(mapped=mapped,with_guid=with_guid)
    ui=section(0x15,"EnvDxe\x00".encode("utf-16le"))
    fv=volume([ffs(SYN_FFS,0x07,pack_sections(ui,section(0x10,image)))])
    compressed=gzip.compress(fv,mtime=0)
    data=bytearray(stock_like_elf(b""))
    data.extend(b"\xff" * (4194304-len(data)))
    at=extract.GZIP_OFFSET
    data[at:at+len(compressed)]=compressed
    return bytes(data),image


class ExactEnvDxeExtractionTests(unittest.TestCase):
    def setUp(self):
        self.source,self.embedded=synthetic_original()
        self.vars={
            "XBL_SHA256":extract.digest(self.source),
            "PE_SHA256":extract.digest(self.embedded),
            "FILE_GUID":SYN_FFS,
            "GUID_PE_FILE_OFFSET":0x300,
        }
        self.original={
            "sha256":extract.digest(self.source),
            "machine":183,"entry":0x100010,"programHeaders":1,
        }

    def candidate(self,data=None,expected=None):
        if data is None:data=self.source
        with patch.multiple(extract,**self.vars):
            with patch.object(extract,"INPUTS",{"xbl.elf":expected or self.original}):
                return extract.exact_candidate(data)

    def test_exact_verified_original_pe_one_module_only(self):
        result=self.candidate()
        self.assertEqual(result["bytes"],self.embedded)
        info=result["manifest"]
        self.assertEqual(info["ui"],"EnvDxe")
        self.assertEqual(info["ffsGuid"],SYN_FFS)
        self.assertEqual(info["guidPeFileOffset"],"0x300")
        self.assertEqual(info["guidPosition"]["guidRva"],"0x2000")
        self.assertEqual(info["originalEnvDxePeSha256"],self.vars["PE_SHA256"])
        self.assertFalse(info["protocolRegistrationProven"])
        self.assertFalse(info["kernelPhysicalEntryVerified"])

    def test_exact_file_offset_to_rva_map(self):
        got=extract.guid_file_offset_to_rva(self.embedded,0x300)
        self.assertEqual(got["guidPosition"]["guidRva"],"0x2000")
        self.assertTrue(got["guidFileOffsetMappedToSection"])

    def test_unmapped_pe_offset_cannot_turn_into_runtime_address(self):
        img=synthetic_pe(mapped=False)
        got=extract.guid_file_offset_to_rva(img,0x300)
        self.assertIsNone(got["guidPosition"])
        self.assertFalse(got["guidFileOffsetMappedToSection"])

    def test_mutated_original_stock_sha_refused(self):
        mutated=bytearray(self.source)
        mutated[0x1000]^=0x80
        with self.assertRaisesRegex(extract.ExtractionError,"SHA256/size"):
            self.candidate(bytes(mutated))

    def test_unrecognized_envdxe_digest_fails_closed(self):
        self.vars["PE_SHA256"]="0"*64
        with self.assertRaisesRegex(extract.ExtractionError,"PE SHA256"):
            self.candidate()

    def test_wrong_original_ffs_guid_not_promoted(self):
        self.vars["FILE_GUID"]="00000000-0000-0000-0000-000000000000"
        with self.assertRaisesRegex(extract.ExtractionError,"Expected one original"):
            self.candidate()

    def test_unknown_original_guid_at_exact_file_offset_refused(self):
        source,img=synthetic_original(with_guid=False)
        self.vars["XBL_SHA256"]=extract.digest(source)
        self.vars["PE_SHA256"]=extract.digest(img)
        original={**self.original,"sha256":extract.digest(source)}
        with self.assertRaisesRegex(extract.ExtractionError,"protocol GUID missing"):
            self.candidate(source,original)

    def test_wrong_compressed_offset_not_searched_broadly(self):
        with patch.object(extract,"GZIP_OFFSET",0xc7000):
            with self.assertRaisesRegex(extract.ExtractionError,"does not decode"):
                self.candidate()

    def test_write_one_original_pe_and_reuse_verbatim(self):
        with tempfile.TemporaryDirectory() as root:
            src=Path(root)/"input"
            out=Path(root)/"out"
            src.mkdir()
            (src/"xbl.elf").write_bytes(self.source)
            with patch.multiple(extract,**self.vars):
                with patch.object(extract,"INPUTS",{"xbl.elf":self.original}):
                    first=extract.run(src,out)
                    second=extract.run(src,out)
            self.assertEqual(first["outputStatus"],"CREATED_ORIGINAL_PE")
            self.assertEqual(second["outputStatus"],"VERIFIED_EXISTING")
            self.assertEqual((out/extract.OUT_NAME).read_bytes(),self.embedded)
            self.assertEqual(json.loads((out/"original-envdxe-hxl1.json").read_text())["guidPosition"]["guidRva"],"0x2000")

    def test_never_overwrite_user_modified_extracted_pe(self):
        with tempfile.TemporaryDirectory() as root:
            src=Path(root)/"input"
            out=Path(root)/"out"
            src.mkdir()
            (src/"xbl.elf").write_bytes(self.source)
            with patch.multiple(extract,**self.vars):
                with patch.object(extract,"INPUTS",{"xbl.elf":self.original}):
                    extract.run(src,out)
                    target=out/extract.OUT_NAME
                    target.write_bytes(b"modified")
                    with self.assertRaisesRegex(extract.ExtractionError,"refusing overwrite"):
                        extract.run(src,out)
            self.assertEqual((out/extract.OUT_NAME).read_bytes(),b"modified")


if __name__=="__main__":
    unittest.main()
