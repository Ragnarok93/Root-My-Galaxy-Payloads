#!/usr/bin/env python3
"""Fail-closed tests of cached original HXL1 ABL independent PE agreement."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from uuid import UUID

from tools import y2q_hxl1_cached_linuxloader as mod
from tools.test_y2q_abl_linuxloader_extract import pe


class CachedLinuxLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.abl=self.root/"abl.elf"
        self.abl.write_bytes(b"synthetic-audit-pin-not-original")
        self.abl_sha=hashlib.sha256(self.abl.read_bytes()).hexdigest()
        self.out=self.root/"LinuxLoader-HXL1.unclassified.pe"
        self.unpacked=self.root/"unpacked"
        self.app=self.unpacked/"outer"/("file-"+str(mod.LOADER_GUID))
        self.app.mkdir(parents=True)
        self.bytes=pe()
        self.source=self.app/"section1.pe"
        self.source.write_bytes(self.bytes)
        (self.app/"section0.ui").write_bytes("LinuxLoader\x00".encode("utf-16-le"))
        self.diag=self.root/"diagnostics.json"
        self.diagdata={
            "status":"NO_VERIFIED_LINUXLOADER",
            "sourceSha256":self.abl_sha,
            "sourceBytes":self.abl.stat().st_size,
            "sections":[{
                "fileGuid":str(mod.LOADER_GUID),"ui":"LinuxLoader",
                "sectionType":"0x10","sectionBodyBytes":len(self.bytes),
                "sha256":mod.digest(self.bytes),"first64Hex":self.bytes[:64].hex(),
            }],
            "ffsFiles":[{
                "fileGuid":str(mod.LOADER_GUID),"fileType":"0x09",
            }],
        }
        self.flush()

    def flush(self):
        self.diag.write_text(json.dumps(self.diagdata))

    def go(self):
        return mod.recover(self.abl,self.diag,self.unpacked,self.out,
                           abl_sha=self.abl_sha,abl_size=self.abl.stat().st_size)

    def test_independent_original_section_equality(self):
        result=self.go()
        self.assertEqual(self.out.read_bytes(),self.bytes)
        self.assertEqual(result["nativeDecoderSectionSha256"],mod.digest(self.bytes))
        self.assertEqual(result["independentDecoderSectionSha256"],mod.digest(self.bytes))
        self.assertEqual(result["verifiedUiName"],"LinuxLoader")
        self.assertFalse(result["physicalKernelLoadVerified"])
        self.assertFalse(result["androidLinuxHandoffVerified"])
        self.assertFalse(result["phoneModified"])

    def test_real_hxl1_pe_stub_at_0xe58_promotes_classification(self):
        import struct
        data=bytearray(0x2000)
        data[:2]=b"MZ"
        struct.pack_into("<I", data, 0x3c, 0xe58)
        header=24+0xf0+3*40
        data[0xe58:0xe58+header]=self.bytes[0x80:0x80+header]
        struct.pack_into("<H", data, 0xe58+6, 3)
        self.source.write_bytes(data)
        self.diagdata["sections"][0].update({
            "sectionBodyBytes":len(data),
            "sha256":mod.digest(data),
            "first64Hex":bytes(data[:64]).hex(),
        })
        self.flush()
        result=self.go()
        self.assertEqual(result["classification"],"PE_HEADER_AARCH64_VERIFIED")
        self.assertEqual(result["peHeader"]["dosPeHeaderOffset"],"0xe58")
        self.assertTrue(result["peHeader"]["strictAarch64Pe32PlusVerified"])

    def test_original_stock_sha_mismatch_fails(self):
        with self.assertRaisesRegex(mod.CorrelationError,"size/hash mismatch"):
            mod.recover(self.abl,self.diag,self.unpacked,self.out)

    def test_tampered_independent_extraction_fails(self):
        raw=bytearray(self.source.read_bytes())
        raw[-1]^=1
        self.source.write_bytes(raw)
        with self.assertRaisesRegex(mod.CorrelationError,"decoder PE bytes differ"):
            self.go()

    def test_wrong_native_section_hash_fails(self):
        self.diagdata["sections"][0]["sha256"]="0"*64
        self.flush()
        with self.assertRaisesRegex(mod.CorrelationError,"decoder PE bytes differ"):
            self.go()

    def test_wrong_ui_fails(self):
        (self.app/"section0.ui").write_bytes("Odin\x00".encode("utf-16-le"))
        with self.assertRaisesRegex(mod.CorrelationError,"UI name mismatch"):
            self.go()

    def test_duplicate_native_pe_sections_fails(self):
        self.diagdata["sections"].append(self.diagdata["sections"][0].copy())
        self.flush()
        with self.assertRaisesRegex(mod.CorrelationError,"Missing/ambiguous"):
            self.go()

    def test_unrecognized_linuxloader_arch_is_reported_without_promotion(self):
        bad=b"MZ"+b"\0"*96
        self.source.write_bytes(bad)
        self.diagdata["sections"][0].update({
            "sectionBodyBytes":len(bad),
            "sha256":mod.digest(bad),
            "first64Hex":bad[:64].hex(),
        })
        self.flush()
        result=self.go()
        self.assertEqual(result["classification"],"FFS_UI_SECTION_PROVENANCE_VERIFIED_PE_ARCH_UNCLASSIFIED")
        self.assertFalse(result["peHeader"]["strictAarch64Pe32PlusVerified"])

    def test_output_collision_cannot_overwrite(self):
        self.out.write_bytes(b"not original")
        with self.assertRaisesRegex(mod.CorrelationError,"Pre-existing"):
            self.go()

    def test_independent_pe_symlink_refused(self):
        self.source.unlink()
        alternate=self.unpacked/"alternate.pe"
        alternate.write_bytes(self.bytes)
        self.source.symlink_to(alternate)
        with self.assertRaisesRegex(mod.CorrelationError,"non-symlinked"):
            self.go()


if __name__=="__main__":
    unittest.main()
