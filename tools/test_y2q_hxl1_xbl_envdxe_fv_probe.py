#!/usr/bin/env python3
"""Offline validated FV/gzip/LZMA XBL EnvDxe probe fixtures, no device."""
from __future__ import annotations
import gzip
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_xbl_envdxe_fv_probe as mod
from tools.test_y2q_abl_linuxloader_extract import (
    section, pack_sections, ffs, volume, pe
)
from tools import y2q_hxl1_xbl_ram_guid_locator as guidtool


def driver_volume(*, named="EnvDxe", with_guid=True):
    pe_image = bytearray(pe())
    if with_guid:
        pe_image.extend(mod.GUID_LE)
    ui = section(0x15, (named + "\x00").encode("utf-16-le"))
    return volume([
        ffs("eaf4d036-8df6-450a-a23a-2b5f56132686", 0x07,
            pack_sections(ui, section(0x10, bytes(pe_image))))
    ])


def stock_like_elf(payload: bytes) -> bytes:
    # Synthetic ELF64, not the original Qualcomm/Samsung ELF.
    start = 0x200
    image = bytearray(start + len(payload) + 0x200)
    image[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16,
                     2, 183, 1, 0x100010, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, start,
                     0x100000, 0x100000, len(payload), len(payload), 0x1000)
    image[start:start + len(payload)] = payload
    return bytes(image)


def expectation(image: bytes) -> dict:
    return {"sha256": hashlib.sha256(image).hexdigest(),
            "class": 2, "machine": 183,
            "entry": 0x100010, "programHeaders": 1}


class OriginalHxl1XblFvFixtures(unittest.TestCase):
    def test_direct_named_driver_and_guid_pe_detected(self):
        result = mod.observe(driver_volume(), "synthetic-direct")
        self.assertEqual(result["status"], "FV_PARSED")
        self.assertEqual(result["eligiblePeCount"], 1)
        self.assertEqual(result["volumeCount"], 1)
        candidates = result["targetCandidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["uiName"], "EnvDxe")
        self.assertEqual(candidates[0]["guidOffsetsWithinPe"], ["0x300"])
        self.assertFalse(candidates[0]["registrationProven"])

    def test_gzip_bounded_fv_detected(self):
        compressed = gzip.compress(driver_volume())
        source = b"ELF prefix " + compressed + b" after"
        gz, n = mod.discover_gzip(source)
        self.assertEqual(n, 1)
        self.assertEqual(gz[0][0], len(b"ELF prefix "))
        detail = mod.observe(gz[0][1], "gzip-fv")
        self.assertEqual(len(detail["targetCandidates"]), 1)
        self.assertEqual(detail["targetCandidates"][0]["uiName"], "EnvDxe")

    def test_corrupt_gzip_crc_is_not_accepted(self):
        compressed = bytearray(gzip.compress(driver_volume()))
        compressed[-5] ^= 0xFF
        result, count = mod.discover_gzip(bytes(compressed))
        self.assertEqual(count, 1)
        self.assertEqual(result, [])

    def test_name_only_is_not_proven_guid(self):
        result = mod.observe(driver_volume(with_guid=False), "fixture")
        self.assertEqual(len(result["targetCandidates"]), 1)
        self.assertEqual(result["targetCandidates"][0]["guidOffsetsWithinPe"], [])
        self.assertEqual(result["targetCandidates"][0]["classification"],
                         "CANDIDATE_BINARY_NAME_OR_DIAGNOSTICS_ONLY")

    def test_guid_without_envdxe_name_still_candidate(self):
        result = mod.observe(driver_volume(named="OtherDriver"), "fixture")
        self.assertEqual(result["targetCandidates"][0]["classification"],
                         "CANDIDATE_BINARY_CONTAINS_PROTOCOL_GUID")
        self.assertEqual(result["targetCandidates"][0]["uiName"], "OtherDriver")

    def test_no_target_is_no_provider_conclusion(self):
        result = mod.observe(driver_volume(named="OtherDriver", with_guid=False),
                             "fixture")
        self.assertEqual(result["volumeCount"], 1)
        self.assertEqual(result["targetCandidates"], [])

    def test_invalid_or_missing_fv_not_claimed_parsed(self):
        result = mod.observe(b"prefix_FVH_bad_payload", "fixture")
        self.assertEqual(result["status"], "NO_VALID_FIRMWARE_VOLUME")
        self.assertEqual(result["targetCandidates"], [])

    def test_corrupted_original_elf_digest_stops(self):
        image = stock_like_elf(gzip.compress(driver_volume()))
        expected = expectation(image)
        expected["sha256"] = "0" * 64
        with self.assertRaisesRegex(mod.ProviderProbeError, "SHA256"):
            mod.analyze_image(image, "xbl.elf", expected)

    def test_whole_original_elf_synthetic_analysis_preserves_limits(self):
        image = stock_like_elf(gzip.compress(driver_volume()))
        answer = mod.analyze_image(image, "fixture.elf", expectation(image))
        self.assertEqual(answer["gzipStreamsContainingFvSignature"], 1)
        self.assertEqual(answer["decodedFvObservations"][0]["volumeCount"], 1)
        self.assertFalse(answer["providerLocated"])
        self.assertFalse(answer["kernelPhysicalEntryVerified"])

    def test_oversized_input_refused(self):
        image = b"\x00" * (mod.MAX_INPUT + 1)
        with self.assertRaisesRegex(mod.ProviderProbeError, "cap"):
            mod.analyze_image(image, "fixture", expectation(image))

    def test_candidate_limit_applies_to_bad_header_signatures(self):
        bad = mod.GZIP_MAGIC * (mod.MAX_GZIP_CANDIDATES + 1)
        with self.assertRaisesRegex(mod.ProviderProbeError, "Too many gzip"):
            mod.discover_gzip(bad)

    def test_fv_is_only_from_file_and_not_live_handset(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            image = stock_like_elf(driver_volume())
            (folder/"xbl.elf").write_bytes(image)
            (folder/"xbl_config.elf").write_bytes(image)
            with patch.object(mod, "INPUTS", {
                "xbl.elf": expectation(image),
                "xbl_config.elf": expectation(image),
            }):
                report = mod.scan_folder(folder)
            self.assertFalse(report["numericRuntimeRamBaseKnown"])
            self.assertFalse(report["deviceModified"])
            (folder/"xbl_config.elf").write_bytes(b"changed")
            with patch.object(mod, "INPUTS", {
                "xbl.elf": expectation(image),
                "xbl_config.elf": expectation(image),
            }):
                with self.assertRaisesRegex(mod.ProviderProbeError, "SHA256"):
                    mod.scan_folder(folder)

    def test_malformed_symlink_original_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"image").write_bytes(b"fake")
            (root/"xbl.elf").symlink_to(root/"image")
            with self.assertRaisesRegex(mod.ProviderProbeError, "regular ELF"):
                mod.scan_folder(root)


if __name__ == "__main__":
    unittest.main()
