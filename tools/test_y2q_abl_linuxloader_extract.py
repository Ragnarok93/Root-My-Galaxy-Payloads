#!/usr/bin/env python3
"""Synthetic nested-UEFI regressions for the pinned HXL1 LinuxLoader extractor."""
from __future__ import annotations

import lzma
from pathlib import Path
import struct
import tempfile
import unittest
from uuid import UUID

from tools import y2q_abl_linuxloader_extract as abl


def section(kind, body):
    size = 4 + len(body)
    assert size < 0xffffff
    return size.to_bytes(3, "little") + bytes([kind]) + body


def pack_sections(*items):
    result = bytearray()
    for item in items:
        result.extend(item)
        result.extend(b"\x00" * ((-len(result)) % 4))
    return bytes(result)


def ffs(guid, typ, payload):
    header = bytearray(24)
    header[:16] = UUID(guid).bytes_le
    header[18] = typ
    header[20:23] = (len(payload) + 24).to_bytes(3, "little")
    header[23] = 7
    return bytes(header) + payload


def volume(files):
    header_len = 0x48
    body = bytearray()
    for entry in files:
        body.extend(entry)
        body.extend(b"\xff" * ((-len(body)) % 8))
    total = abl.aligned(header_len + len(body) + 0x20, 8)
    image = bytearray(b"\xff" * total)
    image[:16] = b"\x00" * 16
    image[0x10:0x20] = UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le
    struct.pack_into("<Q", image, 0x20, total)
    image[0x28:0x2c] = b"_FVH"
    struct.pack_into("<H", image, 0x30, header_len)
    image[0x37] = 2
    image[header_len:header_len + len(body)] = body
    return bytes(image)


def pe():
    image = bytearray(0x300)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3c, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x84, 0xaa64, 1, 0, 0, 0, 0xf0, 2)
    struct.pack_into("<H", image, 0x98, 0x20b)
    struct.pack_into("<I", image, 0x98 + 0x10, 0x120)
    struct.pack_into("<Q", image, 0x98 + 0x18, 0x100000)
    struct.pack_into("<I", image, 0x98 + 0x38, 0x3000)
    return bytes(image)


def fake_abl():
    ui = section(0x15, "LinuxLoader\x00".encode("utf-16-le"))
    inner = volume([ffs(str(abl.LOADER_GUID), 0x09,
                        pack_sections(ui, section(0x10, pe())))])
    fvsec = section(0x17, inner)
    zipped = lzma.compress(fvsec, format=lzma.FORMAT_ALONE)
    guided = abl.LZMA_GUID + struct.pack("<HH", 24, 1) + zipped
    outer = volume([ffs("9e21fd93-9c72-4c15-8c4b-e77f1db2d792",
                        0x0b, section(0x02, guided))])
    return b"\x00" * 0x3000 + outer + b"\x00" * 128


class ExtractionTests(unittest.TestCase):
    def test_nested_qualcomm_lzma_fv_linuxloader(self):
        walker = abl.Walker()
        entry = walker.extract(fake_abl())
        self.assertEqual(entry["image"], pe())
        self.assertEqual(entry["info"]["coffMachine"], "0xaa64")
        self.assertEqual(len(walker.fv_headers), 2)
        self.assertTrue(any("LZMA" in part for part in entry["trace"]))
        self.assertEqual(entry["ui"], "LinuxLoader")

    def test_corrupted_original_rejected(self):
        data = fake_abl()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "abl.elf"
            source.write_bytes(data)
            with self.assertRaisesRegex(abl.ExtractError, "SHA256/size mismatch"):
                abl.run(source, Path(temp) / "out")

    def test_pinned_synthetic_original_extracted(self):
        data = fake_abl()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "abl.elf"
            source.write_bytes(data)
            out = Path(temp) / "out"
            result = abl.run(source, out, pinned_hash=abl.digest(data),
                             pinned_size=len(data))
            self.assertEqual((out / "LinuxLoader-HXL1.efi").read_bytes(), pe())
            self.assertFalse(result["kernelPhysicalAddressVerified"])
            self.assertFalse(result["androidKernelHandoffIdentified"])

    def test_wrong_architecture_pe_rejected(self):
        wrong = bytearray(pe())
        struct.pack_into("<H", wrong, 0x84, 0x8664)
        self.assertIsNone(abl.identify_pe(wrong))

    def test_bad_sections_fail_without_inventing_loader(self):
        damaged = bytearray(fake_abl())
        damaged[0x3000 + 0x28:0x3000 + 0x2c] = b"bad!"
        with self.assertRaisesRegex(abl.ExtractError, "Expected one LinuxLoader"):
            abl.Walker().extract(bytes(damaged))

    def test_megabyte_erased_tail_does_not_exhaust_object_limit(self):
        # The real HXL1 4 MiB ABL has long padded firmware-volume regions.
        # Erased FFS space is an end marker, not thousands of fake files.
        image = fake_abl()
        at = 0x3000
        old_size = struct.unpack_from("<Q", image, at + 0x20)[0]
        volume_data = bytearray(image[at:at + old_size])
        new_size = 1024 * 1024
        volume_data.extend(bytes([0xff]) * (new_size - old_size))
        struct.pack_into("<Q", volume_data, 0x20, new_size)
        enlarged = image[:at] + bytes(volume_data) + image[at + old_size:]
        walker = abl.Walker()
        entry = walker.extract(enlarged)
        self.assertEqual(entry["image"], pe())
        self.assertLess(walker.visited_objects, 100)
        self.assertTrue(any("erased/free tail" in note for note in walker.notes))

    def test_failed_original_produces_diagnostics_without_fake_pe(self):
        damaged = bytearray(fake_abl())
        damaged[0x3000 + 0x28:0x3000 + 0x2c] = b"bad!"
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "abl.elf"
            source.write_bytes(damaged)
            out = Path(temp) / "out"
            with self.assertRaisesRegex(abl.ExtractError, "diagnostics:"):
                abl.run(source, out, pinned_hash=abl.digest(damaged),
                        pinned_size=len(damaged))
            self.assertFalse((out / "LinuxLoader-HXL1.efi").exists())
            import json
            info = json.loads((out / "linuxloader-extraction-diagnostics.json").read_text())
            self.assertEqual(info["status"], "NO_VERIFIED_LINUXLOADER")
            self.assertFalse(info["physicalKernelLoadVerified"])

    def test_nested_fv_keeps_real_section_and_ffs_file_provenance(self):
        walker = abl.Walker()
        entry = walker.extract(fake_abl())
        self.assertEqual(entry["ui"], "LinuxLoader")
        self.assertTrue(any(
            record["fileGuid"] == str(abl.LOADER_GUID)
            and record["fileType"] == "0x09"
            for record in walker.ffs_files))
        self.assertTrue(any(
            item["sectionType"] == "0x10"
            and item["ui"] == "LinuxLoader"
            for item in walker.sections))
        self.assertFalse(walker.unrecognized_executable_sections)

    def test_malformed_pe_records_rejection_and_signature(self):
        wrong = bytearray(pe())
        struct.pack_into("<H", wrong, 0x84, 0x8664)
        w = abl.Walker()
        w.add_pe(bytes(wrong), ["SECTION[0x10]"], "LinuxLoader",
                 str(abl.LOADER_GUID))
        self.assertEqual(w.identified, [])
        self.assertEqual(len(w.unrecognized_executable_sections), 1)
        record = w.unrecognized_executable_sections[0]
        self.assertEqual(record["signature"], "MZ")
        self.assertEqual(record["fileGuid"], str(abl.LOADER_GUID))

    def test_no_device_or_firmware_modification_paths(self):
        source = Path(abl.__file__).read_text()
        for token in ("subprocess.run(", "adb shell", "fastboot flash", "setresuid("):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
