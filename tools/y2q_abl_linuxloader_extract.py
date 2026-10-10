#!/usr/bin/env python3
"""Extract the actual UEFI LinuxLoader PE from original hash-pinned HXL1 ABL.

Offline firmware processing only; no device commands, flash or execution of the PE.
Reads the Qualcomm ELF/FV/FFS/GUID-LZMA/FV/FFS/PE32+ packaging convention.
Never derives a Linux physical kernel address from an ELF or PE image base.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct
import sys
from uuid import UUID

ORIGINAL_ABL_SHA256 = "6d717ef96e7355d72db1ac167ef1b74ff6ef33d22a8bfc08affc62f9cabcdeef"
ORIGINAL_ABL_BYTES = 4194304
LZMA_GUID = UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf").bytes_le
LOADER_GUID = UUID("f536d559-459f-48fa-8bbc-43b554ecae8d")
FV_MAGIC = b"_FVH"
MAX_FV_BYTES = 48 * 1024 * 1024
MAX_LZMA_BYTES = 48 * 1024 * 1024
MAX_DEPTH = 8
MAX_OBJECTS = 5000


class ExtractError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def aligned(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def u24(blob: bytes, at: int) -> int:
    return int.from_bytes(blob[at:at + 3], "little")


def identify_pe(blob: bytes) -> dict | None:
    if len(blob) < 0x90 or blob[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", blob, 0x3c)[0]
    # e_lfanew is a file-relative offset, not limited to a 0x800-byte DOS stub.
    # Original HXL1 LinuxLoader stores a valid AArch64 PE header at 0xe58.
    # Bound all subsequent reads to the input bytes instead of inventing a
    # maximum DOS stub length.
    if not (0x40 <= pe <= len(blob) - 24):
        return None
    if blob[pe:pe + 4] != b"PE\x00\x00":
        return None
    machine, sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", blob, pe + 4)
    opt = pe + 24
    if (machine != 0xAA64 or not 1 <= sections <= 96
            or opt_size < 0x70 or opt + opt_size > len(blob)
            or opt + opt_size + sections * 40 > len(blob)):
        return None
    if struct.unpack_from("<H", blob, opt)[0] != 0x20B:
        return None
    if opt + 0x40 > len(blob):
        return None
    return {
        "architecture": "AArch64 PE32+",
        "coffMachine": "0xaa64",
        "sectionCount": sections,
        "dosPeHeaderOffset": hex(pe),
        "entryPointRva": hex(struct.unpack_from("<I", blob, opt + 0x10)[0]),
        "preferredImageBase": hex(struct.unpack_from("<Q", blob, opt + 0x18)[0]),
        "sizeOfImage": struct.unpack_from("<I", blob, opt + 0x38)[0],
        "fileBytes": len(blob),
        "sha256": digest(blob),
    }


class Walker:
    def __init__(self):
        self.visited_objects = 0
        self.fv_headers = []
        self.identified = []
        self.notes = []
        self.ffs_files = []
        self.sections = []
        self.unrecognized_executable_sections = []

    def tick(self):
        self.visited_objects += 1
        if self.visited_objects > MAX_OBJECTS:
            raise ExtractError(
                f"Firmware container object limit exceeded: "
                f"visited={self.visited_objects}, volumes={len(self.fv_headers)}, "
                f"last_notes={self.notes[-4:]}")

    def add_pe(self, payload: bytes, trace: list[str], ui: str, file_guid: str) -> None:
        info = identify_pe(payload)
        if info:
            self.identified.append({"image": payload, "info": info,
                                    "trace": list(trace), "fileGuid": file_guid,
                                    "ui": ui})
        else:
            self.unrecognized_executable_sections.append({
                "trace": list(trace), "fileGuid": file_guid, "ui": ui,
                "payloadBytes": len(payload),
                "first64Hex": payload[:64].hex(),
                "signature": ("MZ" if payload.startswith(b"MZ") else
                              "TE-VZ" if payload.startswith(b"VZ") else
                              "OTHER"),
                "sha256": digest(payload),
            })

    def search_fv(self, data: bytes, trace: list[str], depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ExtractError("Maximum nested firmware depth exceeded")
        start = 0
        while True:
            hit = data.find(FV_MAGIC, start)
            if hit < 0:
                return
            start = hit + 4
            fv_base = hit - 0x28
            if fv_base < 0 or hit + 0x18 > len(data):
                continue
            length = struct.unpack_from("<Q", data, fv_base + 0x20)[0]
            header_len = struct.unpack_from("<H", data, fv_base + 0x30)[0]
            if not (0x38 <= header_len <= 0x10000 and
                    header_len <= length <= MAX_FV_BYTES and
                    length <= len(data) - fv_base and data[fv_base + 0x37] == 2):
                continue
            volume = data[fv_base:fv_base + length]
            path = trace + [f"FV@0x{fv_base:x} length=0x{length:x}"]
            self.fv_headers.append({"trace": path, "sizeBytes": length})
            self.parse_fv(volume, header_len, path, depth)
            start = fv_base + length

    def parse_fv(self, blob: bytes, header_len: int, trace: list[str], depth: int):
        cursor = aligned(header_len, 8)
        while cursor + 24 <= len(blob):
            self.tick()
            head = blob[cursor:cursor + 24]
            # A firmware volume is erased beyond its final FFS file, commonly
            # with megabytes of 0xff padding. The old code consumed this
            # *eight bytes at a time*, exhausting MAX_OBJECTS before reaching
            # the loader on the original 4 MiB Samsung ABL image.
            # Erased space is an end-of-files marker, NOT another FFS object.
            if head in (b"\xff" * 24, b"\x00" * 24):
                self.notes.append(
                    f"FFS erased/free tail at {trace[-1]}+0x{cursor:x} "
                    f"remaining=0x{len(blob) - cursor:x}")
                break
            fsize = u24(blob, cursor + 20)
            header_size = 24
            if fsize == 0xFFFFFF:
                if cursor + 32 > len(blob):
                    break
                fsize = struct.unpack_from("<Q", blob, cursor + 24)[0]
                header_size = 32
            if fsize < header_size or fsize > len(blob) - cursor:
                # Do not skip thousands of forged headers in invalid/free
                # bytes, or silently declare an unrelated PE as LinuxLoader.
                self.notes.append(f"Bad FFS header at {trace[-1]}+0x{cursor:x}, "
                                  f"size={fsize}, remaining={len(blob) - cursor}")
                break
            file_guid = str(UUID(bytes_le=blob[cursor:cursor + 16]))
            ftype = blob[cursor + 18]
            path = trace + [f"FFS[{file_guid}] type=0x{ftype:x} offset=0x{cursor:x}"]
            body = blob[cursor + header_size:cursor + fsize]
            self.ffs_files.append({
                "trace": list(path), "fileGuid": file_guid,
                "fileType": f"0x{ftype:02x}", "offset": cursor,
                "fileSize": fsize, "fileHeaderSize": header_size,
                "bodyPrefixHex": body[:32].hex(),
            })
            if ftype != 0xF0:  # EFI_FV_FILETYPE_FFS_PAD
                self.parse_sections(body, path, file_guid, depth + 1)
            cursor = aligned(cursor + fsize, 8)

    def parse_sections(self, data: bytes, trace: list[str], ffs_guid: str,
                       depth: int, *, parent_ui: str = "") -> None:
        if depth > MAX_DEPTH:
            raise ExtractError("Maximum nested section depth exceeded")
        cursor = 0
        ui = parent_ui
        sections = []
        while cursor + 4 <= len(data):
            self.tick()
            size = u24(data, cursor)
            stype = data[cursor + 3]
            hdr = 4
            if size == 0xffffff:
                if cursor + 8 > len(data):
                    break
                size = struct.unpack_from("<I", data, cursor + 4)[0]
                hdr = 8
            if size < hdr or size > len(data) - cursor:
                break
            sections.append((cursor, stype, data[cursor + hdr:cursor + size]))
            cursor = aligned(cursor + size, 4)
        for _, stype, payload in sections:
            if stype == 0x15 and len(payload) > 2:
                candidate = payload.decode("utf-16-le", "replace").split("\x00")[0]
                if candidate:
                    ui = candidate[:120]
        for offset, stype, payload in sections:
            path = trace + [f"SECTION[0x{stype:02x}] offset=0x{offset:x}"]
            self.sections.append({
                "trace": list(path),
                "fileGuid": ffs_guid,
                "ui": ui,
                "sectionType": f"0x{stype:02x}",
                "sectionBodyBytes": len(payload),
                "first64Hex": payload[:64].hex(),
                "sha256": digest(payload),
            })
            if stype == 0x10:
                self.add_pe(payload, path, ui, ffs_guid)
            elif stype == 0x17:
                self.search_fv(payload, path, depth + 1)
            elif stype == 0x02:
                if len(payload) < 20:
                    continue
                guid = payload[:16]
                data_off, attrs = struct.unpack_from("<HH", payload, 16)
                common_len = 4 if len(data) >= offset + 4 and u24(data, offset) != 0xffffff else 8
                inside = data_off - common_len
                if inside < 20 or inside > len(payload):
                    self.notes.append(f"GUID section data offset invalid at {path[-1]}")
                    continue
                compressed = payload[inside:]
                if guid != LZMA_GUID:
                    self.notes.append(f"Unhandled GUID section {UUID(bytes_le=guid)}")
                    continue
                try:
                    decoded = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,
                                                      memlimit=MAX_LZMA_BYTES).decompress(
                        compressed, max_length=MAX_LZMA_BYTES + 1)
                    if len(decoded) > MAX_LZMA_BYTES:
                        raise ExtractError("LZMA expansion size exceeded")
                except (lzma.LZMAError, EOFError) as exc:
                    self.notes.append(f"LZMA decompression failed at {path[-1]}: {exc}")
                    continue
                self.parse_sections(decoded, path + [f"LZMA[{UUID(bytes_le=guid)}] decoded={len(decoded)}"],
                                    ffs_guid, depth + 1)
            elif stype == 0x12:
                # EFI_SECTION_TE contains a Terse Executable ("VZ") header.
                # Record, never silently call it PE32+ or rewrite/rebase it.
                self.add_pe(payload, path, ui, ffs_guid)
            elif stype == 0x01:
                if len(payload) >= 5:
                    declared_len = struct.unpack_from("<I", payload)[0]
                    mode = payload[4]
                    if mode == 0 and declared_len == len(payload) - 5:
                        self.parse_sections(
                            payload[5:], path + ["EFI_NOT_COMPRESSED"],
                            ffs_guid, depth + 1, parent_ui=ui)
                    else:
                        self.notes.append(
                            f"Unsupported standard compression mode={mode} "
                            f"declared_uncompressed={declared_len} at {path[-1]}")
                else:
                    self.notes.append(f"Truncated standard-compression section at {path[-1]}")

    def extract(self, original: bytes) -> dict:
        self.search_fv(original, ["original-pinned-abl.elf"], 0)
        qualified = [x for x in self.identified
                     if x["fileGuid"].lower() == str(LOADER_GUID) or
                     "linuxloader" in x["ui"].lower()]
        if len(qualified) != 1:
            raise ExtractError(f"Expected one LinuxLoader AArch64 PE; got {len(qualified)} "
                               f"(all AArch64 PEs={len(self.identified)}, "
                               f"valid FVs={len(self.fv_headers)}, "
                               f"objects={self.visited_objects}; notes={self.notes[:8]})")
        return qualified[0]


def run(source: Path, dest: Path, *, pinned_hash: str = ORIGINAL_ABL_SHA256,
        pinned_size: int = ORIGINAL_ABL_BYTES) -> dict:
    if source.is_symlink() or not source.is_file():
        raise ExtractError("Original ABL must be a regular non-symlinked file")
    if source.resolve() == dest.resolve() or source.resolve() in dest.resolve().parents:
        raise ExtractError("Refusing to overwrite or write inside original ABL input")
    raw = source.read_bytes()
    if len(raw) != pinned_size or digest(raw) != pinned_hash:
        raise ExtractError("Original stock ABL SHA256/size mismatch; stop")
    walker = Walker()
    try:
        entry = walker.extract(raw)
    except ExtractError as exc:
        # Failed extraction still yields a bounded layer-by-layer diagnostic,
        # but never writes an unverified loader executable.
        dest.mkdir(parents=True, exist_ok=True)
        diagnosis = {
            "status": "NO_VERIFIED_LINUXLOADER",
            "sourceSha256": digest(raw),
            "sourceBytes": len(raw),
            "failure": str(exc),
            "firmwareVolumesFound": len(walker.fv_headers),
            "firmwareVolumeTraces": walker.fv_headers[:32],
            "aarch64PeCount": len(walker.identified),
            "aarch64PeMetadata": [
                {"info": x["info"], "fileGuid": x["fileGuid"],
                 "ui": x["ui"], "trace": x["trace"]}
                for x in walker.identified[:32]
            ],
            "objectsInspected": walker.visited_objects,
            "ffsFiles": walker.ffs_files[:128],
            "sections": walker.sections[:256],
            "nonPeExecutableSections": walker.unrecognized_executable_sections[:32],
            "diagnosticNotes": walker.notes[:64],
            "physicalKernelLoadVerified": False,
            "phoneModified": False,
        }
        diagnostic = dest / "linuxloader-extraction-diagnostics.json"
        diagnostic.write_text(json.dumps(diagnosis, indent=2) + "\n")
        raise ExtractError(f"{exc}; diagnostics: {diagnostic}") from exc
    dest.mkdir(parents=True, exist_ok=True)
    binary = dest / "LinuxLoader-HXL1.efi"
    if binary.exists():
        if digest(binary.read_bytes()) != digest(entry["image"]):
            raise ExtractError("Existing PE output differs; refusing overwrite")
    else:
        binary.write_bytes(entry["image"])
    result = {"source": str(source), "sourceSha256": digest(raw),
              "sourceBytes": len(raw), "loader": str(binary),
              "loaderInfo": entry["info"], "loaderGuid": entry["fileGuid"],
              "loaderUiName": entry["ui"], "containerTrace": entry["trace"],
              "validatedFvCount": len(walker.fv_headers),
              "notes": walker.notes,
              "kernelPhysicalAddressVerified": False,
              "androidKernelHandoffIdentified": False,
              "phoneModified": False,
              "classification": "STOCK_HXL1_LINUXLOADER_EXTRACTED_STATIC_ONLY"}
    (dest / "linuxloader-extraction.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abl", type=Path, default=Path.home() / "s20-artifacts/hxl1-research/bl-stock/abl.elf")
    p.add_argument("--output-dir", type=Path, default=Path.home() / "s20-artifacts/hxl1-research/abl-linuxloader")
    opts = p.parse_args()
    try:
        r = run(opts.abl, opts.output_dir)
    except (ExtractError, OSError, struct.error) as err:
        print("[STOP]", err, file=sys.stderr)
        return 2
    print("[PASS] Exact original stock ABL SHA256 / byte count")
    print("[PASS] Extracted LinuxLoader AArch64 PE32+ from nested UEFI firmware volumes")
    print("[loader]", r["loader"])
    print("[sha256]", r["loaderInfo"]["sha256"])
    print("[entry RVA]", r["loaderInfo"]["entryPointRva"])
    print("[trace]", " -> ".join(r["containerTrace"]))
    print("[LIMIT] Loader PE image base and entry RVA are NOT the Linux kernel physical load")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
