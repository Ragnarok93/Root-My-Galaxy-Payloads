#!/usr/bin/env python3
"""Read-only stock-HXL1 ARM64 export-table inspection; never loads kernel code.

Consumes the original extracted raw ARM64 Image, its own recovered kallsyms
listing, and CONFIG_IKCONFIG. Uses *raw* image bytes for PREL32 export entries.
Reported module CRCs are only candidates until checked against Samsung's
original kernel/module.c and independent reference values.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

HXL1_SHA256 = "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
DEFAULT_NAMES = (
    "commit_creds",
    "prepare_kernel_cred",
    "init_task",
    "module_layout",
    "system_unbound_wq",
)

def config_option(config: str, key: str) -> str:
    for line in config.splitlines():
        if line.startswith(f"{key}="):
            return line.partition("=")[2].strip()
        if line == f"# {key} is not set":
            return "n"
    return "absent"

def parse_nm(path: Path) -> dict[str, tuple[int | None, str]]:
    symbols = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        tokens = line.split()
        if len(tokens) == 3:
            address, typ, name = tokens
            try:
                symbols[name] = (int(address, 16), typ)
            except ValueError:
                pass
        elif len(tokens) == 2 and tokens[0] == "U":
            symbols[tokens[1]] = (None, "U")
    return symbols

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-bin", type=Path, required=True)
    parser.add_argument("--nm", type=Path, required=True)
    parser.add_argument("--config-gz", type=Path, required=True)
    parser.add_argument("--names", nargs="+", default=list(DEFAULT_NAMES))
    args = parser.parse_args()

    raw = args.kernel_bin.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != HXL1_SHA256:
        raise ValueError(f"STOP: not the verified HXL1 raw Image: sha256={sha}")
    if len(raw) < 64 or raw[0x38:0x3C] != b"ARM\x64":
        raise ValueError("STOP: invalid ARM64 kernel Image magic")
    symbols = parse_nm(args.nm)
    with gzip.open(args.config_gz, "rt", encoding="utf-8") as inp:
        config = inp.read()
    keys = ("CONFIG_HAVE_ARCH_PREL32_RELOCATIONS", "CONFIG_MODULE_REL_CRCS",
            "CONFIG_MODVERSIONS", "CONFIG_MODULE_SIG_FORCE")
    options = {key: config_option(config, key) for key in keys}

    def address(name: str) -> int:
        item = symbols.get(name)
        if item is None or item[0] is None:
            raise ValueError(f"Required symbol not resolved: {name}")
        return item[0]

    base = address("_text")
    if base != 0xFFFFFF8008080000:
        raise ValueError(f"STOP: unexpected recovered _text base {base:#x}")
    if options["CONFIG_HAVE_ARCH_PREL32_RELOCATIONS"] != "y":
        raise ValueError("PREL32 export layout not established by exact config; refusing to decode")

    def raw_off(va: int, count: int) -> int:
        off = va - base
        if off < 0 or off + count > len(raw):
            raise ValueError(f"Address {va:#x} outside original raw Image")
        return off

    normal_begin = address("__start___ksymtab")
    normal_end = address("__stop___ksymtab")
    gpl_begin = address("__start___ksymtab_gpl")
    gpl_end = address("__stop___ksymtab_gpl")
    crc_begin = address("__start___kcrctab")
    crc_end = address("__stop___kcrctab")
    if normal_end != gpl_begin:
        raise ValueError("Normal/GPL symbol-table boundary mismatch")
    normal_span = normal_end - normal_begin
    crc_span = crc_end - crc_begin
    if normal_span <= 0 or normal_span % 8 or crc_span != (normal_span // 8) * 4:
        raise ValueError("Normal export and CRC table lengths do not match PREL32 expectations")

    gpl_crc = symbols.get("__start___kcrctab_gpl", (None, "U"))[0]
    gpl_crc_end = symbols.get("__stop___kcrctab_gpl", (None, "U"))[0]
    if (gpl_end - gpl_begin) % 8:
        raise ValueError("GPL export table has a non-integral PREL32 entry count")
    if (gpl_crc is not None and gpl_crc != crc_end:
        raise ValueError("GPL CRC table must begin where normal CRC table ends")
    if gpl_crc_end is not None and gpl_crc is not None:
        if (gpl_crc_end - gpl_crc) != ((gpl_end - gpl_begin) // 8) * 4:
            raise ValueError("GPL export count and GPL CRC slot count disagree")
    result = {
        "status": "read-only provisional symbol and CRC audit; NO module-load approval",
        "firmware": "G986U1UESCHXL1",
        "inputKernelSha256": sha,
        "reconstructedVirtualBase": f"{base:#x}",
        "config": options,
        "normalExports": normal_span // 8,
        "normalCrcSlots": crc_span // 4,
        "gplExports": (gpl_end - gpl_begin) // 8,
        "gplCrcStartPresent": gpl_crc is not None,
        "gplCrcEndPresent": gpl_crc_end is not None,
        "gplCrcSlots": (gpl_crc_end - gpl_crc) // 4 if gpl_crc is not None and gpl_crc_end is not None else None,
        "crcInterpretationNote": (
            "The absent CONFIG_MODULE_REL_CRCS config entry does not independently "
            "validate CRC encoding. Stock 4.19 module.c uses IS_ENABLED(CONFIG_MODULE_REL_CRCS): "
            "when undefined, it reads the 32-bit CRC slot directly. Values "
            "reported with the absolute assumption remain provisional until "
            "Samsung's exact source and a known independent CRC are checked."
        ),
        "symbols": [],
    }
    for name in args.names:
        entry = symbols.get(f"__ksymtab_{name}")
        if not entry or entry[0] is None:
            result["symbols"].append({"name": name, "export": "not located"})
            continue
        va = entry[0]
        if normal_begin <= va < normal_end:
            table = "normal"
            tab_start = normal_begin
            crc_start = crc_begin
        elif gpl_begin <= va < gpl_end:
            table = "gpl-only"
            tab_start = gpl_begin
            crc_start = gpl_crc
        else:
            result["symbols"].append({"name": name, "export": "outside known normal/GPL tables"})
            continue
        if (va - tab_start) % 8:
            raise ValueError(f"Unaligned export {name}: {va:#x}")
        index = (va - tab_start) // 8
        sym_off, str_off = struct.unpack_from("<ii", raw, raw_off(va, 8))
        target_va = va + sym_off
        string_va = va + 4 + str_off
        name_off = raw_off(string_va, 1)
        end = raw.find(b"\x00", name_off, name_off + 128)
        if end < 0:
            raise ValueError(f"Unterminated name at {name}: {string_va:#x}")
        resolved_name = raw[name_off:end].decode("ascii")
        target_symbol = symbols.get(name, (None, "absent"))[0]
        item = {
            "name": name,
            "export": table,
            "index": index,
            "entryVA": f"{va:#x}",
            "decodedName": resolved_name,
            "targetVA": f"{target_va:#x}",
            "kallsymsValueMatches": target_symbol == target_va,
            "nameMatches": resolved_name == name,
            "crcEncoding": options["CONFIG_MODULE_REL_CRCS"],
        }
        if crc_start is not None:
            slot_va = crc_start + index * 4
            raw_crc_slot = raw[raw_off(slot_va, 4):raw_off(slot_va, 4) + 4]
            item["crcSlotVA"] = f"{slot_va:#x}"
            item["crcSlotRawHex"] = raw_crc_slot.hex()
            item["crcSlotLittleEndianU32"] = f"0x{struct.unpack('<I', raw_crc_slot)[0]:08x}"
            if options["CONFIG_MODULE_REL_CRCS"] == "n":
                item["candidateCrc"] = f"0x{struct.unpack('<I', raw_crc_slot)[0]:08x}"
            elif options["CONFIG_MODULE_REL_CRCS"] == "y":
                displacement = struct.unpack("<i", raw_crc_slot)[0]
                crc_target = slot_va + displacement
                item["relativeCrcTargetVA"] = f"{crc_target:#x}"
                try:
                    crc_val = struct.unpack_from("<I", raw, raw_off(crc_target, 4))[0]
                    item["candidateCrc"] = f"0x{crc_val:08x}"
                except ValueError:
                    item["crcCaveat"] = "Relative CRC reference outside raw Image; cannot decode offline"
            else:
                item["candidateCrcAssumingAbsolute"] = item["crcSlotLittleEndianU32"]
                item["crcCaveat"] = (
                    "MODULE_REL_CRCS entry absent, not explicitly disabled in provided "
                    "config.gz; absolute interpretation follows upstream 4.19 "
                    "IS_ENABLED fallback but still needs exact-source/CRC cross-check"
                )
        if not item["nameMatches"]:
            raise ValueError(f"STOP: PREL32 name mismatch {name}: found {resolved_name}")
        if target_symbol is not None and not item["kallsymsValueMatches"]:
            raise ValueError(f"STOP: PREL32 target mismatch for {name}")
        result["symbols"].append(item)
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, struct.error, UnicodeDecodeError) as exc:
        print(f"Export audit stopped: {exc}", file=sys.stderr)
        sys.exit(1)
