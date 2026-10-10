#!/usr/bin/env python3
"""Read-only HXL1 stage 3: original structure and ELF debug metadata inventory.

Source definitions are NOT verified compiled field offsets. No compilation,
ADB, kernel writes, CVE triggering, module loading, or root.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

PINNED = {
    "kernel.bin": "ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123",
    "config.gz": "1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd",
}
SOURCE_PINNED = {
    "kernel/locking/rtmutex.c": "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9",
    "kernel/futex.c": "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5",
}
STRUCT_FILES = {
    "task_struct": ["include/linux/sched.h"],
    "rt_mutex_waiter": ["include/linux/rtmutex.h", "kernel/locking/rtmutex.c",
                        "kernel/locking/rtmutex_common.h"],
    "rt_mutex": ["include/linux/rtmutex.h", "kernel/locking/rtmutex.c"],
    "file_operations": ["include/linux/fs.h"],
    "page": ["include/linux/mm_types.h", "include/linux/mm.h"],
    "cred": ["include/linux/cred.h"],
    "configfs_buffer": ["fs/configfs/file.c", "fs/configfs/configfs_internal.h"],
}
OPTIONS = (
    "CONFIG_DEBUG_INFO", "CONFIG_DEBUG_INFO_BTF", "CONFIG_DEBUG_INFO_DWARF4",
    "CONFIG_DEBUG_INFO_REDUCED", "CONFIG_DEBUG_INFO_SPLIT",
    "CONFIG_ARM64", "CONFIG_64BIT", "CONFIG_CC_IS_CLANG",
    "CONFIG_RANDSTRUCT", "CONFIG_GCC_PLUGIN_RANDSTRUCT",
)
SYMBOLS = ("_text", "_stext", "start_kernel", "remove_waiter",
           "rt_mutex_start_proxy_lock", "init_task")


class InventoryError(Exception):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1048576), b""):
            h.update(part)
    return h.hexdigest()


def pin(path: Path, expected: str) -> None:
    if not path.is_file():
        raise InventoryError("Missing original file: " + str(path))
    if digest(path) != expected:
        raise InventoryError("STOP: original file SHA256 mismatch: " + str(path))


def config(path: Path) -> dict[str, str]:
    try:
        raw = gzip.decompress(path.read_bytes()).decode("utf-8")
    except (OSError, UnicodeError, EOFError) as exc:
        raise InventoryError("Original config.gz invalid: " + str(exc))
    out = {}
    for name in OPTIONS:
        match = re.search(r"(?m)^" + name + r"=(.+)$", raw)
        out[name] = match.group(1).strip() if match else (
            "n" if "# " + name + " is not set" in raw else "NOT_LISTED")
    return out


def declarations(root: Path) -> dict:
    results = {}
    for tag, files in STRUCT_FILES.items():
        hits = []
        rx = re.compile(r"(?m)^[ \t]*struct[ \t]+"
                        + re.escape(tag) + r"[ \t]*\{")
        for relative in files:
            path = root / relative
            if path.is_file():
                text = path.read_text(errors="replace")
                for match in list(rx.finditer(text))[:4]:
                    hits.append({"path": relative,
                                 "line": text.count("\n", 0, match.start()) + 1})
        results[tag] = {"definitions": hits, "verifiedOffsets": False,
                        "configuredLayoutVerified": False}
    return results


def sections(path: Path) -> dict:
    if not path.is_file():
        return {"state": "MISSING", "debug": [], "btf": False}
    data = path.read_bytes()
    if (len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2
            or data[5] != 1 or struct.unpack_from("<H", data, 18)[0] != 183):
        raise InventoryError("Recovered analysis ELF not ELF64 LE AArch64")
    off = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strings_idx = struct.unpack_from("<HHH", data, 58)
    if not off or not count:
        return {"state": "NO_SECTION_TABLE", "debug": [], "btf": False}
    if (entsize < 64 or strings_idx >= count
            or off + entsize * count > len(data)):
        raise InventoryError("ELF section table has invalid bounds")
    def hdr(idx: int) -> tuple[int, int, int]:
        start = off + entsize * idx
        return (struct.unpack_from("<I", data, start)[0],
                struct.unpack_from("<Q", data, start + 24)[0],
                struct.unpack_from("<Q", data, start + 32)[0])
    _, str_start, str_size = hdr(strings_idx)
    if str_start + str_size > len(data):
        raise InventoryError("ELF section names outside file")
    names = data[str_start:str_start + str_size]
    found = []
    for i in range(count):
        name_start, _, _ = hdr(i)
        if name_start >= len(names):
            raise InventoryError("ELF section name index outside table")
        name_end = names.find(b"\x00", name_start)
        if name_end < 0:
            raise InventoryError("Unterminated ELF section name")
        found.append(names[name_start:name_end].decode("ascii", "replace"))
    return {"state": "SECTIONS_FOUND", "count": count,
            "debug": [x for x in found if x.startswith((".debug_", ".zdebug_"))],
            "btf": ".BTF" in found,
            "scope": "reconstructed analysis ELF, not an independent stock debug ELF"}


def symbols(path: Path) -> dict:
    if not path.is_file():
        return {name: False for name in SYMBOLS}
    observed = set()
    for line in path.read_text(errors="replace").splitlines():
        columns = line.split()
        if len(columns) >= 2 and columns[-1] in SYMBOLS:
            observed.add(columns[-1])
    return {name: name in observed for name in SYMBOLS}


def make_inventory(source: Path, artifacts: Path) -> dict:
    for name, expected in PINNED.items():
        pin(artifacts / name, expected)
    for relative, expected in SOURCE_PINNED.items():
        pin(source / relative, expected)
    return {
        "schemaVersion": 1, "model": "SM-G986U1",
        "firmware": "G986U1UESCHXL1",
        "stockKernel": "4.19.113-27095354",
        "originalFileHashChecksPassed": True,
        "sourceConfig": config(artifacts / "config.gz"),
        "sourceDeclarations": declarations(source),
        "analysisElf": sections(artifacts / "hxl1-research/vmlinux-stock.elf"),
        "analysisNmSymbols": symbols(artifacts / "hxl1-research/vmlinux-stock.nm"),
        "offsetsVerified": False, "sourceToLiveDeviceLayoutVerified": False,
        "root": False, "kernelSuLoaded": False, "physicalDeviceModified": False,
        "limitation": "Source declaration presence and reconstructed ELF metadata "
                      "do not prove compiled offsets or runtime addresses.",
    }


def as_markdown(report: dict) -> str:
    lines = ["# HXL1 stage 3 — debug/structure inventory", "",
             "Pinned original firmware and source hashes matched.", "",
             "## Original IKCONFIG settings", "",
             "| Key | Value |", "|---|---|"]
    for k, v in report["sourceConfig"].items():
        lines.append("| " + k + " | " + v + " |")
    lines += ["", "## Source declarations", "",
              "| Structure | Verified location |", "|---|---|"]
    for name, obj in report["sourceDeclarations"].items():
        loc = ", ".join(x["path"] + ":" + str(x["line"])
                        for x in obj["definitions"]) or "NOT LOCATED"
        lines.append("| " + name + " | " + loc + " |")
    elf = report["analysisElf"]
    lines += ["", "## Reconstructed ELF", "",
              "Section state: " + elf["state"],
              "Debug sections: " + (", ".join(elf["debug"]) or "none detected"),
              "BTF section: " + str(elf["btf"]), "",
              "## Symbol names found", ""]
    for name, ok in report["analysisNmSymbols"].items():
        lines.append("- " + name + ": " + ("FOUND" if ok else "NOT FOUND"))
    lines += ["", "## Gate remains open", "",
              "These are source locations, not verified compiled field offsets. "
              "Check the exact effective .config, conditional definitions and "
              "matching compiler before accepting layouts. Recovered ELF symbol "
              "names are not measured live kernel addresses. No on-phone test.",
              ""]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path,
                   default=Path.home() / "src/samsung-y2q-hxl1-stock")
    p.add_argument("--artifacts", type=Path,
                   default=Path.home() / "s20-artifacts")
    p.add_argument("--output", type=Path, default=Path.home()
                   / "s20-artifacts/hxl1-research/stage3-layout-inventory.json")
    args = p.parse_args()
    source = args.source.expanduser().resolve()
    artifacts = args.artifacts.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if (output.suffix != ".json" or output == source or source in output.parents
            or output == artifacts / "kernel.bin"
            or output == artifacts / "config.gz"):
        p.error("Report must be JSON, outside original stock sources")
    try:
        result = make_inventory(source, artifacts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        output.with_suffix(".md").write_text(as_markdown(result))
    except (OSError, ValueError, InventoryError) as e:
        print("[STOP]", e, file=sys.stderr)
        return 2
    for name, entry in result["sourceDeclarations"].items():
        print("[FOUND]" if entry["definitions"] else "[NOT_FOUND]", name)
    print("[ELF]", result["analysisElf"]["state"])
    print("[report]", output)
    print("[report]", output.with_suffix(".md"))
    print("[LIMIT] Stage 3 inventory only; no verified compiled offsets/root")
    return 0


if __name__ == "__main__":
    sys.exit(main())
