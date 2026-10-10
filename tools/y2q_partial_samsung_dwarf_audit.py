#!/usr/bin/env python3
"""Inventory exact original HXL1 config/source pins and *provisional* Clang18 objects.

Read-only: no compilation, ADB, root, CVE execution or KernelSU.
No numeric offsets are derived or accepted as OEM factory ABI.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

GENERATED_SHA = "97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09"
STOCK_CONFIG_SHA = "1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd"
SOURCE_PINS = {
    "kernel/locking/rtmutex.c": "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9",
    "kernel/futex.c": "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5",
}
SELECTED = (
    "init/init_task.o", "init/main.o",
    "arch/arm64/kernel/process.o",
    "arch/arm64/kernel/fpsimd.o",
    "kernel/locking/rtmutex.o", "kernel/futex.o",
)

class AuditError(Exception):
    pass

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def pin(path: Path, expected: str) -> None:
    if not path.is_file() or sha(path) != expected:
        raise AuditError("STOP: missing or SHA256-mismatched pinned input: " + str(path))

def config_values(text: str) -> dict:
    items = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, _, value = line.partition("=")
            items[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            items[line[2:-len(" is not set")]] = "n"
    return items

def compare_config(build: Path, stock: Path) -> dict:
    a = config_values(build.read_text(errors="replace"))
    b = config_values(gzip.decompress(stock.read_bytes()).decode("utf-8"))
    both = a.keys() & b.keys()
    differing = {k: {"generated": a[k], "stock": b[k]}
                 for k in sorted(both) if a[k] != b[k]}
    return {
        "commonMatching": sum(a[k] == b[k] for k in both),
        "commonDifferences": differing,
        "generatedOnly": len(a.keys() - b.keys()),
        "stockOnly": len(b.keys() - a.keys()),
        "generatedClangConfig": a.get("CONFIG_CLANG_VERSION"),
        "stockClangConfig": b.get("CONFIG_CLANG_VERSION"),
        "compilerVersionMatches": a.get("CONFIG_CLANG_VERSION") ==
                                  b.get("CONFIG_CLANG_VERSION"),
    }

def arm64_object(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {"kind": "NOT_ELF"}
    if data[4] != 2 or data[5] != 1:
        return {"kind": "NON_ELF64_LE"}
    typ, machine = struct.unpack_from("<HH", data, 16)
    if typ != 1 or machine != 183:
        return {"kind": "NOT_ARM64_REL", "type": typ, "machine": machine}
    off = struct.unpack_from("<Q", data, 40)[0]
    size, count, nameindex = struct.unpack_from("<HHH", data, 58)
    if not off or not count:
        return {"kind": "ARM64_REL_NO_SECTIONS", "hasDwarf": False}
    if size < 64 or nameindex >= count or off + size * count > len(data):
        return {"kind": "MALFORMED_SECTIONS"}
    def shdr(i: int) -> tuple[int, int, int]:
        at = off + size * i
        return (struct.unpack_from("<I", data, at)[0],
                struct.unpack_from("<Q", data, at + 24)[0],
                struct.unpack_from("<Q", data, at + 32)[0])
    _, start, length = shdr(nameindex)
    if start + length > len(data):
        return {"kind": "MALFORMED_NAMES"}
    blob = data[start:start + length]
    names = []
    for i in range(count):
        idx, _, _ = shdr(i)
        if idx >= len(blob):
            return {"kind": "MALFORMED_NAMES"}
        end = blob.find(b"\0", idx)
        if end < 0:
            return {"kind": "MALFORMED_NAMES"}
        names.append(blob[idx:end].decode("ascii", "replace"))
    return {
        "kind": "ARM64_REL",
        "hasDwarf": ".debug_info" in names and ".debug_abbrev" in names,
        "debugSections": sorted(n for n in names if n.startswith((".debug_", ".zdebug_"))),
        "hasSymtab": ".symtab" in names,
    }

def audit(build: Path, source: Path, stock: Path) -> dict:
    pin(build / ".config", GENERATED_SHA)
    pin(stock / "config.gz", STOCK_CONFIG_SHA)
    for rel, expected in SOURCE_PINS.items():
        pin(source / rel, expected)
    objects = []
    for path in sorted(build.rglob("*.o")):
        if not path.is_file() or path.is_symlink():
            continue
        info = arm64_object(path)
        objects.append({"name": path.relative_to(build).as_posix(),
                        "sizeBytes": path.stat().st_size,
                        "sha256": sha(path), **info})
    index = {o["name"]: o for o in objects}
    return {
        "target": "SM-G986U1 G986U1UESCHXL1",
        "buildProvenance": "partial out-of-tree Samsung HXL1 Clang18 test; not OEM Clang10",
        "originalHashPinsMatched": True,
        "buildConfigSha256": GENERATED_SHA,
        "configParity": compare_config(build / ".config", stock / "config.gz"),
        "objectCount": len(objects),
        "arm64RelCount": sum(o["kind"] == "ARM64_REL" for o in objects),
        "arm64DwarfCount": sum(o["kind"] == "ARM64_REL" and o["hasDwarf"] for o in objects),
        "selected": {name: index.get(name, {"kind": "NOT_PRESENT"}) for name in SELECTED},
        "objects": objects,
        "factoryAbiVerified": False, "numericOffsetsVerified": False,
        "actualRootPayloadAvailable": False, "phoneTouched": False,
    }

def to_markdown(r: dict) -> str:
    lines = ["# Samsung HXL1 Clang18 partial object/DWARF inventory", "",
             "Comparison only. Not an OEM ABI or working root payload.", "",
             "Object files: " + str(r["objectCount"]),
             "AArch64 ET_REL objects: " + str(r["arm64RelCount"]),
             "AArch64 with DWARF: " + str(r["arm64DwarfCount"]),
             "Build config SHA256 matched: " + str(r["originalHashPinsMatched"]),
             "", "## Selected objects", "",
             "| File | Kind | DWARF |", "|---|---|---|"]
    for name, obj in r["selected"].items():
        lines.append("| " + name + " | " + obj["kind"] + " | "
                     + str(obj.get("hasDwarf", False)) + " |")
    lines += ["", "## Compiled config differences", "",
              "    " + json.dumps(r["configParity"]["commonDifferences"]),
              "", "## Limitation", "",
              "These incomplete modern-compiler build objects may contain "
              "provisional type information. Their type layouts are NOT proven "
              "equal to the factory Clang10 build or the booted kernel. "
              "Do not use their offsets in a native root target.", ""]
    return "\n".join(lines)

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, default=Path.home() / "src/samsung-y2q-hxl1-config-clang18")
    p.add_argument("--source", type=Path, default=Path.home() / "src/samsung-y2q-hxl1-stock")
    p.add_argument("--artifacts", type=Path, default=Path.home() / "s20-artifacts")
    p.add_argument("--output", type=Path, default=Path.home()
                   / "s20-artifacts/hxl1-research/samsung-clang18-dwarf-inventory.json")
    args = p.parse_args()
    build, source, stock, output = [
        x.expanduser().resolve() for x in
        (args.build, args.source, args.artifacts, args.output)]
    if output.suffix != ".json" or any(output == x or x in output.parents
                                      for x in (build, source)):
        p.error("Refuse report inside original source or compiler output")
    try:
        result = audit(build, source, stock)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        output.with_suffix(".md").write_text(to_markdown(result))
    except (OSError, ValueError, AuditError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    print("[PASS] pinned original Samsung files/config and experimental build config")
    print("[objects] total", result["objectCount"], "AArch64",
          result["arm64RelCount"], "AArch64 with DWARF", result["arm64DwarfCount"])
    for name, obj in result["selected"].items():
        print("[selected]", name, obj["kind"], "DWARF", obj.get("hasDwarf", False))
    print("[output]", output)
    print("[output]", output.with_suffix(".md"))
    print("[LIMIT] Clang18 compilation != original Clang10 stock ABI; no root")
    return 0

if __name__ == "__main__":
    sys.exit(main())
