#!/usr/bin/env python3
"""Compare generated stock Samsung kernel .config with extracted device config.gz.

Read-only; never builds kernels, modifies source, or communicates with a phone.
Reports explicit symbol comparisons, important device security/platform values,
and Kconfig-only or running-kernel-only symbols without inventing default
values for omitted symbols. Output JSON preserves all differences.
"""
import argparse
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

CONFIG_ASSIGNMENT = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
CONFIG_UNSET = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")
CRITICAL = (
    "CONFIG_ARM64", "CONFIG_ARCH_QCOM", "CONFIG_ARCH_KONA",
    "CONFIG_MODULES", "CONFIG_MODULE_SIG", "CONFIG_MODULE_SIG_FORCE",
    "CONFIG_UH_RKP", "CONFIG_KDP_CRED", "CONFIG_KDP_NS",
    "CONFIG_SECURITY_DEFEX", "CONFIG_RANDOMIZE_BASE", "CONFIG_KPROBES",
    "CONFIG_FUTEX_PI", "CONFIG_RT_MUTEXES", "CONFIG_MODVERSIONS",
)
EXPECTED_RUNNING_SHA256 = (
    "1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd"
)
EXPECTED_DEFCONFIG_SHA256 = (
    "61f109752d3c91a5167dddcb05f79707f04f09edd2d4161a384fefa6fa35b5b8"
)


def file_sha256(path):
    hash_obj = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def read_config(path):
    with path.open("rb") as file:
        prefix = file.read(2)
    if prefix == b"\x1f\x8b":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as source:
            text = source.read()
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
    config = {}
    duplicates = {}
    for line in text.splitlines():
        line = line.strip()
        defined = CONFIG_ASSIGNMENT.match(line)
        unset = CONFIG_UNSET.match(line)
        if defined:
            name, value = defined.groups()
        elif unset:
            name, value = unset.group(1), "n"
        else:
            continue
        if name in config and config[name] != value:
            duplicates[name] = {"first": config[name], "last": value}
        config[name] = value
    if not config:
        raise ValueError(f"no CONFIG_* assignments found: {path}")
    return config, duplicates


def compare(source, target, left_name, right_name):
    shared = set(source) & set(target)
    differs = [
        {"symbol": name, left_name: source[name], right_name: target[name]}
        for name in sorted(shared) if source[name] != target[name]
    ]
    return {
        "left": left_name, "right": right_name,
        "leftCount": len(source), "rightCount": len(target),
        "sharedSymbols": len(shared),
        "matchingExplicitSymbols": len(shared) - len(differs),
        "differentExplicitSymbols": len(differs),
        "different": differs,
        "leftOnly": sorted(set(source) - set(target)),
        "rightOnly": sorted(set(target) - set(source)),
    }


def run(generated, running, source_defconfig=None):
    if not generated.is_file() or not running.is_file():
        raise ValueError("generated .config or extracted running config is missing")
    live_hash = file_sha256(running)
    if live_hash != EXPECTED_RUNNING_SHA256:
        raise ValueError("running kernel config.gz does not match the captured S20+ HXL1 SHA-256")
    generated_map, generated_dups = read_config(generated)
    running_map, running_dups = read_config(running)
    out = {
        "firmware": "G986U1UESCHXL1",
        "generatedConfig": str(generated),
        "runningKernelConfig": str(running),
        "generatedSha256": file_sha256(generated),
        "runningConfigGzSha256": live_hash,
        "generatedDuplicateConflicts": generated_dups,
        "runningDuplicateConflicts": running_dups,
        "generatedVsRunning": compare(generated_map, running_map, "generated", "running"),
        "critical": {
            key: {
                "generated": generated_map.get(key),
                "running": running_map.get(key),
                "match": key in generated_map and key in running_map
                         and generated_map[key] == running_map[key],
            } for key in CRITICAL
        },
        "sourceDefconfig": None,
        "sourceVsGenerated": None,
        "notes": [
            "Only explicitly set/unset symbols are compared; omitted symbols are NOT assumed to be 'n'.",
            "A generated .config differing from the device's config.gz may reflect Kconfig defaults/compiler environment; investigate before claiming fidelity.",
            "A matching .config does not establish identical kernel code, compiler, secure boot compatibility, or flashability.",
        ],
    }
    if source_defconfig:
        if not source_defconfig.is_file() or file_sha256(source_defconfig) != EXPECTED_DEFCONFIG_SHA256:
            raise ValueError("source defconfig not found or differs from audited Samsung SHA-256")
        source_map, dup = read_config(source_defconfig)
        out["sourceDefconfig"] = {
            "path": str(source_defconfig),
            "sha256": file_sha256(source_defconfig),
            "conflictingDuplicates": dup,
        }
        out["sourceVsGenerated"] = compare(source_map, generated_map, "source", "generated")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--running-config-gz", type=Path, required=True)
    parser.add_argument("--source-defconfig", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--examples", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.examples <= 100:
        parser.error("--examples must be 1..100")
    try:
        result = run(args.generated.expanduser(), args.running_config_gz.expanduser(),
                     args.source_defconfig.expanduser() if args.source_defconfig else None)
    except (OSError, EOFError, ValueError, gzip.BadGzipFile) as exc:
        parser.error(str(exc))
    print("Firmware:", result["firmware"])
    print("Generated .config SHA-256:", result["generatedSha256"])
    a = result["generatedVsRunning"]
    print(f"Generated vs running: {a['matchingExplicitSymbols']} exact matches; "
          f"{a['differentExplicitSymbols']} differing explicit values; "
          f"{len(a['leftOnly'])} generated-only; {len(a['rightOnly'])} running-only")
    for item in a["different"][:args.examples]:
        print("  DIFFERENT:", item["symbol"],
              "generated:", item["generated"], "running:", item["running"])
    for item in a["leftOnly"][:args.examples]:
        print("  GENERATED ONLY:", item)
    for item in a["rightOnly"][:args.examples]:
        print("  RUNNING ONLY:", item)
    b = result["sourceVsGenerated"]
    if b:
        print(f"Source defconfig vs generated: {b['matchingExplicitSymbols']} exact matches; "
              f"{b['differentExplicitSymbols']} differing; "
              f"{len(b['leftOnly'])} source-only; {len(b['rightOnly'])} generated-only")
        for item in b["different"][:args.examples]:
            print("  SOURCE DIFF:", item["symbol"],
                  "source:", item["source"], "generated:", item["generated"])
    print("Critical platform/security symbols:")
    for key, value in result["critical"].items():
        print(" ", key, "generated:", value["generated"],
              "running:", value["running"], "match:", value["match"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("JSON saved:", args.json)
    print("Status: READ-ONLY CONFIG COMPARISON. NO KERNEL COMPILE OR FLASH.")


if __name__ == "__main__":
    sys.exit(main())
