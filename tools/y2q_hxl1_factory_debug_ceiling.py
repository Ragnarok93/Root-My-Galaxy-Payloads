#!/usr/bin/env python3
"""Audit provenance and limits of HXL1 factory compiler-debug evidence.

Read-only: no ADB, exploit, patch, firmware write or inferred stack offsets.
Inputs are archived owner reports, NOT raw factory debug-symbol files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

CONFIG_SHA = 'ec6da4cfe412f7d0669c7d621751753375e32197a2602f98627eb95e71b9c0b2'
ARTIFACTS = ('stock-sections.txt', 'qemu-lab-sections.txt',
             'qemu-lab-kasan-sections.txt', 'stock-task_struct-errors.txt',
             'stock-rt_mutex_waiter-errors.txt')
FLAGS = ('CONFIG_CC_IS_CLANG', 'CONFIG_CLANG_VERSION', 'CONFIG_LTO_NONE',
         'CONFIG_DEBUG_INFO', 'CONFIG_FRAME_POINTER',
         'CONFIG_STACKPROTECTOR_STRONG', 'CONFIG_MODULE_SIG_FORCE',
         'CONFIG_KPROBES')
MAX_FILE = 100000

class AuditError(ValueError):
    pass

def must(ok: bool, why: str) -> None:
    if not ok:
        raise AuditError(why)

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_config(raw: bytes) -> dict[str, str]:
    must(digest(raw) == CONFIG_SHA, 'Stock config SHA256 mismatch')
    text = raw.decode('utf-8')
    found = {}
    for flag in FLAGS:
        rows = []
        for line in text.splitlines():
            if line.startswith(flag + '='):
                rows.append(line.partition('=')[2])
            elif line == '# ' + flag + ' is not set':
                rows.append('n')
        must(len(rows) == 1, 'Missing or ambiguous original config: ' + flag)
        found[flag] = rows[0]
    expected = {'CONFIG_CC_IS_CLANG': 'y', 'CONFIG_CLANG_VERSION': '100006',
                'CONFIG_LTO_NONE': 'y', 'CONFIG_DEBUG_INFO': 'y',
                'CONFIG_FRAME_POINTER': 'y', 'CONFIG_STACKPROTECTOR_STRONG': 'y',
                'CONFIG_MODULE_SIG_FORCE': 'y', 'CONFIG_KPROBES': 'n'}
    must(all(found[k] == value for k, value in expected.items()),
         'Stock compiler/security config does not match prior HXL1 identity')
    return found

def read_reports(archive: Path) -> tuple[dict[str, bytes], str]:
    must(archive.is_file() and not archive.is_symlink()
         and 0 < archive.stat().st_size < 1000000, 'Archive missing/unsafe/oversized')
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        names = [x.name.removeprefix('./') for x in members if x.isfile()]
        must(len(names) == len(set(names)), 'Duplicate report member')
        must(all(x.isfile() or (x.isdir() and x.name in ('.', './'))
                 for x in members), 'Unexpected symlink or non-regular archive member')
        must(all(x.size <= MAX_FILE for x in members), 'Report member too large')
        must(set(ARTIFACTS).issubset(names), 'Missing required compiler provenance reports')
        return ({name.name.removeprefix('./'): tar.extractfile(name).read()
                 for name in members if name.isfile()}, digest(archive.read_bytes()))

def sections(raw: bytes) -> set[str]:
    # readelf -SW table generated for each reconstructed ELF.
    names = set(re.findall(r'^\s*\[\s*\d+\]\s+(\.[^\s]+)\s+',
                           raw.decode('utf-8'), re.M))
    must(bool(names), 'ELF section inventory missing or malformed')
    return names

def audit(config_path: Path, reports_path: Path) -> dict:
    config = config_path.read_bytes()
    flags = parse_config(config)
    records, archive_hash = read_reports(reports_path)
    stock = sections(records['stock-sections.txt'])
    normal = sections(records['qemu-lab-sections.txt'])
    kasan = sections(records['qemu-lab-kasan-sections.txt'])
    must('.symtab' in stock, 'Reconstructed stock ELF has no symbol table')
    must('.debug_info' not in stock and '.BTF' not in stock,
         'Stock debug-section availability changed; reassess instead of reusing prior ceiling')
    must('.debug_info' in normal and '.debug_info' in kasan,
         'Comparison ELF debug section was not found')
    for name in ARTIFACTS[3:]:
        error = records[name].decode('utf-8').lower()
        must('failed to find' in error and '.btf' in error and 'invalid argument' in error,
             'Stock pahole error changed: ' + name)
    return {
        'target': 'SM-G986U1/G986U1UESCHXL1',
        'scope': 'RECONSTRUCTED_ELF_DEBUG_METADATA_AVAILABILITY',
        'ownerStockConfigSha256': digest(config),
        'ownerDwarfReportArchiveSha256': archive_hash,
        'config': flags,
        'stockReconstructedElf': {'hasSymtab': True, 'hasDebugInfo': False,
                                  'hasBTF': False, 'paholeStockStructRecovery': False,
                                  'originalUnstrippedOEMVmlinuxAvailableInSuppliedEvidence': False},
        'qemuNormalComparison': {'hasDebugInfo': True, 'factoryEquivalent': False},
        'qemuKasanComparison': {'hasDebugInfo': True, 'factoryEquivalent': False},
        'debugInfoConfiguredButAbsentFromReconstructedElf': True,
        'linkTimeOptimizationConfiguredNone': True,
        'recoveredNmProvidesFactoryCVariableLocationLists': False,
        'compilerLocalIdentityProven': False,
        'workingGhostLockOrKernelSu': False,
        'limits': ('Config flags and readelf/pahole listings are original owner reports. '
                   'Reconstructed ELF section absence does not prove the original OEM '
                   'build never had DWARF. QEMU DWARF cannot certify OEM stack locals.'),
    }

def main() -> int:
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--dwarf-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    a = parser.parse_args()
    try:
        result = audit(a.config, a.dwarf_archive)
        if a.output:
            must(not a.output.exists() and not a.output.is_symlink(),
                 'Refusing to overwrite prior evidence')
            a.output.write_text(json.dumps(result, indent=2) + '\n')
        print('[STOCK CLANG] 10.0.6  [LTO] NONE  [DEBUG CONFIG] YES')
        print('[RECONSTRUCTED STOCK ELF .debug_info/BTF] ABSENT')
        print('[QEMU DWARF FACTORY-EQUIVALENT] NO')
        print('[OEM COMPILER LOCAL ATTRIBUTION] UNVERIFIED')
        return 0
    except (OSError, ValueError, tarfile.TarError, UnicodeError) as exc:
        print('[STOP]', exc, file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
