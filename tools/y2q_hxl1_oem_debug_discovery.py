#!/usr/bin/env python3
"""Read-only bounded inventory for OEM HXL1 debug-artifact candidates.

File-name and ELF-section discovery is not OEM provenance. No ADB, device access,
exploit execution, flashing, module loading, or source-code modification.
"""
from __future__ import annotations
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

STOCK_CONFIG_SHA = 'ec6da4cfe412f7d0669c7d621751753375e32197a2602f98627eb95e71b9c0b2'
EXPECTED = {'CONFIG_DEBUG_INFO': 'y', 'CONFIG_DEBUG_INFO_SPLIT': 'n',
            'CONFIG_LTO_NONE': 'y', 'CONFIG_CLANG_VERSION': '100006'}
SKIP_DIRS = {'.git', '.gradle', 'node_modules', '.cache', '__pycache__'}
DEBUG_SECTIONS = {'.debug_info', '.zdebug_info', '.debug_info.dwo', '.BTF'}
DEBUG_LINKS = {'.gnu_debuglink', '.gnu_debugaltlink'}
MAX_CANDIDATES = 1500
MAX_ENTRIES = 40000
MAX_FILE = 2_000_000_000

class DiscoveryError(ValueError):
    pass

def require(ok, msg):
    if not ok: raise DiscoveryError(msg)

def likely_candidate(name: str) -> bool:
    """Filter out kernel source/linker scripts mistaken for DWARF files."""
    lower = name.lower()
    if (lower in {'kconfig.debug', 'vmlinux.lds', 'vmlinux.lds.s',
                  'system.map', 'kallsyms'} or
        lower.endswith(('.lds', '.lds.s', '.debug.c', '.debug.h'))):
        return False
    return (lower == 'vmlinux' or lower.startswith('vmlinux.') or
            lower.startswith('stock-vmlinux') or
            lower.endswith(('.dwo', '.dwp', '.debug', '.sym', '.symbols', '.elf')))


def config_flags(raw: bytes) -> dict:
    require(hashlib.sha256(raw).hexdigest() == STOCK_CONFIG_SHA, 'Stock HXL1 config hash mismatch')
    text = raw.decode('utf-8')
    result = {}
    for key, expected in EXPECTED.items():
        vals = re.findall(r'(?m)^' + re.escape(key) + r'=([^\n]+)$', text)
        if not vals and re.search(r'(?m)^# ' + re.escape(key) + r' is not set$', text): vals = ['n']
        require(len(vals) == 1 and vals[0] == expected, 'Stock config flag disagreement: ' + key)
        result[key] = vals[0]
    return result

def inspect_elf(path: Path) -> dict:
    """Read ELF64 LE section names, not whole file; fail closed on odd layouts."""
    info = {'isElf': False, 'elfMachine': None, 'sections': [],
            'debugSections': [], 'debugLinks': [], 'gnuBuildIdNoteSection': False}
    size = path.stat().st_size
    with path.open('rb') as f:
        ehdr = f.read(64)
        if len(ehdr) < 64 or ehdr[:4] != b'\x7fELF': return info
        info['isElf'] = True
        if ehdr[4] != 2 or ehdr[5] != 1:
            info['unsupportedElfLayout'] = True
            return info
        machine = struct.unpack_from('<H', ehdr, 18)[0]
        info['elfMachine'] = machine
        shoff = struct.unpack_from('<Q', ehdr, 40)[0]
        shentsize, shnum, stridx = struct.unpack_from('<HHH', ehdr, 58)
        if (shnum == 0 or shentsize < 64 or shnum > 20000 or stridx >= shnum or
                shoff + shentsize * shnum > size or shentsize * shnum > 5_000_000):
            info['sectionHeadersUsable'] = False
            return info
        f.seek(shoff)
        table = f.read(shentsize * shnum)
        def head(i):
            off = i * shentsize
            return struct.unpack_from('<IIQQQQIIQQ', table, off)
        names_header = head(stridx)
        str_off, str_len = names_header[4:6]
        if str_len > 5_000_000 or str_off + str_len > size:
            info['sectionHeadersUsable'] = False
            return info
        f.seek(str_off)
        string_table = f.read(str_len)
        sections = []
        for i in range(shnum):
            h = head(i)
            pos = h[0]
            if pos >= len(string_table): continue
            end = string_table.find(b'\x00', pos)
            if end < 0: continue
            name = string_table[pos:end].decode('ascii', 'replace')
            if name:
                sections.append((name, h[4], h[5]))
        info['sectionHeadersUsable'] = True
        info['sections'] = [name for name, _, _ in sections if name.startswith('.debug') or
                            name.startswith('.zdebug') or name.startswith('.gnu_debug') or
                            name in ('.BTF','.symtab','.note.gnu.build-id')]
        info['debugSections'] = [name for name, _, _ in sections if name in DEBUG_SECTIONS]
        info['gnuBuildIdNoteSection'] = any(name == '.note.gnu.build-id' for name, _, _ in sections)
        for name, offset, length in sections:
            if name not in DEBUG_LINKS or length > 2048 or offset + length > size: continue
            f.seek(offset)
            content = f.read(length)
            link_name = content.split(b'\x00',1)[0].decode('utf-8','replace')
            info['debugLinks'].append({'section': name,'name':link_name})
    return info

def classify(path: Path, elf: dict) -> str:
    parts = [s.lower() for s in path.parts]
    if any('qemu' in p or 'kasan' in p or 'clang10-abi-comparison' in p for p in parts):
        return 'COMPARISON_BUILD_NOT_FACTORY'
    if any('stock-vmlinux' in p or 'vmlinux-stock' in p for p in parts):
        return 'STOCK_RECONSTRUCTED_NOT_ORIGINAL_DEBUG_ELF'
    if elf['elfMachine'] != 183:
        return 'NON_AARCH64_OR_NON_ELF_CANDIDATE'
    if elf.get('sectionHeadersUsable') is not True:
        return 'UNREADABLE_ELF_SECTION_TABLE_INDETERMINATE'
    if elf['debugSections']:
        return 'DEBUG_BEARING_CANDIDATE_REQUIRES_OEM_PROVENANCE'
    if elf['debugLinks'] or elf['gnuBuildIdNoteSection']:
        return 'METADATA_ONLY_CANDIDATE_REQUIRES_OEM_PROVENANCE'
    return 'NO_DEBUG_METADATA_IN_CANDIDATE'

def inventory(roots: list[Path], max_depth: int = 7,
              max_entries: int = MAX_ENTRIES) -> dict:
    """Breadth-first, multi-root fair scan with explicit incomplete-coverage flags.

    Previously os.walk exhausted the file budget in an alphabetically first
    Linux source directory before visiting sibling working trees. The queue
    now visits shallower directories across all roots before their subtrees.
    """
    require(0 <= max_depth <= 14, 'Depth must be between 0 and 14')
    require(1 <= max_entries <= 2_000_000, 'Invalid file scanning bound')
    unique = []
    for root in roots:
        require(root.is_dir() and not root.is_symlink(),
                'Missing/unsafe scan root: ' + str(root))
        if root not in unique:
            unique.append(root)
    queue = deque((r, r, 0) for r in unique)
    records, errors = [], []
    files_seen = nonelf = directories = depth_limited = 0
    skipped = 0
    truncated = False
    root_counters = {str(r): {'filesExamined': 0, 'candidateFiles': 0,
                              'directoriesVisited': 0} for r in unique}
    while queue:
        root, directory, depth = queue.popleft()
        try:
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda e: e.name)
        except OSError as exc:
            errors.append({'directory': str(directory),
                           'errorType': type(exc).__name__})
            continue
        directories += 1
        root_counters[str(root)]['directoriesVisited'] += 1
        children = []
        for entry in entries:
            if entry.is_symlink():
                skipped += 1
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIP_DIRS:
                        skipped += 1
                    elif depth < max_depth:
                        children.append((root, Path(entry.path), depth + 1))
                    else:
                        depth_limited += 1
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError as exc:
                errors.append({'path': entry.path,
                               'errorType': type(exc).__name__})
                continue
            if files_seen >= max_entries:
                truncated = True
                break
            files_seen += 1
            root_counters[str(root)]['filesExamined'] += 1
            if not likely_candidate(entry.name):
                continue
            path = Path(entry.path)
            try:
                size = entry.stat(follow_symlinks=False).st_size
                if not (64 <= size <= MAX_FILE):
                    continue
                elf = inspect_elf(path)
            except OSError as exc:
                errors.append({'path': str(path),
                               'errorType': type(exc).__name__})
                continue
            if not elf['isElf']:
                nonelf += 1
                continue
            if len(records) >= MAX_CANDIDATES:
                truncated = True
                break
            records.append({'path': str(path), 'sizeBytes': size,
                            'classification': classify(path, elf), **elf})
            root_counters[str(root)]['candidateFiles'] += 1
        queue.extend(children)
        if truncated:
            break
    summary = {}
    for row in records:
        kind = row['classification']
        summary[kind] = summary.get(kind, 0) + 1
    return {
        'scanStrategy': 'BREADTH_FIRST_ALL_ROOTS',
        'scanRoots': [str(r) for r in unique],
        'filesExamined': files_seen,
        'directoriesVisited': directories,
        'candidateFiles': len(records),
        'filenameMatchedButNonElf': nonelf,
        'skippedSymlinksOrIgnoredDirectoryEntries': skipped,
        'depthLimitedDirectoryCount': depth_limited,
        'maxDepth': max_depth,
        'maxEntries': max_entries,
        'truncated': truncated,
        'pendingDirectoryCountAtTruncation': len(queue) if truncated else 0,
        'pendingDirectoryExamplesAtTruncation':
            [str(item[1]) for item in list(queue)[:12]] if truncated else [],
        'errors': errors[:30],
        'errorCount': len(errors),
        'scopeCompleteAtRequestedDepth': not truncated and not errors,
        'rootCoverage': root_counters,
        'classificationCounts': summary, 'candidates': records,
        'oemSymbolsAuthenticated': False,
        'note': ('Discovery only; no debug-section or build-id match is proof '
                 'of OEM origin. Sections cannot be ruled out for ELF files '
                 'with unreadable section tables. Any truncated scan or '
                 'unvisited deeper directories leaves coverage incomplete.')
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, action='append', required=True)
    ap.add_argument('--stock-config', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--max-depth',type=int,default=7)
    ap.add_argument('--max-entries',type=int,default=180000)
    args = ap.parse_args()
    try:
        require(0 <= args.max_depth <= 14, 'Depth must be between 0 and 14')
        result = inventory(args.root,args.max_depth,args.max_entries)
        if args.stock_config:
            require(args.stock_config.is_file() and not args.stock_config.is_symlink(), 'Original config missing/unsafe')
            result['stockConfigVerification'] = config_flags(args.stock_config.read_bytes())
            result['splitDwarfExpectedFromStockConfig'] = False
        require(not args.output.exists() and not args.output.is_symlink(), 'Report exists; refuse overwrite')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2)+'\n',encoding='utf-8')
        print('[FILES CHECKED]',result['filesExamined'],'[CANDIDATES]', result['candidateFiles'])
        print('[TRUNCATED]', result['truncated'],
              '[PENDING DIRECTORIES]', result['pendingDirectoryCountAtTruncation'],
              '[FACTORY DEBUG AUTHENTICATED] NO')
        for key,value in result['classificationCounts'].items():
            print('[CLASS]', key,value)
        print('[REPORT]',args.output)
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        print('[STOP]',error,file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
