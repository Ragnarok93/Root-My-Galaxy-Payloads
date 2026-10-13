#!/usr/bin/env python3
"""Hash-pinned original HXL1 function-slice inventory for futex/select stack audit.

Consumes only stock raw kernel.bin and its recovered vmlinux-stock.nm listing.
Creates bounded native AArch64 code slices and optionally disassembles them.
It DOES NOT calculate exploit placement, enable root or assert stack overlap.
No ADB, emulator, network, kernel writes, payload or phone operation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

STOCK_SHA = 'ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123'
IMAGE_VA = 0xffffff8008080000  # recovered file-relative _text, NOT live KASLR base
SYMBOLS = (
    'core_sys_select', 'do_select', 'futex_wait_requeue_pi',
    'futex_requeue', 'do_futex', 'futex_lock_pi',
)
MAX_CODE_BYTES = 16384
MAX_NM_BYTES = 16 * 1024 * 1024
OUTPUT_ROOT = Path.home() / 's20-artifacts/hxl1-research'


class GateError(ValueError):
    pass


def require(ok: bool, msg: str) -> None:
    if not ok:
        raise GateError(msg)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_nm(text: str) -> dict[str, tuple[int, str]]:
    """Read genuine nm-style 3-column lines, not arbitrary symbol strings."""
    found: dict[str, tuple[int, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        address, typ, name = parts
        if typ not in ('t', 'T') or not re.fullmatch('[0-9a-fA-F]{8,16}', address):
            continue
        if not re.fullmatch(r'[A-Za-z_.$][\w.$]*', name):
            continue
        va = int(address, 16)
        if name in found and found[name][0] != va:
            raise GateError('Conflicting text symbol definitions: ' + name)
        found[name] = (va, typ)
    return found


def image_slice(raw: bytes, start_va: int, next_va: int | None) -> tuple[bytes, dict]:
    offset = start_va - IMAGE_VA
    require(offset >= 0 and offset % 4 == 0, 'Unaligned or pre-image symbol')
    require(offset < len(raw), 'Function starts past original Image')
    if next_va is None:
        return b'', {'status': 'NO_NEXT_BOUND', 'fileOffset': offset,
                     'byteCount': 0, 'truncated': False}
    size = next_va - start_va
    require(size > 0 and size % 4 == 0, 'Nonpositive/nonaligned function bounds')
    require(size <= len(raw) - offset, 'Function extends beyond original Image')
    take = min(size, MAX_CODE_BYTES)
    return raw[offset:offset + take], {
        'status': 'BOUNDED_CODE_SLICE', 'fileOffset': offset,
        'byteCount': take, 'symbolIntervalBytes': size,
        'truncated': take < size,
    }


def collect(raw: bytes, symbols: dict[str, tuple[int, str]]) -> tuple[dict, dict[str, bytes]]:
    require(digest(raw) == STOCK_SHA, 'Original HXL1 kernel.bin SHA256 mismatch')
    require(len(raw) > 0x3c and raw[0x38:0x3c] == b'ARM\x64',
            'Not original ARM64 Linux kernel Image')
    require(symbols.get('_text', (None,))[0] == IMAGE_VA,
            'Recovered nm _text base does not match validated HXL1 origin')
    ordered = sorted(set(va for va, _ in symbols.values()
                         if IMAGE_VA <= va < IMAGE_VA + len(raw)))
    slices: dict[str, bytes] = {}
    records = []
    for name in SYMBOLS:
        entry = symbols.get(name)
        if entry is None:
            records.append({'symbol': name, 'status': 'NOT_FOUND_IN_RECOVERED_NM',
                            'compiledFunctionAbsenceProven': False})
            continue
        address, typ = entry
        next_candidates = [va for va in ordered if va > address]
        next_va = next_candidates[0] if next_candidates else None
        code, info = image_slice(raw, address, next_va)
        record = {'symbol': name, 'recoveredFileRelativeImageVA': hex(address),
                  'nmType': typ, **info,
                  'nativeBytesFromPinnedImage': bool(code),
                  'nativeCodeSha256': digest(code) if code else None,
                  'actualRuntimeAddressProven': False,
                  'crossFunctionStackGeometryEstablished': False}
        if code:
            slices[name] = code
        records.append(record)
    count = sum(bool(v) for v in slices.values())
    report = {
        'target': 'SM-G986U1/G986U1UESCHXL1',
        'originalKernelSha256Verified': True,
        'originalKernelSha256': STOCK_SHA,
        'fileRelativeRecoveredBase': hex(IMAGE_VA),
        'originalFunctionsWithBoundedCode': count,
        'requestedFunctions': len(SYMBOLS),
        'functions': records,
        'readiness': 'NATIVE_CODE_SLICES_ONLY_STACK_OVERLAP_UNPROVEN',
        'validGhostLockStackReclamationEstablished': False,
        'ptrTypeAndCallsiteFlowEstablished': False,
        'physicalKernelHandoffEstablished': False,
        'workingRootEstablished': False,
        'deviceModified': False,
        'limitations': (
            'Symbol ordering supplies upper bounds but not proven compiler function sizes. '
            'A bounded native function slice is not a Ghidra callgraph, frame-local identity, '
            'relative entry-SP proof or original stack-overlap feasibility determination.'
        )
    }
    return report, slices


def disassemble(code: bytes, va: int, outfile: Path, exe: str) -> dict:
    """GNU AArch64 objdump on a *bounded raw slice*; its stdout is research data."""
    path = outfile.with_suffix('.bin')
    path.write_bytes(code)
    result = subprocess.run(
        [exe, '-b', 'binary', '-m', 'aarch64', '-EL', '-D',
         '--adjust-vma=' + hex(va), str(path)],
        capture_output=True, text=True, timeout=15, check=False)
    if result.returncode != 0:
        return {'status': 'DISASSEMBLER_FAILED',
                'error': result.stderr[-500:]}
    outfile.write_text(result.stdout, encoding='utf-8')
    return {'status': 'DISASSEMBLED', 'file': outfile.name,
            'textSha256': digest(result.stdout.encode('utf-8'))}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path,
                   default=Path.home() / 's20-artifacts/kernel.bin')
    p.add_argument('--nm', type=Path,
                   default=OUTPUT_ROOT / 'vmlinux-stock.nm')
    p.add_argument('--out', type=Path)
    p.add_argument('--no-disassembly', action='store_true')
    args = p.parse_args()
    try:
        kernel, nm = args.kernel.expanduser().absolute(), args.nm.expanduser().absolute()
        require(kernel.is_file() and not kernel.is_symlink(), 'Original kernel.bin missing')
        require(nm.is_file() and not nm.is_symlink()
                and nm.stat().st_size <= MAX_NM_BYTES,
                'Original recovered nm file missing/oversized')
        raw = kernel.read_bytes()
        report, slices = collect(raw, parse_nm(nm.read_text(encoding='utf-8')))
        report['recoveredNmSha256'] = digest(nm.read_bytes())
        out = (args.out or OUTPUT_ROOT /
               ('ghostlock-stack-gate-' +
                datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))).absolute()
        require(not out.exists() and not out.is_symlink(),
                'Use a new output directory; original files are never overwritten')
        out.mkdir(parents=True, exist_ok=False)
        disasm_tool = None if args.no_disassembly else shutil.which('aarch64-linux-gnu-objdump')
        for row in report['functions']:
            name = row['symbol']
            code = slices.get(name)
            if not code:
                continue
            filename = out / (name + '.bin')
            filename.write_bytes(code)
            row['nativeSliceFile'] = filename.name
            if disasm_tool:
                row['disassembly'] = disassemble(
                    code, int(row['recoveredFileRelativeImageVA'], 16),
                    out / (name + '.disasm.txt'), disasm_tool)
            else:
                row['disassembly'] = {'status': 'NOT_REQUESTED_OR_TOOL_MISSING'}
        (out / 'stack-gate.json').write_text(json.dumps(report, indent=2) + '\n')
        summary = [
            '# Original HXL1 futex/select code inventory', '',
            '**Authenticated source-code windows; exploit stack geometry unproven.**', '',
            f"Bounded original code: {report['originalFunctionsWithBoundedCode']}"
            f"/{report['requestedFunctions']}", '',
            '| Symbol | Status | Native bytes | Disassembly |',
            '| --- | --- | ---: | --- |'
        ]
        for item in report['functions']:
            summary.append('| {} | {} | {} | {} |'.format(
                item['symbol'], item['status'], item.get('byteCount', 0),
                item.get('disassembly', {}).get('status', 'UNAVAILABLE')))
        summary += ['', 'A saved disassembly is not proof of relative stack frame '
                    'layout across futex and select call sites. No exploit '
                    'or KernelSU path was executed.', '']
        (out / 'stack-gate.md').write_text('\n'.join(summary), encoding='utf-8')
        print('[PINNED STOCK KERNEL] YES')
        print('[BOUNDED ORIGINAL FUNCTION SLICES]',
              str(report['originalFunctionsWithBoundedCode']) + '/' +
              str(report['requestedFunctions']))
        print('[GHOSTLOCK STACK OVERLAP PROVEN] NO')
        print('[ROOT VERIFIED] NO')
        print('[REPORT]', out / 'stack-gate.md')
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print('[STOP]', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
