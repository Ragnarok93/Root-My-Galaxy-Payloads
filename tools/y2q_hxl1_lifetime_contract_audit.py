#!/usr/bin/env python3
"""Offline source-local lifetime audit for exact Samsung HXL1 stock evidence.

Accepts only archived source files and previously hash-checked native
disassembly. Never derives compiled stack-slot locations, runtime reuse,
privilege escalation, or a KernelSU loader.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import y2q_hxl1_static_cfg_audit as compiled

PINS = {
    'kernel/futex.c': '493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5',
    'fs/select.c': '8b73f69f3f1929a39d7d7549f96cf6fa670420e140b9d67cae8177d1fe4642f3',
}
MAX_ARCHIVE = 1024*1024
MAX_FILE = 250000

class AuditError(ValueError):
    pass

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise AuditError(reason)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def source_archive(path: Path) -> dict[str, str]:
    require(path.is_file() and not path.is_symlink() and
            0 < path.stat().st_size <= MAX_ARCHIVE,
            'Original source archive missing or oversized')
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len(PINS) and
                {m.name for m in members} == set(PINS) and
                all(m.isfile() and 0 < m.size < MAX_FILE for m in members),
                'Unsafe, duplicated or unexpected source archive member')
        output = {}
        for name, digest in PINS.items():
            raw = archive.extractfile(name).read()
            require(sha(raw) == digest, 'Original source SHA mismatch: ' + name)
            output[name] = raw.decode('utf-8')
        return output

def function_region(text: str, declaration: str) -> tuple[str, int]:
    found = list(re.finditer(declaration, text, re.M))
    require(len(found) == 1, 'Missing or ambiguous original C declaration')
    first = found[0].start()
    close = re.search(r'^}\s*$', text[found[0].end():], re.M)
    require(close is not None, 'Original function terminator unavailable')
    return (text[first:found[0].end()+close.end()],
            text.count('\n', 0, first) + 1)

def ordered(body: str, first_line: int, markers) -> list[dict]:
    output = []
    previous = -1
    for label, expr in markers:
        matches = re.finditer(expr, body, re.S)
        match = next((m for m in matches if m.start() > previous), None)
        require(match is not None, 'Missing/reordered original source marker: '+label)
        previous = match.start()
        output.append({'label': label,
                       'line': first_line + body.count('\n', 0, match.start()),
                       'observedIn': 'PINNED_C_SOURCE',
                       'factoryCompiledLocalVerified': False})
    return output

FUTEX = (
    ('waiter_declaration', r'\bstruct\s+rt_mutex_waiter\s+rt_waiter\s*;'),
    ('queue_declaration', r'\bstruct\s+futex_q\s+q\s*=\s*futex_q_init\s*;'),
    ('equal_address_guard', r'if\s*\(\s*uaddr\s*==\s*uaddr2\s*\)'),
    ('waiter_init', r'\brt_mutex_init_waiter\s*\(\s*&rt_waiter\s*\)'),
    ('waiter_address_saved', r'\bq\.rt_waiter\s*=\s*&rt_waiter\s*;'),
    ('wait_setup', r'\bfutex_wait_setup\s*\('),
    ('wait_queue', r'\bfutex_wait_queue_me\s*\('),
    ('conditional_waiter', r'if\s*\(\s*!q\.rt_waiter\s*\)'),
    ('proxy_lock', r'\brt_mutex_wait_proxy_lock\s*\('),
    ('proxy_cleanup', r'\brt_mutex_cleanup_proxy_lock\s*\('),
    ('debug_release', r'\bdebug_rt_mutex_free_waiter\s*\('),
    ('unqueue', r'\bunqueue_me_pi\s*\('),
    ('drop_queue_key', r'\bput_futex_key\s*\(\s*&q\.key\s*\)'),
    ('return', r'\breturn\s+ret\s*;'),
)
BASE_SELECT = (
    ('stack_declaration', r'\blong\s+stack_fds\s*\[\s*SELECT_STACK_ALLOC\s*/\s*sizeof\s*\(\s*long\s*\)\s*\]'),
    ('stack_selected', r'\bbits\s*=\s*stack_fds\s*;'),
    ('dynamic_fallback_condition', r'if\s*\(\s*size\s*>\s*sizeof\s*\(stack_fds\)\s*/\s*6\s*\)'),
)
END_SELECT = (
    ('select_operation', r'\bret\s*=\s*do_select\s*\('),
    ('dynamic_free_condition', r'if\s*\(\s*bits\s*!=\s*stack_fds\s*\)'),
)
TAIL_SELECT = (('return', r'\breturn\s+ret\s*;'),)

SELECT = (BASE_SELECT +
          (('native_kvmalloc', r'\bbits\s*=\s*kvmalloc\s*\('),) +
          END_SELECT +
          (('native_kvfree', r'\bkvfree\s*\(\s*bits\s*\)'),) + TAIL_SELECT)
COMPAT = (BASE_SELECT +
          (('compat_kmalloc', r'\bbits\s*=\s*kmalloc_array\s*\('),) +
          END_SELECT +
          (('compat_kfree', r'\bkfree\s*\(\s*bits\s*\)'),) + TAIL_SELECT)

def analyze_source(source: dict[str, str]) -> dict:
    futex, fline = function_region(source['kernel/futex.c'],
        r'^static\s+int\s+futex_wait_requeue_pi\s*\(')
    native, nline = function_region(source['fs/select.c'],
        r'^int\s+core_sys_select\s*\(')
    compat, cline = function_region(source['fs/select.c'],
        r'^static\s+int\s+compat_core_sys_select\s*\(')
    stages = {
        'futex_wait_requeue_pi': ordered(futex, fline, FUTEX),
        'core_sys_select': ordered(native, nline, SELECT),
        'compat_core_sys_select': ordered(compat, cline, COMPAT)
    }
    require(sum(len(a) for a in stages.values()) == 30,
            'Original source contract marker count changed')
    has_definition = re.search(r'^\s*#\s*define\s+SELECT_STACK_ALLOC\b',
                               source['fs/select.c'], re.M) is not None
    return {
        'stages': stages,
        'landmarksVerified': 30,
        'futexWaiterAndQueueSourceLocal': True,
        'waiterAddressReferencedAcrossWaitInSource': True,
        'nativeSelectStackOrKvmallocPath': True,
        'compatSelectStackOrKmallocArrayPath': True,
        'selectStackAllocationMacroDefinedInProvidedSource': has_definition,
        'numericSelectThresholdValidated': False,
        'factoryCompiledObjectSlotsVerified': False,
        'crossSyscallStackReuseVerified': False,
    }

def audit(source_path: Path, disassembly_path: Path) -> dict:
    source = analyze_source(source_archive(source_path))
    windows = compiled.read_archive(disassembly_path)
    report = compiled.analyze(windows)
    require(report['instructionsChecked'] == 4102,
            'Unexpected archived ARM64 instruction count')
    require(report['operation11Branch']['canReachBranchFromEntry'] is True,
            'Original opcode-11 code path not independently corroborated')
    return {
        'schemaVersion': 1, 'target': 'SM-G986U1/G986U1UESCHXL1',
        'evidence': {
            'sourceArchiveSha256': sha(source_path.read_bytes()),
            'disassemblyArchiveSha256': sha(disassembly_path.read_bytes()),
            'futexSourceStatus': 'EXISTING_STOCK_SHA256_PIN_MATCH',
            'selectSourceStatus': 'MATCH_TO_UPLOADED_SHA256_ONLY',
            'sourceFileDigests': PINS,
            'savedDisassemblyTextHashesVerified': True,
            'instructionSlots': report['instructionsChecked'],
            'originalKernelImageIndependentlyRehashed': False,
        },
        'sourceLifetimeContract': source,
        'compiledOperation11BranchPresent': True,
        'result': 'SOURCE_LOCAL_LIFETIME_CONTRACT_ONLY',
        'factoryCompiledLocalVariablesIdentified': False,
        'runtimeCrossSyscallStackReuseDemonstrated': False,
        'rootOrKernelSuDemonstrated': False,
        'phoneAccessed': False,
    }

def markdown(data: dict) -> str:
    lines = ['# HXL1 source-local object lifetime evidence', '',
             'Read-only analysis; original compiled stack-variable identities '
             'remain unknown.', '',
             '| Source function | Verified ordered landmarks | Compiled local identity |',
             '|---|---:|---|']
    for name, stages in data['sourceLifetimeContract']['stages'].items():
        lines.append(f'| {name} | {len(stages)} | NOT VERIFIED |')
    lines += ['', '## Supported boundaries', '',
              '- Futex source: waiter and queue are declared locally; the queue '
              'references the waiter across the source wait/cleanup sequence.',
              '- Native select source: local stack bitmap or kvmalloc/kvfree.',
              '- Compat select source: separate kmalloc_array/kfree fallback.',
              '- The SELECT_STACK_ALLOC numeric value is not certified by these files.',
              '- The five archived original-image-derived disassembly texts have '
              'matching saved hashes (4102 instructions), not a fresh independent Image digest.',
              '', '## Remains unverified', '',
              '**Status: NOT VERIFIED — source-local evidence only.**',
              '- Factory compiler local-to-stack slot mapping',
              '- Cross-syscall physical stack reuse or runtime exploitability',
              '- Physical bootloader handoff, temporary root and KernelSU', '']
    return '\n'.join(lines)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--disassembly-archive', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path)
    opts = parser.parse_args()
    try:
        result = audit(opts.source_archive, opts.disassembly_archive)
        if opts.output_dir:
            require(not opts.output_dir.exists() and not opts.output_dir.is_symlink(),
                    'Refusing to overwrite previous evidence')
            opts.output_dir.mkdir(parents=True, exist_ok=False)
            (opts.output_dir / 'lifetime-audit.json').write_text(
                json.dumps(result, indent=2) + '\n')
            (opts.output_dir / 'lifetime-audit.md').write_text(markdown(result))
        print('[SOURCE LIFETIME LANDMARKS] 30/30')
        print('[ORIGINAL DISASSEMBLY INSTRUCTIONS] 4102')
        print('[OEM COMPILED OBJECT LOCATIONS / ROOT] UNVERIFIED')
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        print('[STOP]', exc, file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
