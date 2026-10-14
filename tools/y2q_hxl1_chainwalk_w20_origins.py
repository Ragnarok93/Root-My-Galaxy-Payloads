#!/usr/bin/env python3
"""Pinpoint stock HXL1 PI-chain return carrier W20 origins, without runtime claims.

Only the original rt_mutex_adjust_prio_chain function is disassembled. This
is a conservative, CFG-local origin search, not an exploit or execution test.
"""
from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import re
import shutil
import sys

ENTRY = 0xffffff8008146ca4
COPY_OFFSET = 0x7a0
COPY_WORD = '2a1403e0'
OP_BRANCH_NO_WRITE = {'b', 'br', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz',
                      'cmp', 'cmn', 'ccmp', 'ccmn', 'tst', 'prfm', 'nop',
                      'yield', 'wfe', 'wfi', 'sev', 'sevl', 'dmb', 'dsb', 'isb'}
MEMORY_STORES = {'str', 'stur', 'stp', 'stnp', 'stlr', 'sttr', 'st1', 'st2'}
STATUS_STORES = {'stxr', 'stlxr', 'stxp', 'stlxp'}
R20 = {'w20', 'x20'}
NUM = re.compile(r'^#(-?(?:0x[0-9a-f]+|\d+))$', re.I)
WRITEBACK = re.compile(r'\[\s*x20(?:\s*,[^\]]*)?\s*\]!|\[\s*x20\s*\]\s*,', re.I)

class GapError(ValueError):
    pass

def require(condition: bool, message: str):
    if not condition:
        raise GapError(message)

def operands(row):
    return [v.strip().lower() for v in row['args'].split(',')]

def assigns_w20(row):
    """Detect W20/X20 destinations; treat unknown writers as kills."""
    op, args = row['op'], row['args']
    if WRITEBACK.search(args):
        return True
    p = operands(row)
    if op in ('bl','blr') or op in OP_BRANCH_NO_WRITE or op.startswith('b.'):
        return False # X20 is AArch64 callee saved
    if op in MEMORY_STORES:
        return False
    if op in STATUS_STORES:
        return p[0] in R20
    if not p:
        return False
    if p[0] in R20:
        return True
    return op in ('ldp', 'ldnp', 'ldpsw') and len(p)>1 and p[1] in R20

def literal_definition(row):
    """Return signed low 32-bit constant only for known complete assignments."""
    op=row['op'];p=operands(row)
    if not assigns_w20(row) or len(p)!=2 or p[0] not in R20 or op not in ('mov','movz','movn'):
        return None
    m=NUM.fullmatch(p[1])
    if not m:
        return None
    try:
        number=int(m.group(1),0)
    except ValueError:
        return None
    # The original target's return value uses the low 32 bits.
    if op=='movn':
        number=~number
    n=number&0xffffffff
    return n if n<0x80000000 else n-(1<<32)

def unmodified_w20_path(rows, edges, start, target):
    if start not in rows or target not in rows:
        return None
    frontier=deque([(start,[start])]);visited=set()
    while frontier:
        pc,path=frontier.popleft()
        if pc in visited: continue
        visited.add(pc)
        if pc==target:
            return [hex(va-ENTRY) for va in path]
        if assigns_w20(rows[pc]):
            continue
        for child in edges.get(pc,()):
            if child in rows and child not in visited:
                frontier.append((child,path+[child]))
    return None

def statically_reachable(edges, start, goal):
    if start==goal:
        return True
    q=deque([start]);seen=set()
    while q:
        pc=q.popleft()
        if pc in seen:continue
        seen.add(pc)
        for next_pc in edges.get(pc,()):
            if next_pc==goal:return True
            if next_pc not in seen:q.append(next_pc)
    return False

def analyze(rows,edges):
    copy_pc=ENTRY+COPY_OFFSET
    require(copy_pc in rows and rows[copy_pc]['word']==COPY_WORD and
            rows[copy_pc]['op']=='mov' and rows[copy_pc]['args']=='w0, w20',
            'The original chainwalk W20-to-W0 return-copy fingerprint is absent')
    definitions=[]
    for pc,row in sorted(rows.items()):
        if not assigns_w20(row):
            continue
        value=literal_definition(row)
        path=unmodified_w20_path(rows,edges,pc+4,copy_pc)
        entry_reachable=statically_reachable(edges,ENTRY,pc)
        definitions.append({
            'at':row['relative'],
            'instruction':row['op']+' '+row['args'],
            'machineWord':row['word'],
            'signed32Literal':value,
            'entryStaticallyReachable':entry_reachable,
            'mayReachReturnCopyWithoutInterveningW20Write':path is not None,
            'witness':path,
            'isNegativeLiteral':value is not None and value<0,
            'isDeadlockErrorLiteral':value==-35,
            'feasibleWithOtherThreadsProven':False,
        })
    negatives=[d for d in definitions if d['isNegativeLiteral'] and d['witness'] and d['entryStaticallyReachable']]
    return {
        'schemaVersion':1,
        'target':'SM-G986U1/G986U1UESCHXL1',
        'scope':'SINGLE_STOCK_CHAINWALK_W20_RETURN_CARRIER_ORIGINS',
        'originalFunction':'rt_mutex_adjust_prio_chain',
        'originalEntry':hex(ENTRY),
        'instructionCount':len(rows),
        'returnCopyAt':hex(COPY_OFFSET),
        'returnCopy':'mov w0, w20',
        'definitions':definitions,
        'definitionsCount':len(definitions),
        'negativeLiteralOriginsWithConservativeWitness':negatives,
        'negativeLiteralOriginsCount':len(negatives),
        'deadlockLiteralOriginsCount':sum(d['isDeadlockErrorLiteral'] for d in negatives),
        'constantDefinitionCompletenessProven':False,
        'branchPredicateFeasibilityProven':False,
        'originalWaiterPublicationAndOwnerGuardJointlySatisfiableProven':False,
        'runtimeDanglingReferenceOrRootProven':False,
        'deviceModified':False,
        'qualification':'An existential static path avoiding explicit W20 writes does not prove the branch conditions are jointly satisfiable. It also cannot rule out values assembled from multiple instructions or memory without further dataflow.'
    }

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--nm',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    ns=p.parse_args(argv)
    try:
        out=ns.output.expanduser().resolve()
        require(not out.exists() and not ns.output.expanduser().is_symlink()
                and '/src/' not in str(out) and '/Root-My-Galaxy-Payloads/' not in str(out),
                'Output must be new and outside repository/source')
        from tools import y2q_hxl1_chainwalk_original_return_origins as stock
        from tools import y2q_hxl1_static_cfg_audit as graph
        stock.pinned.pin(ns.elf.expanduser(),stock.pinned.ELF_SHA,256_000_000)
        nm=stock.pinned.pin(ns.nm.expanduser(),stock.syms.ORIGINAL_NM_SHA,20_000_000)
        end,_,_=stock.bounds(nm)
        exe=shutil.which('aarch64-linux-gnu-objdump')
        require(bool(exe),'aarch64-linux-gnu-objdump not installed')
        rows=stock.original_rows(ns.elf.expanduser(),end,exe)
        edges,_,_,unknown=graph.edges_for({a:(v['op'],v['args']) for a,v in rows.items()})
        require(unknown==0,'Original compiled CFG contains unresolved edges')
        result=analyze(rows,edges)
        result['originalStockElfSha256']=stock.pinned.ELF_SHA
        result['originalRecoveredNmSha256']=stock.syms.ORIGINAL_NM_SHA
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open('x',encoding='utf-8') as file:
            json.dump(result,file,indent=2)
            file.write('\n')
        print('[W20 ORIGINAL DEFINITIONS]',result['definitionsCount'])
        print('[NEGATIVE LITERAL CANDIDATE PATHS]',result['negativeLiteralOriginsCount'])
        print('[DEADLOCK ERROR LITERAL CANDIDATE PATHS]',result['deadlockLiteralOriginsCount'])
        for d in result['negativeLiteralOriginsWithConservativeWitness']:
            print('[CANDIDATE]',d['at'],d['instruction'],d['signed32Literal'])
        print('[RUNTIME PREDICATES AND LIFETIME] UNVERIFIED')
        print('[REPORT]',out)
        return 0
    except (OSError,ValueError) as e:
        print('[STOP]',e,file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
