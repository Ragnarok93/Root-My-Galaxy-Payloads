"""Offline original HXL1 store/load shortest-path witness (static, not runtime)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import tarfile
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import y2q_hxl1_waiter_store_load_cfg as cfg

CALLS=(0x11d4,0x12a4,0x12b0,0x12e8)
BRANCHES=(0x11dc,0x1230,0x12c0,0x12d0,0x12e0)
STORES={'str','stur','stp','stnp','stxr','stlxr','stlr','sttr','st1','st2'}

def witness(rows):
    cfg.validate_sites(rows)
    path=cfg.shortest_static_path(rows,cfg.BASE+0x11d0,cfg.BASE+0x12ec)
    calls=[];branches=[];stores=[]
    for index,pc in enumerate(path):
        word,op,args=rows[pc]; rel=pc-cfg.BASE
        if op=='bl':
            calls.append({'relativeVA':hex(rel),'word':word,'directTarget':args,
                          'calleeMemoryEffectsExcluded':False})
        if op in ('cbz','cbnz','tbz','tbnz') or op.startswith('b.'):
            following=path[index+1] if index+1<len(path) else None
            cfg.need(following in cfg.successors(rows,pc), 'Invalid static branch edge')
            branches.append({'relativeVA':hex(rel),'opcode':op,
                             'selected':'fallthrough' if following==pc+4 else 'taken',
                             'predicateFeasibleProven':False})
        if op in STORES:
            stores.append({'relativeVA':hex(rel),'opcode':op,'operands':args})
    cfg.need(len(path)==31,'Original shortest path changed')
    cfg.need(tuple(int(x['relativeVA'],16) for x in calls)==CALLS,
             'Four-call witness drift')
    cfg.need(tuple(int(x['relativeVA'],16) for x in branches)==BRANCHES,
             'Five-condition witness drift')
    cfg.need(len(stores)==1 and stores[0]['relativeVA']=='0x11d0' and
             stores[0]['opcode']=='stp','Explicit store census changed')
    return {'staticInstructionCount':len(path),'offsets':[hex(x-cfg.BASE) for x in path],
            'conditionalBranches':branches,'directCalls':calls,'explicitStores':stores,
            'allConditionalPredicatesJointlyFeasibleVerified':False,
            'interproceduralMemoryAliasEffectsExcluded':False,
            'allAlternativePathsAssessed':False,
            'sourceFutexQFieldExactFactoryIdentityVerified':False,
            'pointerLifetimeAcrossWaitVerified':False,
            'crossSyscallStackReuseOrRootVerified':False,'kernelSuLoaded':False}

def run(source,disasm):
    prior=cfg.audit(source,disasm)
    return {'schemaVersion':1,'target':prior['target'],
            'scope':'ORIGINAL_DOFUTEX_SHORTEST_STATIC_STORE_LOAD_PATH_WITNESS',
            'originalSourceArchiveSha256':cfg.PIN_SOURCE,
            'originalDisassemblyArchiveSha256':cfg.PIN_DISASM,
            'priorSourceFieldMapping':prior['calleeSourceFieldQrtWaiterMapping'],
            'witness':witness(cfg.parse(disasm)),
            'interpretation':'Static branch path only; four callee effects and five predicates unproved. No waiter lifetime, alias, root or KernelSU validation.'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-archive',type=Path,required=True)
    p.add_argument('--disassembly-archive',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        out=a.output.expanduser().resolve()
        cfg.need(not a.output.expanduser().is_symlink() and not out.exists() and
                 '/src/' not in str(out), 'Output must be new and outside source')
        source=cfg.member(a.source_archive,cfg.PIN_SOURCE,'kernel/futex.c',cfg.PIN_FUTEX)
        disasm=cfg.member(a.disassembly_archive,cfg.PIN_DISASM,
                          'do_futex.disasm.txt',cfg.PIN_TEXT)
        result=run(source,disasm)
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open('x',encoding='utf-8') as stream:
            json.dump(result,stream,indent=2);stream.write('\n')
        print('[STATIC PATH STEPS]',result['witness']['staticInstructionCount'])
        print('[CONDITIONAL BRANCHES]',len(result['witness']['conditionalBranches']))
        print('[DIRECT CALLS WITH UNKNOWN EFFECTS]',len(result['witness']['directCalls']))
        print('[RUNTIME LIFETIME / ROOT] NOT VERIFIED')
        print('[REPORT]',out)
        return 0
    except (OSError,ValueError,UnicodeError,tarfile.TarError) as e:
        print('[STOP]',e,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
