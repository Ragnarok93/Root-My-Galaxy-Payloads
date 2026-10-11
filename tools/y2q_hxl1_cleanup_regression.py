#!/usr/bin/env python3
"""Read-only pinned HXL1 source gate + compiled USER-SPACE cleanup model.

NOT OEM kernel execution, real futex PI, an exploit, root, or KernelSU.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
if not __package__:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import y2q_rtmutex_fix_audit as stock

MOTIFS=('currentPiLock','currentBlockedOn','proxyWrapperAnyNonzeroCleanup',
        'futexProxyCall','waiterTaskAssignment','waiterEnqueue')
C=r'''
#include <stdio.h>
#include <stdbool.h>
typedef struct { int id; bool blocked; int touched; } Task;
typedef struct { Task *task; bool enqueued; } Waiter;
static void one(const char *scenario, bool same, bool enqueued, int ret, bool fixed) {
    Task current={1,true,0}, other={2,true,0};
    Waiter w={same?&current:&other,enqueued};
    bool cleanup=fixed?(ret<0 && w.enqueued && w.task):(ret!=0);
    int selected=0;
    if(cleanup){Task *p=fixed?w.task:&current;p->blocked=false;p->touched++;selected=p->id;}
    printf("%s %s %d %d %d %d %d %d\n",fixed?"fixed":"stock",scenario,
      selected,(int)current.blocked,(int)other.blocked,current.touched,other.touched,ret);
}
int main(void){for(int fixed=0;fixed<2;fixed++){
    one("same_negative",true,true,-1,fixed);
    one("different_negative",false,true,-1,fixed);
    one("different_success",false,true,0,fixed);
    one("different_positive",false,true,1,fixed);
    one("not_enqueued_negative",false,false,-1,fixed);
}return 0;}
'''
SCENARIOS=('same_negative','different_negative','different_success',
           'different_positive','not_enqueued_negative')

def verify_source(root:Path)->dict:
    if not root.is_dir():raise ValueError('Exact Samsung source directory missing')
    digests=stock.validate_original(root)
    data=stock.inspect_source(root)
    missing=[m for m in MOTIFS if not data.get(m,{}).get('found')]
    if missing:raise ValueError('Original source pattern mismatch: '+','.join(missing))
    return {'originalSourceHashes':digests,'verifiedMotifs':list(MOTIFS)}

def run_model(cc='cc')->list[dict]:
    compiler=shutil.which(cc)
    if compiler is None:raise ValueError('C compiler unavailable: '+cc)
    with tempfile.TemporaryDirectory(prefix='hxl1-isolated-owner-') as temp:
        src=Path(temp)/'model.c';exe=Path(temp)/'model'
        src.write_text(C)
        build=subprocess.run([compiler,'-std=c11','-O0','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],capture_output=True,text=True,timeout=30)
        if build.returncode:raise ValueError('Model compile failed: '+build.stderr[:400])
        result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
        if result.returncode or result.stderr:raise ValueError('Model run failed: '+result.stderr[:400])
    rows=[]
    for line in result.stdout.splitlines():
        tokens=line.split()
        if len(tokens)!=8:raise ValueError('Malformed model output')
        variant,scenario,*values=tokens
        selected,current,other,current_touches,other_touches,ret=map(int,values)
        rows.append(dict(variant=variant,scenario=scenario,touched=selected,
            currentBlocked=bool(current),waiterTaskBlocked=bool(other),
            currentTouches=current_touches,waiterTaskTouches=other_touches,ret=ret))
    verify_rows(rows)
    return rows

def verify_rows(rows:list[dict]):
    if len(rows)!=10 or len({(r['variant'],r['scenario']) for r in rows})!=10:
        raise ValueError('Unexpected scenario coverage')
    d={(r['variant'],r['scenario']):r for r in rows}
    if set(d)!={(v,s) for v in ('stock','fixed') for s in SCENARIOS}:
        raise ValueError('Missing model variant')
    original=d['stock','different_negative'];fixed=d['fixed','different_negative']
    if not (original['touched']==1 and not original['currentBlocked'] and original['waiterTaskBlocked']
            and fixed['touched']==2 and fixed['currentBlocked'] and not fixed['waiterTaskBlocked']):
        raise ValueError('Owner mismatch not demonstrated')
    for variant in ('stock','fixed'):
        if d[variant,'same_negative']['touched']!=1 or d[variant,'different_success']['touched']!=0:
            raise ValueError('Negative baseline or success-path incorrect')
    if d['stock','different_positive']['touched']!=1 or d['fixed','different_positive']['touched']!=0:
        raise ValueError('Nonzero-vs-negative gate incorrect')
    if d['fixed','not_enqueued_negative']['touched']!=0:
        raise ValueError('Never-enqueued guard incorrect')

def analyze(source:Path,cc='cc')->dict:
    verified=verify_source(source)
    rows=run_model(cc)
    return dict(target='SM-G986U1/G986U1UESCHXL1',gate='USERSPACE_SEMANTIC_MODEL_ONLY',
        pinnedSource=verified,modelCsha256=hashlib.sha256(C.encode()).hexdigest(),
        scenarios=rows,modelConditionalMismatchDemonstrated=True,
        originalSamsungKernelExecuted=False,sourceExactKernelGuestReproduced=False,
        hxl1RuntimeReachabilityProven=False,rootPrimitiveVerified=False,kernelSuInstallable=False,
        deviceModified=False)

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path.home()/'src/samsung-y2q-hxl1-stock')
    p.add_argument('--output',type=Path,default=Path.home()/'s20-artifacts/hxl1-research/cleanup-model.json')
    p.add_argument('--cc',default='cc');a=p.parse_args()
    original=a.source.expanduser().resolve();target=a.output.expanduser().absolute()
    if target.suffix!='.json' or target.exists() or original==target or original in target.parents:
        p.error('Use a fresh JSON report outside original Samsung source')
    try:
        report=analyze(original,a.cc);target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(json.dumps(report,indent=2)+'\n')
    except (OSError,ValueError,subprocess.TimeoutExpired,stock.AuditError) as exc:
        print('[STOP]',exc,file=sys.stderr);return 2
    print('[PASS] source SHA/pattern gate and 10 compiled user-space scenarios')
    print('[MODEL] mismatched waiter_task != current affects wrong task in stock branch')
    print('[REPORT]',target)
    print('[LIMIT] kernel runtime, on-device CVE, root, KernelSU NOT demonstrated')
    return 0
if __name__=='__main__':raise SystemExit(main())
