#!/usr/bin/env python3
"""Execute verbatim, SHA-pinned Samsung HXL1 remove_waiter() C with mocked helpers.

No Samsung kernel binary, futex race, live device, privilege escalation or root.
An optional qemu-aarch64 USER-MODE run is not an OEM kernel guest boot.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

SOURCE_REL = "kernel/locking/rtmutex.c"
SOURCE_HASH = "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9"
FUNCTION = re.compile(r"\bstatic\s+void\s+remove_waiter\s*\(",re.M)
STUBS = r"""
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct rt_mutex;
struct task_struct;
struct rt_mutex_waiter { struct task_struct *task; struct rt_mutex *lock; };
struct task_struct { int pi_lock; struct rt_mutex_waiter *pi_blocked_on; int id; };
struct rt_mutex { int wait_lock; struct rt_mutex_waiter *top; struct task_struct *owner; int dequeued; };
static struct task_struct *test_current;
#define current test_current
#define lockdep_assert_held(...) ((void)0)
#define raw_spin_lock(...) ((void)0)
#define raw_spin_unlock(...) ((void)0)
#define raw_spin_lock_irq(...) ((void)0)
#define raw_spin_unlock_irq(...) ((void)0)
#define rt_mutex_dequeue_pi(...) ((void)0)
#define rt_mutex_enqueue_pi(...) ((void)0)
#define rt_mutex_adjust_prio(...) ((void)0)
#define rt_mutex_adjust_prio_chain(...) ((void)0)
#define get_task_struct(...) ((void)0)
#define debug_rt_mutex_print_deadlock(...) ((void)0)
#define RT_MUTEX_MIN_CHAINWALK 0
#define rt_mutex_has_waiters(...) (false)
#define task_blocked_on_lock(...) ((struct rt_mutex*)NULL)
static inline struct rt_mutex_waiter *rt_mutex_top_waiter(struct rt_mutex *l) { return l->top; }
static inline struct task_struct *rt_mutex_owner(struct rt_mutex *l) { return l->owner; }
static inline void rt_mutex_dequeue(struct rt_mutex *l, struct rt_mutex_waiter *w) {
  (void)w; l->dequeued++;
}
"""
TRAILER = r"""
static int check(int same) {
    struct task_struct running={0}, target={0};
    struct rt_mutex lock={0};
    struct rt_mutex_waiter waiter={0};
    running.id=1;target.id=2;
    waiter.task=same ? &running : &target; waiter.lock=&lock;
    lock.top=&waiter;
    lock.owner=NULL; /* bounded early return: never traverse owner PI chains */
    running.pi_blocked_on=&waiter; target.pi_blocked_on=&waiter;
    test_current=&running;
    remove_waiter(&lock,&waiter);
    printf("case=%s current_cleared=%d waiter_task_cleared=%d dequeued=%d\n",
      same?"same":"distinct",running.pi_blocked_on==NULL,
      waiter.task->pi_blocked_on==NULL,lock.dequeued);
    return !(running.pi_blocked_on==NULL && lock.dequeued==1 &&
      (same || waiter.task->pi_blocked_on==&waiter));
}
int main(void) {int a=check(1);int b=check(0);return a||b;}
"""
class OriginalSourceError(ValueError): pass

def scrub(text:str)->str:
    pat=re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',re.S)
    return pat.sub(lambda m:''.join("\n" if c=="\n" else " " for c in m.group(0)),text)

def extract_function(code:str)->str:
    masked=scrub(code)
    matches=list(FUNCTION.finditer(masked))
    if len(matches)!=1:
        raise OriginalSourceError(f"Expected one static remove_waiter definition, found {len(matches)}")
    start=matches[0].start()
    opening=masked.find("{",matches[0].end())
    if opening<0 or ";" in masked[matches[0].end():opening]:
        raise OriginalSourceError("Function body absent")
    depth=0
    for i in range(opening,len(masked)):
        if masked[i]=="{":depth+=1
        elif masked[i]=="}":
            depth-=1
            if depth==0:
                fragment=code[start:i+1]
                if not re.search(r"current\s*->\s*pi_blocked_on\s*=\s*NULL",scrub(fragment)):
                    raise OriginalSourceError("Original current-task cleanup statement missing")
                if "rt_mutex_dequeue(" not in fragment:
                    raise OriginalSourceError("Original rt_mutex_dequeue call absent")
                return fragment
    raise OriginalSourceError("Truncated function body")

def execute(code:str,cc:str,runner:str|None)->dict:
    compiler=shutil.which(cc)
    if not compiler:raise OriginalSourceError("Missing C compiler: "+cc)
    with tempfile.TemporaryDirectory(prefix="hxl1-source-fragment-") as td:
        root=Path(td);src=root/"cleanup.c";exe=root/"regression"
        src.write_text(code)
        build=[compiler,"-std=gnu11","-O0","-Wall","-Wextra",
               "-Wno-unused-variable","-Wno-unused-function",str(src),"-o",str(exe)]
        if runner:build.insert(1,"-static")
        done=subprocess.run(build,capture_output=True,text=True,timeout=90)
        if done.returncode:
            raise OriginalSourceError("Original C fragment compile failed: "+done.stderr[-2400:])
        cmd=[runner,str(exe)] if runner else [str(exe)]
        run=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
        if run.returncode or run.stderr:
            raise OriginalSourceError("Original C fragment regression failed: "+
                                      run.stderr[-800:]+" stdout="+run.stdout[-800:])
    rows=[]
    for line in run.stdout.strip().splitlines():
        m=re.fullmatch(r"case=(same|distinct) current_cleared=([01]) waiter_task_cleared=([01]) dequeued=(\d+)",line)
        if not m:raise OriginalSourceError("Unexpected C regression output: "+line[:250])
        rows.append(dict(scenario=m[1],currentCleared=m[2]=="1",
                         waiterTaskCleared=m[3]=="1",dequeued=int(m[4])))
    wanted=[
        dict(scenario="same",currentCleared=True,waiterTaskCleared=True,dequeued=1),
        dict(scenario="distinct",currentCleared=True,waiterTaskCleared=False,dequeued=1)]
    if rows!=wanted:raise OriginalSourceError("Unexpected original-source result")
    return dict(compiler=compiler,architecture="aarch64-user" if runner else "host-user",
                observations=rows)

def analyze(root:Path,arm64:bool=False)->dict:
    path=root/SOURCE_REL
    if not path.is_file() or path.is_symlink():
        raise OriginalSourceError("Original Samsung RT-mutex C file absent/unsafe")
    content=path.read_bytes()
    digest=hashlib.sha256(content).hexdigest()
    if digest!=SOURCE_HASH:raise OriginalSourceError("Original Samsung HXL1 C SHA-256 mismatch")
    fragment=extract_function(content.decode("utf8"))
    source=STUBS+"\n"+fragment+"\n"+TRAILER
    result=dict(target="SM-G986U1/G986U1UESCHXL1",
        originalSamsungSourceSha256=digest,
        originalFunctionTextSha256=hashlib.sha256(fragment.encode()).hexdigest(),
        functionVerbatimExtracted=True,sourceModified=False,
        dependenciesMocked=True,ownerChainTraversed=False,kernelObjectLinked=False,
        oemKernelGuestExecuted=False,onDeviceExecuted=False,rootOrKernelSuProven=False)
    result["nativeHost"]=execute(source,"cc",None)
    cross=shutil.which("aarch64-linux-gnu-gcc")
    emu=shutil.which("qemu-aarch64")
    if cross and emu:
        result["arm64UserMode"]=execute(source,cross,emu)
    else:
        missing=[name for name,val in (("aarch64-linux-gnu-gcc",cross),("qemu-aarch64",emu)) if not val]
        result["arm64UserMode"]=dict(status="UNAVAILABLE",missing=missing)
        if arm64:raise OriginalSourceError("AArch64 execution required but tools missing: "+", ".join(missing))
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=Path.home()/"src/samsung-y2q-hxl1-stock")
    p.add_argument("--output",type=Path,default=Path.home()/"s20-artifacts/hxl1-research/original-source-fragment-regression.json")
    p.add_argument("--require-arm64",action="store_true")
    args=p.parse_args()
    source=args.source.expanduser().resolve()
    out=args.output.expanduser().absolute()
    if out.suffix!=".json" or out.exists() or source in out.parents:
        p.error("Choose a fresh JSON report outside the Samsung source tree")
    try:
        result=analyze(source,args.require_arm64)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n")
    except (OriginalSourceError,OSError,UnicodeError,subprocess.TimeoutExpired) as exc:
        print("[STOP]",exc,file=sys.stderr);return 2
    print("[PASS] Verbatim HXL1 remove_waiter() source executed with inert dependencies")
    print("[ARM64 USER]",result["arm64UserMode"].get("status","PASS"))
    print("[REPORT]",out)
    print("[LIMIT] No original kernel binary, booted HXL1 guest, real futex, root or KernelSU")
    return 0

if __name__=="__main__":raise SystemExit(main())
