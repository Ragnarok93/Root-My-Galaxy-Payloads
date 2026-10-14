#!/usr/bin/env python3
"""Original HXL1 read-only waiter argument-site/source landmark crosscheck.

No runtime address, control-flow path feasibility, aliasing, exploit or root proof.
Reads ONLY SHA-pinned user-provided stock source and disassembly archives.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

TARGET = 'SM-G986U1/G986U1UESCHXL1'
PINS = {
    'source_archive': 'deac172780286aeca1d3b1d9ab7f036e84532a6d087cc89721fd5cc7d16fe1a3',
    'disasm_archive': '20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997',
    'futex_source': '493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5',
    'do_futex_disasm': '56286516ae9e6a873beab22b16af3ab330a768dc1b02f901854eb96f193789a5',
    'original_nm': 'c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f',
}
BASE=0xffffff800818e52c
# Function labels from earlier owner recovered-NM report; when --nm is absent
# labels are previous reports, not independently reauthenticated by this tool.
SITES=(
    {'role':'initialize','argumentRegister':'x0','argOffset':0x1190,'callOffset':0x1198,
     'callee':'rt_mutex_init_waiter','calleeStaticVA':0xffffff80081474fc,
     'expected':((0x1190,'910303e0','add','x0, sp, #0xc0'),
                 (0x1194,'910303f9','add','x25, sp, #0xc0'),
                 (0x1198,'97fedf8e','bl','0xffffff80081474fc'))},
    {'role':'proxy_wait','argumentRegister':'x2','argOffset':0x12fc,'callOffset':0x1308,
     'callee':'rt_mutex_wait_proxy_lock','calleeStaticVA':0xffffff8008148024,
     'expected':((0x12fc,'910303e2','add','x2, sp, #0xc0'),
                 (0x1300,'aa1303e0','mov','x0, x19'),
                 (0x1304,'aa1403e1','mov','x1, x20'),
                 (0x1308,'97fee1fc','bl','0xffffff8008148024'))},
    {'role':'proxy_cleanup','argumentRegister':'x1','argOffset':0x1320,'callOffset':0x1328,
     'callee':'rt_mutex_cleanup_proxy_lock','calleeStaticVA':0xffffff80081480b4,
     'expected':((0x1320,'910303e1','add','x1, sp, #0xc0'),
                 (0x1324,'aa1303e0','mov','x0, x19'),
                 (0x1328,'97fee218','bl','0xffffff80081480b4'))},
)
LANDMARKS=(
 ('declaration',r'\bstruct\s+rt_mutex_waiter\s+rt_waiter\s*;'),
 ('stack_comment',r'The waiter is allocated on our stack, manipulated by the requeue'),
 ('initializer',r'\brt_mutex_init_waiter\s*\(\s*&rt_waiter\s*\)\s*;'),
 ('queue_pointer',r'\bq\.rt_waiter\s*=\s*&rt_waiter\s*;'),
 ('wait_setup',r'\bfutex_wait_setup\s*\('),
 ('queue_wait',r'\bfutex_wait_queue_me\s*\('),
 ('queue_field_check',r'\bif\s*\(\s*!q\.rt_waiter\s*\)'),
 ('proxy_wait',r'\brt_mutex_wait_proxy_lock\s*\(\s*pi_mutex\s*,\s*to\s*,\s*&rt_waiter\s*\)'),
 ('conditional_cleanup',r'\bif\s*\(\s*ret\s*&&\s*!rt_mutex_cleanup_proxy_lock\s*\(\s*pi_mutex\s*,\s*&rt_waiter\s*\)\s*\)'),
 ('debug_release',r'\bdebug_rt_mutex_free_waiter\s*\(\s*&rt_waiter\s*\)'),
 ('unqueue',r'\bunqueue_me_pi\s*\(\s*&q\s*\)'),
 ('return',r'\breturn\s+ret\s*;'),
)
DISASM_LINE=re.compile(r'^([0-9a-fA-F]{16}):[ \t]+([0-9a-fA-F]{8})[ \t]+([^ \t\r\n]+)(?:[ \t]+([^\r\n]*))?$',re.M)
NM_LINE=re.compile(r'^([0-9a-fA-F]{16})\s+[tT]\s+(\S+)\s*$',re.M)
class AuditError(ValueError): pass

def check(test,why):
    if not test:raise AuditError(why)

def digest(raw):return hashlib.sha256(raw).hexdigest()

def file_bytes(path:Path,limit=4_000_000):
    check(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<limit,
          'Missing or unsafe evidence file: '+str(path))
    return path.read_bytes()

def tar_part(archive:Path,expectedArchiveSha:str,member:str,expectedPartSha:str):
    raw=file_bytes(archive)
    check(digest(raw)==expectedArchiveSha,'Source archive SHA mismatch: '+str(archive))
    with tarfile.open(archive,mode='r:gz') as tf:
        names=tf.getmembers()
        check(len(names)<=8 and all(x.isfile() and 0<x.size<300000 for x in names),
              'Unsafe archive members')
        items=[x for x in names if x.name==member]
        check(len(items)==1,'Expected unique archive member '+member)
        part=tf.extractfile(items[0]).read()
        check(digest(part)==expectedPartSha,'Original member SHA mismatch '+member)
        return part

def parse_original_instructions(raw:bytes):
    rows={}
    for match in DISASM_LINE.finditer(raw.decode('utf-8','strict')):
        addr=int(match.group(1),16)
        check(addr not in rows,'Duplicate instruction location')
        rows[addr]=(match.group(2).lower(),match.group(3).lower(),
                    (match.group(4) or '').split('//',1)[0].strip())
    check(len(rows)==1766,'Original do_futex instruction count drift')
    check(all(BASE+4*i in rows for i in range(len(rows))),
          'Noncontiguous do_futex instruction inventory')
    return rows

def compiled_argument_ledger(rows):
    out=[]
    for entry in SITES:
        for offset,word,mnemonic,args in entry['expected']:
            check(rows.get(BASE+offset)==(word,mnemonic,args),
                  'Original instruction/register provenance drift: '+
                  entry['role']+' '+hex(offset))
        out.append({
            'role':entry['role'],'caller':'do_futex',
            'argumentRegister':entry['argumentRegister'],
            'argumentCreationRelativeVA':hex(entry['argOffset']),
            'calleeCallRelativeVA':hex(entry['callOffset']),
            'calleeStaticVA':hex(entry['calleeStaticVA']),
            'calleeRecoveredLabelFromPriorOwnerNm':entry['callee'],
            'literalArgumentExpression':'sp + 0xc0',
            'consecutiveInstructionWordsMatched':len(entry['expected']),
            'straightLineArgumentConstructionVerified':True,
            'stackPointerEqualityAcrossDistinctCallPathsProven':False,
            'effectiveRuntimeInvocationVerified':False,
        })
    return out

# A code-text SP census is not compiler C-local DWARF or runtime observation.
# Fail closed if this particular original HXL1 function acquires another SP
# adjustment, unexpected SP mnemonic, or an SP memory writeback form.
SP_OPERAND=re.compile(r"(?<![A-Za-z0-9_])sp(?![A-Za-z0-9_])",re.I)
SP_WRITEBACK=re.compile(r"\[sp(?:,\s*[^\]]+)?\]!|\[sp\],",re.I)
SP_KNOWN_OPCODES={"add","sub","ldr","str","stp","ldp"}
ORIGINAL_FRAME_BYTES=0x1e0
EXPECTED_SP_WRITES={
    0x0:("d10783ff","sub","sp, sp, #0x1e0"),
    0xb78:("910783ff","add","sp, sp, #0x1e0"),
}

def compiled_sp_integrity(rows:dict)->dict:
    """Check every emitted SP use, not just the three chosen waiter sites."""
    ref=[]
    writes=[]
    unknown=[]
    writebacks=[]
    for va,(word,op,args) in sorted(rows.items()):
        if not SP_OPERAND.search(args):
            continue
        offset=va-BASE
        ref.append(offset)
        if op not in SP_KNOWN_OPCODES:
            unknown.append((offset,op,args))
        if SP_WRITEBACK.search(args):
            writebacks.append((offset,op,args))
        # For these ARM64 instructions, destination is their first operand.
        # Non-add/sub first-operand SP is unexpected and must also fail.
        first=args.split(",",1)[0].strip().lower()
        if first=="sp":
            writes.append((offset,word,op,args))
    check(not unknown and not writebacks,
          "Unexpected SP instruction form or implicit memory writeback")
    observed={off:(word,op,args) for off,word,op,args in writes}
    check(len(writes)==len(observed)==2 and observed==EXPECTED_SP_WRITES,
          "Original do_futex SP-write instruction inventory drift")
    check(len(ref)==158,"Original do_futex SP reference count drift")
    check(rows.get(BASE+0xb7c)==("d65f03c0","ret",""),
          "Original SP-restoration epilogue is not immediately followed by ret")
    check(all(BASE+site["argOffset"] in rows and
              site["argOffset"] not in observed
              for site in SITES),
          "Unexpected compiled waiter address construction position")
    return {
       "status":"BOUNDED_ORIGINAL_DOFUTEX_SP_WRITE_INVENTORY_VERIFIED",
       "originalFunctionInstructionSlots":len(rows),
       "observedInstructionsReferencingSp":len(ref),
       "observedSpWrites":2,
       "observedSpWriteOffsets":[hex(x) for x in sorted(observed)],
       "entryAdjustment":"sub sp, sp, #0x1e0",
       "epilogueAdjustment":"add sp, sp, #0x1e0",
       "epilogueImmediateReturn":True,
       "writebackMemoryInstructionsTouchingSp":0,
       "unexpectedSpInstructionForms":0,
       "frameAllocationBytes":ORIGINAL_FRAME_BYTES,
       "waiterLiteralStackAddressOffsetBytes":0xc0,
       "waiterLiteralOffsetWithinFrame":True,
       "frameBaseSpHasNoOtherSyntacticWrites":True,
       "normalCallingConventionSpPreservationAssumed":True,
       "allPathCallSequenceAndObjectLifetimeProven":False,
       "compilerCSourceWaiterFieldLayoutCertified":False,
       "runtimeWaiterToSendmsgFrameOverlapProven":False,
    }

X25_USE=re.compile(r"(?<![A-Za-z0-9_])[wx]25(?![A-Za-z0-9_])",re.I)

def compiled_conditional_waiter_pointer_store(rows:dict)->dict:
    """Track a callee-preserved stack-derived register to a conditional store.

    Does not identify which C variable or struct field receives the pointer.
    """
    required={
      0x1194:("910303f9","add","x25, sp, #0xc0"),
      0x1198:("97fedf8e","bl","0xffffff80081474fc"),
      0x11b0:("94000e84","bl","0xffffff80081930ec"),
      0x11b4:("35004ac0","cbnz","w0, 0xffffff8008190038"),
      0x11d0:("a90a6ff9","stp","x25, x27, [sp, #160]"),
    }
    check(all(rows.get(BASE+offset)==expected for offset,expected in required.items()),
          "Original conditional waiter pointer store provenance drift")
    for offset in range(0x1198,0x11d0,4):
        check(BASE+offset in rows,"Incomplete original waiter pointer register interval")
        check(not X25_USE.search(rows[BASE+offset][2]),
              "Intervening original x25/w25 register use requires review")
    return {
      "status":"BOUNDED_ORIGINAL_X25_TO_STACK_STORE_VERIFIED",
      "sourcePointerCreationRelativeOffset":"0x1194",
      "sourcePointerExpression":"sp + 0xc0",
      "calleeSavedRegister":"x25",
      "normalAarch64AbiCalleePreservationAssumed":True,
      "callsitesCrossedBeforeStore":["0x1198","0x11b0"],
      "conditionalBranchRelativeOffset":"0x11b4",
      "branchWhenW0NonzeroSkipsThisStore":True,
      "fallThroughWhenW0ZeroToStore":True,
      "storeRelativeOffset":"0x11d0",
      "storeInstruction":"stp x25, x27, [sp, #160]",
      "firstStoredValue":"x25, presumed sp + 0xc0 under ABI",
      "firstStoredValueStackOffset":"sp + 0xa0",
      "secondStoredValueStackOffset":"sp + 0xa8",
      "interveningSyntacticX25Writes":0,
      "originalCompilerSourceLocalFieldIdentified":False,
      "queuePointerFieldProven":False,
      "conditionalBlockingOrWaiterLifetimeProven":False,
      "crossSyscallStackReuseProven":False,
    }

def source_markers(raw:bytes):
    text=raw.decode('utf-8','strict')
    start=text.find('static int futex_wait_requeue_pi(')
    finish=text.find('\n}',start)
    check(start>=0 and finish>start,'Cannot isolate original futex_wait_requeue_pi source')
    subsection=text[start:finish+2]
    marks=[]
    previous=-1
    for role,expression in LANDMARKS:
        matches=list(re.finditer(expression,subsection,re.S))
        check(len(matches)==1 and matches[0].start()>previous,
              'Missing/reordered source waiter lifetime marker: '+role)
        previous=matches[0].start()
        ln=text[:start+previous].count('\n')+1
        marks.append({'role':role,'sourceLine':ln,'evidenceClass':'PINNED_SAMSUNG_SOURCE'})
    return marks

def exact_nm_labels(raw:bytes):
    check(digest(raw)==PINS['original_nm'],'Original recovered nm SHA mismatch')
    symbols={}
    for m in NM_LINE.finditer(raw.decode('utf-8','strict')):
        symbols.setdefault(int(m.group(1),16),set()).add(m.group(2))
    for site in SITES:
        check(site['callee'] in symbols.get(site['calleeStaticVA'],set()),
              'Original callee symbol not at pinned static address: '+site['callee'])
    return True

def audit(source:Path,disasm:Path,nm:Path|None=None):
    c=tar_part(source,PINS['source_archive'],'kernel/futex.c',PINS['futex_source'])
    a=tar_part(disasm,PINS['disasm_archive'],'do_futex.disasm.txt',PINS['do_futex_disasm'])
    markers=source_markers(c)
    instructions=parse_original_instructions(a)
    uses=compiled_argument_ledger(instructions)
    frame=compiled_sp_integrity(instructions)
    pointer_store=compiled_conditional_waiter_pointer_store(instructions)
    if nm is not None:exact_nm_labels(file_bytes(nm,20_000_000))
    return {
        'schemaVersion':1,'target':TARGET,
        'scope':'OFFLINE_SOURCE_LIFETIME_MARKERS_AND_THREE_ORIGINAL_WAITER_ARGUMENT_SITES',
        'originalSourceArchiveSha256':PINS['source_archive'],
        'originalDisassemblyArchiveSha256':PINS['disasm_archive'],
        'originalFutexSourceSha256':PINS['futex_source'],
        'originalDoFutexDisassemblySha256':PINS['do_futex_disasm'],
        'originalDoFutexInstructionCount':1766,
        'originalRecoveredNmIndependentlyRehashed':nm is not None,
        'waiterSourceMarkers':markers,
        'compiledCallArgumentSites':uses,
        'compiledSpFrameInventory':frame,
        'conditionalWaiterDerivedPointerStore':pointer_store,
        'sameLiteralSpRelativeExpressionAcrossThreeStaticSites':True,
        'compiledSourceLocalWaiterObjectIdentityCertified':False,
        'conditionalWaiterLifetimeAcrossAllPathsCertified':False,
        'crossSyscallStackReuseOrAliasProven':False,
        'runtimeKernelPhysicalAddressesOrKASLRProven':False,
        'usableGhostLockPrimitiveOrRootVerified':False,
        'kernelSuLoaded':False,
        'deviceModified':False,
        'limits':'Source landmarks are ordered textual statements, not a source CFG. Verified '
                 'instruction words show independent SP-relative argument construction at three '
                 'call sites. Full SP stability, path feasibility, compiler-local identity, object '
                 'lifetime, cross-syscall stack reuse, exploitation and root remain unproven.'
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-archive',required=True,type=Path)
    p.add_argument('--disassembly-archive',required=True,type=Path)
    p.add_argument('--nm',type=Path,help='Optional independently SHA-checked original recovered NM')
    p.add_argument('--output',required=True,type=Path)
    opts=p.parse_args()
    try:
        target=opts.output.expanduser().resolve()
        check(not opts.output.expanduser().is_symlink() and not target.exists(),
              'Refusing to overwrite previous evidence')
        result=audit(opts.source_archive.expanduser().resolve(),
                     opts.disassembly_archive.expanduser().resolve(),
                     opts.nm.expanduser().resolve() if opts.nm else None)
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('x',encoding='utf-8') as stream:
            json.dump(result,stream,indent=2)
            stream.write('\n')
        print('[ORIGINAL FUTEX SOURCE LANDMARKS]',len(result['waiterSourceMarkers']))
        print('[ORIGINAL COMPILED SP-DERIVED CALL ARGUMENTS]',len(result['compiledCallArgumentSites']))
        print('[EXPLICIT DO_FUTEX SP WRITES]',result['compiledSpFrameInventory']['observedSpWrites'])
        print('[NM INDEPENDENTLY REHASHED]',result['originalRecoveredNmIndependentlyRehashed'])
        print('[OBJECT LIFETIME / CROSS-SYSCALL ALIAS / ROOT] UNVERIFIED')
        print('[REPORT]',target)
        return 0
    except (OSError,ValueError,tarfile.TarError,TypeError,KeyError) as exc:
        print('[STOP]',exc,file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
