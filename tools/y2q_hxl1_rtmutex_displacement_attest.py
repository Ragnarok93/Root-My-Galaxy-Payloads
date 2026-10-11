#!/usr/bin/env python3
"""Offline pinned-code check of 31 HXL1 RT-mutex displacement witnesses.

This verifies saved original-Image-derived bytes without calling Ghidra or a
phone. Field labels are hypotheses, not complete factory DWARF/BTF layouts.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import sys
import zipfile

ORIGINAL_IMAGE_SHA = 'ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123'
ELFS = {
 'remove_waiter': ('ffffff8008147db4', 568,
  'adca8a2187eb8dc7bcdbb1907d2a6881f7e3f0cac0354946eeb04b8646f4bd0d',
  'f50dd6d1df275e0854e7d255c7f47abff81e2b065977e4a11b56007aa89d0c44'),
 'rt_mutex_start_proxy_lock': ('ffffff8008147d14', 160,
  '141e8a82bfcba07c221ec6686b883e1f9814e371d55d62d47fc2146f4f1d3f5f',
  'c6af65bc07bfa60247e8ab84223334f05e42443339499f013964b41a4966b5e3'),
}
WORDS = {
 'remove_waiter': {
  0x18:'f9400c16',0x1c:'aa0003f3',0x20:'aa0103f7',0x28:'f9401ec8',
  0x2c:'eb13011f',0x3c:'f9401278',0x48:'f94002e8',0x54:'91004261',
  0x70:'eb1702df',0x78:'927ffb15',0x80:'912322b6',0x8c:'f8418ee8',
  0x98:'912382a1',0xa8:'f9400a68',0xb0:'f9400e60',0xc4:'f94472ac',
  0xc8:'912382a1',0xd0:'b940400a',0xe8:'b940298c',0x130:'f94472a8',
  0x138:'f94476a8',0x13c:'f9400d01',0x150:'f9447ea8',
  0x1e0:'f940240c',0x1e4:'f940192d'},
 'rt_mutex_start_proxy_lock': {
  0x1c:'aa0003f3',0x34:'340001a0',0x3c:'aa1303e0',
  0x40:'aa1403e1',0x44:'94000017',0x84:'f9401268'},
}
FIELDS = {
 'rt_mutex': {'waiters.rb_root.rb_node':'0x10',
              'waiters.rb_leftmost':'0x18','owner':'0x20'},
 'rt_mutex_waiter': {'tree_entry':'0x0','pi_tree_entry':'0x18',
                     'task':'0x30','lock':'0x38','prio':'0x40','deadline':'0x48'},
 'task_struct': {'pi_lock':'0x8c8','pi_waiters.rb_root.rb_node':'0x8e0',
                 'pi_waiters.rb_leftmost':'0x8e8','pi_blocked_on':'0x8f8'},
}

def require(ok, why):
    if not ok:
        raise ValueError('HXL1 RT-mutex attestation STOP: '+why)

def sha(data):
    return hashlib.sha256(data).hexdigest()


SOURCE_PINS = {
 'kernel/locking/rtmutex.c': '36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9',
 'kernel/futex.c': '493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5',
}
HEADER_FIELDS = {
 'include/linux/rtmutex.h': ('rt_mutex', ('wait_lock','waiters','owner')),
 'kernel/locking/rtmutex_common.h': ('rt_mutex_waiter',
     ('tree_entry','pi_tree_entry','task','lock','prio','deadline')),
}

def source_headers(source:Path):
    """Accept only pinned original HXL1 Samsung checkout, never public upstream."""
    for relative,digest in SOURCE_PINS.items():
        file=source/relative
        require(file.is_file() and not file.is_symlink() and sha(file.read_bytes())==digest,
                'original HXL1 Samsung C source SHA pin mismatch: '+relative)
    headers={}
    for relative,(tag,fields) in HEADER_FIELDS.items():
        file=source/relative
        require(file.is_file() and not file.is_symlink() and file.stat().st_size < 1024*1024,
                'original Samsung header missing/unsafe: '+relative)
        raw=file.read_bytes()
        text=raw.decode('utf8')
        definition=re.search(r'\bstruct\s+'+re.escape(tag)+r'\s*\{(?P<body>.*?)\n\s*\};',text,re.S)
        require(definition is not None,'original struct definition not found: '+tag)
        body=definition.group('body')
        starts=[]
        for field in fields:
            matches=list(re.finditer(r'\b'+re.escape(field)+r'\s*;',body))
            require(len(matches)==1,'missing or ambiguous Samsung C member: '+tag+'.'+field)
            starts.append(matches[0].start())
        require(starts==sorted(starts),'unexpected Samsung struct member ordering: '+tag)
        headers[relative]={'originalHeaderSha256':sha(raw),
                           'definitionLine':text.count('\n',0,definition.start())+1,
                           'declaredMemberOrder':fields,
                           'conditionalMembersPossible':bool(re.search(r'(?m)^\s*#\s*(?:if|ifdef)',body))}
    return {'sourceCOriginalPinsVerified':True,
            'originalSamsungHeaderDeclarationsFound':headers,
            'fullOriginalFactoryCompiledLayoutProven':False}


def attest(slices:Path,rea:Path,source:Path|None=None):
    with zipfile.ZipFile(slices) as zs, zipfile.ZipFile(rea) as zr:
        manifest=json.loads(zr.read('stage3-rea-correlation.json'))
        require(manifest.get('model')=='SM-G986U1' and
                manifest.get('firmware')=='G986U1UESCHXL1' and
                manifest.get('originalKernelSha256')==ORIGINAL_IMAGE_SHA and
                manifest.get('sourceAndImagePinsVerified') is True,
                'stock image identity not authenticated by WSL manifest')
        out={}
        for name,(static_va,length,elf_sha,text_sha) in ELFS.items():
            file=f'isolated-{name}-{static_va}.elf'
            data=zs.read(file)
            require(sha(data)==elf_sha,'whole ELF digest changed: '+name)
            require(len(data)>4096+length and data[:6]==b'\x7fELF\x02\x01' and
                    struct.unpack_from('<H',data,18)[0]==183,
                    'not the expected ELF64 AArch64 slice: '+name)
            # v4.2 isolated ELF places the exact stock executable code at 0x1000.
            raw=data[4096:4096+length]
            require(sha(raw)==text_sha,'original Image-derived bytes changed: '+name)
            proof=manifest['functions'][name]
            require(proof['isolatedCode']['sha256']==elf_sha and
                    proof['isolatedCode']['originalBytesSha256']==text_sha and
                    proof['symbolVA']==('0x'+static_va),
                    'manifest/function mismatch: '+name)
            records={}
            for offset,expected in WORDS[name].items():
                require(offset%4==0 and 0<=offset<=length-4,
                        'bad bounded instruction offset: '+name)
                actual=raw[offset:offset+4].hex()
                require(actual==bytes.fromhex(expected)[::-1].hex(),
                        'compiled instruction changed: '+name+'+'+hex(offset))
                records[hex(offset)]={'originalStaticVA':hex(int(static_va,16)+offset),
                                      'arm64Word':expected}
            out[name]=records
        return {'target':'SM-G986U1/G986U1UESCHXL1',
                'pinnedOriginalKernelSha256':ORIGINAL_IMAGE_SHA,
                'compiledWordWitnesses':out,
                'witnessCount':sum(map(len,out.values())),
                'sourceCorrelatedMemberCandidates':FIELDS,
                'sourceHeaderHashesAuthenticatedByThisTool':source is not None,
                'sourceProvenance':source_headers(source) if source else None,
                'fullFactoryStructLayoutsAuthenticated':False,
                'rootOrKernelSuVerified':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--slices',type=Path,required=True)
    p.add_argument('--rea',type=Path,required=True)
    p.add_argument('--source',type=Path,help='exact original pinned Samsung HXL1 source checkout')
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    try:
        output=args.output.expanduser().absolute()
        require(output.suffix=='.json' and not output.exists(),
                'use a fresh JSON output path')
        for original in (args.slices,args.rea):
            require(output!=original.expanduser().absolute(),
                    'refuse evidence replacement')
        source=args.source.expanduser().resolve() if args.source else None
        if source:
            require(output!=source and source not in output.parents,
                    'refuse source-tree outputs')
        result=attest(args.slices,args.rea,source=source)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,indent=2)+'\n')
        print('[PASS] compiled witness instructions:',result['witnessCount'])
        print('[SOURCE]','exact Samsung HXL1 header declarations checked' if source else 'not supplied')
        print('[REPORT]',output)
        print('[LIMIT] subset; not OEM debug type layouts, root or KernelSU')
        return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile) as exc:
        print('[STOP]',exc,file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
