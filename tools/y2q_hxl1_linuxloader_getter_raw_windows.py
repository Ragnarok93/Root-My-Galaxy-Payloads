#!/usr/bin/env python3
"""Offline SHA-pinned PE32+ ARM64 getter code windows (NO REA/Ghidra calls).

Emit one portable original-byte report for the two suspected DTB/DTBO
formatter getter RVAs. PE RVA and Ghidra coordinate equivalence is not proved
by their matching hexadecimal notation. Never infer runtime FDT selection.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ORIGINAL_SHA='5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003'
TARGETS=(('dtbo',0x23b00,0x40), ('dtb',0x23b40,0x100))
MAX_PE=64*1024*1024
EXPECTED_CALLSITE_CLASS='VERIFIED_STATIC_FORMATTER_GETTER_CALLSITES_NO_SELECTOR_PROOF'

class FailClosed(ValueError):
    pass

def check(ok,message):
    if not ok:raise FailClosed(message)

def decode_control(word,rva):
    """Only A64 direct control-transfer encodings; do not guess dataflow."""
    sign_extend=lambda x,bits: (x ^ (1<<(bits-1))) - (1<<(bits-1))
    if (word & 0xfc000000)==0x94000000:
        d=sign_extend(word&0x3ffffff,26)*4
        return {'mnemonic':'bl','targetRva':hex(rva+d)}
    if (word & 0xfc000000)==0x14000000:
        d=sign_extend(word&0x3ffffff,26)*4
        return {'mnemonic':'b','targetRva':hex(rva+d)}
    if (word & 0xff000010)==0x54000000:
        d=sign_extend((word>>5)&0x7ffff,19)*4
        return {'mnemonic':'b.cond','targetRva':hex(rva+d), 'conditionCode':word&0xf}
    if (word & 0x7e000000)==0x34000000:
        d=sign_extend((word>>5)&0x7ffff,19)*4
        return {'mnemonic':'cbnz' if word&0x01000000 else 'cbz', 'targetRva':hex(rva+d)}
    if (word & 0x7e000000)==0x36000000:
        d=sign_extend((word>>5)&0x3fff,14)*4
        return {'mnemonic':'tbnz' if word&0x01000000 else 'tbz', 'targetRva':hex(rva+d)}
    if (word & 0xfffffc1f)==0xd65f0000:
        return {'mnemonic':'ret'}
    if (word & 0xfffffc1f)==0xd61f0000:
        return {'mnemonic':'br'}
    if (word & 0xfffffc1f)==0xd63f0000:
        return {'mnemonic':'blr'}
    return None

def sections_for_image(buf):
    check(len(buf)>0x100 and buf[:2]==b'MZ','Not a PE DOS header')
    lf=struct.unpack_from('<I',buf,0x3c)[0]
    check(0x40<=lf<=len(buf)-0x80,'Invalid e_lfanew')
    check(buf[lf:lf+4]==b'PE\0\0','PE signature mismatch')
    machine,count,_,_,_,opt_size,_=struct.unpack_from('<HHIIIHH',buf,lf+4)
    check(machine==0xaa64,'Original loader must be ARM64 PE')
    check(1<=count<=48 and opt_size>=0x70,'Invalid PE section/option count')
    opt=lf+24
    check(opt+opt_size+count*40<=len(buf),'Truncated PE headers/sections')
    check(struct.unpack_from('<H',buf,opt)[0]==0x20b,'Not PE32+')
    image_base=struct.unpack_from('<Q',buf,opt+0x18)[0]
    image_size=struct.unpack_from('<I',buf,opt+0x38)[0]
    check(0<image_size<=MAX_PE*8,'Invalid PE virtual image size')
    out=[]
    for i in range(count):
        p=opt+opt_size+40*i
        name=buf[p:p+8].split(b'\0',1)[0].decode('ascii','replace')
        virtual_size,rva,raw_size,raw_off=struct.unpack_from('<IIII',buf,p+8)
        flags=struct.unpack_from('<I',buf,p+36)[0]
        check(raw_off<=len(buf) and raw_size<=len(buf)-raw_off,'Invalid PE file region')
        check(rva<image_size and rva+max(virtual_size,raw_size)<=image_size+0x1000,
              'Invalid PE virtual region')
        out.append({'name':name,'rva':rva,'virtualBytes':virtual_size,
                    'fileOffset':raw_off,'fileBytes':raw_size,
                    'executable':bool(flags&0x20000000)})
    return image_base,image_size,out

def emit(buf,callsite):
    check(hashlib.sha256(buf).hexdigest()==ORIGINAL_SHA,'Original HXL1 loader SHA mismatch')
    check(callsite.get('target')=='SM-G986U1/G986U1UESCHXL1' and
          callsite.get('originalLinuxLoaderSha256')==ORIGINAL_SHA and
          callsite.get('classification')==EXPECTED_CALLSITE_CLASS and
          callsite.get('allImmediateGetterCallsitesCorroborated') is True and
          callsite.get('getterInternalsOrSelectionAlgorithmVerified') is False,
          'Invalid previously verified getter callsites')
    got={(c.get('indexKind'),c.get('ghidraStaticAnalysisTarget'))
         for c in callsite.get('callsiteEvidence',[])}
    check(got=={('dtbo','0x23b00'),('dtb','0x23b40')} and
          len(callsite['callsiteEvidence'])==2, 'Ambiguous/missing target coordinates')
    base,size,sections=sections_for_image(buf)
    records=[]
    for kind,at,length in TARGETS:
        found=[s for s in sections if s['executable'] and
               s['rva']<=at and at+length<=s['rva']+s['fileBytes']]
        check(len(found)==1,'Getter candidate RVA not uniquely contained in file-backed executable section')
        sec=found[0]
        off=sec['fileOffset']+(at-sec['rva'])
        code=buf[off:off+length]
        check(len(code)==length and length%4==0 and at%4==0,'Window invalid')
        instructions=[]
        for i in range(0,length,4):
            word=int.from_bytes(code[i:i+4],'little')
            row={'rva':hex(at+i),'wordLittleEndianHex':code[i:i+4].hex(),
                 'wordUnsignedHex':f'0x{word:08x}'}
            control=decode_control(word,at+i)
            if control:row['decodedControlTransferOnly']=control
            instructions.append(row)
        records.append({'kind':kind,'analysisCoordinate':hex(at),
                        'coordinateRvaEquivalenceValidated':False,
                        'candidatePeRva':hex(at),'windowByteCount':length,
                        'peFileOffset':hex(off),'peSection':sec['name'],
                        'byteSha256':hashlib.sha256(code).hexdigest(),
                        'nativeWords':instructions})
    return {'schemaVersion':1,'classification':'SHA_PINNED_PE_RVA_WINDOWS_NO_GHIDRA_OR_SELECTOR_CLAIM',
            'device':'SM-G986U1','firmware':'G986U1UESCHXL1',
            'loaderSha256':ORIGINAL_SHA,'peMachine':'0xaa64',
            'pePreferredImageBase':hex(base),'peVirtualImageSize':hex(size),
            'sections':sections,'targets':records,
            'returnedFunctionValueSemanticsVerified':False,
            'ghidraAddressToPeRvaEqualityVerified':False,
            'dtbOrOverlaySelectionVerified':False,'physicalKernelHandoffVerified':False,
            'deviceModified':False,'rootOrKernelSuDemonstrated':False,
            'limitations':'Raw original file-backed bytes only. Candidate Ghidra coordinates may not equal PE RVAs. Control-transfer decoder is intentionally incomplete; no function extent, selector or live base is inferred.'}

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--loader',required=True,type=Path)
    ap.add_argument('--callsites',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    a=ap.parse_args(argv)
    try:
        for p in (a.loader,a.callsites):
            check(not p.is_symlink() and p.is_file() and 0<p.stat().st_size<=MAX_PE,
                  'Unsafe/missing original input: '+str(p))
        output=a.output.expanduser().absolute()
        check(not output.exists() and not output.is_symlink(),'Output exists')
        check('/Root-My-Galaxy-Payloads/' not in str(output), 'Refusing output inside source repository')
        report=emit(a.loader.read_bytes(),json.loads(a.callsites.read_text()))
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x') as fp:json.dump(report,fp,indent=2);fp.write('\n')
        for t in report['targets']:
            print(f'[OFFLINE ORIGINAL RAW WINDOW] {t["kind"]} {t["candidatePeRva"]}: {t["windowByteCount"]} bytes')
        print('[ADDRESS MAPPING / SELECTOR / PHYSICAL HANDOFF] NOT VERIFIED')
        print('[OUTPUT]',output)
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print('[STOP]',exc,file=sys.stderr)
        return 2
    return 0
if __name__=='__main__':raise SystemExit(main())
