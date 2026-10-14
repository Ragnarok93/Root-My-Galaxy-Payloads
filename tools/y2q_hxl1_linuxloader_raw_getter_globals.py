#!/usr/bin/env python3
"""Read-only HXL1 original-PE-RVA ARM64 getter-global audit.

Consumes an independently collected *claimed* SHA-pinned PE code-window JSON;
never reads a device, calls Ghidra, or assumes coordinate equality with Ghidra.
This is static instruction provenance only, not a boot-loader selector proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

LOADER_SHA = '5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003'
COORDS = {'dtbo':0x23b00,'dtb':0x23b40}
TEXT = '.text'

class AuditError(ValueError):
    pass

def need(condition, message):
    if not condition:
        raise AuditError(message)

def field(value):
    need(isinstance(value,str) and re.fullmatch(r'0x[0-9a-fA-F]+',value), 'Missing hexadecimal RVA/word')
    return int(value,16)

def signed21(val):
    return val-(1<<21) if val&(1<<20) else val

def adrp_address(insn,pc,rd):
    need((insn & 0x9f000000)==0x90000000 and (insn&31)==rd, 'Expected ADRP base register')
    encoded=(((insn>>5)&0x7ffff)<<2)|((insn>>29)&3)
    return (pc&~0xfff)+(signed21(encoded)<<12)

def ldr_w_uimm(insn, base, destination):
    need((insn&0xffc00000)==0xb9400000 and (insn&31)==destination and
         ((insn>>5)&31)==base, 'Expected unsigned-immediate LDR W0 from X9')
    return ((insn>>10)&0xfff)*4

def ldr_x_uimm(insn, base, destination):
    need((insn&0xffc00000)==0xf9400000 and (insn&31)==destination and
         ((insn>>5)&31)==base, 'Expected 64-bit shared-checkword load')
    return ((insn>>10)&0xfff)*8

def analyze(obj):
    need(isinstance(obj,dict) and obj.get('schemaVersion')==1 and
         obj.get('classification')=='SHA_PINNED_PE_RVA_WINDOWS_NO_GHIDRA_OR_SELECTOR_CLAIM' and
         obj.get('device')=='SM-G986U1' and obj.get('firmware')=='G986U1UESCHXL1' and
         obj.get('loaderSha256')==LOADER_SHA and obj.get('peMachine')=='0xaa64' and
         obj.get('pePreferredImageBase')=='0x0', 'Untrusted/incorrect original PE identity')
    sections=obj.get('sections')
    need(isinstance(sections,list), 'Missing PE sections')
    section=next((s for s in sections if isinstance(s,dict) and s.get('name')==TEXT), None)
    data=next((s for s in sections if isinstance(s,dict) and s.get('name')=='.data'),None)
    need(section is not None and data is not None and section.get('executable') is True and
         data.get('executable') is False, 'Missing executable .text or data section')
    need(isinstance(obj.get('targets'),list) and len(obj['targets'])==2 and
         {t.get('kind') for t in obj['targets'] if isinstance(t,dict)}==set(COORDS),
         'Expected exactly one DTB and one DTBO candidate')
    results={}
    for t in obj['targets']:
        kind=t['kind']; entry=COORDS[kind]
        need(field(t.get('candidatePeRva'))==entry and t.get('peSection')==TEXT and
             field(t.get('peFileOffset'))==entry and
             isinstance(t.get('nativeWords'),list) and len(t['nativeWords'])>=16,
             'Unexpected candidate RVA/file window')
        need(section['rva']<=entry and entry+64<=section['rva']+section['fileBytes'],
             'Candidate code outside executable original PE section')
        insns={}
        for n in t['nativeWords']:
            pc=field(n['rva']); value=field(n['wordUnsignedHex'])
            need(value<=0xffffffff and n['wordLittleEndianHex']==value.to_bytes(4,'little').hex(),
                 'ARM64 word endian mismatch')
            need(pc not in insns,'Duplicate original instruction address')
            insns[pc]=value
        need(all(entry+i*4 in insns for i in range(16)), 'Incomplete 64-byte getter candidate')
        values=[insns[entry+i*4] for i in range(16)]
        need(values[0]==0xd10083ff and values[1]==0xf9000bfe and
             values[5]==0xf90007e8 and values[8]==0xf94007e8 and
             values[10]==0xeb08013f and values[11]==0x54000081 and
             values[12]==0xf9400bfe and values[13]==0x910083ff and
             values[14]==0xd65f03c0,
             'Getter prologue/check/normal return does not match original window')
        returned_base=adrp_address(values[3],entry+12,9)
        returned_rva=returned_base+ldr_w_uimm(values[6],9,0)
        saved_base=adrp_address(values[2],entry+8,8)
        restored_base=adrp_address(values[7],entry+28,9)
        need(saved_base==restored_base, 'Expected shared checkword base mismatch')
        saved_rva=saved_base+ldr_x_uimm(values[4],8,8)
        restored_rva=restored_base+ldr_x_uimm(values[9],9,9)
        need(saved_rva==restored_rva, 'Shared checkword locations do not match')
        need(data['rva']<=returned_rva and returned_rva+4<=data['rva']+data['virtualBytes'] and
             data['rva']<=saved_rva and saved_rva+8<=data['rva']+data['virtualBytes'],
             'Computed variable/checkword address outside original PE .data')
        need(((values[11]>>5)&0x7ffff)==4 and (values[15]&0xfc000000)==0x94000000,
             'Unexpected shared mismatch branch shape')
        encoded=values[15]&0x3ffffff
        delta=encoded-(1<<26) if encoded&(1<<25) else encoded
        call_target=entry+60+delta*4
        results[kind]={
           'entryCandidateRva':hex(entry),
           'nativeGetterReturnsGlobalU32AtRva':hex(returned_rva),
           'readInstructionRva':hex(entry+24),
           'readOpcodeHex':hex(values[6]),
           'sharedSavedAndComparedCheckwordRva':hex(saved_rva),
           'checkMismatchCallTargetRva':hex(call_target),
           'normalReturnRva':hex(entry+56),
           'returnedIndexValueObserved':False,
        }
    need(results['dtb']['sharedSavedAndComparedCheckwordRva']==
         results['dtbo']['sharedSavedAndComparedCheckwordRva'] and
         results['dtb']['checkMismatchCallTargetRva']==
         results['dtbo']['checkMismatchCallTargetRva'], 'Getter wrappers do not share canary/check target')
    addresses={k:int(v['nativeGetterReturnsGlobalU32AtRva'],16) for k,v in results.items()}
    need(addresses['dtb']-addresses['dtbo']==4, 'DTB and DTBO globals are not adjacent 32-bit fields')
    return {
       'schemaVersion':1, 'target':'SM-G986U1/G986U1UESCHXL1',
       'classification':'TWO_RAW_ORIGINAL_PE_GETTER_CANDIDATES_READ_ADJACENT_GLOBAL_U32',
       'originalPeLoaderSha256ClaimedByInput':LOADER_SHA,
       'sourceLoaderSha256IndependentlyRehashedInThisRun':False,
       'originalPeRvaEqualsGhidraAnalysisCoordinatesProven':False,
       'getterFindings':results,
       'adjacentGlobalsDistanceBytes':4,
       'guardCheckMatchesSharedStackCanaryPattern':True,
       'guardCheckHelperNameAuthenticated':False,
       'globalValuesAndAuthorsIdentified':False,
       'selectedDtbOrDtboOverlayAuthenticated':False,
       'physicalKernelHandoffProven':False,
       'deviceModified':False,'rootOrKernelSuDemonstrated':False,
       'evidenceLimit':'Static decode of supplied original-PE-RVA windows only. No proof '+
                       'that Ghidra coordinates equal these RVAs, no identity of '+
                       'global writes/values or active DTB/DTBO selection.'
    }

def main(argv=None):
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--input',required=True,type=Path)
    cli.add_argument('--output',required=True,type=Path)
    args=cli.parse_args(argv)
    try:
        source=args.input.expanduser().resolve(); dest=args.output.expanduser().resolve()
        need(source.is_file() and not args.input.is_symlink() and source.stat().st_size<=200_000,
             'Missing/unsafe evidence JSON')
        result=analyze(json.loads(source.read_text()))
        need(not dest.exists() and not args.output.is_symlink(),'Refusing to overwrite existing report')
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('x') as file:
            json.dump(result,file,indent=2);file.write('\n')
        for kind,d in result['getterFindings'].items():
            print('[ORIGINAL PE READ]',kind,d['nativeGetterReturnsGlobalU32AtRva'])
        print('[GHIDRA RVA EQUALITY / DTB SELECTION / HANDOFF] NOT PROVEN')
        print('[REPORT]',dest)
        return 0
    except (ValueError,OSError,KeyError,TypeError) as err:
        print('[STOP]',err,file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
