#!/usr/bin/env python3
"""Single-pass direct-reader/writer candidate audit of pinned HXL1 LinuxLoader.

Scan the ORIGINAL PE .text once for ADRP+direct unsigned-offset scalar
memory operations naming precisely the two already verified getter globals.
Only a bounded same-basic-block syntactic match is claimed; indirect calls,
register aliases, pair stores, relocations and runtime values aren't solved.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from tools import y2q_hxl1_linuxloader_getter_raw_windows as pe
from tools import y2q_hxl1_linuxloader_raw_getter_globals as getter

TARGETS={'dtbo':0x32a4cc,'dtb':0x32a4d0}
MAX_AHEAD=28
# AArch64 unsigned-immediate scalar LOAD/STORE opcodes, byte/half/word/dword.
ENCODINGS=((0xffc00000,0x39000000,'WRITE',1),
           (0xffc00000,0x39400000,'READ',1),
           (0xffc00000,0x79000000,'WRITE',2),
           (0xffc00000,0x79400000,'READ',2),
           (0xffc00000,0xb9000000,'WRITE',4),
           (0xffc00000,0xb9400000,'READ',4),
           (0xffc00000,0xf9000000,'WRITE',8),
           (0xffc00000,0xf9400000,'READ',8))

class Stop(ValueError):pass

def need(ok,message):
    if not ok:raise Stop(message)


def overwrites_page_base(word:int,reg:int)->bool:
    """Recognize common A64 writes which invalidate an ADRP register value.

    This is intentionally a *bounded partial kill-set*, not a general AArch64
    def-use solver. Treat matches as candidates, never proof of all writers.
    """
    rd=word&31
    # ADR/ADRP, immediate arithmetic, move-wide and common logical/ALU
    # register/immediate operations. These replace the tracked base register.
    if rd==reg and (
        (word&0x1f000000)==0x10000000  # ADR/ADRP
        or (word&0x1f000000)==0x11000000  # ADD/SUB immediate
        or (word&0x1f800000)==0x12800000  # MOVZ/MOVN/MOVK
        or (word&0x1f000000) in (0x0a000000,0x0b000000)  # logical/arithmetic registers
        or (word&0x1f800000)==0x12000000  # logical immediate
    ):
        return True
    # Loads to the tracked register (including a load through its own base).
    # Stores do not overwrite Rt. This covers exact unsigned immediate
    # scalar encodings already recognized by the scanner.
    for mask,opcode,mode,_size in ENCODINGS:
        if mode=='READ' and (word&mask)==opcode and rd==reg:
            return True
    # LDP/LDNP also assign Rt2; this cannot be detected by merely testing
    # the low destination bits. Ignore STP/STNP which only read both.
    if (word&0x3a000000)==0x28000000 and word&0x00400000:
        if rd==reg or ((word>>10)&31)==reg:
            return True
    return False


def scan_words(code:bytes,text_rva:int,addresses=TARGETS):
    """Return bounded direct same-register references; no path feasibility proof."""
    need(len(code)%4==0,'Text code size is not word-aligned')
    words=struct.unpack('<'+'I'*(len(code)//4),code)
    found=[]
    pages={addr&~0xfff for addr in addresses.values()}
    for i,word in enumerate(words):
        if word&0x9f000000!=0x90000000:continue
        pc=text_rva+i*4
        reg=word&31
        page=getter.adrp_address(word,pc,reg)
        if page not in pages:continue
        for k in range(i+1,min(len(words),i+1+MAX_AHEAD)):
            w=words[k]; at=text_rva+k*4
            if pe.decode_control(w,at):
                break
            for mask,opcode,mode,size in ENCODINGS:
                if w&mask!=opcode or (w>>5)&31!=reg:continue
                addr=page+(((w>>10)&0xfff)*size)
                for kind,target in addresses.items():
                    if addr>=target+4 or addr+size<=target:continue
                    found.append({'indexKind':kind,'ADRP_RVA':hex(pc),
                                  'accessRva':hex(at),'mode':mode,
                                  'accessBytes':size,'effectiveRva':hex(addr),
                                  'instructionWord':f'0x{w:08x}',
                                  'isExact32BitAccess':size==4 and addr==target,
                                  'sameBasicBlockProven':False,
                                  'readWriteRegisterValueProven':False})
            # Do not extend an ADRP provenance beyond a known definition of
            # that same register; otherwise a later STR can be a false global
            # writer. Unrecognized writes remain explicitly out of scope.
            if overwrites_page_base(w,reg):
                break
    return found

def analyze(original:bytes,window:dict):
    need(hashlib.sha256(original).hexdigest()==pe.ORIGINAL_SHA,
         'Exact original LinuxLoader SHA mismatch')
    base,size,sections=pe.sections_for_image(original)
    need(base==0,'Original PE preferred image base changed')
    check=getter.analyze(window)
    need({kind:int(row['nativeGetterReturnsGlobalU32AtRva'],16)
          for kind,row in check['getterFindings'].items()}==TARGETS,
         'Global RVAs differ from verified original getter analysis')
    text=[s for s in sections if s['name']=='.text' and s['executable']]
    need(len(text)==1,'Original executable .text not uniquely identified')
    s=text[0]
    chunk=original[s['fileOffset']:s['fileOffset']+s['fileBytes']]
    need(len(chunk)==s['fileBytes'],'Truncated original executable section')
    # Cross-check the owner supplied code window bytes against the actual
    # exact-hash loader to reject a claimed pin without measured native words.
    for t in window['targets']:
        rva=int(t['candidatePeRva'],16)
        raw=bytes.fromhex(''.join(v['wordLittleEndianHex'] for v in t['nativeWords']))
        pos=rva-s['rva']
        need(0<=pos and pos+len(raw)<=len(chunk) and chunk[pos:pos+len(raw)]==raw,
             'Original getter code window does not match loader bytes')
    matches=scan_words(chunk,s['rva'])
    counters={kind:{'readCandidates':0,'writeCandidates':0} for kind in TARGETS}
    for m in matches:
        counters[m['indexKind']]['readCandidates' if m['mode']=='READ' else 'writeCandidates']+=1
    return {'schemaVersion':1,'target':'SM-G986U1/G986U1UESCHXL1',
            'classification':'EXACT_HASH_ORIGINAL_LOADER_DIRECT_GLOBAL_REFERENCES_ONLY',
            'originalLinuxLoaderSha256':pe.ORIGINAL_SHA,
            'originalPeImageSize':size,
            'textSectionRva':hex(s['rva']),'textBytesScanned':len(chunk),
            'getterGlobalAddresses':{k:hex(v) for k,v in TARGETS.items()},
            'nativeGetterWindowsReconciledAgainstHashedOriginalLoader':True,
            'directScalarReferences':matches,
            'summaryByKind':counters,
            'candidateWritesProveGlobalValueSource':False,
            'noDirectCandidateWritesProvesNoWriters':False,
            'indirectOrAliasedReferencesExhaustivelyEnumerated':False,
            'ghidraAddressToPeRvaMappingIndependentlyProven':False,
            'bootIndicesOrSelectedFdtProven':False,
            'physicalKernelHandoffVerified':False,
            'deviceModified':False,'rootOrKernelSuDemonstrated':False,
            'limitation':'Only ADRP plus unsigned-offset scalar memory operands within 28 instructions. Exact original-binary SHA and getter-window bytes authenticated; alias propagation and branch/register provenance are NOT established. The absence of matches does not exclude indirect authors.'}


def report_writer_window(original:bytes, references:dict):
    """Rehash original loader and export bounded *raw* writer code once.

    This mode uses the preexisting exhaustive-pattern scan report, so owners
    don't need another scan or two more cancelled provider decompilations.
    Only signed-off, word-for-word candidate references are extracted.
    """
    need(hashlib.sha256(original).hexdigest()==pe.ORIGINAL_SHA,
         'Original loader SHA mismatch')
    need(isinstance(references,dict) and
         references.get('schemaVersion')==1 and
         references.get('target')=='SM-G986U1/G986U1UESCHXL1' and
         references.get('classification')==
             'EXACT_HASH_ORIGINAL_LOADER_DIRECT_GLOBAL_REFERENCES_ONLY' and
         references.get('originalLinuxLoaderSha256')==pe.ORIGINAL_SHA and
         references.get('nativeGetterWindowsReconciledAgainstHashedOriginalLoader') is True,
         'Untrusted existing exact-image global-reference report')
    base,size,sections=pe.sections_for_image(original)
    need(base==0 and size==references.get('originalPeImageSize'),
         'Existing PE virtual identity mismatch')
    text=[sec for sec in sections if sec['name']=='.text' and sec['executable']]
    need(len(text)==1,'Expected one executable original .text')
    section=text[0]
    need(references.get('textSectionRva')==hex(section['rva']) and
         references.get('textBytesScanned')==section['fileBytes'],
         'Prior reference report scanned a different PE section')
    need(references.get('getterGlobalAddresses')==
         {k:hex(v) for k,v in TARGETS.items()},
         'Candidate globals changed between original reports')
    chunk=original[section['fileOffset']:
                   section['fileOffset']+section['fileBytes']]
    need(len(chunk)==section['fileBytes'] and len(chunk)%4==0,
         'Truncated or unaligned text')
    references_list=references.get('directScalarReferences')
    need(isinstance(references_list,list) and 0<len(references_list)<=256,
         'Unexpected original reference count')
    counters={kind:{'readCandidates':0,'writeCandidates':0} for kind in TARGETS}
    validated=[]
    for row in references_list:
        need(isinstance(row,dict) and row.get('indexKind') in TARGETS and
             row.get('mode') in ('READ','WRITE') and
             row.get('accessBytes') in (1,2,4,8) and
             isinstance(row.get('instructionWord'),str),
             'Malformed original direct reference')
        kind=row['indexKind']
        try:
            adr=int(row['ADRP_RVA'],16);at=int(row['accessRva'],16)
            saved=int(row['instructionWord'],16)
            stored_rva=int(row['effectiveRva'],16)
        except (ValueError,TypeError,KeyError):
            raise Stop('Malformed original RVA or machine word')
        need(0<=saved<=0xffffffff and
             all(section['rva']<=pc and pc%4==0 and
                 pc+4<=section['rva']+len(chunk) for pc in (adr,at)) and
             0<at-adr<=MAX_AHEAD*4,
             'Out-of-range or unaligned original reference')
        base_word=struct.unpack_from('<I',chunk,adr-section['rva'])[0]
        access_word=struct.unpack_from('<I',chunk,at-section['rva'])[0]
        reg=base_word&31
        page=getter.adrp_address(base_word,adr,reg)
        found=None
        for mask,opcode,mode,width in ENCODINGS:
            if access_word&mask==opcode and ((access_word>>5)&31)==reg:
                calculated=page+(((access_word>>10)&0xfff)*width)
                if mode==row['mode'] and width==row['accessBytes'] and calculated==stored_rva:
                    found=True
                    break
        need(found is True and saved==access_word and
             stored_rva<TARGETS[kind]+4 and stored_rva+row['accessBytes']>TARGETS[kind],
             'Reference not confirmed in exact original ARM64 words')
        counters[kind]['readCandidates' if row['mode']=='READ' else 'writeCandidates']+=1
        validated.append((row,reg,adr,at))
    need(counters==references.get('summaryByKind'),
         'Existing reader/writer summary is inconsistent')
    windows=[]
    for row,reg,adr,at in validated:
        if row['mode']!='WRITE':
            continue
        start=max(section['rva'],at-0x200)
        end=min(section['rva']+len(chunk),at+0x100)
        raw=chunk[start-section['rva']:end-section['rva']]
        words=[]
        for i in range(0,len(raw),4):
            at_word=start+i
            w=struct.unpack_from('<I',raw,i)[0]
            control=pe.decode_control(w,at_word)
            rec={'rva':hex(at_word),'wordLittleEndianHex':raw[i:i+4].hex(),
                 'wordUnsignedHex':f'0x{w:08x}'}
            if control:rec['decodedControlTransferOnly']=control
            words.append(rec)
        windows.append({
            'indexKind':row['indexKind'],
            'writerCandidateRva':row['accessRva'],
            'originalAdrpRva':row['ADRP_RVA'],
            'destinationGlobalRva':row['effectiveRva'],
            'writerValueRegister':f'w{(struct.unpack_from("<I",chunk,at-section["rva"])[0])&31}',
            'writerBaseRegister':f'x{reg}',
            'originalWriterWord':row['instructionWord'],
            'boundedRawWindowStartRva':hex(start),
            'boundedRawWindowByteCount':len(raw),
            'boundedRawWindowSha256':hashlib.sha256(raw).hexdigest(),
            'originalWords':words,
            'valueDefinitionAndBranchFeasibilityEstablished':False,
            'runtimeValueOrPhysicalPlacementProven':False,
        })
    return {
        'schemaVersion':1,
        'target':'SM-G986U1/G986U1UESCHXL1',
        'classification':'EXACT_ORIGINAL_LOADER_BOUNDED_DTB_WRITER_CODE_CONTEXT',
        'originalLinuxLoaderSha256IndependentlyRehashed':pe.ORIGINAL_SHA,
        'originalImageSize':size,
        'priorReferenceWordsAuthenticatedAgainstOriginalImage':True,
        'priorSummaryMatchesOriginalReferenceEntries':True,
        'validatedReferenceCounts':counters,
        'writerWindows':windows,
        'noDirectCandidateDoesNotExcludeIndirectOrDataInitialization':True,
        'branchPredicatesAndWriterValueOriginsProven':False,
        'actualSelectedDtboDtbImagesProven':False,
        'physicalKernelHandoffProven':False,
        'deviceModified':False,'rootOrKernelSuDemonstrated':False,
        'limits':'Portable exact original code words near previously identified direct writer(s); '
                 'no full graph/def-use proof or inferred runtime DTB value.'
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--loader',required=True,type=Path)
    p.add_argument('--raw-windows',type=Path,
                   help='Original getter windows (normal full reference-scan mode)')
    p.add_argument('--existing-refs',type=Path,
                   help='Previously generated exact-loader references; extract only writer code context')
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args(argv)
    try:
        need((a.existing_refs is None)!=(a.raw_windows is None),
             'Provide exactly one of --existing-refs or --raw-windows')
        source=a.existing_refs if a.existing_refs is not None else a.raw_windows
        for path in (a.loader,source):
            need(not path.is_symlink() and path.is_file(), 'Missing or unsafe input')
        need(a.loader.stat().st_size<=pe.MAX_PE and source.stat().st_size<=300_000,
             'Unexpectedly large input')
        out=a.output.expanduser().absolute()
        need(not out.exists() and not out.is_symlink(), 'Output already exists')
        need('Root-My-Galaxy-Payloads' not in str(out),'Output must be outside repository')
        original=a.loader.read_bytes()
        if a.existing_refs is not None:
            r=report_writer_window(original,json.loads(source.read_text()))
        else:
            r=analyze(original,json.loads(source.read_text()))
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
        if a.existing_refs is not None:
            print('[AUTHENTIC ORIGINAL WRITER WINDOWS]',len(r['writerWindows']))
            print('[PRODUCER VALUE / ACTUAL DTB SELECTION] NOT ESTABLISHED')
        else:
            for kind,counts in r['summaryByKind'].items():
                print('[CANDIDATE GLOBAL ACCESSES]',kind,counts)
            print('[INDIRECT WRITERS / ACTUAL SELECTOR VALUES] NOT ESTABLISHED')
        print('[OUTPUT]',out)
        return 0
    except (OSError,ValueError,KeyError,TypeError) as e:
        print('[STOP]',e,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
