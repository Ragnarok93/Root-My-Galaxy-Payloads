#!/usr/bin/env python3
"""Bounded, read-only HXL1 cached LinuxLoader index-formatter audit.

Uses already authenticated REA/Ghidra xrefs and function dossiers, not a new
provider trace. Does not infer DTB selector semantics, physical load, or root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LOADER_PIN = '5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003'
EXPECTED = (
    ('dtb-index', '0xbfd99', '0x2c350'),
    ('dtbo-index', '0xbfd82', '0x2c308'),
)
ENTRY = '0x2bdf8'
TRACE_NAME = 'rea-shared-dtb-dtbo-native-values.partial.json'
MAX_PARTIAL = 1024 * 1024
MAX_SNIPPET_LINES = 120
LITERAL = re.compile(r'androidboot\.(?:dtb|dtbo)_idx', re.I)

class AuditError(ValueError):
    pass


def insist(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def trace_status(path: Path) -> dict:
    if not path.exists():
        return {'state':'NO_SAVED_TRACE', 'verifiedValueFlow':False}
    insist(path.is_file() and not path.is_symlink() and
           0 < path.stat().st_size <= MAX_PARTIAL,
           'Unsafe, empty or oversized saved REA trace')
    raw=path.read_bytes()
    obj=json.loads(raw)
    insist(isinstance(obj,dict), 'Invalid REA trace root JSON')
    report={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),
            'bytes':len(raw), 'verifiedValueFlow':False}
    if 'error' in obj:
        detail=obj.get('details',{})
        report.update(state='SAVED_TRACE_FAILURE',
                      errorType=str(obj.get('error'))[:100],
                      code=str(obj.get('code'))[:100],
                      category=str(obj.get('category'))[:100],
                      operation=str(detail.get('operation'))[:100] if isinstance(detail,dict) else None,
                      cleanup=str(detail.get('cleanup'))[:60] if isinstance(detail,dict) else None)
    else:
        report['state']='SAVED_NONERROR_REPORT_NOT_INDEPENDENTLY_VERIFIED'
        report['operation']=str(obj.get('operation'))[:100]
        report['reason']='A saved nonerror artifact needs separate native-trace schema and input provenance verification.'
    return report


def snippet(pseudocode: str) -> dict:
    insist(isinstance(pseudocode,str) and len(pseudocode)<=5_000_000,
           'Missing or oversized cached Ghidra pseudocode')
    lines=pseudocode.splitlines()
    matches=[i for i,line in enumerate(lines) if LITERAL.search(line)]
    allowed=set()
    for at in matches[:4]:
        allowed.update(range(max(0,at-12),min(len(lines),at+17)))
    result=[{'line':i+1,'text':lines[i][:240]} for i in sorted(allowed)[:MAX_SNIPPET_LINES]]
    return {'pseudocodeSha256':hashlib.sha256(pseudocode.encode('utf-8')).hexdigest(),
            'pseudocodeLineCount':len(lines),
            'indexLiteralLineCount':len(matches),
            'indexLiteralLines':[n+1 for n in matches[:20]],
            'snippetTruncated':len(allowed)>MAX_SNIPPET_LINES or len(matches)>4,
            'boundedPseudocodeExcerpt':result,
            'producerValueFlowProved':False}


def review_cached(run: Path, loader: Path, partial: Path) -> dict:
    insist(run.is_dir() and not run.is_symlink(), 'Missing/symlink cached REA run')
    insist(loader.is_file() and not loader.is_symlink() and sha(loader)==LOADER_PIN,
           'Original stock HXL1 LinuxLoader file SHA mismatch')
    from tools.y2q_linuxloader_rea_stage4_xrefs import parse_xrefs
    from tools.y2q_linuxloader_rea_stage4_functions import validated
    reports=[]
    for name, literal, source in EXPECTED:
        refs=parse_xrefs(run/(name+'-xrefs.json'),literal)
        insist(refs.get('sourceAddresses')==[source],
               'Missing/nonunique original '+name+' xref source')
        row=validated(run,name,source)
        insist(row['entry']==ENTRY and row['pcodeAvailable'] is True,
               'Cached Ghidra function identity / p-code unavailable')
        reports.append(row)
    insist(reports[0]['body']==reports[1]['body'],
           'Cached original body ranges disagree')
    hashes=[hashlib.sha256(x['pseudocode'].encode('utf-8')).hexdigest() for x in reports]
    return {
        'target':'SM-G986U1/G986U1UESCHXL1',
        'classification':'VERIFIED_CACHED_ORIGINAL_CMDLINE_FUNCTION_NO_VALUE_FLOW',
        'originalLinuxLoaderSha256':LOADER_PIN,
        'sharedFunctionAnalysisEntry':ENTRY,
        'sharedFunctionStaticBodyRanges':reports[0]['body'],
        'cachedFunctionPseudocodeConsistent':len(set(hashes))==1,
        'xrefEvidence':[
            {'label':label,'stringAnalysisAddress':literal,'xrefSource':src,
             'functionEvidenceId':row['evidenceId'],
             'pcodeAvailable':row['pcodeAvailable'],
             'pcodeTruncated':row['pcodeTruncated']}
            for (label,literal,src),row in zip(EXPECTED,reports)
        ],
        'formatterContext':snippet(reports[0]['pseudocode']),
        'savedNativeTrace':trace_status(partial),
        'indexOperandsProducerVerified':False,
        'bootloaderDtbSelectionVerified':False,
        'dtbIdx0MapsToFirstEmbeddedFdt':False,
        'dtboIdx2MapsToOriginalOverlay':False,
        'physicalLinuxHandoffVerified':False,
        'rootOrKernelSuDemonstrated':False,
        'scopeLimit':'Static xref and bounded cached pseudocode only. '
                     'A cancelled trace cannot certify def-use, memory aliases, '
                     'runtime selection or kernel physical base. No REA provider is invoked.'
    }


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',type=Path,required=True)
    parser.add_argument('--loader',type=Path,required=True)
    parser.add_argument('--partial',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        partial=args.partial or args.run_dir/TRACE_NAME
        result=review_cached(args.run_dir,args.loader,partial)
        output=args.output.expanduser().resolve()
        repository=Path(__file__).resolve().parents[1]
        insist(output!=repository and repository not in output.parents,
               'Output cannot be written inside source repository')
        insist(not output.exists() and not output.is_symlink(),
               'Refusing to overwrite previous report')
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print('[CACHED ORIGINAL FUNCTION]',result['sharedFunctionAnalysisEntry'])
        print('[SAVED REA TRACE]',result['savedNativeTrace']['state'])
        print('[STATIC INDEX LITERAL LINES]',result['formatterContext']['indexLiteralLineCount'])
        print('[INDEX VALUE PRODUCER VERIFIED] NO')
        print('[REPORT]',output)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as err:
        print('[STOP]',err,file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
