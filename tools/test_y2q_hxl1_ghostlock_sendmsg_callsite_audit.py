"""Offline HXL1 GhostLock original sendmsg static callsite provenance tests."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_ghostlock_sendmsg_callsite_audit as m

NAMES=m.original.prior.NAMES
COUNTS=[60,182,0,102,166,134,102,0]
BASE=0xffffff8008080000
WORD=bytes.fromhex("1f2003d5")

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def fixture(directory):
    functions=[]
    windows=[]
    for i,(name,n) in enumerate(zip(NAMES,COUNTS)):
        if n==0:
            functions.append({"symbol":name,"status":"NOT_FOUND_IN_RECOVERED_NM",
                              "compiledFunctionAbsent":False})
            windows.append({"symbol":name,"status":"NOT_FOUND_IN_RECOVERED_NM",
                            "compiledFunctionAbsenceProven":False})
            continue
        base=BASE+i*0x2000
        raw=WORD*n
        asm=("".join(f"{base+j*4:016x}:\td503201f\t.inst\t0xd503201f\n"
                     for j in range(n))).encode()
        (directory/(name+".bin")).write_bytes(raw)
        (directory/(name+".disasm.txt")).write_bytes(asm)
        decoded=m.original.parse_disasm(asm,raw,base)
        feat=m.original.structural_features(decoded)
        functions.append({
          "symbol":name,"status":"CODE_BYTES_AND_DISASSEMBLY_INDEPENDENTLY_VERIFIED",
          "staticImageVA":hex(base),
          "originalCodeSha256":digest(raw),
          "savedDisassemblySha256":digest(asm),
          "features":feat,
        })
        windows.append({
          "symbol":name,"status":"ORIGINAL_IMAGE_CODE_WINDOW",
          "staticImageVA":hex(base),
          "sampledBytes":len(raw),
          "sliceSha256":digest(raw),
          "disassembly":{"sha256":digest(asm)},
        })
    frame={
      "target":"SM-G986U1/G986U1UESCHXL1",
      "status":"ORIGINAL_CODE_ATTESTED_STACK_RELATIONSHIP_UNPROVEN",
      "originalImageIndependentlyRehashedByThisTool":True,
      "originalKernelSha256":"f"*64,
      "recoveredNmSha256":"e"*64,
      "upstreamWindowManifestSha256":m.EXPECTED_WINDOWS_SHA,
      "codeWindowsVerified":6,
      "requestedSymbols":8,
      "functions":functions,
    }
    for flag in ("exactOriginalCompilerStackObjectsKnown",
                 "danglingWaiterToSendmsgAliasVerified",
                 "runtimeKernelStackReuseVerified",
                 "ghostLockPrimitiveVerified","temporaryRootVerified",
                 "kernelSuLoaded"):
        frame[flag]=False
    window={
      "target":frame["target"],
      "status":"BOUNDED_STOCK_NATIVE_CODE_WINDOWS_NOT_STACK_GEOMETRY",
      "originalKernelSha256":frame["originalKernelSha256"],
      "recoveredNmSha256":frame["recoveredNmSha256"],
      "functions":windows,
    }
    return frame,window

class CachedStaticCallsiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name)
        self.frame,self.windows=fixture(self.directory)

    def check(self):
        return m.audit(self.frame,self.windows,self.directory)

    def test_full_six_functions_and_746_instruction_slots(self):
        result=self.check()
        self.assertEqual(result["verifiedOriginalInstructionSlots"],746)
        self.assertEqual(sum(x["status"]=="ORIGINAL_CALLSITES_REVIEWED"
                             for x in result["functions"]),6)
        self.assertFalse(result["sendmsgWaiterStackOverlapVerified"])
        self.assertFalse(result["temporaryRootVerified"])

    def test_unrecovered_names_are_not_claimed_absent(self):
        result=self.check()
        missing=[x for x in result["functions"] if x["status"]=="NAME_NOT_RECOVERED"]
        self.assertEqual([x["symbol"] for x in missing],
                         ["____sys_sendmsg","futex_wait_requeue_pi"])
        self.assertTrue(all(x["compilerEmittedFunctionAbsent"] is False for x in missing))

    def test_raw_bin_mutation_stops_before_correlation(self):
        (self.directory/"__sys_sendmsg.bin").write_bytes(b"\0"*240)
        with self.assertRaisesRegex(m.EvidenceError,"bytes/disassembly mismatch"):
            self.check()

    def test_disassembly_mutation_stops(self):
        p=self.directory/"__sys_sendmsg.disasm.txt"
        p.write_bytes(p.read_bytes()+b"untrusted\n")
        with self.assertRaisesRegex(m.EvidenceError,"bytes/disassembly mismatch"):
            self.check()

    def test_wrong_upstream_manifest_digest_stops(self):
        self.frame["upstreamWindowManifestSha256"]="0"*64
        with self.assertRaisesRegex(m.EvidenceError,"identity/count mismatch"):
            self.check()

    def test_wrong_original_kernel_identity_stops(self):
        self.windows["originalKernelSha256"]="0"*64
        with self.assertRaisesRegex(m.EvidenceError,"provenance mismatch"):
            self.check()

    def test_reordered_functions_stop(self):
        self.frame["functions"].reverse()
        with self.assertRaisesRegex(m.EvidenceError,"inventory mismatch"):
            self.check()

    def test_upstream_claim_of_root_stops(self):
        self.frame["temporaryRootVerified"]=True
        with self.assertRaisesRegex(m.EvidenceError,"Unproven positive claim"):
            self.check()

    def test_direct_call_near_sp_is_only_lexical(self):
        rows=[
          (0x100,"add","x9, sp, #0x38"),
          (0x104,"mov","x0, x9"),
          (0x108,"bl","0xffffff8008002000 <foo>"),
          (0x10c,"ret",""),
        ]
        feature={"spRelativeAddressConstructs":[
          {"staticImageVA":"0x100","instruction":"add x9, sp, #0x38"}]}
        result=m.callsite_summary(rows,feature)
        self.assertEqual(result["totalCalls"],1)
        self.assertEqual(result["calls"][0]["directTargetText"],"0xffffff8008002000")
        self.assertEqual(result["calls"][0]["nearbySpConstructionTextualOnly"][0]
                         ["linearInstructionDistance"],2)
        self.assertFalse(result["calls"][0]["pointerEscapeProved"])

    def test_branch_between_call_and_sp_is_expressly_flagged(self):
        rows=[(0x100,"mov","x2, sp"),(0x104,"b.eq","0x200"),
              (0x108,"bl","0xffffff8008082000")]
        r=m.callsite_summary(rows,{"spRelativeAddressConstructs":[
          {"staticImageVA":"0x100","instruction":"mov x2, sp"}]})
        self.assertTrue(r["calls"][0]["interveningBranchInTwelveInstructionWindow"])
        self.assertFalse(r["interproceduralDataflowVerified"])

    def test_indirect_blr_not_claimed_as_direct_target(self):
        result=m.callsite_summary([(0x100,"blr","x8")],
                                  {"spRelativeAddressConstructs":[]})
        self.assertEqual(result["indirectCalls"],1)
        self.assertIsNone(result["calls"][0]["directTargetText"])
        self.assertEqual(result["calls"][0]["indirectCallRegister"],"x8")

    def test_hash_exact_report_discovery_refuses_duplicates(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path)
            (root/"a.json").write_bytes(b"fixed")
            expected=digest(b"fixed")
            self.assertEqual(m.find_unique(root,"*.json",expected,200),
                             root/"a.json")
            (root/"b.json").write_bytes(b"fixed")
            with self.assertRaisesRegex(m.EvidenceError,"found 2"):
                m.find_unique(root,"*.json",expected,200)

    def test_standalone_cli_imports_outside_checkout(self):
        with tempfile.TemporaryDirectory() as path:
            result=subprocess.run(
                [sys.executable,"-I",str(Path(m.__file__).resolve()),"--help"],
                cwd=path,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("--evidence-dir",result.stdout)

if __name__=="__main__":
    unittest.main()
