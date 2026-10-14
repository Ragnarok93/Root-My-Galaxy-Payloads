"""HXL1 original sendmsg instruction/manifest attestation fail-closed regressions."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_ghostlock_sendmsg_frame_attest as m

BASE=m.gate.IMAGE_VA
CODE=bytes.fromhex("ff8300d1ff830091")  # AArch64 sub sp,#0x20; add sp,#0x20

def sha(value):
    return hashlib.sha256(value).hexdigest()

def fixture(path:Path):
    image=bytearray(0x1000)
    image[0x38:0x3c]=b"ARM\x64"
    image[0x100:0x108]=CODE
    image=bytes(image)
    nm=f"{BASE:x} T _text\n{BASE+0x100:x} t __sys_sendmsg\n{BASE+0x108:x} t after\n".encode()
    asm=(f"{BASE+0x100:016x}:\td10083ff\tsub\tsp, sp, #0x20\n"
         f"{BASE+0x104:016x}:\t910083ff\tadd\tsp, sp, #0x20\n").encode()
    (path/"__sys_sendmsg.bin").write_bytes(CODE)
    (path/"__sys_sendmsg.disasm.txt").write_bytes(asm)
    functions=[]
    for name in m.prior.NAMES:
        if name=="__sys_sendmsg":
            functions.append({
                "symbol":name,"status":"ORIGINAL_IMAGE_CODE_WINDOW",
                "staticImageVA":hex(BASE+0x100),
                "imageRelativeOffset":"0x100",
                "nextRecoveredTextVA":hex(BASE+0x108),
                "originalFullTextIntervalBytes":8,
                "sampledBytes":8,"capped":False,"sliceSha256":sha(CODE),
                "nativeBytesFile":name+".bin",
                "disassembly":{"status":"SAVED_NATIVE_DISASSEMBLY",
                               "filename":name+".disasm.txt","sha256":sha(asm)}
            })
        else:
            functions.append({"symbol":name,"status":"NOT_FOUND_IN_RECOVERED_NM",
                              "compiledFunctionAbsenceProven":False})
    report={
        "schemaVersion":1,
        "target":"SM-G986U1/G986U1UESCHXL1",
        "status":"BOUNDED_STOCK_NATIVE_CODE_WINDOWS_NOT_STACK_GEOMETRY",
        "originalKernelSha256Verified":True,
        "originalKernelSha256":sha(image),
        "staticImageTextVA":hex(BASE),
        "recoveredNmSha256":sha(nm),
        "requestedSymbols":8,
        "boundedCodeWindows":1,
        "functions":functions,
        "exactCompiledWaiterLocalIdentified":False,
        "sendmsgFrameAliasVerified":False,
        "crossSyscallLifetimeReclamationVerified":False,
        "actualGhostLockPrimitiveOrRootVerified":False,
        "physicalKernelHandoffVerified":False,
    }
    return report,image,nm

class FrameAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)
        self.report,self.image,self.nm=fixture(self.path)
        self.pin=patch.object(m.gate,"STOCK_SHA",sha(self.image))
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def audit(self):
        return m.audit(self.report,self.image,self.nm,self.path)

    def test_real_opcodes_word_order_and_static_stack_adjustments(self):
        result=self.audit()
        self.assertEqual(result["codeWindowsVerified"],1)
        w=result["functions"][0]
        self.assertEqual(w["features"]["instructionSlotsChecked"],2)
        self.assertEqual(w["features"]["literalSpAdjustments"]["staticEntryBytes"],32)
        self.assertFalse(w["features"]["compilerLocalVariablesRecovered"])
        self.assertFalse(result["danglingWaiterToSendmsgAliasVerified"])

    def test_mutated_original_kernel_image_rejected(self):
        self.image=self.image[:-1]+b"x"
        with self.assertRaisesRegex(m.VerifyError,"independent original kernel"):
            self.audit()

    def test_changed_saved_bin_rejected(self):
        (self.path/"__sys_sendmsg.bin").write_bytes(b"\0"*8)
        with self.assertRaisesRegex(m.VerifyError,"cached raw function bytes"):
            self.audit()

    def test_changed_saved_disasm_digest_rejected(self):
        with (self.path/"__sys_sendmsg.disasm.txt").open("ab") as fp:
            fp.write(b"another line\n")
        with self.assertRaisesRegex(m.VerifyError,"disassembly SHA mismatch"):
            self.audit()

    def test_modified_opcode_even_if_disasm_digest_updated_rejected(self):
        path=self.path/"__sys_sendmsg.disasm.txt"
        raw=path.read_bytes().replace(b"d10083ff",b"d10087ff")
        path.write_bytes(raw)
        self.report["functions"][0]["disassembly"]["sha256"]=sha(raw)
        with self.assertRaisesRegex(m.VerifyError,"word differs"):
            self.audit()

    def test_gnu_unknown_inst_still_accounts_for_authenticated_machine_word(self):
        path=self.path/"__sys_sendmsg.disasm.txt"
        raw=path.read_bytes().replace(b"\tsub\t",b"\t.inst\t")
        path.write_bytes(raw)
        self.report["functions"][0]["disassembly"]["sha256"]=sha(raw)
        result=self.audit()
        self.assertEqual(result["functions"][0]["features"]["instructionSlotsChecked"],2)
        self.assertFalse(result["exactOriginalCompilerStackObjectsKnown"])

    def test_disasm_missing_one_slot_rejected(self):
        path=self.path/"__sys_sendmsg.disasm.txt"
        raw=path.read_bytes().splitlines(keepends=True)[0]
        path.write_bytes(raw)
        self.report["functions"][0]["disassembly"]["sha256"]=sha(raw)
        with self.assertRaisesRegex(m.VerifyError,"missing disassembly instruction slots"):
            self.audit()

    def test_reordered_manifest_function_entries_rejected(self):
        self.report["functions"].reverse()
        with self.assertRaisesRegex(m.VerifyError,"reordered"):
            self.audit()

    def test_false_missing_name_rejected(self):
        self.report["functions"][0]["status"]="NOT_FOUND_IN_RECOVERED_NM"
        self.report["functions"][0]["compiledFunctionAbsenceProven"]=False
        with self.assertRaisesRegex(m.VerifyError,"unverified absence"):
            self.audit()

    def test_wrong_next_text_symbol_rejected(self):
        self.report["functions"][0]["nextRecoveredTextVA"]=hex(BASE+0x10c)
        with self.assertRaisesRegex(m.VerifyError,"code interval provenance"):
            self.audit()

    def test_premature_runtime_overlap_claim_in_input_is_rejected(self):
        self.report["sendmsgFrameAliasVerified"]=True
        with self.assertRaisesRegex(m.VerifyError,"improperly certifies"):
            self.audit()

    def test_premature_exploit_claim_in_input_is_rejected(self):
        self.report["actualGhostLockPrimitiveOrRootVerified"]=True
        with self.assertRaisesRegex(m.VerifyError,"improperly certifies"):
            self.audit()

    def test_unpinned_recovered_nm_digest_rejected(self):
        self.nm+=b"incorrect"
        with self.assertRaisesRegex(m.VerifyError,"recovered nm SHA mismatch"):
            self.audit()

    def test_no_missing_symbol_promotion_to_factory_absence(self):
        result=self.audit()
        missing=[x for x in result["functions"] if x["status"]=="NOT_FOUND_IN_RECOVERED_NM"]
        self.assertEqual(len(missing),7)
        self.assertTrue(all(x["compiledFunctionAbsent"] is False for x in missing))

    def test_direct_entry_help_runs_outside_repository(self):
        with tempfile.TemporaryDirectory() as other:
            p=subprocess.run([sys.executable,"-I",str(Path(m.__file__).resolve()),"--help"],
                             cwd=other,capture_output=True,text=True,timeout=15)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("--report",p.stdout)
        self.assertNotIn("ModuleNotFoundError",p.stderr)

if __name__=="__main__":
    unittest.main()
