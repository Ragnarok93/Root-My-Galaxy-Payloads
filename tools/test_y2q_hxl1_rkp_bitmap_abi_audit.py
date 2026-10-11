"""Offline RKP bitmap ABI checks on synthetic source/GDB fixtures only."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_rkp_bitmap_abi_audit as t

UH=r"""
#define APP_RKP 2
#define UH_PREFIX UL(0xc300c000)
#define UH_APPID(APP_ID)  ((UL(APP_ID) & UL(0xFF)) | UH_PREFIX)
#define UH_APP_RKP UH_APPID(APP_RKP)
int uh_call(u64 app_id,u64 command,u64 arg0,u64 arg1,u64 arg2,u64 arg3);
"""
RKP=r"""
enum __RKP_CMD_ID {
 RKP_START = 0x01,
 RKP_GET_RKP_GET_BUFFER_BITMAP = 0x15,
};
extern s64 memstart_addr;
static inline void rkp_robuffer_init(void)
{
 uh_call(UH_APP_RKP, RKP_GET_RKP_GET_BUFFER_BITMAP,
         (u64)&rkp_s_bitmap_buffer, (u64)memstart_addr, 0, 0);
}
"""
GDB=r"""The target architecture is set to "aarch64".
0x0000000040000000 in ?? ()
Hardware assisted breakpoint 1 at 0xffffff80080a5794
Breakpoint 1, 0xffffff80080a5794 in ?? ()
HXL1_SMC_BREAKPOINT_HIT PC=0xffffff80080a5794
X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000
X4=0x0 X5=0x0 X6=0x3f
0xffffff80080a5794:     0xd4000003
"""

class BitmapAbiTests(unittest.TestCase):
    def test_source_macros_identify_rkp_not_fork_kdp(self):
        x=t.parse_source(UH,RKP)
        self.assertEqual(x["computedUhAppRkp"],"0xc300c002")
        self.assertEqual(x["rkpGetBufferBitmapCommand"],"0x15")
        self.assertTrue(x["rkpRobufferInitPassesBitmapAndMemstart"])
    def test_real_register_fixture_identifies_call(self):
        g=t.parse_gdb_log(GDB)
        self.assertEqual(g["registers"]["X0"],"0xc300c002")
        self.assertEqual(g["registers"]["X1"],"0x15")
        self.assertEqual(g["registers"]["X2"],"0xffffff800a4dd0b8")
        self.assertEqual(g["registers"]["X3"],"0x40000000")
        self.assertEqual(g["registers"]["X6"],"0x3f")
    def test_fork_collision_is_not_hidden(self):
        source=t.parse_source(UH,RKP)
        log=t.parse_gdb_log(GDB)
        result=t.analyze(source,log,{"status":"RECOVERED_NM_UNAVAILABLE"}, {})
        self.assertTrue(result["sourceCallCompatible"])
        self.assertIn("RKP_BITMAP_CALL",result["abiOutcome"])
        self.assertEqual(result["criticalForkAbiCollision"]["forkNamesSameId"],"KDP")
        self.assertEqual(result["criticalForkAbiCollision"]["examinedSM8250KernelNamesSameId"],"RKP")
        self.assertFalse(result["sourceFaithfulGuestOrKernelSuProven"])
        self.assertFalse(result["x6IsAnUhCallArgument"])
    def test_conflicting_kernel_source_must_not_pass(self):
        src=t.parse_source(UH.replace("APP_RKP 2","APP_RKP 1"),RKP)
        out=t.analyze(src,t.parse_gdb_log(GDB),{"status":"MISSING"}, {})
        self.assertEqual(out["abiOutcome"],"LOCAL_SOURCE_ABI_MISMATCH_OR_UNVERIFIED")
        self.assertFalse(out["sourceCallCompatible"])
    def test_wrong_source_command_must_not_pass(self):
        src=t.parse_source(UH,RKP.replace("= 0x15","= 0x14"))
        out=t.analyze(src,t.parse_gdb_log(GDB),{"status":"MISSING"}, {})
        self.assertFalse(out["sourceCallCompatible"])
    def test_missing_robuffer_function_must_reject(self):
        with self.assertRaisesRegex(t.AuditError,"rkp_robuffer_init"):
            t.parse_source(UH,RKP.split("static inline void")[0])
    def test_mismatched_original_gdb_address_must_reject(self):
        with self.assertRaisesRegex(t.AuditError,"pinned original"):
            t.parse_gdb_log(GDB.replace("HXL1_SMC_BREAKPOINT_HIT PC=0xffffff80080a5794",
                                        "HXL1_SMC_BREAKPOINT_HIT PC=0xffffff80080a5798"))
    def test_missing_opcode_rejected(self):
        with self.assertRaisesRegex(t.AuditError,"stock SMC opcode"):
            t.parse_gdb_log(GDB.replace("0xd4000003","0xd4200000"))
    def test_missing_register_rejected(self):
        with self.assertRaisesRegex(t.AuditError,"X0-X6"):
            t.parse_gdb_log(GDB.replace("X6=0x3f",""))
    def test_recovered_symbol_x2_exact_identity(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"recovered.nm"
            p.write_text("ffffff800a4dd0b8 B rkp_s_bitmap_buffer\n"
                         "ffffff8008084000 T init_kernel\n")
            s=t.recovered_bitmap_symbol(p,0xffffff800a4dd0b8)
            self.assertEqual(s["status"],"RECOVERED_SYMBOL_ADDRESS_CORRELATES")
            self.assertTrue(s["addressMatched"])
    def test_mismatched_recovered_symbol_is_not_promoted(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"recovered.nm"
            p.write_text("ffffff800a4dd0b0 b rkp_s_bitmap_buffer\n")
            s=t.recovered_bitmap_symbol(p,0xffffff800a4dd0b8)
            self.assertEqual(s["status"],"RECOVERED_SYMBOL_ADDRESS_DIFFERS")
            self.assertFalse(s["addressMatched"])
    def test_missing_nm_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as d:
            s=t.recovered_bitmap_symbol(Path(d)/"missing.nm",0x40000000)
            self.assertEqual(s["status"],"RECOVERED_NM_UNAVAILABLE")
    def test_gdb_log_sha_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"captured.log";p.write_text(GDB)
            body,digest=t.secure_read(p)
            self.assertEqual(body,GDB)
            self.assertEqual(digest,hashlib.sha256(GDB.encode()).hexdigest())
    def test_direct_entrypoint_with_isolated_python(self):
        script=Path(t.__file__).resolve()
        with tempfile.TemporaryDirectory() as d:
            proc=subprocess.run([sys.executable,"-I",str(script),"--help"],
                               cwd=d,text=True,capture_output=True,timeout=15)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn("--source-root",proc.stdout)
    def test_no_guest_actions(self):
        self.assertIn("never launches QEMU",t.__doc__)
        self.assertFalse(hasattr(t,"run_qemu"))

if __name__=="__main__":
    unittest.main()
