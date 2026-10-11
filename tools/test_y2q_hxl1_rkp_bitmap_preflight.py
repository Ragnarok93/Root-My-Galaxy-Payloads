"""Synthetic source regression tests for the original HXL1 RKP QEMU preflight."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_rkp_bitmap_preflight as p

UH=r"""
#define APP_RKP 2
#define UH_PREFIX UL(0xc300c000)
#define UH_APPID(APP_ID) ((UL(APP_ID)&UL(0xFF))|UH_PREFIX)
"""
RKP=r"""
enum __RKP_CMD_ID{
 RKP_RKP_ROBUFFER_ALLOC = 0x11,
 RKP_RKP_ROBUFFER_FREE = 0x12,
 RKP_GET_RO_BITMAP = 0x13,
 RKP_GET_DBL_BITMAP = 0x14,
 RKP_GET_RKP_GET_BUFFER_BITMAP = 0x15
};
#define SPARSE_UNIT_BIT (30)
typedef struct sparse_bitmap_for_kernel {
 u64 start_addr;
 u64 end_addr;
 u64 maxn;
 char **map;
} sparse_bitmap_for_kernel_t;
static inline u8 rkp_check_bitmap(u64 pa, sparse_bitmap_for_kernel_t *kernel_bitmap, u8 overflow_ret, u8 uninitialized_ret){
 u64 offset, map_loc, bit_offset;
 offset = pa - kernel_bitmap->start_addr;
 map_loc = ((offset % SPARSE_UNIT_SIZE) / PAGE_SIZE) >> 3;
 bit_offset = ((offset % SPARSE_UNIT_SIZE) / PAGE_SIZE) % 8;
 if (kernel_bitmap->maxn <= (offset >> SPARSE_UNIT_BIT)) return overflow_ret;
 map = kernel_bitmap->map[(offset >> SPARSE_UNIT_BIT)];
 if (!map) return uninitialized_ret;
 val = (u8)map[map_loc];
 return val >> bit_offset & 1;
}
static inline void *rkp_ro_alloc(void) {
 u64 addr=0xDEAD;
 uh_call_static(UH_APP_RKP,RKP_RKP_ROBUFFER_ALLOC,(u64)&addr);
 if (addr==0xDEAD) BUG_ON(1);
 return __phys_to_virt(addr);
}
"""
MMU=r"""
void __init paging_init(void) {
 pgd_phys = early_pgtable_alloc();
 pgdp=pgd_set_fixmap(pgd_phys);
 #ifdef CONFIG_UH_RKP
 rkp_robuffer_init();
 #endif
 map_kernel(pgdp);
 map_mem(pgdp);
}
"""
MAIN=r"""
static void __init rkp_init(void){
 uh_call(UH_APP_RKP, RKP_GET_RO_BITMAP, (u64)&rkp_s_bitmap_ro, 0, 0, 0);
 uh_call(UH_APP_RKP, RKP_GET_DBL_BITMAP, (u64)&rkp_s_bitmap_dbl, 0, 0, 0);
 uh_call(UH_APP_RKP, RKP_START, (u64)&rkp_init_data, 0, 0, 0);
}
"""
PGD=r"""
pgd_t *pgd_alloc(struct mm_struct *mm) {
 #ifdef CONFIG_UH_RKP
 ret = (pgd_t *)rkp_ro_alloc();
 #endif
 return ret;
}
void pgd_free(struct mm_struct *mm, pgd_t *pgd){
 if (is_rkp_ro_page((unsigned long)pgd)) rkp_ro_free((void *)pgd);
}
"""

def sources():
    examples={"include/linux/uh.h":UH,"include/linux/rkp.h":RKP,
       "arch/arm64/mm/mmu.c":MMU,"init/main.c":MAIN,
       "arch/arm64/mm/pgd.c":PGD}
    return {name:{"text":v,"sha256":hashlib.sha256(v.encode()).hexdigest()}
            for name,v in examples.items()}

def abi(source=None):
    s=source or sources()
    return {"target":p.TARGET,"sourceCallCompatible":True,
     "sourceFiles":{"uhSha256":s["include/linux/uh.h"]["sha256"],
                    "rkpSha256":s["include/linux/rkp.h"]["sha256"]},
     "gdbCapture":{"registers":{"X0":"0xc300c002","X1":"0x15",
                                "X2":"0xffffff800a4dd0b8","X3":"0x40000000"}}}

class RkpBitmapPreflightTests(unittest.TestCase):
    def test_captured_hxl1_abi_sha_chain(self):
        a=p.verify_prior_abi(abi(),sources())
        self.assertEqual(a["status"],"PASSED_RECHECKED_SOURCE_DIGESTS_AND_SMC_CAPTURE")
    def test_changed_original_source_rejected(self):
        s=sources()
        s["include/linux/rkp.h"]["sha256"]="0"*64
        with self.assertRaisesRegex(p.PreflightError,"rkp.h changed"):
            p.verify_prior_abi(abi(),s)
    def test_wrong_smc_id_refused(self):
        a=abi();a["gdbCapture"]["registers"]["X0"]="0xc300c001"
        with self.assertRaisesRegex(p.PreflightError,"differ"):
            p.verify_prior_abi(a,sources())
    def test_source_bitmap_prerequisites_pass(self):
        w=p.source_witnesses(sources())
        self.assertTrue(w["allRequirementsConfirmed"],
          [k for k,v in w["checks"].items() if not v])
        self.assertEqual(w["commandIds"]["RKP_GET_RKP_GET_BUFFER_BITMAP"]["sourceValue"],"0x15")
        self.assertEqual(w["relevantWitnesses"]["bitmapSparseUnitBytes"],1<<30)
    def test_swapped_init_order_detected(self):
        s=sources()
        s["arch/arm64/mm/mmu.c"]["text"]=MMU.replace(
             "rkp_robuffer_init();","OTHER();").replace(
             "map_mem(pgdp);","rkp_robuffer_init();\n map_mem(pgdp);")
        w=p.source_witnesses(s)
        self.assertFalse(w["checks"]["pagingInvokesBitmapBeforeNormalMappings"])
        self.assertFalse(w["allRequirementsConfirmed"])
    def test_incompatible_command_id_detected(self):
        s=sources()
        s["include/linux/rkp.h"]["text"]=RKP.replace(
             "RKP_RKP_ROBUFFER_ALLOC = 0x11","RKP_RKP_ROBUFFER_ALLOC = 0x07")
        w=p.source_witnesses(s)
        self.assertFalse(w["checks"]["commandIdsMatchCapturedHxl1"])
    def test_missing_descriptor_field_detected(self):
        s=sources()
        s["include/linux/rkp.h"]["text"]=RKP.replace("char **map;","u64 placeholder;")
        w=p.source_witnesses(s)
        self.assertFalse(w["checks"]["sparseBitmapHasStartEndMaxnAndMap"])
    def test_bitmap_page_size_obtained_from_config(self):
        with tempfile.TemporaryDirectory() as td:
            x=Path(td)/"config"
            x.write_text("CONFIG_UH_RKP=y\nCONFIG_ARM64_4K_PAGES=y\n")
            result=p.read_kernel_config(x)
            self.assertEqual(result["pageSizeBytes"],4096)
            self.assertTrue(result["CONFIG_UH_RKP"])
    def test_config_missing_does_not_invent_page_size(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(p.read_kernel_config(Path(td)/"none")["status"],"UNAVAILABLE")
    def test_complete_source_does_not_claim_emulator_ready(self):
        result=p.preflight(abi(),sources(),{"pageSizeBytes":4096})
        self.assertTrue(result["exactSourceFindings"]["allRequirementsConfirmed"])
        self.assertFalse(result["qemuAdapterReadiness"]["SourceFaithfulEmulatorReady"])
        self.assertFalse(result["qemuAdapterReadiness"]["UHProtectedPagePoolReservedAndAllocated"])
    def test_direct_cli_import_from_unrelated_directory(self):
        script=Path(p.__file__).resolve()
        with tempfile.TemporaryDirectory() as td:
            proc=subprocess.run([sys.executable,"-I",str(script),"--help"],cwd=td,
                                text=True,capture_output=True,timeout=15)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn("--prior-abi",proc.stdout)
    def test_tool_is_offline_by_construction(self):
        self.assertIn("Never starts QEMU",p.__doc__)
        self.assertFalse(hasattr(p,"write_guest"))
    def test_extract_c_function_nested_braces(self):
        src="static int rkp_check_bitmap(void) { if (x) { return 1; } return 0; }"
        self.assertIn("return 0;",p.extract_c_body(src,"rkp_check_bitmap"))
    def test_refuse_missing_prior_proof_gate(self):
        x=abi();x["sourceCallCompatible"]=False
        with self.assertRaisesRegex(p.PreflightError,"not an exact-source match"):
            p.preflight(x,sources(),{})
if __name__=="__main__":
    unittest.main()
