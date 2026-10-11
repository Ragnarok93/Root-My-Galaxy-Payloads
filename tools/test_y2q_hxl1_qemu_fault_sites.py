"""Offline synthetic tests for exact HXL1 Image-relative QEMU fault attribution."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_qemu_fault_sites as t

def example_summary():
    return {
        "target":t.TARGET, "factoryImageTranslationCorrelated":True,
        "head":{"exceptionExamples":[
            {"lineInSample":501,"details":[
                "Taking exception 1 [Undefined Instruction] on CPU 0",
                "...from EL1 to EL1",
                "...with ESR 0x0/0x2000000",
                "...with ELR 0xffffff80080a5794"]},
            {"lineInSample":850,"details":[
                "Taking exception 4 [Data Abort] on CPU 0",
                "...from EL1 to EL1",
                "...with ESR 0x25/0x96000005",
                "...with FAR 0x58",
                "...with ELR 0xffffff80082ac90c"]},
            {"lineInSample":920,"details":[
                "Taking exception 4 [Data Abort] on CPU 0",
                "...with ESR 0x25/0x96000005",
                "...with FAR 0x10",
                "...with ELR 0xffffff80086de39c"]},
        ]},
        "tail":{"exceptionExamples":[]}
    }

class FaultSiteTests(unittest.TestCase):
    def test_exception_offsets_from_pinned_virtual_base(self):
        image=bytes(0x660000)  # zero fixture, NOT factory Samsung data
        data=t.build_report(example_summary(),image,{"status":"MISSING","entries":[]},None)
        self.assertEqual([e["originalImage"]["candidateImageOffset"]
                          for e in data["exceptions"]],
                         ["0x25794","0x22c90c","0x65e39c"])
        self.assertEqual([e["far"] for e in data["exceptions"]],[None,0x58,0x10])
        self.assertEqual(data["exceptions"][0]["esrDecoded"]["ec"],"0x0")
        self.assertEqual(data["exceptions"][1]["esrDecoded"]["ec"],"0x25")
        self.assertFalse(data["bootloaderUnlockOrRootProven"])
    def test_read_only_translation_level_one(self):
        x=t.decode_esr(0x96000005)
        self.assertEqual(x["faultClass"],"TRANSLATION_FAULT_LEVEL_1")
        self.assertEqual(x["memoryAccess"],"read")
        self.assertFalse(x["stage1WalkFaultFlag"])
    def test_writing_fault_decode(self):
        x=t.decode_esr(0x96000045)
        self.assertEqual(x["memoryAccess"],"write")
    def test_original_opcode_unchanged_from_image(self):
        image=bytearray(96)
        image[32:36]=bytes.fromhex("050040f9")
        area=t.window(bytes(image),t.VM_BASE+32,t.VM_BASE)
        self.assertEqual(area["candidateImageOffset"],"0x20")
        self.assertEqual(area["originalOpcode"],"f9400005")
        self.assertEqual(sum(w["faultingElr"] for w in area["words"]),1)
        self.assertEqual(area["status"],"ORIGINAL_STOCK_IMAGE_BYTES_FOUND")
    def test_elr_outside_image_cannot_resolve(self):
        result=t.window(bytes(32),t.VM_BASE+64,t.VM_BASE)
        self.assertEqual(result["status"],"ELR_OUTSIDE_OR_UNALIGNED_TO_ORIGINAL_IMAGE")
    def test_nearest_recovered_symbol_is_never_proof_of_function_membership(self):
        symbols={"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
                 "entries":[(t.VM_BASE+0x20000,"T","head_func"),
                            (t.VM_BASE+0x25780,"t","candidate_func")]}
        near=t.nearest_symbol(symbols,t.VM_BASE+0x25794)
        self.assertEqual(near["name"],"candidate_func")
        self.assertEqual(near["distance"],"0x14")
        self.assertIn("UNVERIFIED",near["status"])
    def test_nearest_symbol_missing_returns_status(self):
        self.assertEqual(t.nearest_symbol({"entries":[]},t.VM_BASE)["status"],
                         "NO_RECONSTRUCTED_TEXT_SYMBOL")
    def test_invalid_source_report_stops_before_attribution(self):
        bad=example_summary()
        bad["target"]="WRONG"
        with self.assertRaisesRegex(t.AttributionError,"evidence gate"):
            t.build_report(bad,bytes(0x660000),{"status":"MISSING","entries":[]},None)
    def test_malformed_exception_rejected(self):
        with self.assertRaisesRegex(t.AttributionError,"ELR"):
            t.parse_event({"details":["Taking exception 4 [Data Abort]"]},"head")
    def test_read_recovered_symbol_map(self):
        with tempfile.TemporaryDirectory() as dirname:
            p=Path(dirname)/"stock.nm"
            data=b"ffffff80080a5780 t candidate\nffffff80080a7000 T next\n"
            p.write_bytes(data)
            r=t.load_recovered_symbols(p)
            self.assertEqual(len(r["entries"]),2)
            self.assertEqual(r["sourceSha256"],hashlib.sha256(data).hexdigest())
    def test_read_missing_symbol_map_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as dirname:
            r=t.load_recovered_symbols(Path(dirname)/"absent.nm")
            self.assertEqual(r["status"],"MISSING_RECOVERED_SYMBOL_MAP")
    def test_direct_script_entrypoint_in_isolated_python(self):
        import subprocess
        with tempfile.TemporaryDirectory() as dirname:
            script=Path(t.__file__).resolve()
            result=subprocess.run([sys.executable,"-I",str(script),"--help"],
                                  cwd=dirname,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("--virtual-base",result.stdout)
    def test_report_rejects_unverified_factory_data(self):
        bad=example_summary()
        bad["factoryImageTranslationCorrelated"]=False
        with self.assertRaises(t.AttributionError):
            t.build_report(bad,bytes(0x660000),{"status":"MISSING","entries":[]},None)

if __name__=="__main__":
    unittest.main()
