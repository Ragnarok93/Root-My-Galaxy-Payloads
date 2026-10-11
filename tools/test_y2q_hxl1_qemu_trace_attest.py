"""Bounded offline trace matching tests. No QEMU launch or device access."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_qemu_trace_attest as t

def sample_image():
    image=bytearray(4096)
    image[0x38:0x3c]=b"ARM\x64"
    image[8:16]=(0x80000).to_bytes(8,"little")
    words={0:0x14000004,0x100:0xd2800000,0x104:0xf9400008,
           0x108:0x91000508,0x10c:0xd65f03c0}
    for off,w in words.items():image[off:off+4]=w.to_bytes(4,"little")
    return bytes(image)

def trace_for(base=0x40080000,include_header=True):
    w={0:0x14000004,0x100:0xd2800000,0x104:0xf9400008,
       0x108:0x91000508,0x10c:0xd65f03c0}
    if not include_header:del w[0]
    return ("IN:\n"+"\n".join(f"0x{base+off:016x}:  {word:08x}  nop" for off,word in w.items())+"\n").encode()

class OfflineImageTraceTests(unittest.TestCase):
    def test_multi_instruction_exact_stock_image(self):
        image=sample_image()
        r=t.analyze(image,trace_for(),b"",b"",[],len(trace_for()))
        self.assertEqual(r["evidenceStatus"],"FACTORY_IMAGE_INSTRUCTION_CORRELATION")
        a=r["candidateImageStarts"][0]
        self.assertTrue(a["headerEntryInstructionMatched"])
        self.assertTrue(a["multiInstructionBinaryCorrelation"])
        self.assertEqual(a["uniqueMatchingImageOffsets"],5)
        self.assertFalse(r["evidenceFlags"]["factoryKernelEntryIndependentlyEstablished"])
        self.assertFalse(r["evidenceFlags"]["rootOrKernelSuVerified"])
    def test_only_bootstub_does_not_equal_kernel(self):
        image=sample_image()
        trace=b"IN:\n0x0000000040000000:  580000c0 ldr x0, #0\n"
        r=t.analyze(image,trace,b"",b"",[],len(trace))
        self.assertFalse(r["evidenceFlags"]["factoryImageCorrelatedInHead"])
        self.assertEqual(r["candidateImageStarts"][0]["uniqueMatchingImageOffsets"],0)
    def test_bad_opcode_not_a_positive_match(self):
        image=sample_image()
        trace=trace_for().replace(b"d2800000",b"d2800001")
        r=t.analyze(image,trace,b"",b"",[],len(trace))
        a=r["candidateImageStarts"][0]
        self.assertEqual(a["mismatchedWordComparisons"],1)
        self.assertEqual(a["uniqueMatchingImageOffsets"],4)
        self.assertEqual(a["firstMismatch"]["imageOffset"],"0x100")
    def test_repeated_nops_not_sufficient(self):
        image=sample_image()
        trace=("IN:\n"+"\n".join(f"0x{0x40080100+off:x}:  d503201f nop" for off in (0,4,8,12))).encode()
        r=t.analyze(image,trace,b"",b"",[],len(trace))
        self.assertFalse(r["candidateImageStarts"][0]["multiInstructionBinaryCorrelation"])
    def test_tail_is_distinct_from_head(self):
        image=sample_image()
        tail=trace_for()
        r=t.analyze(image,b"",tail,b"",[],len(tail))
        self.assertFalse(r["evidenceFlags"]["factoryImageCorrelatedInHead"])
        self.assertTrue(r["evidenceFlags"]["factoryImageCorrelatedInTail"])
    def test_candidate_custom_base(self):
        image=sample_image()
        alt=0xc7800000
        trace=trace_for(alt)
        r=t.analyze(image,trace,b"",b"",[alt],len(trace))
        self.assertTrue(r["candidateImageStarts"][2]["multiInstructionBinaryCorrelation"])
        self.assertFalse(r["candidateImageStarts"][0]["multiInstructionBinaryCorrelation"])
    def test_original_sha_must_match(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"kernel.bin";p.write_bytes(sample_image())
            with self.assertRaisesRegex(t.EvidenceError,"digest mismatch"):
                t.checked_image(p)
            with patch.object(t,"KERNEL_HASH",hashlib.sha256(sample_image()).hexdigest()):
                self.assertEqual(t.checked_image(p),sample_image())
    def test_parse_out_of_range_trace(self):
        x=b"IN:\n0x0000000040080100:  d2800000  mov x0, #0\nbadline\n"
        self.assertEqual(list(t.parsed_words(x)),[(0x40080100,0xd2800000)])
    def test_refuse_unaligned_extra_base(self):
        with self.assertRaisesRegex(t.EvidenceError,"4-byte aligned"):
            t.candidate_bases(sample_image(),[0x40080001])
    def test_trace_file_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"trace.log"
            p.write_bytes(b"A"*32 + trace_for())
            head,tail,size=t.sample_trace(p)
            self.assertEqual(size,len(head))
            self.assertEqual(tail,b"")

if __name__=="__main__":
    unittest.main()
