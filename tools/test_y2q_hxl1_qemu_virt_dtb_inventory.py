"""Synthetic device-tree and safe-dump tests; never launches a real QEMU guest."""
from pathlib import Path
import os
import struct
import subprocess
import tempfile
import unittest
from tools import y2q_hxl1_qemu_virt_dtb_inventory as d

ROOT=Path(__file__).resolve().parent
CAPTURE=ROOT/"run_y2q_hxl1_qemu_virt_dtb_capture.sh"

def make_dtb(reserve=((0x60000000,0x10000),),
             memory=(0x40000000,0x80000000),reserved=True):
    # Synthetic standard version-17 flattened device tree.
    names={}
    string_blob=bytearray()
    tokens=bytearray()
    def nameoff(s):
        if s not in names:
            names[s]=len(string_blob)
            string_blob.extend(s.encode()+b"\0")
        return names[s]
    def align():
        while len(tokens)%4:tokens.append(0)
    def begin(name):
        tokens.extend(struct.pack(">I",1))
        tokens.extend(name.encode()+b"\0")
        align()
    def end():
        tokens.extend(struct.pack(">I",2))
    def prop(key,val):
        tokens.extend(struct.pack(">III",3,len(val),nameoff(key)))
        tokens.extend(val)
        align()
    def w32(*xs):return struct.pack(">"+("I"*len(xs)),*xs)
    begin("")
    prop("#address-cells",w32(2))
    prop("#size-cells",w32(2))
    begin("memory@40000000")
    prop("device_type",b"memory\0")
    prop("reg",w32(0,memory[0],0,memory[1]))
    end()
    begin("chosen")
    prop("linux,initrd-start",w32(0,0x43a00000))
    prop("linux,initrd-end",w32(0,0x43b00000))
    end()
    if reserved:
        begin("reserved-memory")
        prop("#address-cells",w32(2))
        prop("#size-cells",w32(2))
        prop("ranges",b"")
        begin("test-reserved@60000000")
        prop("reg",w32(0,0x60000000,0,0x10000))
        prop("no-map",b"")
        end()
        end()
    end()
    tokens.extend(struct.pack(">I",9))
    rsv=b"".join(struct.pack(">QQ",a,b) for a,b in reserve)+struct.pack(">QQ",0,0)
    off_rsv=40
    off_struct=off_rsv+len(rsv)
    off_strings=off_struct+len(tokens)
    total=off_strings+len(string_blob)
    header=struct.pack(">10I",d.MAGIC,total,off_struct,off_strings,
                       off_rsv,17,16,0,len(string_blob),len(tokens))
    return header+rsv+tokens+string_blob

class VirtDtbTests(unittest.TestCase):
    def test_realistic_virt_ram_and_reservation(self):
        data=make_dtb()
        out=d.parse_fdt(data)
        self.assertEqual(out["memoryRanges"][0]["start"],"0x40000000")
        self.assertEqual(out["memoryRanges"][0]["endExclusive"],"0xc0000000")
        self.assertEqual(out["memoryReservationEntries"][0]["start"],"0x60000000")
        self.assertEqual(out["reservedMemoryRanges"][0]["sizeBytes"],65536)
        self.assertEqual(out["chosenInitrd"]["linux,initrd-start"],"0x43a00000")
        self.assertFalse(out["suitableProtectedPoolProven"])
        self.assertFalse(out["guestLinuxMemblockReservationProven"])
    def test_no_reservation_does_not_imply_free_memory(self):
        out=d.parse_fdt(make_dtb(reserve=(),reserved=False))
        self.assertEqual(out["reservedMemoryRanges"],[])
        self.assertEqual(out["memoryReservationEntries"],[])
        self.assertFalse(out["reservedMemoryNodePresent"])
        self.assertIn("does NOT identify empty",out["warning"])
    def test_invalid_magic_refused(self):
        original=bytearray(make_dtb())
        original[0]=0
        with self.assertRaisesRegex(d.FdtError,"magic"):
            d.parse_fdt(bytes(original))
    def test_broken_node_token_refused(self):
        original=bytearray(make_dtb())
        off=struct.unpack_from(">I",original,8)[0]
        struct.pack_into(">I",original,off,0xff)
        with self.assertRaisesRegex(d.FdtError,"token"):
            d.parse_fdt(bytes(original))
    def test_truncated_fdt_refused(self):
        with self.assertRaises(d.FdtError):
            d.parse_fdt(make_dtb()[:32])
    def test_invalid_reg_cell_count_refused(self):
        with self.assertRaisesRegex(d.FdtError,"length"):
            d.reg_pairs(b"\0"*4,2,2)
    def test_phys_range_overflow_and_zero_rejected(self):
        with self.assertRaises(d.FdtError):d.checked_range(0x1000,0)
        with self.assertRaises(d.FdtError):d.checked_range(2**64-8,16)
    def test_source_only_never_reserves_real_ram(self):
        import inspect
        code=inspect.getsource(d)
        self.assertNotIn("cpu_physical_memory_write",code)
        self.assertNotIn("address_space_write",code)
        self.assertIn("suitableProtectedPoolProven",code)
    def test_dump_script_bash_syntax(self):
        result=subprocess.run(["bash","-n",str(CAPTURE)],
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_dump_does_not_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"old"
            p.mkdir()
            (p/"evidence").write_text("keep")
            result=subprocess.run(["bash",str(CAPTURE),str(p)],
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn("Output already exists",result.stderr)
            self.assertEqual((p/"evidence").read_text(),"keep")
    def test_dump_invalid_image_refused_before_qemu(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"s20-artifacts").mkdir()
            (root/"s20-artifacts/kernel.bin").write_bytes(b"not stock")
            out=root/"dump"
            env=os.environ.copy()
            env["HOME"]=str(root)
            result=subprocess.run(["bash",str(CAPTURE),str(out)],
                                  env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn("Image SHA mismatch",result.stderr)
            self.assertFalse(out.exists())

if __name__=="__main__":
    unittest.main()
