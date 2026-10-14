"""Fail-closed HXL1-vs-K40 GhostLock 4.19 static compatibility gate tests."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_ghostlock_crossfork_419_gate as m

def fixtures(path:Path):
    sam=path/"samsung"
    fork=path/"fork"
    source={
        "kernel/locking/rtmutex.c":
            "static void remove_waiter(void) { current->pi_blocked_on = NULL; }\n"
            "void f(void) { waiter->task; }\n",
        "kernel/futex.c":"int futex_requeue(void) { return 0; }\n",
        "net/socket.c":"int __sys_sendmsg(void) {return 0;}\n",
        "fs/read_write.c":"int rw_copy_check_uvector(void) {return 0;}\n",
    }
    pins={}
    for rel,content in source.items():
        f=sam/rel;f.parent.mkdir(parents=True,exist_ok=True)
        f.write_text(content)
        if rel in ("kernel/locking/rtmutex.c","kernel/futex.c"):
            pins[rel]=hashlib.sha256(content.encode()).hexdigest()
    docs={
        "docs/status.md":
            "| 4 Root Chain | blocked | Eng | blocked by M3 |\n"
            "H1A-S2 sendmsg returned ret=65540 errno=0\n"
            "H1A-S2 deterministic TCP blocking redesign\n",
        "docs/specs/kernel-frame-placement-enumeration.md":
            "TCP sendmsg iovstack[8] stacked adjacent address\n",
        "docs/specs/rt-waiter-placement-audit.md":
            "futex_wait_requeue_pi owns an rt_waiter\n",
    }
    hashes={}
    for rel,content in docs.items():
        f=fork/rel;f.parent.mkdir(parents=True,exist_ok=True)
        f.write_text(content)
        hashes[rel]=m.git_blob_id(content.encode())
    return sam,fork,pins,hashes

class CrossForkTests(unittest.TestCase):
    def test_git_blob_hash_object_equivalence(self):
        raw=b"abc\n"
        self.assertEqual(m.git_blob_id(raw),
                         hashlib.sha1(b"blob 4\x00abc\n").hexdigest())

    def test_synthetic_fork_reference_is_bounded_and_not_samsung(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            r=m.verify_reference(fork,hashes)
        self.assertEqual(r["rootChainStatus"],"BLOCKED_IN_THIS_PINNED_REFERENCE_REVISION")
        self.assertFalse(r["k40PhysicalConstantsPortable"])

    def test_full_fork_audit_does_not_promote_deployable_target(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            r=m.audit(sam,fork,source_pins=pins,fork_pins=hashes)
        self.assertTrue(r["conclusions"]["originalSamsungSourcePathCorroborated"])
        for gate in ("originalFactoryCompiledWaiterObjectPlacementVerified",
                     "identicalSendmsgStackGeometryDemonstrated",
                     "runtimeGhostLockRootVerified",
                     "readyToGenerateHxl1TargetHeader"):
            self.assertFalse(r["conclusions"][gate])
        self.assertFalse(r["deviceModified"])

    def test_original_samsung_source_hash_change_fails(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            (sam/"kernel/futex.c").write_text("modified")
            with self.assertRaisesRegex(ValueError,"SHA mismatch"):
                m.audit(sam,fork,source_pins=pins,fork_pins=hashes)

    def test_fork_reference_changed_fails_and_cannot_promote(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            with (fork/"docs/status.md").open("a") as f:
                f.write("changed revision")
            with self.assertRaisesRegex(m.AuditStop,"revision drift"):
                m.audit(sam,fork,source_pins=pins,fork_pins=hashes)

    def test_fork_root_milestone_must_be_blocked_in_pinned_doc(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            status=fork/"docs/status.md"
            status.write_text(status.read_text().replace(
                "| 4 Root Chain | blocked |", "| 4 Root Chain | complete |"))
            hashes["docs/status.md"]=m.git_blob_id(status.read_bytes())
            with self.assertRaisesRegex(m.AuditStop,"root-chain blocked"):
                m.verify_reference(fork,hashes)

    def test_fork_sendmsg_failure_is_required_and_not_assumed(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            status=fork/"docs/status.md"
            status.write_text(status.read_text().replace("ret=65540","ret=0"))
            hashes["docs/status.md"]=m.git_blob_id(status.read_bytes())
            with self.assertRaisesRegex(m.AuditStop,"failure/redesign"):
                m.verify_reference(fork,hashes)

    def test_missing_additional_vendor_source_is_not_factory_proof(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            (sam/"net/socket.c").unlink()
            r=m.audit(sam,fork,source_pins=pins,fork_pins=hashes)
        self.assertEqual(r["additionalSamsungSource"]["net/socket.c"]["status"],
                         "SOURCE_NOT_AVAILABLE")
        self.assertFalse(r["conclusions"]["identicalSendmsgStackGeometryDemonstrated"])

    def test_original_source_missing_bug_path_fails_even_when_hash_pinned(self):
        with tempfile.TemporaryDirectory() as d:
            sam,fork,pins,hashes=fixtures(Path(d))
            rt=sam/"kernel/locking/rtmutex.c"
            rt.write_text("static void remove_waiter(void){}\n")
            pins["kernel/locking/rtmutex.c"]=hashlib.sha256(rt.read_bytes()).hexdigest()
            with self.assertRaisesRegex(m.AuditStop,"GhostLock path"):
                m.audit(sam,fork,source_pins=pins,fork_pins=hashes)

    def test_outside_cwd_cli_help_imports_without_tools_module_error(self):
        script=Path(m.__file__).resolve()
        with tempfile.TemporaryDirectory() as d:
            res=subprocess.run([sys.executable,"-I",str(script),"--help"],
                               cwd=d,capture_output=True,text=True,timeout=15)
        self.assertEqual(res.returncode,0,res.stderr)
        self.assertIn("--reference-fork",res.stdout)
        self.assertNotIn("ModuleNotFoundError",res.stderr)

if __name__=="__main__":
    unittest.main()
