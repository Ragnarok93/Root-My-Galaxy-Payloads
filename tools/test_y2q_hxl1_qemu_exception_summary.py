"""No-device tests for HXL1 offline QEMU exception and image-location summary."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_qemu_exception_summary as t

def correlated_report():
    return {
        "target":"SM-G986U1/G986U1UESCHXL1",
        "evidenceStatus":"FACTORY_IMAGE_INSTRUCTION_CORRELATION",
        "candidateImageStarts":[{
            "candidateImagePhysicalStart":"0x40080000",
            "multiInstructionBinaryCorrelation":True,
            "uniqueMatchingImageOffsets":270,
            "traceWordComparisonsInImageRange":288,
            "mismatchedWordComparisons":6,
            "firstMismatch":{"pc":"0x40080100","imageOffset":"0x100"},
            "headerEntryInstructionMatched":True,
            "matchesEnd":["0x200","0x204","0x208"],
        }]
    }

class ExistingTraceSummaryTests(unittest.TestCase):
    def test_exception_context_and_translated_pc_logged(self):
        head=(b"IN:\n0x0000000040080000:  14000004 b +16\n"
              b"Taking exception 4 [Data Abort]\n"
              b"...from EL1 to EL1\n...with ESR 0x25/0x96000010\n"
              b"...with FAR 0x104010ca28\n...with ELR 0x400195d8\n"
              b"...to EL1 PC 0x40018200 PSTATE 0x3c5\n")
        output=t.extract_events(head)
        self.assertEqual(output["exceptionLineCount"],1)
        self.assertTrue(any("with ESR" in line for line in output["exceptionExamples"][0]["details"]))
        self.assertEqual(output["firstTranslatedGuestPcOpcode"][0]["pc"],"0x40080000")
        self.assertEqual(output["lastTranslatedGuestPcOpcode"][0]["pc"],"0x40080000")
    def test_user_evidence_summary_does_not_promote_boot(self):
        original=t.correlated_report if hasattr(t,"correlated_report") else correlated_report
        report=original() if callable(original) else correlated_report()
        output=t.summarize(report,b"IN:\n0x40080000: 14000004 nop\n",b"",23,b"")
        self.assertEqual(output["matchedOriginalImageOffsets"],270)
        self.assertEqual(output["mismatchedOpcodeComparisons"],6)
        self.assertFalse(output["lastExecutedPcEstablished"])
        self.assertFalse(output["hxl1UserspaceBootProven"])
        self.assertFalse(output["rootOrKernelSuProven"])
    def test_wrong_target_rejected(self):
        report=correlated_report()
        report["target"]="ANOTHER_DEVICE"
        with self.assertRaisesRegex(t.SummaryError,"Wrong trace"):
            t.summarize(report,b"",b"",0,b"")
    def test_no_correlated_hxl1_code_rejected(self):
        report=correlated_report()
        report["candidateImageStarts"][0]["uniqueMatchingImageOffsets"]=0
        with self.assertRaisesRegex(t.SummaryError,"Too few"):
            t.summarize(report,b"",b"",0,b"")
    def test_empty_sample_contains_no_false_exceptions(self):
        e=t.extract_events(b"")
        self.assertEqual(e["exceptionLineCount"],0)
        self.assertEqual(e["firstTranslatedGuestPcOpcode"],[])
        self.assertEqual(e["lastTranslatedGuestPcOpcode"],[])
    def test_guest_error_distinct_from_exception(self):
        e=t.extract_events(b"unimplemented device access\nnot relevant\n")
        self.assertEqual(e["exceptionLineCount"],0)
        self.assertEqual(len(e["signalExamples"]),1)
    def test_direct_script_entry_point_in_python_isolated_mode(self):
        # This invokes the actual user command shape, not package import.
        # -I removes PYTHONPATH and current-directory influence.
        script=Path(t.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="hxl1-exception-cli-") as dirname:
            child_env=os.environ.copy()
            child_env.pop("PYTHONPATH",None)
            result=subprocess.run(
                [sys.executable,"-I",str(script),"--help"],
                cwd=dirname,env=child_env,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("--report",result.stdout)
        self.assertIn("--trace",result.stdout)
    def test_direct_script_cli_stops_safely_before_overwriting_evidence(self):
        script=Path(t.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="hxl1-exception-guard-") as dirname:
            output=Path(dirname)/"existing.json"
            output.write_text('{"preserve":"original"}')
            result=subprocess.run(
                [sys.executable,"-I",str(script),"--output",str(output)],
                cwd=dirname,capture_output=True,text=True,timeout=15)
            self.assertEqual(output.read_text(),'{"preserve":"original"}')
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertIn("Use fresh JSON output",result.stderr)
        self.assertNotIn("Traceback",result.stderr)
    def test_source_does_not_start_emulator(self):
        # Static nonbehavior marker: parser relies on retained files only.
        self.assertIn("existing HXL1",t.__doc__)
        self.assertFalse(hasattr(t,"boot_qemu"))

if __name__=="__main__":
    unittest.main()
