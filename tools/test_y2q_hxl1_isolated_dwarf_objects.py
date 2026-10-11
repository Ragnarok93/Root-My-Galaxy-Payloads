#!/usr/bin/env python3
"""Independent tests of write-once off-device RT-mutex object compilation.

No host make, no Linux privilege changes and no phone. Mock object generation
while asserting source integrity, pinned Clang18 config, separate O=, strict
targets, failure termination and refusal to infer OEM offsets/KernelSU.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_isolated_dwarf_objects as tool


class IsolatedDwarfBuildTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.stock=root/"stock"
        self.clone=root/"compat"
        self.template=root/"old-objects"
        self.dest=root/"only-target-objects"
        self.log=root/"new-build.log"
        self.report=root/"new-build.json"
        self.audit=root/"official-source-audit.json"
        self.clang=root/"bin/clang"
        self.gcc_prefix=str(root/"bin/aarch64-linux-gnu-")
        self.source= self.stock/"Makefile"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("VERSION = 4\nPATCHLEVEL = 19\n")
        self.clone.mkdir()
        dtc=self.clone/"tools/dtc"
        dtc.parent.mkdir()
        self.template.mkdir()
        (self.template/".config").write_text(
            "CONFIG_ARCH_QCOM=y\nCONFIG_RT_MUTEXES=y\nCONFIG_FUTEX=y\n")
        for f in (dtc,self.clang,Path(self.gcc_prefix+"gcc"),Path(self.gcc_prefix+"ld")):
            f.parent.mkdir(parents=True,exist_ok=True)
            f.write_text("#!/bin/sh\nexit 0\n")
            f.chmod(0o755)
        self.audit.write_text("{}")
        self.args=argparse.Namespace(
            source=self.stock,clone=self.clone,template=self.template,
            output=self.dest,log=self.log,report=self.report,audit=self.audit,
            clang=self.clang,gcc_prefix=self.gcc_prefix,python2=None,
            jobs=2,execute=False,
        )

    def fake_manifest(self):
        from tools.prepare_samsung_vdso_compat import PATCHES
        return {"schema":3,"patches":{
            **{k:{"replacements":v["expectedReplacements"]}
               for k,v in PATCHES.items()},
            tool.INIT_MAIN:{"replacements":1},
            tool.ARM64_ALTERNATIVE:{"replacements":1},
        },"stockTreeSha256":"1"*64,"compatTreeSha256":"2"*64}

    def plan(self):
        def fingerprint(p):
            import hashlib
            with p.open("rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        with patch.object(tool.prior,"GENERATED_CONFIG_SHA256",
                          fingerprint(self.template/".config")):
            with patch.object(tool.prior,"MAKEFILE_SHA256",
                              fingerprint(self.source)):
                with patch.object(tool.prior,"source_preflight_run",return_value={
                    "makefileVersion":{"matchesExpected":True},
                    "overlayVerification":{"verified":40},
                    "deviceConfigs":{"openw":{"matchesOfficialAudit":True},
                                     "singlew":{"matchesOfficialAudit":True}}
                }):
                    with patch.object(tool,"verify_compat",return_value=self.fake_manifest()):
                        with patch.object(tool,"resolve_python2",return_value="/usr/bin/python2"):
                            return tool.plan(self.args)

    def test_python2_pyenv_installation_detected_without_global_path(self):
        private=self.stock.parent/".pyenv/versions/2.7.18/bin/python2"
        private.parent.mkdir(parents=True)
        private.write_text("#!/bin/sh\\n")
        private.chmod(0o755)
        class Interpreter:
            returncode=0
            stdout="2.7"
            stderr=""
        with patch.object(tool.shutil,"which",return_value=None):
            with patch.object(tool.prior.subprocess,"run",return_value=Interpreter()) as runner:
                found=tool.resolve_python2(None,home=self.stock.parent)
        self.assertEqual(found,str(private))
        self.assertEqual(runner.call_args.args[0][0],str(private))

    def test_python2_explicit_override_validated_with_real_27_check(self):
        private=self.stock.parent/"custom/python2"
        private.parent.mkdir(parents=True)
        private.write_text("#!/bin/sh\\n")
        private.chmod(0o755)
        class Interpreter:
            returncode=0
            stdout="2.7"
            stderr=""
        with patch.object(tool.prior.subprocess,"run",return_value=Interpreter()):
            self.assertEqual(tool.resolve_python2(private),str(private))

    def test_python2_explicit_fake_python3_cannot_be_accepted(self):
        private=self.stock.parent/"custom/python2"
        private.parent.mkdir(parents=True)
        private.write_text("#!/bin/sh\\n")
        private.chmod(0o755)
        class Interpreter:
            returncode=0
            stdout="3.12"
            stderr=""
        with patch.object(tool.prior.subprocess,"run",return_value=Interpreter()):
            with self.assertRaisesRegex(ValueError,"genuine Python 2.7"):
                tool.resolve_python2(private)

    def test_python2_path_alias_to_python3_not_permitted(self):
        private=self.stock.parent/"custom/python2"
        private.parent.mkdir(parents=True)
        private.write_text("#!/bin/sh\\n")
        private.chmod(0o755)
        class Interpreter:
            returncode=0
            stdout="3.9"
            stderr=""
        with patch.object(tool.shutil,"which",return_value=str(private)):
            with patch.object(tool.prior.subprocess,"run",return_value=Interpreter()):
                with self.assertRaisesRegex(ValueError,"genuine Python 2.7"):
                    tool.resolve_python2(None,home=self.stock.parent)

    def test_python2_not_installed_yields_explicit_remedy(self):
        with patch.object(tool.shutil,"which",return_value=None):
            with self.assertRaisesRegex(tool.TargetBuildError,"pyenv install 2.7.18"):
                tool.resolve_python2(None,home=self.stock.parent)

    def test_python2_shim_on_path_checked_as_python2_7(self):
        private=self.stock.parent/"bin/python2"
        private.parent.mkdir(parents=True)
        private.write_text("#!/bin/sh\\n")
        private.chmod(0o755)
        class Interpreter:
            returncode=0
            stdout="2.7"
            stderr=""
        with patch.object(tool.shutil,"which",return_value=str(private)):
            with patch.object(tool.prior.subprocess,"run",return_value=Interpreter()):
                self.assertEqual(tool.resolve_python2(None,home=self.stock.parent),str(private))

    def test_dry_run_never_writes_or_builds(self):
        info=self.plan()
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.log.exists())
        self.assertEqual(info["targetOutputs"],list(tool.TARGETS))
        self.assertFalse(info["factoryCompiledOffsetsVerified"])

    def test_exact_target_only_commands(self):
        info=self.plan()
        c=info["objectCommand"]
        self.assertEqual(c[-2:],list(tool.TARGETS))
        self.assertNotIn("Image",c)
        self.assertNotIn("modules",c)
        self.assertNotIn("flash",c)
        self.assertIn("O="+str(self.dest),c)
        self.assertIn("CFP_CC="+str(self.clang),c)
        self.assertIn("REAL_CC="+str(self.clang),c)
        self.assertTrue(any(x.startswith("KCFLAGS=") and "-integrated-as" in x for x in c))
        self.assertTrue(any(x.startswith("KAFLAGS=") and "-integrated-as" in x for x in c))

    def test_original_source_clone_and_build_paths_distinct(self):
        x=self.plan()
        self.assertEqual(x["source"],str(self.stock))
        self.assertEqual(x["experimentalClang18Source"],str(self.clone))
        self.assertEqual(x["previousClang18OutputUntouched"],str(self.template))
        self.assertNotEqual(x["freshOutput"],x["previousClang18OutputUntouched"])

    def test_original_factory_offset_not_promoted(self):
        x=self.plan()
        self.assertFalse(x["factoryCompiledOffsetsVerified"])
        self.assertFalse(x["physicalKernelBaseKnown"])
        self.assertFalse(x["rootOrKernelSUInstalled"])

    def test_existing_target_output_rejected(self):
        self.dest.mkdir()
        with self.assertRaisesRegex(tool.TargetBuildError,"reuse/overwrite"):
            self.plan()

    def test_symlinked_target_output_rejected(self):
        self.dest.symlink_to(self.template,target_is_directory=True)
        with self.assertRaisesRegex(tool.TargetBuildError,"reuse/overwrite"):
            self.plan()

    def test_output_inside_clone_rejected(self):
        self.args.output=self.clone/"children"
        with self.assertRaisesRegex(tool.TargetBuildError,"separate"):
            self.plan()

    def test_output_inside_old_build_rejected(self):
        self.args.output=self.template/"some-other"
        with self.assertRaisesRegex(tool.TargetBuildError,"separate"):
            self.plan()

    def test_invalid_jobs_rejected(self):
        for count in (0,-1,9,100):
            with self.subTest(jobs=count):
                self.args.jobs=count
                with self.assertRaisesRegex(tool.TargetBuildError,"jobs"):
                    self.plan()

    def test_source_log_or_report_cannot_overlap(self):
        self.args.report=self.clone/"report.json"
        with self.assertRaisesRegex(tool.TargetBuildError,"overlap"):
            self.plan()

    def test_existing_log_or_report_rejected(self):
        self.log.write_text("OLD LOG MUST REMAIN")
        with self.assertRaisesRegex(tool.TargetBuildError,"existing/symlinked"):
            self.plan()
        self.assertEqual(self.log.read_text(),"OLD LOG MUST REMAIN")

    def test_nonabsolute_gcc_cross_prefix_rejected(self):
        self.args.gcc_prefix="aarch64-linux-gnu-"
        with self.assertRaisesRegex(tool.TargetBuildError,"Absolute"):
            self.plan()

    def test_config_mismatch_rejected(self):
        orig=tool.prior.sha256_file
        def pinned(path):
            if path.name==".config":
                return "f"*64
            return orig(path)
        with patch.object(tool.prior,"GENERATED_CONFIG_SHA256","0"*64),patch.object(
            tool.prior,"sha256_file",side_effect=pinned):
            with self.assertRaisesRegex(tool.TargetBuildError,"hash"):
                tool.plan(self.args)

    def test_compat_manifest_must_include_four_exact_patch_paths(self):
        with patch.object(tool,"verify_compat",return_value={
            "schema":2,"patches":{},"stockTreeSha256":"a",
            "compatTreeSha256":"b"}):
            # Verify the manifest is rejected even with otherwise valid inputs.
            def shas(path):
                return (tool.prior.MAKEFILE_SHA256 if path.name=="Makefile"
                        else tool.prior.GENERATED_CONFIG_SHA256)
            with patch.object(tool.prior,"sha256_file",side_effect=shas),patch.object(
                tool.prior,"source_preflight_run",return_value={
                    "makefileVersion":{"matchesExpected":True},
                    "overlayVerification":{"verified":40},
                    "deviceConfigs":{"a":{"matchesOfficialAudit":True}}
                }),patch.object(tool.prior,"find_python2",return_value="/usr/bin/python2"):
                with self.assertRaisesRegex(tool.TargetBuildError,"manifest"):
                    tool.plan(self.args)

    def test_no_target_objects_in_failed_partial_output(self):
        self.dest.mkdir()
        obs=tool.inspect_targets(self.dest)
        self.assertEqual(set(obs),set(tool.TARGETS))
        self.assertTrue(all(v["status"]=="NOT_PRODUCED" for v in obs.values()))

    def test_non_elf_object_not_counted_as_factory_layout(self):
        self.dest.mkdir()
        o=self.dest/"kernel/futex.o"
        o.parent.mkdir(parents=True)
        o.write_bytes(b"invalid ELF")
        obs=tool.inspect_targets(self.dest)
        self.assertEqual(obs["kernel/futex.o"]["status"],"NOT_ELF")
        self.assertFalse(obs["kernel/futex.o"]["factoryLayoutAuthenticated"])

    def test_successful_mock_target_only_build_preserves_template(self):
        info=self.plan()
        expected=self.template.joinpath(".config").read_bytes()
        called=[]
        class Success:
            returncode=0
        def invoke(argv,**kwargs):
            called.append(argv[-1])
            return Success()
        with patch.object(tool.subprocess,"run",side_effect=invoke):
            result=tool.execute(info)
        self.assertEqual(result["phase"],"TARGET_COMMAND_COMPLETED")
        self.assertEqual(called,["olddefconfig","prepare",tool.TARGETS[-1]])
        self.assertEqual((self.template/".config").read_bytes(),expected)
        self.assertEqual((self.dest/".config").read_bytes(),expected)
        self.assertFalse(result["factoryAbiAuthenticated"])
        self.assertFalse(result["rootOrKernelSUInstalled"])

    def test_compiler_error_stops_before_later_phases(self):
        info=self.plan()
        class Failure:
            returncode=1
        with patch.object(tool.subprocess,"run",return_value=Failure()) as mock:
            result=tool.execute(info)
        self.assertEqual(mock.call_count,1)
        self.assertEqual(result["phase"],"COMPILATION_FAILED_olddefconfig")
        self.assertFalse(result["kernelImageCompiled"])
        self.assertTrue(self.log.exists())

    def test_mutated_kconfig_stops_before_compiling_targets(self):
        info=self.plan()
        class Success:
            returncode=0
        def mutate(argv,**kwargs):
            (self.dest/".config").write_text("COMPILER_CHANGED_CONFIG\n")
            return Success()
        with patch.object(tool.subprocess,"run",side_effect=mutate) as mock:
            result=tool.execute(info)
        self.assertEqual(mock.call_count,1)
        self.assertEqual(result["phase"],"PINNED_CONFIG_CHANGED_olddefconfig")
        self.assertTrue((self.dest/".config").exists())


if __name__=="__main__":
    unittest.main()
