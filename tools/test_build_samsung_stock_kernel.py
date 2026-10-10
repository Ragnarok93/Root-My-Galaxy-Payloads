"""Regression tests for guarded, stock-only Samsung HXL1 off-device Image build."""
import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("build_samsung_stock_kernel.py")
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("build_y2q_stock_kernel", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def create_exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)


def mocked_preflight():
    return {
        "makefileVersion": {"matchesExpected": True},
        "overlayVerification": {"verified": 40},
        "deviceConfigs": {"openw": {"matchesOfficialAudit": True},
                          "singlew": {"matchesOfficialAudit": True}},
    }


class ImageBuildPlanTests(unittest.TestCase):
    def setup_case(self, temporary):
        root = Path(temporary)
        source = root / "samsung-stock"
        output = root / "kconfig-clang18"
        source.mkdir()
        output.mkdir()
        makefile = source / "Makefile"
        makefile.write_text("VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\n")
        config = output / ".config"
        config.write_text("CONFIG_ARCH_QCOM=y\nCONFIG_CLANG_VERSION=180103\n")
        clang = root / "clang"
        cross_prefix = str(root / "aarch64-linux-gnu-")
        for executable in (clang, Path(cross_prefix + "gcc"), Path(cross_prefix + "ld"),
                           source / "tools/dtc"):
            create_exe(executable)
        comparison = {
            "firmware": module.FIRMWARE,
            "generatedConfig": str(config),
            "generatedSha256": module.sha256_file(config),
            "runningConfigGzSha256": module.RUNNING_CONFIG_GZ_SHA256,
            "generatedVsRunning": {
                "matchingExplicitSymbols": 5790,
                "differentExplicitSymbols": 1,
                "different": [{"symbol": "CONFIG_CLANG_VERSION",
                               "generated": "180103", "running": "100006"}],
                "leftOnly": [],
                "rightOnly": [f"CONFIG_MACH_UNUSED_{i:02d}" for i in range(18)],
            },
            "critical": {key: {"generated": "y", "running": "y", "match": True}
                         for key in module.CRITICAL},
        }
        comparison_path = root / "comparison.json"
        comparison_path.write_text(json.dumps(comparison))
        args = argparse.Namespace(
            source_dir=source,
            output_dir=output,
            audit_json=root / "audit.json",
            comparison_json=comparison_path,
            clang=clang,
            gcc_prefix=cross_prefix,
            jobs=2,
            execute=False,
            log=None,
            json=root / "dry-run.json",
        )
        return args, comparison, makefile, config

    def test_python2_missing_is_reported_before_make(self):
        with patch.object(module.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "Install real Python 2.7"):
                module.find_python2()

    def test_python3_executable_is_not_accepted_as_python2(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "python2"
            create_exe(binary)
            class Version:
                returncode = 0
                stdout = "3.12"
                stderr = ""
            with patch.object(module.subprocess, "run", return_value=Version()):
                with self.assertRaisesRegex(ValueError, "genuine Python 2.7"):
                    module.find_python2(binary)

    def test_python2_path_validates_real_27(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "python2"
            create_exe(binary)
            class Version:
                returncode = 0
                stdout = "2.7"
                stderr = ""
            with patch.object(module.subprocess, "run", return_value=Version()) as run:
                self.assertEqual(module.find_python2(binary), str(binary))
                self.assertEqual(run.call_args.args[0][0], str(binary))
            with self.assertRaisesRegex(ValueError, "name an executable 'python2'"):
                module.find_python2(Path(tmp) / "python2.7")

    def test_dry_run_uses_only_stock_image_target_and_does_not_modify_files(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            before = (makefile.read_bytes(), config.read_bytes())
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"):
                result, report_path = module.plan(args)
            self.assertEqual(result["command"][-1], "Image")
            self.assertIn("O=" + str(args.output_dir), result["command"])
            self.assertIn("REAL_CC=" + str(args.clang), result["command"])
            self.assertIn("CFP_CC=" + str(args.clang), result["command"])
            self.assertEqual(result["compilerRouting"]["CFP_CC"], str(args.clang))
            self.assertEqual(result["compilerRouting"]["REAL_CC"], str(args.clang))
            self.assertEqual(result["command"].count("CFP_CC=" + str(args.clang)), 1)
            self.assertIn("-j2", result["command"])
            self.assertEqual(result["status"], "dry_run")
            self.assertEqual(report_path, args.json)
            self.assertEqual((makefile.read_bytes(), config.read_bytes()), before)
            self.assertFalse((args.output_dir / "arch/arm64/boot/Image").exists())

    def test_probe_requires_cross_assembler_and_checks_external_route(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            prefix = args.gcc_prefix
            with self.assertRaisesRegex(ValueError, "AArch64 GNU assembler not executable"):
                module.check_arm64_external_assembler(args.clang, prefix)
            create_exe(Path(prefix + "as"))
            class ProbeResult:
                returncode = 0
                stdout = ""
                stderr = (prefix + "as") + " -EL\\n"
            with patch.object(module.subprocess, "run", return_value=ProbeResult()) as run:
                observed = module.check_arm64_external_assembler(args.clang, prefix)
                self.assertEqual(observed["assembler"], prefix + "as")
                invoked = run.call_args.args[0]
                self.assertIn("--target=aarch64-linux-gnu", invoked)
                self.assertIn("-no-integrated-as", invoked)
                self.assertIn("-B" + prefix, invoked)

    def test_integrated_arm64_probe_compiles_elf64_aarch64_disposable_object(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, _, _ = self.setup_case(temp)
            class Driver:
                returncode = 0
                stdout = ""
                stderr = (
                    ' "/usr/bin/clang" "-cc1" "-triple" "aarch64-unknown-linux-gnu" '
                    '"-emit-obj" "-o" "/dev/null"'
                )
            class Compiler:
                returncode = 0
                stdout = ""
                stderr = ""
            observed_commands = []
            def call(command, **kwargs):
                observed_commands.append(command)
                if "-###" in command:
                    return Driver()
                target = Path(command[-1])
                target.write_bytes(
                    b"\x7fELF" + bytes([2, 1, 1]) + bytes(11)
                    + b"\xb7\x00" + bytes(32)
                )
                return Compiler()
            with patch.object(module.subprocess, "run", side_effect=call):
                result = module.check_arm64_integrated_assembler(args.clang)
            self.assertEqual(result["mode"], "clang-integrated-aarch64")
            self.assertTrue(result["actualObjectCompiled"])
            self.assertIn("--prefix=/usr/bin/", observed_commands[0])
            self.assertLess(observed_commands[0].index("-no-integrated-as"),
                            observed_commands[0].index("-integrated-as"))

    def test_integrated_arm64_probe_refuses_external_host_as(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, _, _ = self.setup_case(temp)
            class BadDriver:
                returncode = 0
                stdout = ""
                stderr = ' "/usr/bin/as" "-EL" "-o" "/dev/null"'
            with patch.object(module.subprocess, "run", return_value=BadDriver()):
                with self.assertRaisesRegex(ValueError, "did not select integrated"):
                    module.check_arm64_integrated_assembler(args.clang)

    def test_opt_in_integrated_assembler_routes_kcflags_and_kaflags(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, makefile, config = self.setup_case(temp)
            args.integrated_arm64_as = True
            args.verbose = True
            unchanged = (makefile.read_bytes(), config.read_bytes())
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"), \
                 patch.object(module, "check_arm64_integrated_assembler",
                              return_value={"mode": "clang-integrated-aarch64", "actualObjectCompiled": True}):
                result, _ = module.plan(args)
            self.assertIn("KCFLAGS=--target=aarch64-linux-gnu -integrated-as", result["command"])
            self.assertIn("KAFLAGS=--target=aarch64-linux-gnu -integrated-as", result["command"])
            self.assertEqual(result["command"][-1], "Image")
            self.assertEqual((makefile.read_bytes(), config.read_bytes()), unchanged)

    def test_assembler_modes_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, makefile, config = self.setup_case(temp)
            args.integrated_arm64_as = True
            args.external_arm64_as = True
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"):
                with self.assertRaisesRegex(ValueError, "choose one assembler mode"):
                    module.plan(args)

    def test_opt_in_external_assembler_adds_target_flags_without_source_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            args.external_arm64_as = True
            args.verbose = True
            before = (makefile.read_bytes(), config.read_bytes())
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"), \
                 patch.object(module, "check_arm64_external_assembler",
                              return_value={"assembler": args.gcc_prefix + "as"}):
                result, _ = module.plan(args)
            self.assertIn("KCFLAGS=--target=aarch64-linux-gnu -B" + args.gcc_prefix,
                          result["command"])
            self.assertIn("KAFLAGS=--target=aarch64-linux-gnu -B" + args.gcc_prefix,
                          result["command"])
            self.assertIn("V=1", result["command"])
            self.assertEqual(result["crossAssemblerProbe"]["assembler"], args.gcc_prefix + "as")
            self.assertEqual((makefile.read_bytes(), config.read_bytes()), before)

    def test_rejects_unexpected_security_difference(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            comparison["critical"]["CONFIG_UH_RKP"]["match"] = False
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)):
                with self.assertRaisesRegex(ValueError, "platform/security"):
                    module.check_comparison(comparison, args.output_dir)

    def test_rejects_additional_config_delta(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            comparison["generatedVsRunning"]["different"].append(
                {"symbol": "CONFIG_MODULE_SIG_FORCE", "generated": "n", "running": "y"}
            )
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)):
                with self.assertRaisesRegex(ValueError, "exceed audited"):
                    module.check_comparison(comparison, args.output_dir)

    def test_rejects_config_file_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            config.write_text("CONFIG_CLANG_VERSION=180103\nCONFIG_MODULES=n\n")
            with self.assertRaisesRegex(ValueError, "unexpected .config checksum"):
                module.plan(args)

    def test_build_requires_explicit_external_log_and_rejects_preexisting_image(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            args.execute = True
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"):
                with self.assertRaisesRegex(ValueError, "requires --log"):
                    module.plan(args)
                args.log = args.output_dir / "bad.log"
                with self.assertRaisesRegex(ValueError, "outside kernel source"):
                    module.plan(args)
                args.log = Path(temp) / "kernel-build.log"
                result, _ = module.plan(args)
                self.assertEqual(result["log"], str(args.log))
                image = args.output_dir / "arch/arm64/boot/Image"
                image.parent.mkdir(parents=True)
                image.write_bytes(b"already compiled")
                with self.assertRaisesRegex(ValueError, "Image already exists"):
                    module.plan(args)


if __name__ == "__main__":
    unittest.main()
