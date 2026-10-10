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

                stderr = '"' + (prefix + "as") + '" "-EL"'
            with patch.object(module.subprocess, "run", return_value=ProbeResult()) as run:
                observed = module.check_arm64_external_assembler(args.clang, prefix)
                self.assertEqual(observed["assembler"], prefix + "as")
                invoked = run.call_args.args[0]
                self.assertIn("--target=aarch64-linux-gnu", invoked)
                self.assertIn("-no-integrated-as", invoked)
                self.assertIn("-B" + prefix, invoked)

    def test_external_assembler_probe_rejects_host_prefix_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, _, _ = self.setup_case(temp)
            create_exe(Path(args.gcc_prefix + "as"))
            class HostSelected:
                returncode = 0
                stdout = ""
                stderr = ' "/usr/bin/as" "-EL" "-o" "/dev/null"'
            with patch.object(module.subprocess, "run", return_value=HostSelected()) as run:
                with self.assertRaisesRegex(ValueError, "still routes"):
                    module.check_arm64_external_assembler(args.clang, args.gcc_prefix)
                self.assertIn("--prefix=/usr/bin/", run.call_args.args[0])
                self.assertIn("-no-integrated-as", run.call_args.args[0])

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

    def test_cross_linker_probe_checks_actual_aarch64_dso(self):
        with tempfile.TemporaryDirectory() as folder:
            args, _, _, _ = self.setup_case(folder)
            linker = Path(args.gcc_prefix + "ld")
            invocation_list = []
            class Outcome:
                def __init__(self, stderr=""):
                    self.returncode = 0
                    self.stdout = ""
                    self.stderr = stderr
            def exec_probe(command, **kwargs):
                invocation_list.append(command)
                if "-###" in command:
                    return Outcome(' "' + str(linker) + '" "-m" "aarch64linux"')
                target = Path(command[-1])
                target.write_bytes(
                    b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
                    + b"\x03\x00" + b"\xb7\x00" + bytes(32)
                )
                return Outcome()
            with patch.object(module.subprocess, "run", side_effect=exec_probe):
                validated = module.check_arm64_cross_linker(args.clang, linker)
            self.assertEqual(validated["linker"], str(linker))
            self.assertTrue(validated["actualSharedObjectLinked"])
            self.assertIn("--prefix=/usr/bin/", invocation_list[0])
            self.assertIn("--ld-path=" + str(linker), invocation_list[1])
            self.assertIn(module.CROSS_LINKER_UNUSED_ARG_SUPPRESSION, invocation_list[1])

    def test_cross_linker_probe_rejects_native_host_linker(self):
        with tempfile.TemporaryDirectory() as folder:
            args, _, _, _ = self.setup_case(folder)
            class BadDriver:
                returncode = 0
                stdout = ""
                stderr = ' "/usr/bin/ld" "-m" "aarch64linux"'
            with patch.object(module.subprocess, "run", return_value=BadDriver()):
                with self.assertRaisesRegex(ValueError, "did not select requested ARM64"):
                    module.check_arm64_cross_linker(args.clang, Path(args.gcc_prefix + "ld"))

    def test_linker_override_is_scoped_and_preserves_all_build_fingerprints(self):
        with tempfile.TemporaryDirectory() as folder:
            args, _, makefile, config = self.setup_case(folder)
            args.integrated_arm64_as = True
            args.cross_arm64_linker = True
            args.suppress_cgroup_layout_warning = True
            unchanged = (makefile.read_bytes(), config.read_bytes())
            linker = Path(args.gcc_prefix + "ld")
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"), \
                 patch.object(module, "check_arm64_integrated_assembler",
                              return_value={"mode": "clang-integrated-aarch64"}), \
                 patch.object(module, "check_cgroup_layout_warning_compat",
                              return_value={"suppression": module.CGROUP_SUPPRESSION}), \
                 patch.object(module, "check_arm64_cross_linker",
                              return_value={"linker": str(linker)}) as checked:
                result, _ = module.plan(args)
            checked.assert_called_once_with(args.clang, linker)
            command = result["command"]
            flags = next(x for x in command if x.startswith("KCFLAGS="))
            asm_flags = next(x for x in command if x.startswith("KAFLAGS="))
            self.assertIn("--ld-path=" + str(linker), flags)
            self.assertIn(module.CROSS_LINKER_UNUSED_ARG_SUPPRESSION, flags)
            self.assertIn(module.CGROUP_SUPPRESSION, flags)
            self.assertNotIn("--ld-path=", asm_flags)
            self.assertNotIn("-Wno-unused-command-line-argument", asm_flags)
            self.assertEqual((makefile.read_bytes(), config.read_bytes()), unchanged)

    def test_cross_linker_without_integrated_as_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            args, _, makefile, config = self.setup_case(folder)
            args.cross_arm64_linker = True
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"):
                with self.assertRaisesRegex(ValueError, "requires --integrated-arm64-as"):
                    module.plan(args)

    def test_cgroup_warning_probe_detects_and_suppresses_only_named_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, _, _ = self.setup_case(temp)
            class Result:
                returncode = 0
                stdout = ""
                stderr = ""
            executed = []
            def run(command, **kwargs):
                executed.append((command, kwargs))
                instance = Result()
                if module.CGROUP_SUPPRESSION not in command:
                    instance.stderr = "warning: cgroup struct [-Wgnu-variable-sized-type-not-at-end]"
                return instance
            with patch.object(module.subprocess, "run", side_effect=run):
                result = module.check_cgroup_layout_warning_compat(args.clang)
            self.assertTrue(result["diagnosticObservedBefore"])
            self.assertTrue(result["diagnosticAbsentAfter"])
            self.assertEqual(len(executed), 2)
            self.assertIn(module.CGROUP_SUPPRESSION, executed[1][0])
            self.assertIn("-fsyntax-only", executed[0][0])
            self.assertNotIn("-w", executed[1][0])

    def test_cgroup_warning_mode_requires_integrated_arm64_assembler(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, makefile, config = self.setup_case(temp)
            args.suppress_cgroup_layout_warning = True
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"):
                with self.assertRaisesRegex(ValueError, "requires --integrated-arm64-as"):
                    module.plan(args)

    def test_cgroup_warning_compat_changes_only_c_compiler_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _, makefile, config = self.setup_case(temp)
            args.integrated_arm64_as = True
            args.suppress_cgroup_layout_warning = True
            args.verbose = True
            untouched = (makefile.read_bytes(), config.read_bytes())
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"), \
                 patch.object(module, "check_arm64_integrated_assembler",
                              return_value={"mode": "clang-integrated-aarch64", "actualObjectCompiled": True}), \
                 patch.object(module, "check_cgroup_layout_warning_compat",
                              return_value={"suppression": module.CGROUP_SUPPRESSION}):
                result, _ = module.plan(args)
            cmd = result["command"]
            self.assertIn("KCFLAGS=--target=aarch64-linux-gnu -integrated-as " +
                          module.CGROUP_SUPPRESSION, cmd)
            self.assertIn("KAFLAGS=--target=aarch64-linux-gnu -integrated-as", cmd)
            self.assertNotIn("KAFLAGS=--target=aarch64-linux-gnu -integrated-as " +
                             module.CGROUP_SUPPRESSION, cmd)
            self.assertNotIn("-w", " ".join(cmd))
            self.assertEqual(result["cgroupLayoutWarningCompatibilityProbe"]["suppression"],
                             module.CGROUP_SUPPRESSION)
            self.assertEqual((makefile.read_bytes(), config.read_bytes()), untouched)

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

    def test_separate_upstream_compatibility_source_is_opt_in_and_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _, makefile, config = self.setup_case(temporary)
            alternative = Path(temporary) / "isolated-vdso-source"
            alternative.mkdir()
            (alternative / "Makefile").write_bytes(makefile.read_bytes())
            create_exe(alternative / "tools/dtc")
            args.compat_source_dir = alternative
            original = config.read_bytes()
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"), \
                 patch.object(module, "verify_compat",
                              return_value={"firmware": module.FIRMWARE}) as verifier:
                result, _ = module.plan(args)
            verifier.assert_called_once_with(args.source_dir, alternative)
            self.assertEqual(result["buildSource"], str(alternative))
            self.assertIn(str(alternative), result["command"])
            self.assertIn("DTC_EXT=" + str(alternative / "tools/dtc"), result["command"])
            self.assertEqual(config.read_bytes(), original)
            self.assertEqual(result["upstreamCompatibilityManifest"]["firmware"],
                             module.FIRMWARE)

    def test_refuse_compat_tree_with_mutated_stock_makefile(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _, makefile, config = self.setup_case(temporary)
            alternative = Path(temporary) / "isolated-vdso-source"
            alternative.mkdir()
            (alternative / "Makefile").write_text("untrusted makefile")
            create_exe(alternative / "tools/dtc")
            args.compat_source_dir = alternative
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"), \
                 patch.object(module, "find_python2", return_value="/opt/legacy/python2"):
                with self.assertRaisesRegex(ValueError, "unexpected Samsung Makefile"):
                    module.plan(args)

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
