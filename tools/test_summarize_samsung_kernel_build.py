"""Regression checks for compact Samsung Kbuild error extraction."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "samsung_build_summary", ROOT / "summarize_samsung_kernel_build.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BuildLogSummaryTests(unittest.TestCase):
    def test_correlate_parallel_interleaved_warnings_with_fatal_wrapper(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "build-09.log"
            log.write_text(
                "COMMAND: make V=1 Image\n"
                " /usr/bin/clang: -c init/main.c\n"
                "/root/include/linux/seq_buf.h:35:12: warning: bad char pointer [-Wpointer-sign]\n"
                "  clang -c other.c\n"
                "/root/init/main.c:720:3: warning: target attribute ignored [-Wattributes]\n"
                " /root/arch/arm64/kernel/entry.S:488:2: warning: DWARF2 only supports one section per compilation unit\n"
                "('error, forbidden warning:', 'main.c:720')\n"
                "make[2]: *** [init/main.o] Error 1\n"
            )
            result = module.scan_log(log)
            self.assertEqual(result["warningCount"], 3)
            self.assertEqual(result["forbiddenWarningCount"], 1)
            self.assertEqual(result["forbiddenWarningCategories"], {"-Wattributes": 1})
            exact = result["forbiddenWarnings"][0]
            self.assertEqual(exact["diagnostic"]["source"], "/root/init/main.c")
            self.assertEqual(exact["diagnostic"]["line"], 720)
            self.assertEqual(exact["diagnostic"]["category"], "-Wattributes")
            self.assertEqual(exact["logLine"], 7)
            self.assertEqual(len(result["buildErrors"]), 1)

    def test_unknown_warning_remains_unknown_and_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "partial.log"
            log.write_text(
                "('error, forbidden warning:', 'main.c:720')\n"
                "make: *** [Makefile:146: sub-make] Error 2\n"
            )
            result = module.scan_log(log)
            self.assertEqual(result["unresolvedForbiddenWarnings"], 1)
            self.assertEqual(result["forbiddenWarningCategories"], {})
            self.assertIsNone(result["forbiddenWarnings"][0]["diagnostic"])

    def test_diagnostic_category_and_filename_scoping(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "many.log"
            log.write_text(
                "/src/something/main.c:720:1: warning: unrelated [-Wuninitialized]\n"
                "/src/actual/main.c:720:1: warning: actual [-Wreturn-type]\n"
                "('error, forbidden warning:', 'main.c:720')\n"
                "/src/init/main.c:721:12: error: undefined function\n"
            )
            result = module.scan_log(log)
            self.assertEqual(
                result["forbiddenWarnings"][0]["diagnostic"]["category"], "-Wreturn-type"
            )
            self.assertEqual(result["otherDiagnostics"][0]["level"], "error")

    def test_missing_file_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "does not exist"):
                module.scan_log(Path(temp) / "not-there.log")


if __name__ == "__main__":
    unittest.main()
