"""Synthetic regression tests: isolated copied source, exact stable patches, tree digests."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("prepare_samsung_vdso_compat.py")
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("samsung_vdso_compat", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VdsoCompatTests(unittest.TestCase):
    def fixture(self, location):
        root = Path(location)
        stock = root / "stock"
        (stock / "arch/arm64/kernel/vdso").mkdir(parents=True)
        (stock / "include/linux").mkdir(parents=True)
        (stock / "Makefile").write_text("VERSION = 4\nPATCHLEVEL = 19\n")
        (stock / module.VDSO).write_text(
            ".macro clock_gettime_return shift=0\n.endm\n"
            + "\tclock_gettime_return, shift=1\n" * 3
        )
        (stock / module.ELFNOTE).write_text(
            '#define ELFNOTE(name, type, desc) \\\n'
            '\tELFNOTE_START(name, type, "") \\\n'
            '\tdesc;\n'
        )
        (stock / "arch/arm64/readme").write_text("do not change\n")
        (stock / "unmodified-link").symlink_to("arch/arm64/readme")
        return stock, root / "compat"

    def test_precise_upstream_replacements_and_preserve_stock(self):
        with tempfile.TemporaryDirectory() as temporary:
            stock, dest = self.fixture(temporary)
            before = module.tree_digest(stock)
            with patch.object(module, "source_gate"):
                orig, target, patches = module.plan(stock, dest, stock / "audit.json")
            self.assertEqual(orig, stock)
            self.assertEqual(target, dest)
            self.assertEqual(patches[module.VDSO]["replacements"], 3)
            self.assertEqual(patches[module.ELFNOTE]["replacements"], 1)
            manifest = module.create(stock, dest, patches)
            self.assertEqual(module.tree_digest(stock), before)
            self.assertEqual(manifest["stockTreeSha256"], before)
            self.assertTrue((dest / "unmodified-link").is_symlink())
            self.assertEqual(
                (dest / module.VDSO).read_text().count("clock_gettime_return shift=1"), 3)
            self.assertIn('ELFNOTE_START(name, type, "a")',
                          (dest / module.ELFNOTE).read_text())
            self.assertEqual(module.verify_compat(stock, dest)["compatTreeSha256"],
                             module.tree_digest(dest))

    def test_refuse_changed_expected_macro_or_note_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            stock, dest = self.fixture(temporary)
            (stock / module.VDSO).write_text("no legacy macro calls\n")
            with patch.object(module, "source_gate"):
                with self.assertRaisesRegex(ValueError, "expected 3 precise matches"):
                    module.plan(stock, dest, stock / "audit.json")
            self.assertFalse(dest.exists())

    def test_refuse_modified_experimental_or_original_trees(self):
        with tempfile.TemporaryDirectory() as temporary:
            stock, dest = self.fixture(temporary)
            with patch.object(module, "source_gate"):
                _, _, changes = module.plan(stock, dest, stock / "audit.json")
            module.create(stock, dest, changes)
            (dest / "arch/arm64/readme").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "compatibility source tree mutated"):
                module.verify_compat(stock, dest)
            (dest / "arch/arm64/readme").write_text("do not change\n")
            (stock / "arch/arm64/readme").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "stock source changed"):
                module.verify_compat(stock, dest)

    def test_refuse_existing_destination_even_when_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            stock, dest = self.fixture(temporary)
            dest.mkdir()
            with patch.object(module, "source_gate"):
                with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                    module.plan(stock, dest, stock / "audit.json")
            self.assertEqual(list(dest.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
