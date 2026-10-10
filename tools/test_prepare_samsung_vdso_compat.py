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

    def test_format_option_creates_new_three_patch_tree_without_mutating_vdso_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            stock, vdso = self.fixture(temp)
            original_line = (
                '        pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);\n'
            )
            (stock / "init").mkdir()
            (stock / module.INIT_MAIN).write_text(
                "void init_ropp(void) {\n" + original_line +
                "        BUG_ON(0 != ropp_master_key);\n}\n"
            )
            before = module.tree_digest(stock)
            with patch.object(module, "source_gate"):
                _, _, default_patches = module.plan(stock, vdso, stock / "audit.json")
            base_manifest = module.create(stock, vdso, default_patches)
            before_vdso = module.tree_digest(vdso)
            expanded = Path(temp) / "new-format-source"
            with patch.object(module, "source_gate"):
                _, _, formatted_patches = module.plan(
                    stock, expanded, stock / "audit.json", format_fix=True
                )
            self.assertEqual(set(formatted_patches), set(module.PATCHES) | {module.INIT_MAIN})
            self.assertEqual(formatted_patches[module.INIT_MAIN]["replacements"], 1)
            manifest = module.create(stock, expanded, formatted_patches)
            self.assertEqual(manifest["schema"], 2)
            self.assertEqual(manifest["kind"], module.FORMAT_KIND)
            self.assertIn(
                'mk=%llx\\n", (unsigned long long)ropp_master_key);',
                (expanded / module.INIT_MAIN).read_text()
            )
            self.assertEqual(module.verify_compat(stock, expanded)["schema"], 2)
            self.assertEqual(module.verify_compat(stock, vdso)["schema"], 1)
            self.assertEqual(module.tree_digest(stock), before)
            self.assertEqual(module.tree_digest(vdso), before_vdso)
            self.assertEqual(base_manifest["kind"], module.VDSO_KIND)

    def test_format_patch_requires_one_exact_original_call(self):
        good = 'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);'
        changed, count = module.upstream_fixes(good, module.INIT_MAIN)
        self.assertEqual(count, 1)
        self.assertIn(
            'mk=%llx\\n", (unsigned long long)ropp_master_key);', changed
        )
        with self.assertRaisesRegex(ValueError, "expected 1 exact matches"):
            module.upstream_fixes(good + "\n" + good, module.INIT_MAIN)
        with self.assertRaisesRegex(ValueError, "expected 1 exact matches"):
            module.upstream_fixes(changed, module.INIT_MAIN)

    def test_format_compat_manifest_rejects_mutated_security_source(self):
        with tempfile.TemporaryDirectory() as temp:
            stock, new = self.fixture(temp)
            (stock / "init").mkdir()
            (stock / module.INIT_MAIN).write_text(
                'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);\n'
            )
            with patch.object(module, "source_gate"):
                _, _, edits = module.plan(stock, new, stock / "audit.json", True)
            module.create(stock, new, edits)
            (new / module.INIT_MAIN).write_text("malicious change\n")
            with self.assertRaisesRegex(ValueError, "patched compatibility file changed"):
                module.verify_compat(stock, new)

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
