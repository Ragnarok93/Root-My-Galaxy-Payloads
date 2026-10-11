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

    def alternative_fixture(self,stock,old=True):
        alt=stock/module.ARM64_ALTERNATIVE
        alt.parent.mkdir(parents=True,exist_ok=True)
        symbol="_ASM_EXTABLE" if old else "_asm_extable"
        alt.write_text(
            "#include <asm/assembler.h>\n"
            ".macro other, foo\n"
            " _ASM_EXTABLE 5b, 6f\n"
            ".endm\n"
            ".macro user_alt, label, oldinstr, newinstr, cond\n"
            '9999: alternative_insn "\\oldinstr", "\\newinstr", \\cond\n'
            f"    {symbol} 9999b, \\label\n"
            ".endm\n"
            ".macro another, x\n"
            " _ASM_EXTABLE 5b, 6f\n"
            ".endm\n"
        )
        return alt

    def test_exact_upstream_arm64_alternative_patch_in_user_alt_only(self):
        with tempfile.TemporaryDirectory() as path:
            stock,dest=self.fixture(path)
            alt=self.alternative_fixture(stock)
            original=alt.read_bytes()
            updated,n=module.upstream_fixes(alt.read_text(),module.ARM64_ALTERNATIVE)
            self.assertEqual(n,1)
            self.assertIn("    _asm_extable 9999b, \\label",updated)
            self.assertIn(" _ASM_EXTABLE 5b, 6f",updated)
            self.assertEqual(alt.read_bytes(),original)

    def test_arm64_ias_patch_refuses_prepatched_unchanged_source(self):
        with tempfile.TemporaryDirectory() as path:
            stock,_=self.fixture(path)
            alt=self.alternative_fixture(stock,old=False)
            with self.assertRaisesRegex(ValueError,"expected 1 exact matches"):
                module.upstream_fixes(alt.read_text(),module.ARM64_ALTERNATIVE)

    def test_arm64_ias_patch_refuses_different_macro_and_no_broad_replacement(self):
        for input_text in (
            ".macro user_alt, label, oldinstr, newinstr, cond\n"
            "  _ASM_EXTABLE 9999b, \\label\n.endm\n",
            ".macro user_alt, label, oldinstr, newinstr, cond\n"
            "9999: alternative_insn nop, nop, 0\n"
            "  _ASM_EXTABLE 9999b, 8f\n.endm\n",
            ".macro nothing, x\n"
            "  _ASM_EXTABLE 9999b, \\label\n.endm\n",
        ):
            with self.subTest(source=input_text):
                with self.assertRaises(ValueError):
                    module.upstream_fixes(input_text,module.ARM64_ALTERNATIVE)

    def test_arm64_fix_requires_explicit_prior_format_chain(self):
        with self.assertRaisesRegex(ValueError,"requires --init-format-fix"):
            module.patch_catalog(format_fix=False,extable_fix=True)

    def test_arm64_compat_four_patch_clone_preserves_original_and_old_tree(self):
        with tempfile.TemporaryDirectory() as path:
            stock,legacy=self.fixture(path)
            init=stock/module.INIT_MAIN
            init.parent.mkdir(parents=True)
            init.write_text(
                'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);\n')
            self.alternative_fixture(stock)
            original=module.tree_digest(stock)
            with patch.object(module,"source_gate"):
                _,_,old_changes=module.plan(stock,legacy,stock/"audit.json",True)
            old_manifest=module.create(stock,legacy,old_changes)
            old_digest=module.tree_digest(legacy)
            new=Path(path)/"separate-arm64-ias-tree"
            with patch.object(module,"source_gate"):
                _,_,all_changes=module.plan(stock,new,stock/"audit.json",True,True)
            self.assertEqual(len(all_changes),4)
            self.assertEqual(all_changes[module.ARM64_ALTERNATIVE]["replacements"],1)
            manifest=module.create(stock,new,all_changes)
            self.assertEqual(manifest["schema"],3)
            self.assertEqual(manifest["kind"],module.IAS_EXTABLE_KIND)
            self.assertEqual(module.verify_compat(stock,new)["schema"],3)
            self.assertEqual(module.verify_compat(stock,legacy)["schema"],2)
            self.assertEqual(module.tree_digest(stock),original)
            self.assertEqual(module.tree_digest(legacy),old_digest)
            self.assertNotEqual(manifest["compatTreeSha256"],old_digest)

    def test_arm64_compat_refuses_modified_copy_after_creation(self):
        with tempfile.TemporaryDirectory() as path:
            stock,dest=self.fixture(path)
            (stock/"init").mkdir()
            (stock/module.INIT_MAIN).write_text(
                'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);\n')
            self.alternative_fixture(stock)
            with patch.object(module,"source_gate"):
                _,_,patches=module.plan(stock,dest,stock/"audit.json",True,True)
            module.create(stock,dest,patches)
            (dest/module.ARM64_ALTERNATIVE).write_text("unrelated malicious modification")
            with self.assertRaisesRegex(ValueError,"patched compatibility file changed"):
                module.verify_compat(stock,dest)

    def test_arm64_compat_refuses_source_drift_after_creation(self):
        with tempfile.TemporaryDirectory() as path:
            stock,dest=self.fixture(path)
            (stock/"init").mkdir()
            (stock/module.INIT_MAIN).write_text(
                'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);\n')
            alt=self.alternative_fixture(stock)
            with patch.object(module,"source_gate"):
                _,_,patches=module.plan(stock,dest,stock/"audit.json",True,True)
            module.create(stock,dest,patches)
            alt.write_text(alt.read_text()+"\n")
            with self.assertRaisesRegex(ValueError,"stock source changed"):
                module.verify_compat(stock,dest)

    def test_arm64_ias_variant_manifest_cannot_drop_one_patch(self):
        with tempfile.TemporaryDirectory() as path:
            stock,dest=self.fixture(path)
            (stock/"init").mkdir()
            (stock/module.INIT_MAIN).write_text(
                'pr_info("SYSREG, after zeroing out master key, mk=%lx\\n", ropp_master_key);\n')
            self.alternative_fixture(stock)
            with patch.object(module,"source_gate"):
                _,_,patches=module.plan(stock,dest,stock/"audit.json",True,True)
            module.create(stock,dest,patches)
            manifest_file=dest/module.MANIFEST
            import json
            manifest=json.loads(manifest_file.read_text())
            manifest["patches"].pop(module.ELFNOTE)
            manifest_file.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,"wrong stock origin"):
                module.verify_compat(stock,dest)

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
                with self.assertRaisesRegex(ValueError, "expected 3 exact matches"):
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
