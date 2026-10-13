"""Regression tests for HXL1 original-source/recovered-symbol provenance."""
import gzip
import hashlib
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_futex_symbol_provenance as m
from tools import y2q_hxl1_ghostlock_stack_gate as base


class FutexSymbolProvenanceTests(unittest.TestCase):
    def test_exact_samsung_source_pin_is_mandatory(self):
        with self.assertRaisesRegex(m.EvidenceError, "SHA256 mismatch"):
            m.check_source(b"static int futex_wait_requeue_pi(void)\n{\n}\n")

    def test_source_function_declaration_found_not_call_sites(self):
        raw = (b"// mention futex_wait_requeue_pi() only\n"
               b"static int futex_wait_requeue_pi(\n"
               b"  u32 __user *uaddr)\n{\n"
               b"  return 0;\n}\n"
               b"int wrapper(void) { return futex_wait_requeue_pi(0); }\n")
        with patch.object(m, "STOCK_FUTEX_SHA",
                          hashlib.sha256(raw).hexdigest()):
            got = m.check_source(raw)
        self.assertEqual(got["sourceDeclarationCount"], 1)
        self.assertEqual(got["sourceDeclarations"][0]["line"], 2)
        self.assertTrue(got["sourceDeclarations"][0]["declaredStatic"])
        self.assertFalse(got["factoryCodeEmissionProven"])

    def test_invalid_original_config_pin_fails(self):
        raw = gzip.compress(b"CONFIG_FUTEX=y\n")
        with self.assertRaisesRegex(m.EvidenceError, "SHA256 mismatch"):
            m.check_config(raw)

    def test_config_flags_parse_including_missing_and_no(self):
        raw = gzip.compress(
            b"CONFIG_FUTEX=y\nCONFIG_FUTEX_PI=y\n"
            b"# CONFIG_LTO_CLANG is not set\n")
        with patch.object(m, "STOCK_CONFIG_SHA",
                          hashlib.sha256(raw).hexdigest()):
            parsed = m.check_config(raw)["values"]
        self.assertEqual(parsed["CONFIG_FUTEX"], "y")
        self.assertEqual(parsed["CONFIG_FUTEX_PI"], "y")
        self.assertEqual(parsed["CONFIG_LTO_CLANG"], "n")
        self.assertEqual(parsed["CONFIG_KALLSYMS_ALL"], "NOT_RECORDED")

    def test_duplicate_kernel_config_is_rejected(self):
        with self.assertRaisesRegex(m.EvidenceError, "Ambiguous"):
            m.config_value("CONFIG_FUTEX=y\nCONFIG_FUTEX=n", "CONFIG_FUTEX")

    def test_recovered_name_missing_does_not_prove_compiled_function_absent(self):
        symbols = (f"{base.IMAGE_VA:x} T _text\n"
                   f"{base.IMAGE_VA+0x100:x} t futex_requeue\n"
                   f"{base.IMAGE_VA+0x200:x} t futex_wait_setup\n")
        parsed = m.name_inventory(symbols)
        self.assertFalse(parsed["exactNamedTextSymbolPresent"])
        result = m.evaluate(
            {"sourceDeclarationCount": 1, "sourceDeclarations": []},
            {"values": {}}, parsed)
        self.assertEqual(result["status"],
                         "PINNED_SOURCE_DECLARATION_PRESENT_RECOVERED_NAME_ABSENT")
        self.assertFalse(result["compiledFunctionAbsenceProven"])
        self.assertFalse(result["inliningOrOptimizationProven"])
        self.assertFalse(result["usableExploitPathProven"])

    def test_source_and_symbol_both_present_only_inventory(self):
        symbols = (f"{base.IMAGE_VA:x} T _text\n"
                   f"{base.IMAGE_VA+0x100:x} t futex_wait_requeue_pi\n")
        parsed = m.name_inventory(symbols)
        result = m.evaluate(
            {"sourceDeclarationCount": 1, "sourceDeclarations": [
                {"line": 1, "qualifiers": ["static", "int"]}]},
            {"values": {"CONFIG_FUTEX": "y"}}, parsed)
        self.assertEqual(result["status"], "SOURCE_AND_RECOVERED_SYMBOL_PRESENT")
        self.assertFalse(result["compiledFunctionAbsenceProven"])
        self.assertIn("no compilation", m.markdown(result).lower())

    def test_related_named_variants_do_not_count_as_exact(self):
        symbols = (f"{base.IMAGE_VA:x} T _text\n"
                   f"{base.IMAGE_VA+0x100:x} t futex_wait_requeue_pi.constprop.1\n")
        got = m.name_inventory(symbols)
        self.assertFalse(got["exactNamedTextSymbolPresent"])
        self.assertEqual(got["nameContainingVariants"][0]["name"],
                         "futex_wait_requeue_pi.constprop.1")


if __name__ == "__main__":
    unittest.main()
