import unittest
from unittest.mock import patch
from tools import y2q_rea_export_budget as m

class ExportBudgetTests(unittest.TestCase):
    def test_unknown_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "reviewed source"):
            m.enlarge(b"unexpected bridge")

    def test_budget_change_preserves_unrelated_bytes(self):
        original = b"header\n" + b"\n".join(m.REPLACEMENTS) + b"\nfooter"
        with patch.object(m, "PIN", m.git_blob_sha(original)):
            changed = m.enlarge(original)
        self.assertTrue(changed.startswith(b"header\n"))
        self.assertTrue(changed.endswith(b"\nfooter"))
        for declaration in m.REPLACEMENTS.values():
            self.assertIn(declaration, changed)

    def test_duplicate_declaration_rejected_even_with_matching_pin(self):
        original = b"\n".join(m.REPLACEMENTS)*2
        with patch.object(m, "PIN", m.git_blob_sha(original)):
            with self.assertRaisesRegex(ValueError, "exactly one"):
                m.enlarge(original)
