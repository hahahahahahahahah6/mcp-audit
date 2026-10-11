"""Tests for the bundled CVE table."""

import unittest

from mcp_audit.cve_db import (
    CVE_DB,
    affected_cves,
    get_cve,
    version_matches_affected,
)


class TestVersionMatching(unittest.TestCase):
    def test_less_than(self):
        self.assertTrue(version_matches_affected("0.13.0", "<0.14.1"))
        self.assertTrue(version_matches_affected("0.14.0", "<0.14.1"))
        self.assertFalse(version_matches_affected("0.14.1", "<0.14.1"))
        self.assertFalse(version_matches_affected("0.15.0", "<0.14.1"))

    def test_numeric_not_lexicographic(self):
        # 1.10.3 > 1.9.0 numerically; a string compare would get this wrong.
        self.assertFalse(version_matches_affected("1.10.3", "<1.9.0"))
        self.assertTrue(version_matches_affected("1.9.0", "<1.10.3"))

    def test_patch_boundary(self):
        self.assertTrue(version_matches_affected("1.2.0", "<1.2.1"))
        self.assertFalse(version_matches_affected("1.2.1", "<1.2.1"))


class TestCveDb(unittest.TestCase):
    def test_table_has_required_ids(self):
        ids = {e["id"] for e in CVE_DB}
        for required in ("CVE-2026-89039", "CVE-2026-105793",
                         "CVE-2026-94486", "CVE-2026-19807",
                         "CVE-2025-49596", "CVE-2026-76404",
                         "CVE-2026-58201"):
            self.assertIn(required, ids)

    def test_get_cve(self):
        entry = get_cve("CVE-2025-49596")
        self.assertIsNotNone(entry)
        self.assertIn("0.14.1", entry["fixed_in"])
        self.assertIsNone(get_cve("CVE-9999-00000"))

    def test_inspector_match(self):
        hits = affected_cves("@modelcontextprotocol/inspector", "0.13.0")
        self.assertEqual([h["id"] for h in hits], ["CVE-2025-49596"])
        self.assertEqual(affected_cves("@modelcontextprotocol/inspector", "0.14.1"), [])

    def test_splunk_match(self):
        hits = affected_cves("splunk-mcp-server", "1.1.0")
        self.assertEqual([h["id"] for h in hits], ["CVE-2026-76404"])
        self.assertEqual(affected_cves("splunk-mcp-server", "1.2.1"), [])

    def test_lokka_match(self):
        hits = affected_cves("lokka", "2.1.0")
        self.assertEqual([h["id"] for h in hits], ["CVE-2026-58201"])
        self.assertEqual(affected_cves("lokka", "2.1.2"), [])

    def test_langflow_match(self):
        hits = affected_cves("langflow", "1.9.0")
        self.assertEqual([h["id"] for h in hits], ["CVE-2026-105697"])
        self.assertEqual(affected_cves("langflow", "1.10.3"), [])

    def test_match_case_insensitive(self):
        self.assertTrue(affected_cves("LOKKA", "2.0.0"))

    def test_unmapped_cve_never_matches(self):
        # Entries without product mapping must not produce false positives.
        self.assertEqual(affected_cves("some-random-package", "0.0.1"), [])

    def test_empty_inputs(self):
        self.assertEqual(affected_cves("", "1.0.0"), [])
        self.assertEqual(affected_cves("lokka", ""), [])


if __name__ == "__main__":
    unittest.main()
