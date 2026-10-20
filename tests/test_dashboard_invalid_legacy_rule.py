"""Legacy invalid custom rules must not take the whole Rules page offline."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from threat_research import core, dashboard, workflow, rules, store

class LegacyRulePageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "intel.sqlite3"
        core.ingest([{"id":"IOC-LEGACY-1","title":"Fixture", "source":"https://example.test/source",
                      "kind":"advisory"}], self.path)
        with store.connection(self.path) as db:
            db.execute("""INSERT INTO rules
                (id,threat_id,behavior,fingerprint,title,sigma,kql,spl,telemetry,rationale,status,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("invalid-legacy","IOC-LEGACY-1","custom","legacy-hash","Legacy draft",
                 "title: legacy rule", "DeviceProcessEvents", "index=endpoint",
                 "Sysmon Event 1", "Test fixture", "draft","2099-01-01T00:00:00Z"))

    def test_rules_page_survives_invalid_spec(self):
        real = rules.get_rule
        def invalid_only(rule_id, path=None):
            if rule_id == "invalid-legacy":
                raise ValueError("provide 2-12 bounded conditions, or one exact file SHA-256")
            return real(rule_id, path)
        with patch.object(rules, "get_rule", side_effect=invalid_only):
            result = workflow.list_rules(self.path, state="draft")
            self.assertEqual(result["total"], 1)
            page = dashboard.render_rules(self.path)
        self.assertIn("Legacy draft", page)
        self.assertIn("Legacy rule needs repair", page)
        self.assertIn("title: legacy rule", page)
        self.assertIn("DeviceProcessEvents", page)

if __name__=="__main__":
    unittest.main()
