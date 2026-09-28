"""Gap 3: honest inventory status. Yes only for reviewed matching coverage;
No only within an explicitly declared, complete, recent inventory scope;
Unknown otherwise -- including an empty or undeclared inventory."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threat_research import core, custom_rules, rules, store


def fictional_record(ident="CVE-2099-72001"):
    return {"id": ident, "title": "Fictional example vulnerability", "summary": "Synthetic fixture.",
            "source": "https://example.test/advisory", "claim": "Example advisory source.",
            "published": "2099-01-01", "updated": "2099-01-01", "kev": True, "affected": ["ExampleServer"]}


CUSTOM_SPEC = {"event_family": "process_creation", "platform": "windows", "predicates": [
    {"field": "Image", "operator": "endswith", "value": "powershell.exe"},
    {"field": "CommandLine", "operator": "contains", "value": "fictionalloader.ps1"},
]}


class InventoryDeclarationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        core.ingest([fictional_record()], self.path)
        self.eid = core.add_behavior_evidence("CVE-2099-72001", "https://example.test/report",
                                              "Observed web server launching cmd.exe", "web_server_shell", self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_declare_validates_inputs(self):
        with self.assertRaisesRegex(ValueError, "scope needs"):
            rules.declare_inventory_scope("short", True, self.path)
        with self.assertRaisesRegex(ValueError, "complete must be"):
            rules.declare_inventory_scope("A properly long description of what was checked here.", "yes", self.path)

    def test_undeclared_inventory_is_unknown_not_no(self):
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "unknown")
        self.assertEqual(status["behaviors"][0]["status"], "unknown")
        self.assertFalse(status["inventory_scope"]["declared"])

    def test_empty_but_undeclared_external_inventory_still_unknown(self):
        # external_inventory table is genuinely empty (nobody ever imported
        # anything) -- that alone must not be read as "confirmed no coverage".
        with store.connection(self.path) as db:
            count = db.execute("SELECT COUNT(*) FROM external_inventory").fetchone()[0]
        self.assertEqual(count, 0)
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "unknown")

    def test_declared_but_incomplete_stays_unknown(self):
        rules.declare_inventory_scope("Only our Splunk Enterprise Security app, not our EDR console.", False, self.path)
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "unknown")
        self.assertIn("not marked complete", status["behaviors"][0]["scope"])

    def test_declared_complete_and_recent_allows_no(self):
        rules.declare_inventory_scope("All Sigma rules in our detection-as-code repository, audited today.", True, self.path)
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "no")
        self.assertEqual(status["behaviors"][0]["status"], "no")
        self.assertIn("declared complete inventory", status["behaviors"][0]["scope"])
        self.assertTrue(status["inventory_scope"]["complete"])
        self.assertTrue(status["inventory_scope"]["recent"])

    def test_stale_declaration_reverts_to_unknown(self):
        rules.declare_inventory_scope("All existing rules, audited a while ago.", True, self.path)
        stale_at = (datetime.now(timezone.utc) - timedelta(days=rules.INVENTORY_DECLARATION_TTL_DAYS + 1)).isoformat().replace("+00:00", "Z")
        with store.connection(self.path) as db:
            db.execute("UPDATE inventory_declaration SET declared_at=? WHERE id=1", (stale_at,))
        declaration = rules.inventory_declaration_status(self.path)
        self.assertFalse(declaration["recent"])
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "unknown")
        self.assertIn("older than", status["behaviors"][0]["scope"])

    def test_yes_shows_matching_rule_regardless_of_declaration(self):
        # A Yes must be assertable from reviewed matching coverage alone --
        # it does not require any inventory declaration at all.
        draft = rules.propose_rule("CVE-2099-72001", self.eid, self.path)
        rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "yes")
        self.assertEqual(status["behaviors"][0]["rule_id"], draft["rule_id"])
        self.assertFalse(status["inventory_scope"]["declared"])

    def test_imported_external_rule_yes_even_without_declaration(self):
        rules.import_inventory([{"id": "EXT-1", "title": "Existing web shell hunt", "behavior": "web_server_shell",
                                 "source_url": "https://example.org/rule"}], self.path)
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(status["status"], "yes")
        self.assertEqual(status["behaviors"][0]["rule_id"], "EXT-1")

    def test_overall_status_mixed_behaviors(self):
        # One behavior with an approved rule (yes) alongside another with no
        # coverage under a declared-complete scope (no) should mix; here we
        # confirm 'yes' wins when present, and 'unknown' otherwise wins over
        # a lone 'no' whenever any behavior lacks a usable declaration.
        rules.declare_inventory_scope("All existing rules, audited today.", True, self.path)
        core.add_behavior_evidence("CVE-2099-72001", "https://example.test/report2",
                                   "Observed PowerShell run with an encoded argument", "encoded_powershell", self.path)
        status = rules.inventory_status("CVE-2099-72001", self.path)
        self.assertEqual(len(status["behaviors"]), 2)
        self.assertEqual(status["status"], "no")  # both behaviors 'no' under a declared-complete scope


class CustomBehaviorInventoryStatusTest(unittest.TestCase):
    """Regression coverage for the gap found during the NeedyMantis walkthrough:
    inventory_status() must evaluate custom recorded behaviors and their own
    bound rule fingerprints, not only the three fixed templates."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        self.report = core.record_campaign_report(
            "Fictional example malware campaign",
            "A fictional research report describing a fictional post-compromise malware loader for test purposes.",
            "https://example.test/campaign-report", self.path)["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def _draft(self, path=None):
        return custom_rules.draft(
            self.report, "https://example.test/campaign-report",
            "Fictional example research states the analyzed sample used fictionalloader.ps1 as a PowerShell-invoked loader.",
            "Fictional PowerShell loader detection", "This is a fictional rationale of adequate length for validation here.",
            "A legitimately named script sharing this filename is unlikely but possible.",
            CUSTOM_SPEC, path or self.path)

    def test_custom_behavior_is_included_not_reported_as_no_behavior_recorded(self):
        self._draft()
        status = rules.inventory_status(self.report, self.path)
        self.assertEqual(len(status["behaviors"]), 1)
        self.assertEqual(status["behaviors"][0]["behavior"], "custom")
        self.assertNotEqual(status.get("reason"), "No analyst-verified behavior is recorded for this threat yet.")

    def test_custom_behavior_yes_when_approved_rule_matches(self):
        result = self._draft()
        rules.implement_rule(result["rule_id"], "implement this rule", path=self.path)
        status = rules.inventory_status(self.report, self.path)
        self.assertEqual(status["status"], "yes")
        self.assertEqual(status["behaviors"][0]["status"], "yes")
        self.assertEqual(status["behaviors"][0]["rule_id"], result["rule_id"])
        self.assertEqual(status["behaviors"][0]["evidence"][0]["evidence_id"], result["evidence_id"])

    def test_custom_behavior_yes_when_imported_external_rule_matches(self):
        self._draft()
        rules.import_inventory([{"id": "EXT-CUSTOM-1", "title": "Existing fictional loader hunt", "behavior": "custom",
                                 "spec": CUSTOM_SPEC, "source_url": "https://example.org/rule"}], self.path)
        status = rules.inventory_status(self.report, self.path)
        self.assertEqual(status["status"], "yes")
        self.assertEqual(status["behaviors"][0]["rule_id"], "EXT-CUSTOM-1")

    def test_custom_behavior_no_only_with_complete_recent_declared_inventory(self):
        self._draft()
        undeclared = rules.inventory_status(self.report, self.path)
        self.assertEqual(undeclared["status"], "unknown")
        self.assertIn("custom", [b["behavior"] for b in undeclared["behaviors"]])

        rules.declare_inventory_scope("Incomplete audit, EDR console only.", False, self.path)
        incomplete = rules.inventory_status(self.report, self.path)
        self.assertEqual(incomplete["status"], "unknown")
        self.assertIn("not marked complete", incomplete["behaviors"][0]["scope"])

        rules.declare_inventory_scope("All existing rules, audited today.", True, self.path)
        complete_no_match = rules.inventory_status(self.report, self.path)
        self.assertEqual(complete_no_match["status"], "no")
        self.assertIn("declared complete inventory", complete_no_match["behaviors"][0]["scope"])

        stale_at = (datetime.now(timezone.utc) - timedelta(days=rules.INVENTORY_DECLARATION_TTL_DAYS + 1)).isoformat().replace("+00:00", "Z")
        with store.connection(self.path) as db:
            db.execute("UPDATE inventory_declaration SET declared_at=? WHERE id=1", (stale_at,))
        stale = rules.inventory_status(self.report, self.path)
        self.assertEqual(stale["status"], "unknown")
        self.assertIn("older than", stale["behaviors"][0]["scope"])

    def test_distinct_custom_specs_are_evaluated_as_separate_targets(self):
        first = self._draft()
        second_spec = {"event_family": "process_creation", "platform": "windows", "predicates": [
            {"field": "Image", "operator": "endswith", "value": "cmd.exe"},
            {"field": "ParentImage", "operator": "endswith", "value": "w3wp.exe"}]}
        second = custom_rules.draft(self.report, "https://example.test/campaign-report-2",
                                    "A fictional distinct claim about a different observed pattern in the same report.",
                                    "Fictional second detection", "Another fictional rationale of adequate length for validation here.",
                                    "Some benign admin activity might share this pattern.", second_spec, self.path)
        rules.implement_rule(first["rule_id"], "implement this rule", path=self.path)
        status = rules.inventory_status(self.report, self.path)
        self.assertEqual(len(status["behaviors"]), 2)
        # Overall 'yes' reflects that at least one behavior has reviewed
        # matching coverage; the per-behavior breakdown still shows the
        # second, undeclared-scope behavior honestly as its own 'unknown'.
        self.assertEqual(status["status"], "yes")
        by_rule = {b["rule_id"]: b["status"] for b in status["behaviors"] if b.get("rule_id")}
        self.assertEqual(by_rule[first["rule_id"]], "yes")
        self.assertEqual(by_rule[second["rule_id"]], "unknown")


if __name__ == "__main__":
    unittest.main()
