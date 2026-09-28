"""Tests for the local, Git-ready rule repository (gap 2)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_research import core, custom_rules, rule_repository, rules, store


def fictional_record(ident="CVE-2099-71001"):
    return {"id": ident, "title": "Fictional example vulnerability", "summary": "Synthetic fixture.",
            "source": "https://example.test/advisory", "claim": "Example advisory source.",
            "published": "2099-01-01", "updated": "2099-01-01", "kev": True, "affected": ["ExampleServer"]}


class RuleRepositoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        self.repo_root = self.path.parent / "rule-repository"

    def tearDown(self):
        self.tmp.cleanup()

    def test_repo_dir_defaults_beside_the_database(self):
        self.assertEqual(rule_repository.repo_dir(self.path), self.repo_root)

    def test_draft_creation_writes_a_complete_draft_snapshot(self):
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-71001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2099-71001", eid, self.path)
        draft_file = self.repo_root / "draft" / f"{draft['rule_id']}.json"
        self.assertTrue(draft_file.is_file())
        self.assertFalse((self.repo_root / "approved" / f"{draft['rule_id']}.json").exists())
        payload = json.loads(draft_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "draft")
        self.assertIn("ParentImage", payload["detections"]["sigma"])
        self.assertTrue(payload["detections"]["kql"])
        self.assertTrue(payload["detections"]["spl"])
        self.assertEqual(payload["threat"]["published"], "2099-01-01")
        self.assertEqual(len(payload["analyst_observations"]), 1)
        self.assertIn("Authorized administration", payload["false_positives"][0])
        self.assertIn("exact_local_behavior_and_telemetry", payload["inventory_comparison"])
        self.assertEqual(payload["framework_mappings"]["behavior"], "web_server_shell")
        self.assertIn("attack", payload["framework_mappings"]["mappings"])
        self.assertEqual(payload["test_results"], [])
        self.assertEqual(payload["approval_history"][0]["action"], "rule_drafted")
        self.assertEqual(payload["deployment"], "not_deployed_to_any_siem; local repository only; never pushed to a remote")
        readme = (self.repo_root / "README.md").read_text(encoding="utf-8")
        self.assertIn("pushes anything on your behalf", readme)

    def test_approval_moves_snapshot_to_approved_and_keeps_draft_history(self):
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-71001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2099-71001", eid, self.path)
        pre_approval_draft = json.loads((self.repo_root / "draft" / f"{draft['rule_id']}.json").read_text())
        rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        approved_file = self.repo_root / "approved" / f"{draft['rule_id']}.json"
        self.assertTrue(approved_file.is_file())
        payload = json.loads(approved_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "approved")
        actions = [h["action"] for h in payload["approval_history"]]
        self.assertIn("rule_drafted", actions)
        self.assertIn("rule_approved", actions)
        # The last pre-approval draft snapshot remains on disk for historical review.
        self.assertEqual(pre_approval_draft["status"], "draft")
        self.assertTrue((self.repo_root / "draft" / f"{draft['rule_id']}.json").exists())

    def test_rejected_draft_stays_in_draft_folder_with_reason_and_can_reopen(self):
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-71001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2099-71001", eid, self.path)
        rules.reject_rule(draft["rule_id"], "Needs a second independent source before approval.", self.path)
        payload = json.loads((self.repo_root / "draft" / f"{draft['rule_id']}.json").read_text())
        self.assertEqual(payload["status"], "rejected")
        self.assertIn("second independent source", payload["rejected_reason"])
        self.assertFalse((self.repo_root / "approved" / f"{draft['rule_id']}.json").exists())
        rules.reopen_rule(draft["rule_id"], self.path)
        payload = json.loads((self.repo_root / "draft" / f"{draft['rule_id']}.json").read_text())
        self.assertEqual(payload["status"], "draft")
        self.assertIsNone(payload["rejected_reason"])

    def test_custom_and_ioc_drafts_are_also_exported(self):
        core.ingest([fictional_record()], self.path)
        result = custom_rules.draft(
            "CVE-2099-71001", "https://example.test/custom-report",
            "Fictional example analyst-verified claim describing a specific process pattern.",
            "Fictional custom detection", "This is a rationale of adequate length for validation purposes here.",
            "Administrative scripts may share this literal pattern occasionally.",
            {"event_family": "process_creation", "platform": "windows", "predicates": [
                {"field": "Image", "operator": "endswith", "value": "cmd.exe"},
                {"field": "ParentImage", "operator": "endswith", "value": "w3wp.exe"}]}, self.path)
        payload = json.loads((self.repo_root / "draft" / f"{result['rule_id']}.json").read_text())
        self.assertEqual(payload["behavior"], "custom")
        self.assertIsNotNone(payload["custom_spec"])

    def test_list_repository_reads_disk_state_offline(self):
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-71001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2099-71001", eid, self.path)
        listing = rule_repository.list_repository(self.path)
        self.assertEqual(len(listing["draft"]), 1)
        self.assertEqual(listing["draft"][0]["rule_id"], draft["rule_id"])
        self.assertEqual(listing["approved"], [])
        rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        listing = rule_repository.list_repository(self.path)
        self.assertEqual(listing["draft"][0]["status"], "draft")  # historical, unapproved snapshot
        self.assertEqual(len(listing["approved"]), 1)
        self.assertEqual(listing["approved"][0]["status"], "approved")

    def test_repository_never_touches_git_or_network(self):
        # subprocess/git and urllib are never imported by this module.
        import ast
        source = Path(rule_repository.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("urllib.request", imported)

    def test_env_override_isolates_repository_location(self):
        other = Path(self.tmp.name) / "elsewhere"
        with patch.dict("os.environ", {"RULE_REPOSITORY_DIR": str(other)}):
            self.assertEqual(rule_repository.repo_dir(self.path), other.expanduser().resolve())


if __name__ == "__main__":
    unittest.main()
