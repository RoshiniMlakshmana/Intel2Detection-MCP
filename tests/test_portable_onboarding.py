"""Gap 4: portable onboarding. An environment pack another organization can
fill with its own asset inventory, telemetry mapping, and existing rules;
validated before scoring or drafting; isolated database and rule repository
per organization; no credentials in any exported file."""

import json
import tempfile
import unittest
from pathlib import Path

from threat_research import core, enterprise, environment, rule_repository, rules, store


class PortableOnboardingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_pack_scaffolds_isolated_rule_repository(self):
        pack = enterprise.create_pack(self.root / "org-a", "Org A", "generic")
        repo = Path(pack["rule_repository"])
        self.assertTrue((repo / "draft").is_dir())
        self.assertTrue((repo / "approved").is_dir())
        self.assertTrue((repo / "README.md").is_file())
        self.assertEqual(repo, Path(pack["database"]).parent / "rule-repository")

    def test_two_organizations_stay_fully_isolated(self):
        a = enterprise.create_pack(self.root / "org-a", "Org A", "generic")
        b = enterprise.create_pack(self.root / "org-b", "Org B", "splunk")
        self.assertNotEqual(a["database"], b["database"])
        self.assertNotEqual(a["rule_repository"], b["rule_repository"])

        # Onboard org A with a mapped field and a fictional confirmed asset.
        profile_a = json.loads((self.root / "org-a" / "profile.json").read_text())
        profile_a["telemetry"] = {"process_creation": {"source": "org-a-edr", "field_map": {
            "ParentImage": "parent.path", "Image": "process.path", "CommandLine": "process.command_line"}}}
        (self.root / "org-a" / "profile.json").write_text(json.dumps(profile_a))
        (self.root / "org-a" / "assets.csv").write_text(enterprise.ASSET_HEADER +
                                                         "a-1,host-1,ExampleServer,1.0,CVE-2099-73001,true,high,general\n")
        enterprise.onboard_pack(self.root / "org-a")

        core.ingest([{"id": "CVE-2099-73001", "title": "Fictional vulnerability", "summary": "fixture",
                     "source": "https://example.test/adv", "claim": "fixture", "kev": True}], Path(a["database"]))
        eid = core.add_behavior_evidence("CVE-2099-73001", "https://example.test/report",
                                         "Observed web worker launching cmd.exe", "web_server_shell", Path(a["database"]))
        rule_id = rules.propose_rule("CVE-2099-73001", eid, Path(a["database"]))["rule_id"]

        # Org B's database and repository must show nothing from org A.
        self.assertIsNone(core.get_threat("CVE-2099-73001", Path(b["database"])))
        self.assertIsNone(rules.get_rule(rule_id, Path(b["database"])))
        self.assertFalse(environment.status(Path(b["database"]))["configured"])
        b_listing = rule_repository.list_repository(Path(b["database"]))
        self.assertEqual(b_listing["draft"], [])
        a_listing = rule_repository.list_repository(Path(a["database"]))
        self.assertEqual(len(a_listing["draft"]), 1)
        self.assertEqual(a_listing["draft"][0]["rule_id"], rule_id)

    def test_no_credentials_in_any_exported_file(self):
        pack = enterprise.create_pack(self.root / "org-c", "Org C", "splunk")
        core.ingest([{"id": "CVE-2099-73002", "title": "Fictional vulnerability", "summary": "fixture",
                     "source": "https://example.test/adv", "claim": "fixture", "kev": True}], Path(pack["database"]))
        eid = core.add_behavior_evidence("CVE-2099-73002", "https://example.test/report",
                                         "Observed web worker launching cmd.exe", "web_server_shell", Path(pack["database"]))
        rules.propose_rule("CVE-2099-73002", eid, Path(pack["database"]))
        target = Path(pack["directory"])
        checked = 0
        for file in target.rglob("*.json"):
            text = file.read_text(encoding="utf-8")
            self.assertNotIn("SPLUNK_TOKEN", text)
            self.assertNotIn("password", text.lower())
            self.assertNotIn("secret", text.lower())
            checked += 1
        self.assertGreater(checked, 0)
        claude_config = json.loads((target / "claude-mcp.json").read_text())
        self.assertEqual(set(claude_config["mcpServers"]["threat-research"]["env"]), {"THREAT_RESEARCH_DB"})

    def test_onboarding_validates_before_scoring_or_drafting(self):
        target = self.root / "org-d"
        enterprise.create_pack(target, "Org D", "generic")
        profile = json.loads((target / "profile.json").read_text())
        profile["telemetry"] = {"process_creation": {"source": "org-d-edr", "field_map": {
            "ParentImage": "parent.path", "Image": "process.path", "CommandLine": "command.line"}}}
        (target / "profile.json").write_text(json.dumps(profile))
        (target / "assets.csv").write_text(enterprise.ASSET_HEADER +
                                           "a-1,host-1,ExampleServer,1.0,,true,high,general\n")
        # inventory.json with an invalid behavior mapping must block onboarding
        # entirely -- nothing gets scored or drafted from a half-valid pack.
        (target / "inventory.json").write_text('[{"id":"bad"}]')
        with self.assertRaisesRegex(ValueError, "mapped behavior"):
            enterprise.onboard_pack(target)
        self.assertFalse(environment.status(enterprise.pack_database(target))["configured"])
        with self.assertRaises(ValueError):
            environment.risk_from_assets("CVE-2099-73003", enterprise.pack_database(target))


if __name__ == "__main__":
    unittest.main()
