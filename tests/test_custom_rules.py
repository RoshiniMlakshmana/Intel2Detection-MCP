import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_research import core, custom_rules, enterprise, environment, live_validation, rules, soc_replay, store


SPEC = {"event_family": "process_creation", "platform": "windows", "predicates": [
    {"field": "ParentImage", "operator": "endswith", "value": "w3wp.exe"},
    {"field": "CommandLine", "operator": "contains", "value": "certutil"},
]}


class CustomDetectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        core.ingest([{"id": "CVE-2099-11111", "title": "Fictional newly disclosed flaw",
                      "summary": "Details still require technical research.",
                      "source": "https://example.org/advisory", "claim": "Fictional advisory published."}], self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def draft(self, source="https://example.org/report-one", claim="Researcher observed IIS spawning certutil after exploitation."):
        return custom_rules.draft("CVE-2099-11111", source, claim,
                                  "IIS child process uses certutil", "Find a reported post-exploitation process chain on IIS hosts.",
                                  "Administrators may use certutil during maintenance.", SPEC, self.path)

    def test_no_siem_draft_then_client_mapping_and_read_only_query(self):
        assert core.research_view("CVE-2099-11111", self.path)["detection_readiness"] == "research_needed_no_behavior_rule"
        proposal = self.draft()
        self.assertEqual(proposal["status"], "draft")
        self.assertIn("ParentImage|endswith", proposal["sigma"])
        self.assertEqual(environment.check_rule_fit(proposal["rule_id"], self.path)["ready"], False)
        rule = rules.get_rule(proposal["rule_id"], self.path)
        self.assertEqual(rule["custom_spec"]["event_family"], "process_creation")
        sample = [{"event_id": "e1", "event_type": "process_creation", "timestamp": "2099-01-01T00:00:00Z",
                   "ParentImage": "C:\\Windows\\w3wp.exe", "CommandLine": "certutil -urlcache",
                   "expected_malicious": True, "scenario": "hypothetical positive"},
                  {"event_id": "e2", "event_type": "process_creation", "timestamp": "2099-01-01T00:00:01Z",
                   "ParentImage": "C:\\Windows\\services.exe", "CommandLine": "certutil -urlcache",
                   "expected_malicious": False, "scenario": "hypothetical benign"}]
        local = soc_replay.local_rules(self.path, include_drafts=True)
        self.assertEqual(soc_replay.replay(sample, local)["counts"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        profile = {"name": "Fixture SOC", "siem": "splunk", "splunk_url": "https://splunk.example.org:8089",
                   "telemetry": {"process_creation": {"index": "endpoint", "sourcetype": "sysmon:test",
                                                     "fields": ["ParentImage", "CommandLine"]}}}
        environment.onboard(profile, [{"asset_id": "host-1", "hostname": "host-1", "product": "Fixture",
                                     "version": "1", "confirmed_cves": ["CVE-2099-11111"],
                                     "internet_exposed": True, "criticality": "high", "asset_role": "general"}], self.path)
        fit = environment.check_rule_fit(proposal["rule_id"], self.path)
        self.assertTrue(fit["ready"])
        self.assertIn("index=endpoint sourcetype=sysmon:test", fit["mapped_query"])
        with patch.dict("os.environ", {"SPLUNK_TOKEN": "synthetic"}):
            result = live_validation.check_live_query(proposal["rule_id"], self.path,
                splunk_fetch=lambda endpoint, body: b'{"result":{"host":"fixture"}}\n')
        self.assertEqual(result["status"], "query_executed")
        self.assertEqual(result["sample_matches"], 1)
        review = rules.review_for_client(proposal["rule_id"], self.path, update_frameworks=False)
        self.assertEqual(review["environment_risk"]["confirmed_affected_count"], 1)
        self.assertEqual(review["framework_context"]["mappings"], {})

    def test_duplicate_and_distinct_approval_evidence(self):
        first = self.draft()
        second = self.draft("https://another.example.org/independent-report", "A second report confirms IIS spawned certutil on a host.")
        self.assertEqual(second["status"], "existing_coverage")
        self.assertEqual(first["rule_id"], second["rule_id"])
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            rules.implement_rule(first["rule_id"], "yes", path=self.path)
        self.assertEqual(rules.implement_rule(first["rule_id"], "implement this rule", path=self.path)["pattern_score"], 0)
        self.assertEqual(rules.implement_rule(first["rule_id"], "implement this rule", second["evidence_id"], self.path)["pattern_score"], 1)
        self.assertEqual(rules.implement_rule(first["rule_id"], "implement this rule", second["evidence_id"], self.path)["pattern_score"], 1)
        same = self.draft("https://example.org/report-one", "Same source publishes a second wording for the claim.")
        with self.assertRaisesRegex(ValueError, "distinct independent source"):
            rules.implement_rule(first["rule_id"], "implement this rule", same["evidence_id"], self.path)

    def test_imported_custom_coverage_and_missing_field(self):
        rules.import_inventory([{"id": "EXT-NEW", "title": "Reviewed existing hunt", "source_url": "https://example.org/rule",
                                "behavior": "custom", "spec": SPEC}], self.path)
        result = self.draft()
        self.assertEqual(result["status"], "existing_external_coverage")
        self.assertEqual(rules.acknowledge_existing("EXT-NEW", result["evidence_id"], "implement this rule", self.path)["pattern_score"], 1)
        self.assertEqual(rules.acknowledge_existing("EXT-NEW", result["evidence_id"], "implement this rule", self.path)["pattern_score"], 1)
        profile = {"name": "Fixture Defender", "siem": "defender", "telemetry": {"process_creation": {
            "table": "DeviceProcessEvents", "fields": ["InitiatingProcessFileName"]}}}
        environment.onboard(profile, [{"asset_id": "host-1", "hostname": "host-1", "product": "Fixture",
                                     "version": "1", "confirmed_cves": [], "internet_exposed": False,
                                     "criticality": "low", "asset_role": "general"}], self.path)
        # The external rule is not a local draft; create a different local spec
        # to exercise the missing target field without claiming coverage.
        local_spec = {**SPEC, "predicates": [SPEC["predicates"][0],
                                             {"field": "Image", "operator": "equals", "value": "cmd.exe"}]}
        draft = custom_rules.draft("CVE-2099-11111", "https://example.org/other", "Separate tested process lineage observation.",
                                   "Separate child process pattern", "This catches a different process chain on affected IIS hosts.",
                                   "Deploy scripts can produce this chain.", local_spec, self.path)
        fit = environment.check_rule_fit(draft["rule_id"], self.path)
        self.assertFalse(fit["ready"])
        self.assertEqual(fit["missing_fields"], ["Image"])
        profile["telemetry"]["process_creation"]["fields"].append("FileName")
        environment.onboard(profile, [{"asset_id": "host-1", "hostname": "host-1", "product": "Fixture",
                                     "version": "1", "confirmed_cves": [], "internet_exposed": False,
                                     "criticality": "low", "asset_role": "general"}], self.path)
        mapped = environment.check_rule_fit(draft["rule_id"], self.path)
        self.assertTrue(mapped["ready"])
        self.assertIn("DeviceProcessEvents", mapped["mapped_query"])
        self.assertIn("FileName", mapped["mapped_query"])
        with patch.dict("os.environ", {"GRAPH_TOKEN": "synthetic"}):
            native = live_validation.check_live_query(draft["rule_id"], self.path,
                        graph_fetch=lambda endpoint, body: b'{"results":[]}')
        self.assertEqual(native["status"], "query_executed")

    def test_rejects_query_injection_and_unsupported_pattern(self):
        bad = json.loads(json.dumps(SPEC))
        bad["predicates"][1]["value"] = 'certutil" | delete *'
        with self.assertRaisesRegex(ValueError, "bounded literal"):
            self.draft_spec(bad)
        bad = json.loads(json.dumps(SPEC))
        bad["predicates"][1]["field"] = "ParentImage"
        with self.assertRaisesRegex(ValueError, "one predicate per field"):
            self.draft_spec(bad)
        self.assertEqual(core.research_view("CVE-2099-11111", self.path)["detection_readiness"], "research_needed_no_behavior_rule")

    def test_tampered_custom_rule_is_not_executed(self):
        draft = self.draft()
        with store.connection(self.path) as db:
            db.execute("UPDATE rules SET sigma=sigma||'\n# unexpected' WHERE id=?", (draft["rule_id"],))
        with self.assertRaisesRegex(ValueError, "differs"):
            live_validation._generated_rule_only(rules.get_rule(draft["rule_id"], self.path), self.path)

    def test_arbitrary_published_cve_can_be_intaken_on_demand(self):
        new = core.intake_cve("CVE-2099-22222", self.path, fetch=lambda ident: {
            "id": ident, "title": ident, "summary": "Published CVE with no tested behavior.",
            "source": "https://www.cve.org/CVERecord?id=" + ident,
            "claim": "CNA published a vulnerability record."})
        self.assertEqual(new["id"], "CVE-2099-22222")
        self.assertEqual(core.research_view(new["id"], self.path)["detection_readiness"], "research_needed_no_behavior_rule")

    def test_imported_inventory_after_draft_blocks_local_approval(self):
        draft = self.draft()
        rules.import_inventory([{"id": "EXT-LATE", "title": "Deployed review", "source_url": "https://example.org/late",
                                "behavior": "custom", "spec": SPEC}], self.path)
        outcome = rules.implement_or_corroborate(draft["rule_id"], "implement this rule", draft["evidence_id"], self.path)
        self.assertEqual(outcome["status"], "existing_inventory_updated")
        self.assertEqual(outcome["pattern_score"], 1)
        self.assertEqual(rules.get_rule(draft["rule_id"], self.path)["status"], "draft")

    def test_generic_pack_exports_custom_sigma_and_field_pipeline(self):
        directory = Path(self.tmp.name) / "client-pack"
        enterprise.create_pack(directory, "Example Client", "generic")
        db = directory / "intel.sqlite3"
        core.ingest([{"id": "CVE-2099-11111", "title": "Fictional flaw", "summary": "Fixture",
                      "source": "https://example.org/advisory", "claim": "Fictional advisory."}], db)
        draft = custom_rules.draft("CVE-2099-11111", "https://example.org/report-one",
                                  "Verified process chain after exploitation in fictional data.",
                                  "IIS child process uses certutil", "Find a reported process chain on IIS hosts.",
                                  "Administrative maintenance can match.", SPEC, db)
        profile = {"name": "Example Client", "siem": "generic", "telemetry": {"process_creation": {
            "source": "process_logs", "field_map": {"ParentImage": "parent_path", "CommandLine": "cmdline"}}}}
        environment.onboard(profile, [{"asset_id": "h1", "hostname": "h1", "product": "Fixture", "version": "1",
                                     "confirmed_cves": [], "internet_exposed": False, "criticality": "low", "asset_role": "general"}], db)
        exported = enterprise.export_sigma_bundle(directory, draft["rule_id"])
        self.assertIn("ParentImage|endswith", Path(exported["rule"]).read_text())
        self.assertIn("parent_path", Path(exported["field_pipeline"]).read_text())

    def draft_spec(self, spec):
        return custom_rules.draft("CVE-2099-11111", "https://example.org/report", "Researcher verifies specific malicious process chain.",
                                  "Investigate process execution", "This report describes an actionable process chain.",
                                  "Administrative activity may overlap.", spec, self.path)


if __name__ == "__main__":
    unittest.main()
