import json
import unittest

import yaml

from threat_research import custom_rules, proposal_pass, publisher_queries, soc_replay


class SequenceRegressionTest(unittest.TestCase):
    def setUp(self):
        self.spec = custom_rules.validate_spec({"event_family": "process_creation", "platform": "windows",
            "sequence": {"group_by": "DeviceId", "within_seconds": 60, "steps": [
                [{"field": "Image", "operator": "endswith", "value": "mshta.exe"},
                 {"field": "CommandLine", "operator": "contains", "value": "pages.dev"}],
                [{"field": "Image", "operator": "endswith", "value": "GatherOsState.exe"},
                 {"field": "ParentImage", "operator": "endswith", "value": "mshta.exe"}]]}})
        self.rule = {"id": "sequence", "behavior": "custom", "custom_spec": json.dumps(self.spec),
                     "status": "draft", "threat_id": "fixture"}

    def event(self, ident, second, stage, group="host1", malicious=False):
        return {"event_id": ident, "event_type": "process_creation",
                "timestamp": f"2099-01-01T00:{second // 60:02}:{second % 60:02}Z", "DeviceId": group,
                "Image": "mshta.exe" if stage == 1 else "GatherOsState.exe",
                "CommandLine": "mshta pages.dev", "ParentImage": "mshta.exe",
                "expected_malicious": malicious, "scenario": "synthetic sequence"}

    def test_order_window_grouping_and_missing_fields(self):
        first = self.event("first", 0, 1)
        for second, group, matches in [(1, "host1", True), (60, "host1", True),
                                        (61, "host1", False), (0, "host1", False),
                                        (1, "other", False), (1, None, False), (1, "", False)]:
            with self.subTest(second=second, group=group):
                last = self.event("last", second, 2, group, malicious=matches)
                result = soc_replay.replay([last, first], [self.rule])  # unsorted input
                self.assertEqual(result["cases"][0]["rule_ids"], ["sequence"] if matches else [])
        self.assertEqual(soc_replay.detect(first, [self.rule]), [])
        missing = self.event("missing", 1, 2)
        missing.pop("ParentImage")
        self.assertEqual(soc_replay.replay([first, missing], [self.rule])["counts"]["fp"], 0)
        reverse = [self.event("early", 0, 2), self.event("late", 1, 1)]
        self.assertEqual(soc_replay.replay(reverse, [self.rule])["counts"]["fp"], 0)

    def test_sigma_and_mapped_templates_require_correlation_fields(self):
        sigma = list(yaml.safe_load_all(custom_rules._sigma("Fictional ordered activity", self.spec, "Admin automation")))
        self.assertEqual(len(sigma), 3)
        self.assertEqual(sigma[-1]["correlation"]["condition"], {"gte": 2})
        self.assertEqual(sigma[-1]["correlation"]["rules"], [s["name"] for s in sigma[:2]])
        templates = custom_rules.generic_queries(self.spec)
        self.assertIn("second_time > first_time", templates["kql"])
        self.assertIn("max=0 correlation_key", templates["spl"])
        self.assertTrue(templates["limitations"])
        fields = custom_rules.required_fields(self.spec)
        self.assertIn("Timestamp", fields)
        query, missing = custom_rules._query(self.spec, {"table": "Events", "fields": fields[:-1]}, "template")
        self.assertIsNone(query)
        self.assertEqual(missing, ["Timestamp"])

    def test_publisher_filters_preserve_case_and_reject_query_expressions(self):
        text = "DeviceProcessEvents | where FileName == 'mshta.exe' | where ProcessCommandLine contains 'pages.dev' | project FileName"
        spec = publisher_queries.bounded_spec(text)
        self.assertIsNotNone(spec)
        rule = {**self.rule, "custom_spec": json.dumps(spec)}
        event = self.event("query", 0, 1)
        self.assertEqual(len(soc_replay.detect(event, [rule])), 1)
        event["Image"] = "MSHTA.EXE"
        self.assertEqual(soc_replay.detect(event, [rule]), [])
        self.assertIn('"Image|cased"', custom_rules._sigma("Publisher hunt", spec, "Administration"))
        self.assertIn("tostring(Image) == 'mshta.exe'", custom_rules.generic_queries(spec)["kql"])
        self.assertIsNone(publisher_queries.bounded_spec(text.replace("project FileName", "project FileName=tolower(FileName)")))

    def test_process_command_requires_a_relationship(self):
        candidate = proposal_pass.behavior_spec({"quoted_paragraph": "The attacker used conhost.exe to execute curl during the intrusion."})
        self.assertEqual({p["field"] for p in candidate["predicates"]}, {"Image", "CommandLine"})
        self.assertIsNone(proposal_pass.behavior_spec({"quoted_paragraph": "The attacker listed conhost.exe and curl among many tools."}))


if __name__ == "__main__":
    unittest.main()
