"""Synthetic challenge replay uses exactly the source-linked unverified draft."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts import benchmark_reports, replay_benchmark


def report_manifest(missing=False):
    preds = [{"field": "ParentImage", "value": "RMM.Agent.exe"},
             {"field": "Image", "value": "PowerShell"},
             {"field": "CommandLine", "value": "Invoke-WebRequest"}]
    if missing:
        preds.append({"field": "GrandparentImage", "value": "absent.exe"})
    return {
        "schema_version": 1,
        "benchmark_id": "fictional-only",
        "cases": [{
            "id": "fictional-rmm",
            "title": "Entirely fictional research, not a real publisher report",
            "source_url": "https://www.microsoft.com/en-us/security/blog/2099/01/01/fake-test-only",
            "reference_behaviors": [{"name": "RMM to PowerShell", "event_family": "process_creation",
                                     "required_predicates": preds}]
        }]
    }


HTML = (b"<html><body><article>"
        b"<p>This fictional report describes a simulated security investigation of maintenance events.</p>"
        b"<p>In the incident RMM.Agent.exe launched PowerShell with Invoke-WebRequest to download the malicious payload.</p>"
        b"<p>Authorized administrators may sometimes issue the same commands in benign circumstances.</p>"
        b"<p>Process ancestry and command line fields are required for reliable interpretation of this case.</p>"
        b"</article></body></html>")


def challenge_manifest():
    return {"schema_version": 1, "provenance": "analyst_authored_synthetic_scenarios_not_real_incident_logs",
            "cases": [{
                "report_id": "fictional-rmm", "reference_name": "RMM to PowerShell",
                "scenarios": [
                    {"id": "synthetic-attack", "scenario": "Attacker does the reported behavior",
                     "expected_malicious": True, "event": {
                         "event_type": "process_creation", "ParentImage": "RMM.Agent.exe",
                         "Image": "PowerShell.exe", "CommandLine": "Invoke-WebRequest https://example.test"}},
                    {"id": "synthetic-benign-overlap", "scenario": "Admin issues the same command",
                     "expected_malicious": False, "event": {
                         "event_type": "process_creation", "ParentImage": "RMM.Agent.exe",
                         "Image": "PowerShell.exe", "CommandLine": "Invoke-WebRequest https://example.test"}},
                    {"id": "synthetic-attack-miss", "scenario": "Attacker substitutes a different command",
                     "expected_malicious": True, "event": {
                         "event_type": "process_creation", "ParentImage": "RMM.Agent.exe",
                         "Image": "PowerShell.exe", "CommandLine": "Invoke-RestMethod https://example.test"}},
                    {"id": "synthetic-benign", "scenario": "Administrator inspects services",
                     "expected_malicious": False, "event": {
                         "event_type": "process_creation", "ParentImage": "RMM.Agent.exe",
                         "Image": "PowerShell.exe", "CommandLine": "Get-Service"}}
                ]}
            ]}


class ReplayBenchmarkTests(unittest.TestCase):
    def test_confusion_matrix_of_exact_source_linked_draft(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            benchmark_reports.evaluate(report_manifest(), report_dir, fetch=lambda _: HTML)
            challenge_dir = root / "challenge"
            result = replay_benchmark.evaluate(report_dir, challenge_manifest(), challenge_dir)
            self.assertEqual(result["counts"]["references_scored"], 1)
            self.assertEqual(result["counts"]["fictional_events_scored"], 4)
            self.assertEqual({k: result["counts"][k] for k in ("tp", "fp", "fn", "tn")},
                             {"tp": 1, "fp": 1, "fn": 1, "tn": 1})
            self.assertFalse(result["native_siem_executed"])
            self.assertFalse(result["production_accuracy_inferred"])
            self.assertTrue(result["cases"][0]["rule_content_hashes"])
            self.assertEqual(len(result["cases"][0]["cases"]), 4)
            self.assertIn("Fictional event", (challenge_dir / "SUMMARY.md").read_text())
            self.assertIn("RMM to PowerShell", (challenge_dir / "results.json").read_text())

    def test_unextracted_behavior_is_explicitly_unscored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            benchmark_reports.evaluate(report_manifest(missing=True), report_dir, fetch=lambda _: HTML)
            result = replay_benchmark.evaluate(report_dir, challenge_manifest(), root / "challenge")
            self.assertEqual(result["counts"]["references_scored"], 0)
            self.assertEqual(result["counts"]["references_unscored"], 1)
            self.assertEqual(result["counts"]["fictional_events_unscored"], 4)
            self.assertEqual(result["counts"]["tp"], 0)
            self.assertEqual(result["cases"][0]["reason"], "no_rule_with_complete_reference_behavior")

    def test_unreadable_publisher_does_not_create_fake_true_negatives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            def blocked(_):
                raise ValueError("HTTP 403: publisher blocked the automated article fetch")
            benchmark_reports.evaluate(report_manifest(), report_dir, fetch=blocked)
            result = replay_benchmark.evaluate(report_dir, challenge_manifest(), root / "challenge")
            self.assertEqual(result["cases"][0]["status"], "unscored")
            self.assertEqual(result["cases"][0]["reason"], "source_report_not_readable")

    def test_labels_rejected_if_not_explicit_and_balanced(self):
        case = challenge_manifest()
        case["cases"][0]["scenarios"][0]["expected_malicious"] = "true"
        with self.assertRaisesRegex(ValueError, "boolean"):
            replay_benchmark.validate_challenges(case)
        case = challenge_manifest()
        for event in case["cases"][0]["scenarios"]:
            event["expected_malicious"] = True
        with self.assertRaisesRegex(ValueError, "both benign and malicious"):
            replay_benchmark.validate_challenges(case)

    def test_injected_rule_id_not_treated_as_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            benchmark_reports.evaluate(report_manifest(), report_dir, fetch=lambda _: HTML)
            data = json.loads((report_dir / "results.json").read_text())
            data["cases"][0]["reference_behaviors"][0]["matching_rule_ids"].append("forged-rule-id")
            (report_dir / "results.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "authored drafts"):
                replay_benchmark.evaluate(report_dir, challenge_manifest(), root / "challenges")

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            benchmark_reports.evaluate(report_manifest(), report_dir, fetch=lambda _: HTML)
            dest = root / "challenge"
            dest.mkdir()
            (dest / "do-not-delete").write_text("preserve")
            with self.assertRaisesRegex(ValueError, "new or empty"):
                replay_benchmark.evaluate(report_dir, challenge_manifest(), dest)
            self.assertEqual((dest / "do-not-delete").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
