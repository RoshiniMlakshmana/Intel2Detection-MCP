"""End-to-end full report benchmark checks with fictional HTML and zero HTTP."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import benchmark_reports


def manifest():
    return {"schema_version": 1, "cases": [{
        "id": "fictional-rmm", "title": "Test-only RMM incident",
        "source_url": "https://www.microsoft.com/en-us/security/blog/2099/01/01/fictional-rmm",
        "reference_behaviors": [{
            "name": "RMM agent launch of downloader", "event_family": "process_creation",
            "required_predicates": [
                {"field": "ParentImage", "value": "RMM.Agent.exe"},
                {"field": "Image", "value": "PowerShell"},
                {"field": "CommandLine", "value": "Invoke-WebRequest"}]
        }]
    }]}


HTML = (b"<html><body><article>"
        b"<p>Fictional background to an investigation of endpoint activities and system telemetry.</p>"
        b"<p>During the attack RMM.Agent.exe launched PowerShell with Invoke-WebRequest to retrieve a malicious package.</p>"
        b"<p>Separate ordinary software maintenance could cause noisy detections in a normal environment.</p>"
        b"<p>Other details are withheld in this fictional research experiment and remain unproven.</p>"
        b"</article></body></html>")


class FullHTMLBenchmarkTest(unittest.TestCase):
    def test_manifest_rejects_untrusted_host_and_duplicate_ids(self):
        payload = manifest()
        self.assertEqual(len(benchmark_reports.validate_manifest(payload)), 1)
        bad = copy.deepcopy(payload)
        bad["cases"][0]["source_url"] = "https://127.0.0.1/report"
        with self.assertRaisesRegex(ValueError, "allowlist"):
            benchmark_reports.validate_manifest(bad)
        bad = copy.deepcopy(payload)
        bad["cases"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            benchmark_reports.validate_manifest(bad)

    def test_injected_full_page_produces_review_only_draft(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            with patch.object(benchmark_reports.report_inspection, "fetch_article") as live:
                result = benchmark_reports.evaluate(manifest(), out, lambda _: HTML)
                live.assert_not_called()
            self.assertEqual(result["counts"]["reports_scored"], 1)
            self.assertEqual(result["counts"]["annotated_behaviors_scored"], 1)
            self.assertEqual(result["counts"]["reference_behaviors_extracted"], 1)
            self.assertGreaterEqual(result["counts"]["drafts_on_scored_reports"], 1)
            self.assertEqual(result["cases"][0]["generated_drafts"][0]["status"], "draft_unverified")
            self.assertEqual(len(result["cases"][0]["page_sha256"]), 64)
            self.assertFalse(result["rules_approved"])
            self.assertFalse(result["native_siem_executed"])
            self.assertTrue((out / "results.json").is_file())
            self.assertTrue((out / "SUMMARY.md").is_file())
            self.assertNotIn("Separate ordinary software maintenance", (out / "results.json").read_text())

    def test_blocked_report_is_unscored_not_a_false_negative(self):
        def blocked(_):
            raise ValueError("HTTP 403: publisher blocked the automated article fetch")
        with tempfile.TemporaryDirectory() as temp:
            result = benchmark_reports.evaluate(manifest(), Path(temp) / "out", blocked)
            self.assertEqual(result["counts"]["reports_unscored"], 1)
            self.assertEqual(result["counts"]["annotated_behaviors_scored"], 0)
            self.assertEqual(result["counts"]["reference_behaviors_missed"], 0)
            self.assertIsNone(result["annotated_behavior_recall"])
            self.assertFalse(result["cases"][0]["scored"])
            self.assertFalse(result["cases"][0]["generated_drafts"])

    def test_missing_reference_predicate_counts_as_miss(self):
        payload = manifest()
        payload["cases"][0]["reference_behaviors"][0]["required_predicates"].append(
            {"field": "GrandparentImage", "value": "not_in_report.exe"})
        with tempfile.TemporaryDirectory() as temp:
            result = benchmark_reports.evaluate(payload, Path(temp) / "out", lambda _: HTML)
            self.assertEqual(result["counts"]["reference_behaviors_extracted"], 0)
            self.assertEqual(result["counts"]["reference_behaviors_missed"], 1)

    def test_nonempty_output_folder_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "existing"
            out.mkdir()
            (out / "keep").write_text("preserve")
            with self.assertRaisesRegex(ValueError, "empty"):
                benchmark_reports.evaluate(manifest(), out, lambda _: HTML)
            self.assertEqual((out / "keep").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
