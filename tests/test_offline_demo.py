"""Unit tests for the documentation-facing offline entry point; no SOC needed."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import offline_demo


def sample_report():
    return {
        "lab_notice": "All sources, events and assets are synthetic.",
        "drafts_tested": 3,
        "measurement": {"sample_size": 4, "counts": {"tp": 1, "fp": 1, "fn": 1, "tn": 1},
                        "precision": 0.5, "recall": 0.5, "false_positive_rate": 0.5},
        "automatic_drafting": {"status": "passed", "reports_tested": 5,
                               "automatic_drafts": 12, "checks_passed": 26},
    }


class OfflineDemoTests(unittest.TestCase):
    def test_renders_a_plainly_scoped_human_review(self):
        summary = offline_demo.summary_markdown(sample_report())
        self.assertIn("synthetic fixtures only", summary)
        self.assertIn("false positives: 1", summary)
        self.assertIn("real-world or production detection accuracy", summary)
        self.assertIn("unverified lab drafts", summary)
        self.assertIn("automatically generated", summary.lower())

    def test_rejects_missing_synthetic_disclosure(self):
        report = sample_report()
        report["lab_notice"] = ""
        with self.assertRaisesRegex(ValueError, "synthetic"):
            offline_demo.validate_report(report)

    def test_rejects_mismatched_measurement(self):
        report = sample_report()
        report["measurement"]["sample_size"] = 10
        with self.assertRaisesRegex(ValueError, "counts"):
            offline_demo.validate_report(report)

    def test_rejects_failed_automatic_drafting(self):
        report = sample_report()
        report["automatic_drafting"]["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "did not pass"):
            offline_demo.validate_report(report)

    def test_refuses_to_overwrite_previous_demo(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "prior-run"
            output.mkdir()
            (output / "report.json").write_text("preserve", encoding="utf-8")
            with patch.object(offline_demo, "_run_lab") as run:
                with self.assertRaises(SystemExit):
                    offline_demo.main(["--output-directory", str(output)])
                run.assert_not_called()
            self.assertEqual((output / "report.json").read_text(encoding="utf-8"), "preserve")

    def test_writes_summary_after_verified_lab(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "fresh-run"

            def fake_lab(destination):
                destination.mkdir()
                (destination / "report.json").write_text(json.dumps(sample_report()), encoding="utf-8")

            with patch.object(offline_demo, "_run_lab", side_effect=fake_lab) as lab:
                self.assertEqual(offline_demo.main(["--output-directory", str(output)]), 0)
                lab.assert_called_once()
            self.assertIn("Fixture precision: 0.500", (output / "DEMO_SUMMARY.md").read_text(encoding="utf-8"))
            self.assertTrue((output / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
