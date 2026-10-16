"""Review packages contain real generated (unverified) text and scoped synthetic limits."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts import benchmark_reports, replay_benchmark, export_review_bundles
from test_replay_benchmark import report_manifest, challenge_manifest, HTML


class BundleExportTest(unittest.TestCase):
    def test_source_linked_package_contains_untouched_queries_and_test_caveats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source"
            challenge = root / "challenge"
            dest = root / "bundles"
            benchmark_reports.evaluate(report_manifest(), src, fetch=lambda _: HTML)
            replay_benchmark.evaluate(src, challenge_manifest(), challenge)
            result = export_review_bundles.export(src, dest, challenge)
            self.assertTrue(result["review_only"])
            self.assertFalse(result["native_siem_executed"])
            self.assertEqual(result["rules_exported"], 1)
            entry = result["packaged"][0]
            folder = dest / entry["report_id"] / entry["rule_id"]
            metadata = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["status"], "draft_unverified")
            self.assertEqual(metadata["source_link_status"], "unverified")
            self.assertFalse(metadata["deployed"])
            self.assertFalse(metadata["native_siem_executed"])
            self.assertIn("ParentImage", metadata["required_canonical_fields"])
            self.assertEqual(metadata["synthetic_tests"][0]["counts"],
                             {"tp": 1, "fp": 1, "fn": 1, "tn": 1})
            self.assertEqual(metadata["synthetic_tests"][0]["rule_hash_from_replay"],
                             metadata["rule_content_hash"])
            self.assertIn("invoke-webrequest", (folder / "detection.kql").read_text().lower())
            self.assertIn("invoke-webrequest", (folder / "detection.spl").read_text().lower())
            self.assertIn("fictional", ((folder / "REVIEW.md").read_text() +
                          (dest / "README.md").read_text()).lower())
            self.assertTrue((folder / "detection.yml").exists())
            self.assertTrue((dest / "INDEX.json").exists())

    def test_export_without_challenge_is_labeled_untested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source"
            dest = root / "export"
            benchmark_reports.evaluate(report_manifest(), src, fetch=lambda _: HTML)
            result = export_review_bundles.export(src, dest)
            self.assertFalse(result["packaged"][0]["synthetic_replay_attached"])
            folder = dest / result["packaged"][0]["report_id"] / result["packaged"][0]["rule_id"]
            metadata = json.loads((folder / "metadata.json").read_text())
            self.assertEqual(metadata["synthetic_tests"], [])
            self.assertIn("No per-rule synthetic event replay", (folder / "REVIEW.md").read_text())

    def test_no_overwrite_and_no_output_inside_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source"
            benchmark_reports.evaluate(report_manifest(), src, fetch=lambda _: HTML)
            out = root / "existing"
            out.mkdir()
            (out / "keep.txt").write_text("preserve")
            with self.assertRaisesRegex(ValueError, "new or empty"):
                export_review_bundles.export(src, out)
            self.assertEqual((out / "keep.txt").read_text(), "preserve")
            with self.assertRaisesRegex(ValueError, "separate"):
                export_review_bundles.export(src, src / "child")

    def test_invalid_rule_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source"
            benchmark_reports.evaluate(report_manifest(), src, fetch=lambda _: HTML)
            report = json.loads((src / "results.json").read_text(encoding="utf-8"))
            report["cases"][0]["generated_drafts"][0]["rule_id"] = "../../evil"
            (src / "results.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "invalid rule UUID"):
                export_review_bundles.export(src, root / "bundles")


if __name__ == "__main__":
    unittest.main()
