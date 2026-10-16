"""Frozen public-report evaluation sample: validate provenance before first score.

A manually nominated label is a research hypothesis, NOT ground truth about
every behavior present in a full article. Do not change this manifest based
on benchmark scores; use a new partition for future error analysis.
"""
import json
import unittest
from pathlib import Path

from scripts import benchmark_reports

ROOT = Path(__file__).resolve().parents[1]
LOCKED = ROOT / "benchmarks" / "full_reports_holdout_v1.json"
DEV = ROOT / "benchmarks" / "full_reports_v1.json"


class LockedHoldoutCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.holdout = json.loads(LOCKED.read_text(encoding="utf-8"))
        cls.dev = json.loads(DEV.read_text(encoding="utf-8"))

    def test_seven_distinct_publisher_reports_have_independent_dev_urls(self):
        holdout = benchmark_reports.validate_manifest(self.holdout)
        development = benchmark_reports.validate_manifest(self.dev)
        self.assertEqual(len(holdout), 7)
        self.assertEqual(len(set(c["source_url"] for c in holdout)), 7)
        self.assertTrue(set(c["source_url"] for c in holdout).isdisjoint(
            set(c["source_url"] for c in development)))
        self.assertTrue(set(c["id"] for c in holdout).isdisjoint(set(c["id"] for c in development)))

    def test_heldout_partition_is_explicitly_never_used_to_tune(self):
        self.assertEqual(self.holdout["benchmark_partition"], "locked_holdout_no_tuning")
        self.assertIn("before any extractor measurement", self.holdout["selection_method"])
        self.assertIn("independent second reviewer not obtained", self.holdout["annotator"])
        self.assertIn("NOT verified full-report ground truth", self.holdout["note"])

    def test_partial_annotations_do_not_promise_all_behavior_extraction(self):
        for case in self.holdout["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(len(case["reference_behaviors"]), 1)
                self.assertTrue(case["source_url"].startswith("https://www.microsoft.com/en-us/security/blog/2026/"))
                for behavior in case["reference_behaviors"]:
                    self.assertTrue(behavior["required_predicates"])

    def test_duplicate_reference_not_accepted_as_second_report(self):
        clone = json.loads(json.dumps(self.holdout))
        clone["cases"].append(dict(clone["cases"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            benchmark_reports.validate_manifest(clone)


if __name__ == "__main__":
    unittest.main()
