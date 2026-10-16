"""Pre-registered 10-report multivendor challenge is distinct from prior reports.

Labels are partial, not independently adjudicated ground truth. This file
must be committed BEFORE its first live scoring workflow executes.
"""
import json
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from scripts import benchmark_reports

ROOT=Path(__file__).resolve().parents[1] / "benchmarks"
NEW=ROOT / "multivendor_holdout_v1.json"
OLD=[ROOT / "full_reports_v1.json", ROOT / "full_reports_holdout_v1.json"]


class MultiVendorCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=json.loads(NEW.read_text(encoding="utf-8"))

    def test_ten_distinct_reports_with_disjoint_urls(self):
        cases=benchmark_reports.validate_manifest(self.manifest)
        self.assertEqual(len(cases),10)
        urls={c["source_url"] for c in cases}
        self.assertEqual(len(urls),10)
        for file in OLD:
            earlier={c["source_url"] for c in json.loads(file.read_text())["cases"]}
            self.assertTrue(urls.isdisjoint(earlier),str(file))

    def test_multiple_publishers_and_unambiguous_partial_caveats(self):
        cases=self.manifest["cases"]
        sources={urlsplit(c["source_url"]).hostname for c in cases}
        self.assertGreaterEqual(len(sources),3)
        self.assertEqual(set(c["publisher"] for c in cases),
                         {"Google Mandiant","Palo Alto Unit 42","Cisco Talos"})
        self.assertIn("BEFORE first scoring",self.manifest["selection_method"])
        self.assertIn("Second expert review pending",self.manifest["reference_limitations"])
        self.assertEqual(self.manifest["benchmark_partition"],
                         "new_multivendor_challenge_before_first_score")
        self.assertTrue(all(len(c["reference_behaviors"])==1 for c in cases))
        self.assertTrue(all("annotation_note" in c["reference_behaviors"][0] for c in cases))

    def test_frozen_manifest_refs_are_bounded_field_hypotheses(self):
        for c in self.manifest["cases"]:
            with self.subTest(c["id"]):
                for label in c["reference_behaviors"]:
                    self.assertIn(label["event_family"],("process_creation","image_load"))
                    self.assertGreaterEqual(len(label["required_predicates"]),2)
                    self.assertIn("https",c["source_url"])
                    self.assertTrue(benchmark_reports.validate_manifest({
                        "schema_version":1,"cases":[c]}))


if __name__=="__main__":
    unittest.main()
