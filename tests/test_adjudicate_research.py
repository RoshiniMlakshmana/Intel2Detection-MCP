"""Review worksheets never silently become independently verified labels."""
import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts import adjudicate_research


def manifests():
    ref = {"name": "Compiler launch hypothesis",
           "event_family": "process_creation",
           "required_predicates": [
               {"field": "ParentImage", "value": "BuildTool.exe"},
               {"field": "Image", "value": "ResourceTool.exe"}]}
    url = "https://www.microsoft.com/en-us/security/blog/2099/01/01/test-only"
    manifest = {"schema_version": 1, "benchmark_id": "hypothetical",
                "cases": [{"id": "fictional-build", "title": "Entirely fictional case",
                           "source_url": url, "reference_behaviors": [ref]}]}
    results = {"benchmark_id": "hypothetical", "cases": [
        {"id": "fictional-build", "source_url": url, "scored": True,
         "page_status": "inspected", "page_sha256": "a" * 64,
         "reference_behaviors": [{**copy.deepcopy(ref), "extracted": False, "matching_rule_ids": []}],
         "generated_drafts": [{"rule_id": "fictional", "spec": {
             "event_family": "process_creation",
             "predicates": [{"field": "ParentImage", "value": "BuildTool.exe"}]}}]}
    ]}
    return manifest, results


class AdjudicationWorksheetTests(unittest.TestCase):
    def test_partial_match_does_not_convert_into_a_pass(self):
        manifest, results = manifests()
        output = adjudicate_research.prepare(manifest, results)
        self.assertFalse(output["human_review_complete"])
        self.assertFalse(output["source_refetched"])
        self.assertFalse(output["native_siem_tested"])
        self.assertEqual(len(output["rows"]), 1)
        row = output["rows"][0]
        self.assertEqual(row["best_literal_overlap"], "1/2")
        self.assertEqual(row["structural_gap"], "OTHER_OR_PARTIAL_PREDICATES")
        self.assertFalse(row["exact_machine_match"])
        self.assertEqual(row["manual_review_status"], "PENDING_INDEPENDENT_REVIEW")
        self.assertEqual(row["source_sha256"], "a" * 64)
        self.assertEqual(row["independent_reviewer"], "")

    def test_changes_to_original_references_are_not_silently_scored(self):
        manifest, results = manifests()
        results["cases"][0]["reference_behaviors"][0]["required_predicates"][0]["value"] = "SomeOther.exe"
        with self.assertRaisesRegex(ValueError, "reference predicates"):
            adjudicate_research.prepare(manifest, results)

    def test_changes_to_report_url_are_refused(self):
        manifest, results = manifests()
        results["cases"][0]["source_url"] = "https://unrelated.test/"
        with self.assertRaisesRegex(ValueError, "URL"):
            adjudicate_research.prepare(manifest, results)

    def test_export_writes_blank_csv_without_changing_source(self):
        manifest, results = manifests()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir, out = root / "existing-input", root / "review-packet"
            input_dir.mkdir()
            (root / "manifest.json").write_text(json.dumps(manifest))
            original = json.dumps(results)
            (input_dir / "results.json").write_text(original)
            generated = adjudicate_research.export(root / "manifest.json", input_dir, out)
            self.assertEqual(generated["reference_count"], 1)
            with (out / "INDEPENDENT_REVIEW.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["manual_review_status"], "PENDING_INDEPENDENT_REVIEW")
            self.assertIn("NOT YET COMPLETED", (out / "README.md").read_text())
            self.assertEqual((input_dir / "results.json").read_text(), original)

    def test_no_overwrite_and_no_nested_output(self):
        manifest, results = manifests()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "results.json").write_text(json.dumps(results))
            m = root / "manifest.json"
            m.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "outside"):
                adjudicate_research.export(m, source, source / "nested")
            target = root / "existing"
            target.mkdir()
            (target / "keep").write_text("preserve")
            with self.assertRaisesRegex(ValueError, "new or empty"):
                adjudicate_research.export(m, source, target)
            self.assertEqual((target / "keep").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
