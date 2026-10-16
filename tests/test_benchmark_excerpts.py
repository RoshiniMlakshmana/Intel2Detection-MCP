"""Regression tests for carefully scoped public research excerpt evaluation."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import benchmark_excerpts

MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks" / "public_excerpts_v1.json"


class ExcerptBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_curated_inputs_are_source_attributed_and_bounded(self):
        cases = benchmark_excerpts._check_manifest(self.manifest)
        self.assertGreaterEqual(len(cases), 3)
        self.assertTrue(all(c["source_url"].startswith("https://") for c in cases))

    def test_expected_predictions_count_without_claiming_production_accuracy(self):
        report = benchmark_excerpts.evaluate(self.manifest)
        c = report["counts"]
        self.assertEqual(c["cases"], len(self.manifest["cases"]))
        self.assertEqual(c["expected_supported"] + c["expected_unsupported"], c["cases"])
        self.assertEqual(c["supported_with_all_expected_predicates"] + c["missed_expected"], c["expected_supported"])
        self.assertEqual(c["unsupported_correctly_withheld"] + c["unexpected_candidates"], c["expected_unsupported"])
        self.assertFalse(report["native_siem_executed"])
        self.assertFalse(report["rules_approved"])
        self.assertIn("NOT full reports", report["scope"])

    def test_expected_predicates_need_one_complete_candidate(self):
        case = {"expected_event_family": "process_creation", "required_predicates": [
            {"field": "Image", "value": "PowerShell"}, {"field": "ParentImage", "value": "RMM.Agent.exe"}]}
        one = {"event_family": "process_creation", "predicates": [{"field": "Image", "value": "powershell"}]}
        two = {"event_family": "process_creation", "predicates": [{"field": "ParentImage", "value": "rmm.agent.exe"}]}
        self.assertFalse(any(benchmark_excerpts._matches_expected(s, case) for s in (one, two)))
        joined = {"event_family": "process_creation", "predicates": one["predicates"] + two["predicates"]}
        self.assertTrue(benchmark_excerpts._matches_expected(joined, case))

    def test_positive_and_negative_scoring_and_no_hidden_approval(self):
        payload = copy.deepcopy(self.manifest)
        sample_pos = next(c for c in payload["cases"] if c["expected_draftable"])
        sample_neg = next(c for c in payload["cases"] if not c["expected_draftable"])
        payload["cases"] = [sample_pos, sample_neg]
        with patch.object(benchmark_excerpts, "_candidate_specs", side_effect=[
            ([{"event_family": sample_pos["expected_event_family"],
               "predicates": [{"field": p["field"], "value": p["value"]} for p in sample_pos["required_predicates"]]}], "tested"),
            ([], "withheld")
        ]):
            result = benchmark_excerpts.evaluate(payload)
        self.assertEqual(result["counts"]["supported_with_all_expected_predicates"], 1)
        self.assertEqual(result["counts"]["unsupported_correctly_withheld"], 1)
        self.assertIn("no full-report evaluation", benchmark_excerpts.markdown_summary(result).lower())
        self.assertFalse(result["rules_approved"])

    def test_duplicate_identifiers_refused(self):
        payload = copy.deepcopy(self.manifest)
        payload["cases"].append(copy.deepcopy(payload["cases"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            benchmark_excerpts.evaluate(payload)

    def test_no_overlong_publisher_quotations(self):
        payload = copy.deepcopy(self.manifest)
        payload["cases"][0]["excerpt"] = "word " * 26
        with self.assertRaisesRegex(ValueError, "25 words"):
            benchmark_excerpts.evaluate(payload)

    def test_refuses_negative_case_with_expected_detection(self):
        payload = copy.deepcopy(self.manifest)
        case = next(c for c in payload["cases"] if not c["expected_draftable"])
        case["required_predicates"] = [{"field": "Image", "value": "powershell.exe"}]
        with self.assertRaisesRegex(ValueError, "positive cases"):
            benchmark_excerpts.evaluate(payload)


if __name__ == "__main__":
    unittest.main()
