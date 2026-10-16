"""Regression tests for source-level passive malicious DLL image-load statements.

All report content below is fictional. No publisher or SIEM is contacted.
"""
import tempfile
import unittest
from pathlib import Path

from threat_research import behavior_leads, core, proposal_pass, research_pass, rule_repository, store


class PassiveDLLLoadTest(unittest.TestCase):
    def pattern(self, paragraph):
        types = [p["behavior"] for p in behavior_leads.behavior_patterns([paragraph])]
        self.assertIn("dll_sideloading", types)
        return {"quoted_paragraph": paragraph, "observable": {"lexical_behavior": "dll_sideloading"}}

    def test_passive_loaded_by_creates_process_and_dll_predicates(self):
        # Intentionally different wording from the Cisco Talos publisher text.
        text = 'The file "mindclient.dll" is a malicious DLL loaded by "TiVoDiag.exe" during execution.'
        spec = proposal_pass.behavior_spec(self.pattern(text))
        self.assertIsNotNone(spec)
        self.assertEqual(spec["event_family"], "image_load")
        self.assertEqual(spec["platform"], "windows")
        self.assertEqual({p["field"]: p["value"] for p in spec["predicates"]},
                         {"Image": "TiVoDiag.exe", "ImageLoaded": "mindclient.dll"})
        self.assertEqual(spec["exclude"][0]["value"], "C:\\Windows\\System32\\")

    def test_passive_unicode_quotes_supported(self):
        text = "The file “mindclient.dll” is the malicious DLL which is loaded by “TiVoDiag.exe” during execution."
        spec = proposal_pass.behavior_spec(self.pattern(text))
        self.assertEqual(spec["predicates"][0]["value"], "TiVoDiag.exe")

    def test_benign_or_unrelated_load_will_not_generate_draft(self):
        paragraphs = [
            "The benign system DLL mindclient.dll is loaded by TiVoDiag.exe during a legitimate installation.",
            "The malicious file mindclient.dll was identified. Separately TiVoDiag.exe was loaded by the service.",
            "The malicious mindclient.dll was discussed in an old incident. The signed TiVoDiag.exe loaded clean.dll.",
            "The malicious DLL mindclient.dll was not loaded by TiVoDiag.exe in the investigation.",
        ]
        for text in paragraphs:
            with self.subTest(text=text):
                kinds = {p["behavior"] for p in behavior_leads.behavior_patterns([text])}
                observable = {"lexical_behavior": "dll_sideloading"} if "dll_sideloading" in kinds else {}
                candidate = proposal_pass.behavior_spec({"quoted_paragraph": text, "observable": observable})
                self.assertIsNone(candidate, text)

    def test_complete_pipeline_recovers_passive_relation_as_unverified_draft(self):
        url = "https://blog.talosintelligence.com/fictional-passive-test/"
        paragraph = 'The file "mindclient.dll" is a malicious DLL loaded by "TiVoDiag.exe" during execution.'
        html = ("<html><article>"
                "<p>A fictional report investigates a loader and a malicious component.</p>"
                "<p>" + paragraph + "</p>"
                "<p>Malware operators are described in this independent fictional narrative.</p>"
                "<p>A normal application can load DLLs during a benign installation.</p>"
                "</article></html>").encode()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "isolated.sqlite3"
            store.initialize(path)
            with rule_repository.isolated_repository(Path(tmp) / "rules"):
                core.ingest([{
                    "id": "REPORT-TESTPASSIVE",
                    "kind": "campaign",
                    "title": "Fictional passive DLL load",
                    "source": url,
                    "summary": "Unit-test only",
                    "claim": "Fictional source test"
                }], path)
                result = research_pass.run_pass(path, threat_ids=["REPORT-TESTPASSIVE"], fetch=lambda _: html)
                proposed = result["results"][0]["rule_proposals"]["proposals"]
                specs = [p["candidate_spec"] for p in proposed if p.get("candidate_spec")]
                self.assertTrue(any(spec["event_family"] == "image_load" and
                                    {p["field"]: p["value"] for p in spec["predicates"]} ==
                                    {"Image": "TiVoDiag.exe", "ImageLoaded": "mindclient.dll"}
                                    for spec in specs), result["results"])
                self.assertTrue(all(p["status"] == "draft_unverified" for p in proposed))
                self.assertEqual(result["drafts_created"], len(proposed))


if __name__ == "__main__":
    unittest.main()
