"""Fictional regression cases for source-backed Windows command predicates.

No actual publisher page, offensive instruction, SIEM or SOC is accessed.
Each generated rule remains a draft. Negative cases protect against benign,
negated, cross-sentence and non-specific clauses.
"""
import json
import tempfile
import unittest
from pathlib import Path

from threat_research import (behavior_leads, core, custom_rules, proposal_pass,
                             research_pass, rule_repository, soc_replay, store)


class BoundedCommandPatternsTest(unittest.TestCase):
    def proposals(self, text):
        return proposal_pass.behavior_specs({"quoted_paragraph": text, "observable": {}})

    def test_defender_exclusion_requires_cited_executable_and_both_commands(self):
        text = ("The fictional malware operator used powershell.exe with "
                "Add-MpPreference -ExclusionPath C:\\Example\\Stage.")
        specs = self.proposals(text)
        exact = [s for s in specs if s["event_family"] == "process_creation"
                 and any(p["value"].lower() == "add-mppreference" for p in s["predicates"])]
        self.assertEqual(len(exact), 1, specs)
        spec = exact[0]
        self.assertEqual(spec["platform"], "windows")
        self.assertEqual({p["value"] for p in spec["predicates"]},
                         {"powershell.exe", "Add-MpPreference", "-ExclusionPath"})
        self.assertEqual(len(custom_rules.validate_spec(spec)["predicates"]), 3)
        self.assertTrue(soc_replay._matches(
            {"behavior": "custom", "custom_spec": json.dumps(spec)},
            {"event_type": "process_creation", "Image": "C:\\Windows\\System32\\powershell.exe",
             "CommandLine": "powershell.exe -Command Add-MpPreference -ExclusionPath C:\\Example\\Stage"}))
        self.assertFalse(soc_replay._matches(
            {"behavior": "custom", "custom_spec": json.dumps(spec)},
            {"event_type": "process_creation", "Image": "powershell.exe",
             "CommandLine": "powershell.exe Get-MpPreference"}))

    def test_literal_hta_url_is_required_not_http_scheme_alone(self):
        good = ("The malicious loader used mshta.exe to load from "
                "https://assets.example.test/audit.hta during execution.")
        spec = next(s for s in self.proposals(good)
                    if any(p["field"] == "Image" and p["value"] == "mshta.exe"
                           for p in s["predicates"]))
        self.assertEqual(spec["platform"], "windows")
        self.assertEqual({p["field"]: p["value"] for p in spec["predicates"]},
                         {"Image": "mshta.exe", "CommandLine": "https://assets.example.test/audit.hta"})
        for text in [
            "The malicious loader used mshta.exe with an HTTPS URL during execution.",
            "The malicious loader used mshta.exe with https:// only.",
            "An analyst documented mshta.exe with https://assets.example.test/audit.hta as an example.",
        ]:
            with self.subTest(text=text):
                self.assertFalse(any(
                    s.get("event_family") == "process_creation" and
                    any(p.get("field") == "CommandLine" and ".hta" in p.get("value", "")
                        for p in s["predicates"])
                    for s in self.proposals(text)))

    def test_no_rules_from_negation_or_benign_or_joining_two_sentences(self):
        paragraphs = [
            "The benign administrator used powershell.exe with Add-MpPreference -ExclusionPath for approved antivirus configuration.",
            "The attacker did not use powershell.exe with Add-MpPreference -ExclusionPath.",
            "The attacker used powershell.exe to read a file. The manual describes Add-MpPreference -ExclusionPath.",
            "The malware operator used mshta.exe to load a help file. See https://assets.example.test/audit.hta.",
            "Defenders recommend reviewing mshta.exe usage from https://assets.example.test/audit.hta.",
            "The malware operator used PowerShell with Add-MpPreference -ExclusionPath in this report.",
        ]
        for text in paragraphs:
            with self.subTest(text=text):
                bounded = [s for s in self.proposals(text)
                           if any(p["field"] == "CommandLine" and
                                  (p["value"].lower().startswith(("add-mp", "-exclusion", "https://")))
                                  for p in s.get("predicates", []))]
                self.assertEqual(bounded, [], text)

    def test_full_source_ingestion_creates_review_only_drafts(self):
        a = ("The fictional malware operator used powershell.exe with "
             "Add-MpPreference -ExclusionPath C:\\Example\\Stage during execution.")
        b = ("The malicious loader used mshta.exe to load from "
             "https://assets.example.test/audit.hta during execution.")
        html = ("<html><body><article>"
                "<p>A fictional security laboratory traces two unrelated attacker actions.</p>"
                "<p>" + a + "</p><p>" + b + "</p>"
                "<p>An authorized operator may issue the same antivirus command for benign purposes.</p>"
                "</article></body></html>").encode()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "local.sqlite3"
            store.initialize(db)
            link = "https://www.microsoft.com/en-us/security/blog/2099/02/03/fictional"
            core.ingest([{"id": "REPORT-FICTCMD2026", "kind": "campaign",
                          "title": "Fictional command chain", "source": link,
                          "claim": "Synthetic experiment only", "summary": "No real publisher report"}], db)
            with rule_repository.isolated_repository(root / "repo"):
                result = research_pass.run_pass(db, threat_ids=["REPORT-FICTCMD2026"], fetch=lambda _: html)
            proposals = result["results"][0]["rule_proposals"]["proposals"]
            specs = [p["candidate_spec"] for p in proposals if p.get("candidate_spec")]
            self.assertGreaterEqual(len(specs), 2, result)
            assert_values = ["Add-MpPreference", "https://assets.example.test/audit.hta"]
            for term in assert_values:
                self.assertTrue(any(term in [p["value"] for p in spec["predicates"]] for spec in specs), result)
            self.assertTrue(all(p["status"] == "draft_unverified" for p in proposals))
            self.assertEqual(result["drafts_created"], len(proposals))


if __name__ == "__main__":
    unittest.main()
