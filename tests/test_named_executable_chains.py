"""Source-backed, named EXE parent-child research lead tests.

Fictional reports only. No public holdout report is fetched or rescored.
The goal is generalizable process relationship extraction, not a new
success statistic on the previously observed 17-case corpus.
"""
import tempfile
import unittest
from pathlib import Path

from threat_research import (behavior_leads, core, drafting, proposal_pass,
                             research_pass, rule_repository, rules, store)


class GenericProcessRelationshipTests(unittest.TestCase):
    def test_attacker_attributed_executable_pair_becomes_bounded_draft(self):
        sample = "The attacker launched csc.exe, which spawned cvtres.exe to process the payload resources."
        patterns = behavior_leads.behavior_patterns([sample])
        self.assertEqual([p["behavior"] for p in patterns], ["process_chain"])
        specs = proposal_pass.behavior_specs({
            "quoted_paragraph": sample,
            "observable": {"lexical_behavior": patterns[0]["behavior"]},
        })
        match = [s for s in specs if s.get("event_family") == "process_creation"
                 and s["platform"] == "windows"
                 and {p["field"]: p["value"] for p in s["predicates"]} ==
                 {"ParentImage": "csc.exe", "Image": "cvtres.exe"}]
        self.assertEqual(len(match), 1, specs)

    def test_renamed_pair_uses_literals_in_text_not_hardcoded_names(self):
        sample = "The malicious loader ran MyCompiler.exe, which launched MyConverter.exe during execution."
        patterns = behavior_leads.behavior_patterns([sample])
        self.assertEqual(patterns[0]["behavior"], "process_chain")
        specs = proposal_pass.behavior_specs({"quoted_paragraph": sample, "observable": {}})
        self.assertTrue(any(s["predicates"] == [
            {"field": "ParentImage", "operator": "endswith", "value": "MyCompiler.exe"},
            {"field": "Image", "operator": "endswith", "value": "MyConverter.exe"}
        ] for s in specs), specs)

    def test_do_not_join_benign_processes_to_unrelated_attacker_sentence(self):
        negatives = [
            "The attacker stole credentials. The administrator launched csc.exe, which spawned cvtres.exe for a normal build.",
            "An operator deployed safe patches. Legitimate csc.exe spawned cvtres.exe during routine builds.",
            "The attacker observed csc.exe and cvtres.exe as unrelated processes, without a confirmed parent-child action.",
            "The attacker did not launch csc.exe, which spawned cvtres.exe.",
            "The attacker launched csc.exe. A separate benign build spawned cvtres.exe.",
            "The attacker launched csc.exe. Later, cvtres.exe executed routine maintenance.",
        ]
        for sample in negatives:
            with self.subTest(sample=sample):
                self.assertNotIn("process_chain",
                    [p["behavior"] for p in behavior_leads.behavior_patterns([sample])])
                # Some other proposal paths may find an unrelated, legitimate
                # behavior; assert specifically no fabricated csc -> cvtres.
                specs = proposal_pass.behavior_specs({"quoted_paragraph": sample, "observable": {}})
                self.assertFalse(any(
                    {p["field"]: p["value"] for p in s.get("predicates", [])}.get("ParentImage") == "csc.exe"
                    and {p["field"]: p["value"] for p in s.get("predicates", [])}.get("Image") == "cvtres.exe"
                    for s in specs), sample)

    def test_named_executable_pair_is_drafted_and_source_linked_in_pipeline(self):
        article = (
            "<html><body><article>"
            "<p>This fictional exercise documents a simulated software compromise.</p>"
            "<p>The attacker launched BuildTool.exe, which spawned ConvertTool.exe to stage the malicious payload.</p>"
            "<p>Other benign software builds may involve legitimate resource converters.</p>"
            "<p>This article is entirely fabricated and has no real-world incident evidence.</p>"
            "</article></body></html>"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db = root / "test.sqlite3"
            store.initialize(db)
            url = "https://www.microsoft.com/en-us/security/blog/2099/01/01/fictional"
            core.ingest([{
                "id": "REPORT-EXEPIPELINETEST", "kind": "campaign",
                "title": "Synthetic process chain", "source": url,
                "summary": "Local fictional fixture only",
                "claim": "Synthetic report, no publisher validation"
            }], db)
            with rule_repository.isolated_repository(root / "repository"):
                result = research_pass.run_pass(db, threat_ids=["REPORT-EXEPIPELINETEST"],
                                                fetch=lambda _: article)
                self.assertEqual(result["drafts_created"], 1, result)
                proposal = result["results"][0]["rule_proposals"]["proposals"][0]
                rule = rules.get_rule(proposal["rule_id"], db)
                self.assertEqual(rule["status"], "draft")
                self.assertEqual(rule["custom_spec"]["platform"], "windows")
                self.assertEqual(rule["custom_spec"]["event_family"], "process_creation")
                self.assertEqual({p["field"]: p["value"] for p in rule["custom_spec"]["predicates"]},
                                 {"ParentImage": "BuildTool.exe", "Image": "ConvertTool.exe"})
                self.assertEqual(drafting.source_link(rule["id"], db)["status"], "unverified")
                self.assertIn("BuildTool.exe", rule["sigma"])
                self.assertIn("ConvertTool.exe", rule["kql"])
                self.assertIn("ConvertTool.exe", rule["spl"])


if __name__ == "__main__":
    unittest.main()
