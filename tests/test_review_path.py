"""Review path, risk attribution, sample provenance, manual source review and triage grouping.

Fixtures are fictional (FictLoader, CVE-2099-*, lab assets); fetches are injected. Approvals here act
only on fictional rules in temporary databases.
"""

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path

from threat_research import (core, corroboration, drafting, environment, research_pass, rules, soc_replay, store,
                             workflow, workup)

HASH = "e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e"
URL = "https://www.microsoft.com/en-us/security/blog/2099/01/01/fictloader-analysis"
FRESH = "https://unit42.paloaltonetworks.com/fictional-fictloader-followup"
PARA = f"In the analyzed sample, the loader DLL was named FictLoader.dll (SHA-256: {HASH})."
HTML = (f"<html><body><p>Fictional analysis of a modular post-compromise malware family.</p><p>{PARA}</p>"
        "</body></html>").encode()
FRESH_HTML = (f"<html><body><p>Responders recovered the malicious loader FictLoader.dll with SHA-256 {HASH}."
              "</p></body></html>").encode()
SPEC = {"event_family": "file_event", "platform": "windows",
        "predicates": [{"field": "SHA256", "operator": "equals", "value": HASH},
                       {"field": "TargetFilename", "operator": "endswith", "value": "FictLoader.dll"}]}
TEXT = ("FictLoader loader DLL by SHA-256 (fictional)",
        "The cited paragraph names the loader DLL FictLoader.dll with its SHA-256 in the analyzed sample.",
        "A legitimate file with the same name differs by hash; exact hash match only.")
FIXTURES = resources.files("threat_research") / "lab_fixtures"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def onboard(self):
        environment.onboard(json.loads((FIXTURES / "profile.json").read_text(encoding="utf-8")),
                            environment.parse_assets((FIXTURES / "assets.csv").read_text(encoding="utf-8")),
                            self.path)

    def draft(self):
        core.ingest([{"id": "REPORT-FICTLOADER0001", "title": "FictMantis: a fictional malware family",
                      "summary": "fixture", "kind": "campaign", "source": URL, "claim": "listed",
                      "published": "2099-01-01T00:00:00Z"}], self.path)
        research_pass.research_lead("REPORT-FICTLOADER0001", self.path, fetch=lambda u: HTML, refresh=True)
        return drafting.propose("REPORT-FICTLOADER0001", URL, 2, SPEC, *TEXT, path=self.path)["rule_id"]

    def events(self, name, synthetic=False):
        rows = [{"event_id": "E1", "timestamp": "2099-01-01T00:00:00Z", "event_type": "file_event", "SHA256": HASH,
                 "TargetFilename": "C:\\Users\\a\\FictLoader.dll", "expected_malicious": True,
                 "scenario": "reported loader written"},
                {"event_id": "E2", "timestamp": "2099-01-01T00:01:00Z", "event_type": "file_event", "SHA256": "0" * 64,
                 "TargetFilename": "C:\\Program Files\\App\\FictLoader.dll", "expected_malicious": False,
                 "scenario": "legitimate same-name library"}]
        if synthetic:
            rows[0]["synthetic"] = True
        path = self.dir / name
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return str(path)


class RiskAttributionTest(Base):
    def setUp(self):
        super().setUp()
        self.onboard()  # lab-web-01 confirms CVE-2099-99999 (exposed, high); lab-agent-01 does not
        core.ingest([{"id": "CVE-2099-99999", "title": "Fictional", "summary": "fixture", "kev": True,
                      "source": "https://example.test/advisory", "claim": "fixture"}], self.path)

    def test_event_on_asset_b_is_never_combined_with_asset_a_confirmation(self):
        workup.record_local_event_context("CVE-2099-99999", "yes", "Defender file events on lab-agent-01, 7 days",
                                          "lab-agent-01", self.path)
        env = workup.risk_view("CVE-2099-99999", self.path)["environment_risk"]
        self.assertIsNone(env["score"])
        self.assertIn("recorded for asset lab-agent-01, which is not confirmed", env["missing_inputs"][0])
        self.assertIn("lab-web-01", env["missing_inputs"][0])

    def test_context_without_an_asset_cannot_score(self):
        workup.record_local_event_context("CVE-2099-99999", "yes", "Checked the SIEM broadly for 7 days", None,
                                          self.path)
        env = workup.risk_view("CVE-2099-99999", self.path)["environment_risk"]
        self.assertIsNone(env["score"])
        self.assertIn("names no asset", env["missing_inputs"][0])

    def test_score_uses_only_the_same_confirmed_asset(self):
        workup.record_local_event_context("CVE-2099-99999", "yes", "Defender file events on lab-web-01, 7 days",
                                          "lab-web-01", self.path)
        env = workup.risk_view("CVE-2099-99999", self.path)["environment_risk"]
        self.assertEqual((env["asset_id"], env["score"]), ("lab-web-01", 100))
        self.assertEqual(env["components"], {"affected_version_confirmed": 30, "internet_exposed": 20,
                                             "asset_criticality": 20, "local_event_observed": 30})

    def test_report_lead_scores_the_context_asset_only(self):
        rule_id = self.draft()
        self.assertTrue(rule_id)
        workup.record_local_event_context("REPORT-FICTLOADER0001", "no", "Defender file events on lab-agent-01, 30d",
                                          "lab-agent-01", self.path)
        env = workup.risk_view("REPORT-FICTLOADER0001", self.path)["environment_risk"]
        self.assertEqual((env["asset_id"], env["components"]),
                         ("lab-agent-01", {"local_event_observed": 0, "internet_exposed": 0, "asset_criticality": 30}))


class ProvenanceAndGateOrderTest(Base):
    def test_fixture_events_never_satisfy_the_gate_and_steps_open_in_order(self):
        rule_id = self.draft()
        ident = "REPORT-FICTLOADER0001"

        def states():
            path = workup.lead_workup(ident, self.path)["drafts"][0]["review_path"]
            return {s["key"]: s["state"] for s in path}
        self.assertEqual((states()["source_verification"], states()["labeled_events"], states()["approval"]),
                         ("current", "waiting", "waiting"))
        self.assertIn("verify_draft_source", workup.lead_workup(ident, self.path)["next_analyst_decision"])
        drafting.verify(rule_id, "I verified this source paragraph", path=self.path)
        self.assertEqual(states()["labeled_events"], "current")
        lab = soc_replay.test_rule_against_samples(rule_id, str(FIXTURES / "events.jsonl"), self.path)
        self.assertEqual(lab["sample_provenance"], "bundled_synthetic_fixture")
        marked = soc_replay.test_rule_against_samples(rule_id, self.events("marked.jsonl", True), self.path)
        self.assertEqual(marked["sample_provenance"], "bundled_synthetic_fixture")
        with self.assertRaisesRegex(ValueError, "synthetic fixture events"):
            rules.implement_rule(rule_id, "implement this rule", path=self.path)
        self.assertEqual(states()["approval"], "waiting")
        real = soc_replay.test_rule_against_samples(rule_id, self.events("analyst.jsonl"), self.path)
        self.assertEqual((real["sample_provenance"], real["counts"]["tp"], real["counts"]["tn"]),
                         ("analyst_supplied_file", 1, 1))
        self.assertEqual((states()["labeled_events"], states()["approval"]), ("done", "current"))
        self.assertEqual(states()["inventory"], "attention")  # scope undeclared; the analyst's call, not a gate
        rules.implement_rule(rule_id, "implement this rule", path=self.path)
        final = {s["key"]: s for s in workup.lead_workup(ident, self.path)["drafts"][0]["review_path"]}
        self.assertEqual(final["approval"]["state"], "done")
        self.assertIn("approved/", final["repository"]["detail"])
        self.assertEqual(final["native_siem_test"]["state"], "pending")

    def test_matching_source_stays_pending_until_approved(self):
        rule_id = self.draft()
        core.ingest([{"id": "REPORT-FICTFOLLOWUP1", "title": "Fictional follow-up", "summary": "fixture",
                      "kind": "campaign", "source": FRESH, "claim": "listed"}], self.path)
        research_pass.research_lead("REPORT-FICTFOLLOWUP1", self.path, fetch=lambda u: FRESH_HTML, refresh=True)
        step = next(s for s in workup.lead_workup("REPORT-FICTLOADER0001", self.path)["drafts"][0]["review_path"]
                    if s["key"] == "corroboration")
        self.assertEqual(step["state"], "current")
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 0)
        review = corroboration.list_pending(self.path)[0]
        corroboration.approve(review["id"], "implement this rule", self.path)
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 1)


class ManualReviewTest(Base):
    def setUp(self):
        super().setUp()
        core.ingest([{"id": "REPORT-FICTBLOCKED01", "title": "Fictional blocked article", "summary": "fixture",
                      "kind": "campaign", "source": "https://www.darkreading.com/fictional-blocked",
                      "claim": "listed"}], self.path)

    def test_url_must_belong_to_the_lead_and_text_stays_unverified(self):
        with self.assertRaisesRegex(ValueError, "not cited by this lead"):
            drafting.record_manual_review("REPORT-FICTBLOCKED01", "https://attacker.example/x", "x" * 40, "browser",
                                          "undecided", "read in browser", self.path)
        with self.assertRaisesRegex(ValueError, "decision must be"):
            drafting.record_manual_review("REPORT-FICTBLOCKED01", "https://www.darkreading.com/fictional-blocked",
                                          "x" * 40, "browser", "verified", "read in browser", self.path)
        text = f"The attackers dropped the malicious loader FictLoader.dll (SHA-256: {HASH}) on each host."
        entry = drafting.record_manual_review("REPORT-FICTBLOCKED01", "https://www.darkreading.com/fictional-blocked",
                                              text, "browser", "contains_detection_detail",
                                              "Read the article in a browser; paragraph 6.", self.path)
        self.assertEqual((entry["provenance"], entry["verified"]), ("analyst_manual_entry", False))
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)
        result = drafting.propose("REPORT-FICTBLOCKED01", "https://www.darkreading.com/fictional-blocked", 0, SPEC,
                                  *TEXT, path=self.path, manual_review_id=entry["manual_review_id"])
        self.assertEqual((result["status"], result["source"]["provenance"]),
                         ("draft_unverified", "analyst_manual_entry"))
        link = drafting.source_link(result["rule_id"], self.path)
        self.assertEqual((link["status"], link["proposed_by"]),
                         ("unverified", "claude_proposal_from_analyst_manual_entry"))
        with self.assertRaisesRegex(ValueError, "has not verified"):
            rules.implement_rule(result["rule_id"], "implement this rule", path=self.path)
        work = workup.lead_workup("REPORT-FICTBLOCKED01", self.path)
        self.assertEqual(work["manual_source_reviews"][0]["provenance"], "analyst_manual_entry")

    def test_no_detection_detail_decision_closes_as_analyst_read(self):
        drafting.record_manual_review("REPORT-FICTBLOCKED01", "https://www.darkreading.com/fictional-blocked",
                                      "An opinion piece about the cloud security market with no indicators.",
                                      "browser", "no_detection_detail", "Read fully; commentary only.", self.path)
        status = research_pass.status("REPORT-FICTBLOCKED01", self.path)
        self.assertEqual((status["status"], status["provenance"]),
                         ("completed_insufficient_detail", "analyst_manual_review"))
        self.assertEqual(research_pass.triage_summary(self.path)["read_no_detection_detail"],
                         {"analyst_manual_review": 1})
        with self.assertRaisesRegex(ValueError, "does not record this source as containing"):
            reviews = drafting.manual_reviews("REPORT-FICTBLOCKED01", self.path)
            drafting.propose("REPORT-FICTBLOCKED01", "https://www.darkreading.com/fictional-blocked", 0, SPEC, *TEXT,
                             path=self.path, manual_review_id=reviews[0]["id"])


class TriageGroupingTest(Base):
    def test_open_leads_grouped_by_need_and_unread_never_counted_as_researched(self):
        core.ingest([{"id": "LEAK-FICT-0001", "title": "Fictional leak claim", "summary": "fixture",
                      "kind": "leak_claim", "source": "https://www.ransomlook.io/recent", "claim": "fixture"}],
                    self.path)
        core.ingest([{"id": "CVE-2099-10001", "title": "Fictional non-KEV", "summary": "fixture",
                      "source": "https://nvd.nist.gov/vuln/detail/CVE-2099-10001", "claim": "fixture",
                      "references": ["https://github.com/example/fictional"]}], self.path)
        core.ingest([{"id": "REPORT-FICTSCRIPT001", "title": "Fictional script page", "summary": "fixture",
                      "kind": "campaign", "source": "https://www.securityweek.com/fictional-script", "claim": "x"}],
                    self.path)
        script = b"<html><head><script>app()</script></head><body><div id=root></div></body></html>"
        result = research_pass.triage_raw(self.path, fetch=lambda u: script)
        self.assertEqual({p["result"] for p in result["processed"]},
                         {"skipped_not_researchable", "no_allowlisted_source", "unreadable_source"})
        summary = research_pass.triage_summary(self.path)
        groups = summary["groups"]
        self.assertEqual(groups["no_detection_detail_by_kind"]["by_kind"], {"leak_claim": 1})
        self.assertEqual(groups["needs_browser_review"]["by_cause"], {"script_rendered": 1})
        self.assertEqual(groups["needs_analyst_source_decision"]["top_cited_hosts"], {"github.com": 1})
        self.assertEqual(summary["open_total"], 3)
        self.assertEqual(summary["read_no_detection_detail"], {})
        self.assertEqual(workflow.workflow_counts(self.path)["research_completed_insufficient_detail"], 0)


if __name__ == "__main__":
    unittest.main()
