"""Regressions for the 2026-09-29 workflow audit against real stored leads.

Defects found tracing CVE-2026-88771 (CISA KEV), a Fortinet threat-signal
entry and Microsoft's NeedyMantis report through the MCP tools:

1. risk_from_asset_inventory raised without an asset inventory, so Claude saw
   only "Error executing tool" instead of why the score is withheld.
2. lead_progression had no framework-mapping or environment-risk step and
   the inventory step omitted its scope, so those stages never reached chat.
3. list_leads showed status "research_needed" beside queue "research_completed".
4. research_detection_plan kept detection_readiness "research_needed..." after
   research had completed.
5. A malware analysis naming a loader DLL and SHA-256 hashes (in prose and
   tables) was concluded "no specific observable", and after article-queue
   inspection it stayed a raw lead.

Fixtures are fictional (CVE-2099-*, example hosts); fetches are injected.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_research import (behavior_leads, core, lead_queue, report_inspection, research_pass, rules, server,
                             store, workflow)

HASH = "e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e"
REPORT_URL = "https://www.microsoft.com/en-us/security/blog/2099/01/01/fictional-malware-family"
MALWARE_HTML = (
    "<html><body><article>"
    "<p>Microsoft Threat Intelligence identified FictionalMantis, a modular post-compromise malware family "
    "observed in a limited number of targeted operations.</p>"
    f"<p>In the analyzed sample, the loader DLL was named FictSparkle.dll (SHA-256: {HASH}).</p>"
    "<table><tr><td>Indicator</td><td>Type</td></tr>"
    "<tr><td>c82520eb03c084226be4eafbff46f56dca0aa8804a2a7f23a085a96afe71ef77</td><td>SHA-256 of an older archive</td></tr>"
    "</table>"
    '<a href="https://learn.microsoft.com/en-us/security">Microsoft Learn</a>'
    '<a href="https://uhf.microsoft.com/statics/style.css">x</a>'
    '<a href="https://fictsparkle.org/">FictSparkle project (legitimate software the loader abuses)</a>'
    "</article></body></html>").encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def kev(self, ident="CVE-2099-10001"):
        core.ingest([{"id": ident, "title": "Fictional KEV", "summary": "fixture", "kev": True,
                      "source": f"https://nvd.nist.gov/vuln/detail/{ident}", "claim": "KEV listed.",
                      "references": ["https://support.citrix.com/external/article/CTX9/f.html"]}], self.path)
        return ident

    def mcp(self):
        return patch.dict("os.environ", {"THREAT_RESEARCH_DB": str(self.path)})


class WithheldRiskTest(Base):
    def test_risk_tool_returns_withheld_reason_as_data_without_assets(self):
        ident = self.kev()
        with self.mcp():
            result = server.risk_from_asset_inventory(ident)
        self.assertEqual((result["status"], result["score"]), ("withheld", None))
        self.assertIn("no environment risk score can be assigned", result["reason"])


class GateRefusalVisibilityTest(Base):
    def test_decision_refusals_are_reported_as_data_and_change_nothing(self):
        lead = core.record_campaign_report("Fictional encoded PowerShell campaign",
                                           "Synthetic report documents encoded PowerShell launched by a dropped binary.",
                                           "https://example.test/fictional-report", self.path)
        evidence = core.add_behavior_evidence(lead["id"], "https://example.test/fictional-report",
                                              "Paragraph 4 shows powershell.exe -enc launched by invoice.exe.",
                                              "encoded_powershell", self.path)
        rule_id = rules.propose_rule(lead["id"], evidence, self.path)["rule_id"]
        with self.mcp():
            refused = server.implement_rule(rule_id, "looks fine")
            review = server.approve_corroboration_review(999, "implement this rule")
        self.assertEqual(refused["status"], "refused")
        self.assertIn("implement this rule", refused["reason"])
        self.assertEqual((review["status"], review["reason"]), ("refused", "unknown corroboration review"))
        rule = rules.get_rule(rule_id, self.path)
        self.assertEqual((rule["status"], rule["pattern_score"]), ("draft", 0))


class ProgressionStagesTest(Base):
    def test_every_intended_stage_is_in_the_progression(self):
        lead = core.record_campaign_report("Fictional encoded PowerShell campaign",
                                           "Synthetic report documents encoded PowerShell launched by a dropped binary.",
                                           "https://example.test/fictional-report", self.path)
        evidence = core.add_behavior_evidence(lead["id"], "https://example.test/fictional-report",
                                              "Paragraph 4 shows powershell.exe -enc launched by invoice.exe.",
                                              "encoded_powershell", self.path)
        prog = workflow.lead_progression(lead["id"], self.path)
        steps = {s["key"]: s for s in prog["steps"]}
        self.assertIn(steps["framework"]["state"], ("done", "attention"))
        self.assertTrue(steps["framework"]["mappings"])  # crosswalk IDs even without a stored snapshot
        self.assertEqual(steps["environment_risk"]["summary"][:15], "Not applicable:")
        self.assertIsNone(steps["environment_risk"]["score"])
        self.assertIn("scope", steps["inventory"])
        self.assertEqual(prog["next_action"], f"draft_detection('{lead['id']}', evidence_id={evidence})")
        rule = rules.propose_rule(lead["id"], evidence, self.path)
        prog = workflow.lead_progression(lead["id"], self.path)
        self.assertIn(f"test_rule_against_samples('{rule['rule_id']}'", prog["next_action"])
        self.assertEqual(rules.get_rule(rule["rule_id"], self.path)["status"], "draft")


class ResearchLabelsTest(Base):
    def test_completed_research_is_labeled_consistently(self):
        ident = self.kev()
        page = (b"<html><body><p>" + ident.encode() + b" is an input validation flaw in the fictional "
                b"appliance; upgrade to the fixed release to remediate it.</p></body></html>")
        research_pass.research_lead(ident, self.path, fetch=lambda url: page)
        item = workflow.list_leads(self.path, queue="research_completed")["items"][0]
        self.assertEqual((item["status"], item["queue"]), ("research_completed", "research_completed"))
        with self.mcp(), patch.object(report_inspection, "fetch_article", lambda url: page):
            plan = server.research_detection_plan(ident)
        self.assertEqual(plan["research"]["detection_readiness"], "completed_insufficient_detail")


class MalwareArtifactTest(Base):
    def test_hashes_in_prose_and_tables_are_flagged_without_actor_words(self):
        page = report_inspection.extract_report_html("REPORT-X", REPORT_URL, MALWARE_HTML)
        artifacts = [a for d in page["specific_details"] for a in d["artifacts_as_written"]]
        self.assertIn(HASH, artifacts)
        self.assertIn("FictSparkle.dll", artifacts)
        self.assertIn("c82520eb03c084226be4eafbff46f56dca0aa8804a2a7f23a085a96afe71ef77", artifacts)  # table cell
        self.assertEqual(behavior_leads.specific_details(
            ["Organizations should patch appliances to version 14.1-73.37 and review the vendor advisory."]), [])
        windows = behavior_leads.specific_details(
            [r"The loader copied itself to C:\ProgramData\FictUpdate\fict.bin before the payload ran."])
        self.assertEqual(windows[0]["artifacts_as_written"], [r"C:\ProgramData\FictUpdate\fict.bin"])

    def test_inspected_malware_report_moves_to_backlog_for_verification_not_evidence(self):
        core.ingest([{"id": "REPORT-FICTMALWARE01", "title": "FictionalMantis", "summary": "fixture",
                      "kind": "campaign", "source": REPORT_URL, "claim": "Feed listed this report."}], self.path)
        self.assertEqual(workflow.list_leads(self.path, queue="raw_unreviewed")["total"], 1)
        lead_queue.queue_new_report_articles(["REPORT-FICTMALWARE01"], self.path)
        lead_queue.inspect_due(self.path, fetch=lambda url: MALWARE_HTML)
        self.assertEqual(workflow.list_leads(self.path, queue="research_backlog")["total"], 1)
        self.assertEqual(research_pass.due_leads(self.path), ["REPORT-FICTMALWARE01"])
        status = research_pass.run_pass(self.path, fetch=lambda url: MALWARE_HTML)["results"][0]
        self.assertEqual(status["status"], "observables_need_analyst_verification")
        # The vendor is the original publisher: its own site links are not "original publications".
        self.assertEqual({u for d in status["specific_details_to_verify"]
                          for u in d["original_publication_candidates"]}, set())
        self.assertIn(HASH, [a for d in status["specific_details_to_verify"] for a in d["artifacts_as_written"]])
        counts = workflow.workflow_counts(self.path)
        self.assertEqual((counts["actionable_research_backlog"], counts["raw_unreviewed_leads"]), (1, 0))
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM corroboration_reviews").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
