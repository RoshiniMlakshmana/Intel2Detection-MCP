"""Lead listing, per-lead progression and workflow tabs (dashboard and MCP share these).

Fixtures are fictional (CVE-2099-*, example.test); labeled events come from the
bundled synthetic SOC lab. Nothing here approves a rule unless the test is
explicitly about an analyst's approval, and nothing is deployed.
"""

import http.client
import json
import tempfile
import unittest
import urllib.parse
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from threat_research import core, dashboard, poller, rules, sources, store, workflow

LAB_EVENTS = resources.files("threat_research") / "lab_fixtures" / "events.jsonl"
REPORT = "https://example.test/fictional-encoded-powershell-report"


def advisory(n, published="2099-01-01"):
    return {"id": f"CVE-2099-{n:05d}", "title": f"Fictional advisory {n}", "summary": "Synthetic fixture.",
            "source": f"https://example.test/advisory/{n}", "claim": "Example advisory listed this record.",
            "published": published}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def poll(self, adapters):
        with patch.object(sources, "enrich_epss", return_value={}):
            return poller.run_poll(self.path, adapters=adapters)

    def cited_lead(self):
        lead = core.record_campaign_report("Fictional encoded PowerShell campaign",
                                           "Synthetic report documents encoded PowerShell launched by a dropped invoice binary.",
                                           REPORT, self.path)
        evidence = core.add_behavior_evidence(lead["id"], REPORT,
                                              "Report paragraph 4 shows powershell.exe -enc launched by invoice.exe.",
                                              "encoded_powershell", self.path)
        return lead["id"], evidence


class ListLeadsTest(Base):
    def test_fifty_per_page_with_total_and_next_previous(self):
        self.poll({"CISA KEV": lambda: [advisory(i, f"2099-01-{1 + i % 28:02d}") for i in range(120)]})
        first = workflow.list_leads(self.path)
        self.assertEqual((first["total"], first["pages"], len(first["items"])), (120, 3, 50))
        self.assertTrue(first["has_next"])
        self.assertFalse(first["has_previous"])
        last = workflow.list_leads(self.path, page=3)
        self.assertEqual(len(last["items"]), 20)
        self.assertFalse(last["has_next"])
        self.assertEqual(len(workflow.list_leads(self.path, per_page=500)["items"]), 50)
        ids = {i["id"] for p in (1, 2, 3) for i in workflow.list_leads(self.path, page=p)["items"]}
        self.assertEqual(len(ids), 120)

    def test_each_item_keeps_dates_url_and_latest_fetch_status(self):
        self.poll({"CISA KEV": lambda: [advisory(1)]})
        item = workflow.list_leads(self.path)["items"][0]
        self.assertEqual(item["published"], "2099-01-01")
        self.assertIsNotNone(item["collected"])
        self.assertEqual(item["source_url"], "https://example.test/advisory/1")
        self.assertEqual(item["source_name"], "CISA KEV")
        self.assertEqual(item["latest_fetch"]["status"], "ok")

    def test_source_date_status_and_rule_state_filters(self):
        self.poll({"CISA KEV": lambda: [advisory(1, "2099-01-01"), advisory(2, "2099-03-01")],
                   "GitHub advisories": lambda: [advisory(3, "2099-02-01")]})
        self.assertEqual(workflow.list_leads(self.path, source="GitHub advisories")["total"], 1)
        self.assertEqual(workflow.list_leads(self.path, date_from="2099-02-01")["total"], 2)
        self.assertEqual(workflow.list_leads(self.path, date_from="2099-01-15", date_to="2099-02-15")["total"], 1)
        evidence = core.add_behavior_evidence("CVE-2099-00002", REPORT, "Fictional report shows w3wp.exe spawning cmd.exe.",
                                              "web_server_shell", self.path)
        rules.propose_rule("CVE-2099-00002", evidence, self.path)
        self.assertEqual([i["id"] for i in workflow.list_leads(self.path, status="evidence_recorded")["items"]],
                         ["CVE-2099-00002"])
        self.assertEqual(workflow.list_leads(self.path, rule_state="draft")["total"], 1)
        self.assertEqual(workflow.list_leads(self.path, rule_state="none")["total"], 2)
        with self.assertRaisesRegex(ValueError, "rule_state"):
            workflow.list_leads(self.path, rule_state="deployed")
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            workflow.list_leads(self.path, date_from="yesterday")


class ProgressionTest(Base):
    def test_cve_only_lead_explains_missing_input_and_never_drafts(self):
        self.poll({"CISA KEV": lambda: [advisory(7)]})
        prog = workflow.lead_progression("CVE-2099-00007", self.path)
        self.assertFalse(prog["can_draft"])
        self.assertEqual(prog["next_step"], "research")
        self.assertIn("not behavior evidence", prog["steps"][0]["missing"])
        self.assertEqual([s["key"] for s in prog["steps"]],
                         ["research", "evidence", "telemetry", "inventory", "candidate", "checks", "decision", "repository"])
        self.assertIn("never generated from a CVE title", prog["steps"][4]["missing"])
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)

    def test_complete_flow_cited_lead_to_labeled_check_without_approval(self):
        threat_id, evidence = self.cited_lead()
        prog = workflow.lead_progression(threat_id, self.path)
        self.assertTrue(prog["can_draft"])
        self.assertEqual(prog["draftable_evidence"], [evidence])
        self.assertEqual(next(s for s in prog["steps"] if s["key"] == "inventory")["answer"], "Unknown")

        drafted = rules.propose_rule(threat_id, evidence, self.path)
        self.assertEqual(drafted["status"], "draft")
        from threat_research import soc_replay
        result = soc_replay.test_rule_against_samples(drafted["rule_id"], LAB_EVENTS, self.path)
        # Bundled labels: E03 malicious encoded PowerShell (TP), E04 approved deployment (FP).
        self.assertEqual(result["counts"]["tp"], 1)
        self.assertEqual(result["counts"]["fp"], 1)

        prog = workflow.lead_progression(threat_id, self.path)
        steps = {s["key"]: s for s in prog["steps"]}
        self.assertEqual(steps["checks"]["state"], "done")
        self.assertEqual(steps["decision"]["state"], "current")
        self.assertIn("Awaiting an explicit analyst", steps["decision"]["summary"])
        self.assertTrue(steps["repository"]["files"][drafted["rule_id"]]["exists"])
        self.assertEqual(steps["repository"]["files"][drafted["rule_id"]]["folder"], "draft")
        self.assertFalse(prog["can_draft"])
        self.assertEqual(rules.get_rule(drafted["rule_id"], self.path)["status"], "draft")

    def test_inventory_match_shows_existing_rule_and_proposed_corroboration(self):
        first_id, first_evidence = self.cited_lead()
        rule_id = rules.propose_rule(first_id, first_evidence, self.path)["rule_id"]
        rules.implement_rule(rule_id, "implement this rule", path=self.path)  # analyst decision under test
        self.poll({"CISA KEV": lambda: [advisory(9)]})
        second = core.add_behavior_evidence("CVE-2099-00009", "https://example.test/second-independent-report",
                                            "Second report shows powershell.exe -encodedcommand from a macro.",
                                            "encoded_powershell", self.path)
        prog = workflow.lead_progression("CVE-2099-00009", self.path)
        inventory = next(s for s in prog["steps"] if s["key"] == "inventory")
        self.assertEqual(inventory["answer"], "Yes")
        self.assertEqual(inventory["existing_rules"][0]["rule_id"], rule_id)
        self.assertEqual(inventory["proposed_corroboration"][0]["evidence_id"], second)
        self.assertFalse(prog["can_draft"])
        self.assertIn("existing rule already covers", prog["draft_blocked_reason"])
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 0)  # nothing applied automatically


class CountsAndErrorsTest(Base):
    def test_tab_counts_and_tools(self):
        self.poll({"CISA KEV": lambda: [advisory(1), advisory(2)], "Broken": lambda: (_ for _ in ()).throw(OSError("refused"))})
        threat_id, evidence = self.cited_lead()
        rules.propose_rule(threat_id, evidence, self.path)
        counts = workflow.workflow_counts(self.path)
        self.assertEqual(counts["research_needed"], 2)
        self.assertEqual(counts["draft_rules"], 1)
        self.assertEqual(counts["approved_rules"], 0)
        self.assertEqual(counts["pending_reviews"], 0)
        self.assertEqual(counts["source_errors"], 1)
        self.assertEqual(counts["mcp_tools"]["draft_rules"], "list_rules(state='draft')")
        errors = workflow.source_errors(self.path)["sources"]
        self.assertEqual((errors[0]["name"], errors[0]["status"], errors[0]["detail"]), ("Broken", "error", "refused"))


class DashboardWorkflowHttpTest(Base):
    def setUp(self):
        super().setUp()
        self.poll({"CISA KEV": lambda: [advisory(i) for i in range(60)]})
        self.threat_id, self.evidence = self.cited_lead()
        self.server, self.stop_event = dashboard.serve(host="127.0.0.1", port=0, path=self.path,
                                                        auto_refresh=False, block=False)
        self.port = self.server.server_address[1]

    def tearDown(self):
        dashboard.stop(self.server, self.stop_event)
        super().tearDown()

    def request(self, method, path, fields=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = urllib.parse.urlencode(fields) if fields else None
        conn.request(method, path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
        resp = conn.getresponse()
        text = resp.read().decode("utf-8")
        conn.close()
        return resp.status, text, resp.getheader("Location")

    def test_tabs_leads_pagination_and_source_dropdown(self):
        status, body, _ = self.request("GET", "/leads")
        self.assertEqual(status, 200)
        for tab in ("Research needed", "Draft rules", "Pending reviews", "Approved rules", "Source errors", "MCP tools"):
            self.assertIn(tab, body)
        self.assertIn("Showing 1&ndash;50 of <b>61</b>", body)
        self.assertIn('href="/leads?date_field=published&page=2"', body)
        self.assertIn('<option value="RSS: CISA advisories">', body)
        _, page2, _ = self.request("GET", "/leads?page=2")
        self.assertIn("Showing 51&ndash;61 of <b>61</b>", page2)
        _, filtered, _ = self.request("GET", "/leads?source=" + urllib.parse.quote("CISA KEV") + "&status=research_needed")
        self.assertIn("of <b>60</b>", filtered)
        self.assertIn("list_leads(source=&#x27;CISA KEV&#x27;, status=&#x27;research_needed&#x27;)", filtered)
        _, bad, _ = self.request("GET", "/leads?rule_state=deployed")
        self.assertIn("Filter ignored", bad)

    def test_lead_page_progression_draft_check_and_rule_tabs(self):
        _, cve_page, _ = self.request("GET", "/threat?id=CVE-2099-00001")
        self.assertIn("Drafting unavailable", cve_page)
        self.assertNotIn("Research / Draft detection</button>", cve_page)

        _, page, _ = self.request("GET", f"/threat?id={self.threat_id}")
        self.assertIn("Research / Draft detection</button>", page)
        self.assertIn("Cited behavior / evidence", page)
        status, _, location = self.request("POST", "/threat/draft", {"id": self.threat_id, "evidence_id": self.evidence})
        self.assertEqual(status, 303)
        rule_id = workflow.list_rules(self.path, "draft")["items"][0]["id"]

        events = LAB_EVENTS.read_text(encoding="utf-8")
        status, _, location = self.request("POST", "/rule/check", {"id": rule_id, "threat_id": self.threat_id, "events": events})
        self.assertIn("nothing%20was%20approved", location)
        self.assertEqual(rules.get_rule(rule_id, self.path)["status"], "draft")
        _, drafts, _ = self.request("GET", "/rules?state=draft")
        self.assertIn(rule_id, drafts)
        self.assertIn("TP 1 / FP 1", drafts)
        _, approved, _ = self.request("GET", "/rules?state=approved")
        self.assertIn("None.", approved)
        _, tools, _ = self.request("GET", "/tools")
        self.assertIn("lead_progression", tools)
        self.assertIn("list_leads(status=&#x27;research_needed&#x27;)", tools)
        _, api, _ = self.request("GET", f"/api/progression?id={self.threat_id}")
        self.assertEqual(json.loads(api)["next_step"], "decision")

    def test_cross_origin_post_is_refused(self):
        status, _, _ = self.request("POST", "/threat/draft", {"id": self.threat_id, "evidence_id": self.evidence},
                                    headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(workflow.list_rules(self.path, "draft")["total"], 0)


if __name__ == "__main__":
    unittest.main()
