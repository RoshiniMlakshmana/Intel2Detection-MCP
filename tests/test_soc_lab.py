import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from threat_research import core, lead_queue, poller, soc_lab, soc_replay, store


class SocLabTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name) / "output"
        soc_lab.run(self.directory)
        self.report = json.loads((self.directory / "report.json").read_text())

    def tearDown(self):
        self.tmp.cleanup()

    def test_source_review_to_drafts_and_labeled_misses(self):
        sources = self.report["source_paths"]
        self.assertEqual(len(sources), 3)
        self.assertEqual(sources[0]["linked_cve"], ["CVE-2099-99999"])
        self.assertEqual(sources[1]["linked_cve"], [])
        self.assertTrue(all("cited analyst observation" in row["metadata_draft_blocked"] for row in sources))
        self.assertEqual(sources[0]["leads"][0]["behavior"], "web_server_shell")
        self.assertEqual(len(sources[0]["leads"]), 1)  # Negated encoded-command sentence is ignored.
        self.assertEqual(self.report["inventory_duplicate_check"]["status"], "existing_coverage")
        self.assertEqual(self.report["cve_asset_risk"]["confirmed_affected_count"], 1)
        contexts = self.report["illustrative_environment_comparison"]
        self.assertEqual(contexts["version_not_verified"]["priority"], "verify_affected_version")
        self.assertEqual(contexts["product_not_present"]["priority"], "not_applicable_to_this_asset")
        self.assertEqual(self.report["measurement"]["counts"], {"tp": 3, "fp": 2, "fn": 2, "tn": 5})
        failed = [row["scenario"] for row in self.report["measurement"]["cases"] if row["outcome"] in ("fp", "fn")]
        self.assertTrue(any("rundll32" in name for name in failed))
        self.assertTrue(any("maintenance" in name for name in failed))
        self.assertEqual(len(soc_replay.local_rules(self.directory / "lab.sqlite3")), 0)
        self.assertEqual(len(soc_replay.local_rules(self.directory / "lab.sqlite3", include_drafts=True)), 3)

    def test_local_appended_event_stream_and_partial_line(self):
        target = self.directory / "live_events.jsonl"
        events = list(soc_replay.read_jsonl(self.directory / "events.jsonl"))
        raw = json.dumps(events[0]).encode() + b"\n"
        with target.open("wb") as out:
            out.write(raw + raw + json.dumps(events[6]).encode() + b"\n")
            out.write(b'{"event_id":"unfinished"')
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch("threat_research.soc_replay.time.sleep", side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                soc_replay.watch_jsonl(str(target), str(self.directory / "lab.sqlite3"), include_drafts=True)
        alerts = [json.loads(row) for row in stdout.getvalue().splitlines()]
        self.assertEqual([row["event_id"] for row in alerts], ["E01"])
        self.assertEqual(alerts[0]["rule_status"], "draft")
        self.assertNotIn("whoami", stdout.getvalue())

    def test_replay_rejects_missing_truth_and_does_not_conflate_ioc(self):
        rules = soc_replay.local_rules(self.directory / "lab.sqlite3", include_drafts=True)
        event = {"event_id": "new", "timestamp": "2026-09-28T12:00:00Z", "event_type": "network_connection",
                 "DestinationIp": "8.8.4.4", "DestinationPort": 443}
        self.assertEqual(soc_replay.detect(event, rules), [])
        with self.assertRaisesRegex(ValueError, "expected_malicious"):
            soc_replay.replay([event], rules)

    def test_continuous_article_queue_keeps_research_leads_separate(self):
        db = self.directory / "lab.sqlite3"
        source = "https://thedfirreport.com/fictional-test-article"
        report = {"id": "REPORT-LIVE-TEST", "kind": "campaign", "title": "Fictional source triage article",
                  "summary": "A local fixture demonstrates bounded technical article triage without contacting the real publisher.",
                  "source": source}
        core.ingest([report], db)
        self.assertEqual(lead_queue.queue_new_report_articles([report["id"]], db), 1)
        self.assertEqual(lead_queue.queue_new_report_articles([report["id"]], db), 0)
        fixture = (soc_lab.FIXTURES / "web_shell.html").read_bytes()
        result = lead_queue.inspect_due(db, fetch=lambda url: fixture)
        self.assertEqual((result["inspected"], result["leads"]), (1, 1))
        lead = lead_queue.list_leads(db)[0]
        self.assertEqual((lead["behavior"], lead["status"]), ("web_server_shell", "analyst_review_required"))
        self.assertFalse(any(e["kind"] == "analyst_observation" for e in core.get_threat(report["id"], db)["evidence"]))
        self.assertEqual(lead_queue.inspect_due(db, fetch=lambda url: fixture)["attempted"], 0)

    def test_article_failure_is_visible_and_retryable(self):
        db = self.directory / "lab.sqlite3"
        report = {"id": "REPORT-FAILED-TEST", "kind": "campaign", "title": "Fictional article access failure",
                  "summary": "A bounded fixture represents an inaccessible source without inventing technical behavior.",
                  "source": "https://unit42.paloaltonetworks.com/fictional-test-article"}
        core.ingest([report], db)
        lead_queue.queue_new_report_articles([report["id"]], db)
        attempted = lead_queue.inspect_due(db, fetch=lambda url: (_ for _ in ()).throw(OSError("publisher blocked")))
        self.assertIn(report["id"], attempted["errors"])
        self.assertEqual(lead_queue.queue_status(db)["article_queue"]["pending"], 1)
        with store.connection(db) as connection:
            connection.execute("UPDATE article_inspection_queue SET next_try='2000-01-01T00:00:00Z' WHERE threat_id=?", (report["id"],))
        result = lead_queue.inspect_due(db, fetch=lambda url: (soc_lab.FIXTURES / "agent_tool.html").read_bytes())
        self.assertEqual(result["leads"], 1)
        self.assertEqual(lead_queue.queue_status(db)["article_queue"]["inspected"], 1)

    def test_live_poll_queues_new_article_and_surfaces_review_lead(self):
        db = self.directory / "lab.sqlite3"
        report = {"id": "REPORT-POLL-TEST", "kind": "campaign", "title": "Fictional continuous polling article",
                  "summary": "A synthetic report exercises the collector path without requiring a publisher connection.",
                  "source": "https://thedfirreport.com/fictional-poll-article"}
        core.ingest([report], db)
        collection = {"new_records": 1, "sources": {"RSS: test": 1}, "errors": {},
                      "new_ids": [report["id"]], "alert_ids": []}
        fixture = (soc_lab.FIXTURES / "encoded_campaign.html").read_bytes()
        real_inspector = lead_queue.inspect_due
        with patch("threat_research.poller.collect_daily", return_value=collection), \
             patch("threat_research.poller.lead_queue.inspect_due",
                   side_effect=lambda path: real_inspector(path, fetch=lambda url: fixture)):
            result = poller.run_poll(db)
        self.assertEqual(result["article_review"]["queued"], 1)
        self.assertEqual(result["article_review"]["leads"], 1)
        self.assertEqual(lead_queue.list_leads(db)[0]["behavior"], "encoded_powershell")


if __name__ == "__main__":
    unittest.main()
