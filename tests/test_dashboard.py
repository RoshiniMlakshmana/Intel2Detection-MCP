"""Tests for the analyst dashboard: backend aggregation, poll-failure fixes,
and a full HTTP walkthrough. All fixtures here are fictional (CVE-2099-...,
example.org/example.test domains) per this project's isolated-lab convention
(see soc_lab.py); nothing here contacts a real SIEM or claims SIEM accuracy.
"""

import gzip
import http.client
import json
import tempfile
import unittest
import urllib.parse
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import yaml

from threat_research import core, dashboard, dashboard_data, frameworks, poller, research_feeds, rules, sources, store, workflow


def fictional_record(ident="CVE-2099-70001", source="https://example.test/advisory/example"):
    return {"id": ident, "title": "Fictional example vulnerability", "summary": "Synthetic fixture, not a real CVE.",
            "source": source, "claim": "Example advisory source listed this fictional record.",
            "published": "2099-01-01", "updated": "2099-01-01", "kev": True, "affected": ["ExampleServer"]}


class DashboardDataTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_source_name_is_backfilled_and_counted_per_card(self):
        with patch.object(sources, "enrich_epss", return_value={}):
            result = poller.run_poll(self.path, adapters={"CISA KEV": lambda: [fictional_record()]})
        self.assertEqual(result["new_records"], 1)
        overview = dashboard_data.sources_overview(self.path)
        card = next(c for c in overview["sources"] if c["name"] == "CISA KEV")
        self.assertEqual(card["record_count"], 1)
        self.assertEqual(card["status"], "ok")
        self.assertIsNotNone(card["last_success"])
        self.assertEqual(card["latest_publication"], "2099-01-01")
        threats = dashboard_data.threats_for_source("CISA KEV", self.path)
        self.assertEqual(threats[0]["id"], "CVE-2099-70001")

    def test_source_card_distinguishes_collected_from_researched_and_drafted(self):
        with patch.object(sources, "enrich_epss", return_value={}):
            poller.run_poll(self.path, adapters={"CISA KEV": lambda: [fictional_record()]})
        before = next(c for c in dashboard_data.sources_overview(self.path)["sources"]
                      if c["name"] == "CISA KEV")
        self.assertEqual(before["record_count"], 1)
        self.assertEqual(before["research_counts"], {
            "research_attempted": 0, "readable_page_leads": 0,
            "blocked_page_leads": 0, "unreadable_page_leads": 0, "not_allowlisted_leads": 0,
            "pattern_or_artifact_leads": 0, "draft_leads": 0})
        with store.connection(self.path) as db:
            db.execute("INSERT INTO research_outcomes(threat_id,status,completed_at,detail) VALUES(?,?,?,?)",
                       ("CVE-2099-70001", "observables_need_analyst_verification", "2099-01-02",
                        json.dumps({"specific_details_to_verify": [{"excerpt": "fictional hash"}]})))
            db.execute("INSERT INTO research_page_inspections"
                       "(threat_id,url,role,status,paragraphs_scanned,inspected_at) VALUES(?,?,?,?,?,?)",
                       ("CVE-2099-70001", "https://example.test/report", "primary_advisory",
                        "inspected", 3, "2099-01-02"))
            db.execute("INSERT INTO research_page_inspections"
                       "(threat_id,url,role,status,inspected_at) VALUES(?,?,?,?,?)",
                       ("CVE-2099-70001", "https://example.test/blocked", "cited_report",
                        "publisher_blocked", "2099-01-02"))
        evidence_id = core.add_behavior_evidence("CVE-2099-70001", "https://example.test/report",
                                                  "Fictional web server launched cmd.exe", "web_server_shell", self.path)
        rules.propose_rule("CVE-2099-70001", evidence_id, self.path)
        after = next(c for c in dashboard_data.sources_overview(self.path)["sources"]
                     if c["name"] == "CISA KEV")
        self.assertEqual(after["research_counts"], {
            "research_attempted": 1, "readable_page_leads": 1,
            "blocked_page_leads": 1, "unreadable_page_leads": 0, "not_allowlisted_leads": 0,
            "pattern_or_artifact_leads": 1, "draft_leads": 1})
        page = dashboard.render_sources(self.path)
        self.assertIn("Research attempted", page)
        self.assertIn("Cited pattern or artifact", page)

    def test_source_counts_article_review_before_research_pass(self):
        with patch.object(sources, "enrich_epss", return_value={}):
            poller.run_poll(self.path, adapters={"CISA KEV": lambda: [fictional_record()]})
        with store.connection(self.path) as db:
            db.execute("INSERT INTO article_inspection_queue"
                       "(threat_id,source_url,status,attempts,next_try) VALUES(?,?,?,?,?)",
                       ("CVE-2099-70001", "https://example.test/report", "inspected", 1, "2099-01-02"))
            db.execute("INSERT INTO article_behavior_leads"
                       "(threat_id,source_url,sha256,behavior,paragraph,excerpt,first_seen)"
                       " VALUES(?,?,?,?,?,?,?)",
                       ("CVE-2099-70001", "https://example.test/report", "example", "specific_artifacts",
                        1, "Fictional artifact", "2099-01-02"))
        card = next(c for c in dashboard_data.sources_overview(self.path)["sources"]
                    if c["name"] == "CISA KEV")
        self.assertEqual(card["research_counts"]["research_attempted"], 1)
        self.assertEqual(card["research_counts"]["readable_page_leads"], 1)
        self.assertEqual(card["research_counts"]["pattern_or_artifact_leads"], 1)
        self.assertEqual(card["research_counts"]["draft_leads"], 0)

    def test_source_card_shows_collection_error(self):
        def fail():
            raise ValueError("example source unavailable")
        with patch.object(sources, "enrich_epss", return_value={}):
            poller.run_poll(self.path, adapters={"CISA KEV": fail})
        overview = dashboard_data.sources_overview(self.path)
        card = next(c for c in overview["sources"] if c["name"] == "CISA KEV")
        self.assertEqual(card["status"], "error")
        self.assertIn("unavailable", card["error"])

    def test_never_collected_source_still_gets_a_card(self):
        overview = dashboard_data.sources_overview(self.path)
        names = {c["name"] for c in overview["sources"]}
        self.assertIn("RSS: BleepingComputer", names)
        self.assertIn("GitHub: SigmaHQ community rules", names)
        card = next(c for c in overview["sources"] if c["name"] == "NVD")
        self.assertEqual(card["status"], "never_collected")
        self.assertEqual(card["record_count"], 0)

    def test_backfill_labels_pre_existing_rows_without_reported_by(self):
        core.ingest([fictional_record()], self.path)  # No reported_by; simulates data from before this change.
        self.assertEqual(core.backfill_source_names(self.path), 0)  # Source not in KEV's fixed URL pattern here.
        core.ingest([fictional_record(source="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")], self.path)
        updated = core.backfill_source_names(self.path)
        self.assertGreaterEqual(updated, 1)
        overview = dashboard_data.sources_overview(self.path)
        card = next(c for c in overview["sources"] if c["name"] == "CISA KEV")
        self.assertGreaterEqual(card["record_count"], 1)
        self.assertEqual(core.backfill_source_names(self.path), 0)  # Idempotent.

    def test_inventory_status_unknown_no_then_yes(self):
        core.ingest([fictional_record()], self.path)
        unknown = rules.inventory_status("CVE-2099-70001", self.path)
        self.assertEqual(unknown["status"], "unknown")
        eid = core.add_behavior_evidence("CVE-2099-70001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        # Without a declared complete/recent inventory scope, a non-match is
        # still Unknown, never No (gap 3: an undeclared/empty inventory
        # must never be presented as confirmed absence of coverage).
        undeclared = rules.inventory_status("CVE-2099-70001", self.path)
        self.assertEqual(undeclared["status"], "unknown")
        self.assertFalse(undeclared["inventory_scope"]["declared"])
        rules.declare_inventory_scope("All Sigma rules in our detection-as-code repo, reviewed today.", True, self.path)
        no_yet = rules.inventory_status("CVE-2099-70001", self.path)
        self.assertEqual(no_yet["status"], "no")
        self.assertIn("declared complete inventory", no_yet["behaviors"][0]["scope"])
        draft = rules.propose_rule("CVE-2099-70001", eid, self.path)
        still_no = rules.inventory_status("CVE-2099-70001", self.path)
        self.assertEqual(still_no["behaviors"][0]["status"], "no")  # Draft only, not approved.
        rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        yes = rules.inventory_status("CVE-2099-70001", self.path)
        self.assertEqual(yes["status"], "yes")
        self.assertEqual(yes["behaviors"][0]["rule_id"], draft["rule_id"])

    def test_reject_keeps_draft_for_later_review_and_reopen(self):
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-70001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2099-70001", eid, self.path)
        with self.assertRaisesRegex(ValueError, "reason"):
            rules.reject_rule(draft["rule_id"], "no", self.path)  # Too short.
        result = rules.reject_rule(draft["rule_id"], "Behavior not confirmed in our environment yet.", self.path)
        self.assertEqual(result["status"], "rejected")
        stored = rules.get_rule(draft["rule_id"], self.path)
        self.assertEqual(stored["status"], "rejected")
        self.assertIn("not confirmed", stored["rejected_reason"])
        with self.assertRaisesRegex(ValueError, "unknown rule"):
            rules.reopen_rule(draft["rule_id"] + "-missing", self.path)
        rules.reopen_rule(draft["rule_id"], self.path)
        self.assertEqual(rules.get_rule(draft["rule_id"], self.path)["status"], "draft")
        rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        with self.assertRaisesRegex(ValueError, "approved rule cannot"):
            rules.reject_rule(draft["rule_id"], "changed my mind about an approved rule", self.path)

    def test_workspace_notes_recorded_and_validated(self):
        core.ingest([fictional_record()], self.path)
        note_id = dashboard_data.add_workspace_note("CVE-2099-70001", "telemetry_fields", "ParentImage, Image, CommandLine", self.path)
        self.assertIsInstance(note_id, int)
        dashboard_data.add_workspace_note("CVE-2099-70001", "benign_example", "Scheduled deployment script also spawns cmd.exe", self.path)
        dashboard_data.add_workspace_note("CVE-2099-70001", "feedback", "Looks solid, watch for false positives.", self.path)
        notes = dashboard_data.workspace_notes("CVE-2099-70001", self.path)
        self.assertEqual(len(notes), 3)
        with self.assertRaisesRegex(ValueError, "note_type"):
            dashboard_data.add_workspace_note("CVE-2099-70001", "not_a_type", "some content", self.path)
        with self.assertRaisesRegex(ValueError, "unknown threat"):
            dashboard_data.add_workspace_note("CVE-2099-99999", "feedback", "orphan note", self.path)

    def test_threat_detail_view_assembles_all_five_sections(self):
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-70001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        rules.propose_rule("CVE-2099-70001", eid, self.path)
        view = dashboard_data.threat_detail_view("CVE-2099-70001", self.path)
        self.assertIn("web_server_shell", view["framework_context"])
        self.assertEqual(len(view["rules"]), 1)
        self.assertEqual(view["inventory_status"]["behaviors"][0]["behavior"], "web_server_shell")
        self.assertIsNone(dashboard_data.threat_detail_view("CVE-2099-99999", self.path))


class FrameworkFixLiveShapeTest(unittest.TestCase):
    """Reproduces the exact real-world shape observed live (see PR notes):
    a git symlink blob chain for ATLAS-latest.yaml."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_atlas_symlink_pointer_chain_is_followed(self):
        real = {"format-version": "1.0.0", "collection": {"version": "2099.01"},
                "techniques": {f"AML.T{i:04d}": {"name": "Fixture technique", "description": "Fixture"} for i in range(1, 22)}}
        real["techniques"]["AML.T0053"] = {"name": "AI Agent Tool Invocation", "description": "Tool execution"}
        calls = []

        def fetch(url, limit):
            calls.append(url)
            if url == frameworks.ATLAS_URL:
                return b"v9/ATLAS-latest.yaml"
            if url == "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v9/ATLAS-latest.yaml":
                return b"ATLAS-2099.01.yaml"
            if url == "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v9/ATLAS-2099.01.yaml":
                return yaml.safe_dump(real).encode()
            raise AssertionError(f"unexpected fetch {url}")

        url, data = frameworks._fetch_atlas(fetch)
        self.assertEqual(url, "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v9/ATLAS-2099.01.yaml")
        self.assertEqual(len(calls), 3)
        version, entries = frameworks._parse_atlas(data)
        self.assertEqual(version, "2099.01")
        self.assertIn("AML.T0053", entries)

    def test_pointer_chain_exceeding_hop_limit_raises_clearly(self):
        def fetch(url, limit):
            return b"next.yaml"  # Always another pointer; never resolves.
        with self.assertRaisesRegex(ValueError, "hop limit"):
            frameworks._fetch_atlas(fetch)

    def test_short_real_mapping_is_not_mistaken_for_a_pointer(self):
        # A tiny but genuine mapping must never be treated as a symlink pointer.
        tiny = yaml.safe_dump({"techniques": {"AML.T0001": {"name": "x", "description": "y"}}}).encode()
        self.assertIsNone(frameworks._symlink_pointer_target(tiny))


class ResearchFeedFixTest(unittest.TestCase):
    def test_doctype_without_entity_now_parses(self):
        since = datetime(2099, 1, 1, tzinfo=timezone.utc)
        until = datetime(2099, 1, 3, tzinfo=timezone.utc)
        data = (b'<?xml version="1.0"?><!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN" '
                b'"http://my.netscape.com/publish/formats/rss-0.91.dtd">'
                b'<rss><channel><item><title>Fictional research finding</title>'
                b'<link>https://example.test/finding</link>'
                b'<pubDate>Sat, 02 Jan 2099 10:00:00 GMT</pubDate></item></channel></rss>')
        rows = research_feeds.parse_feed(data, "Example Feed", "research", since, until)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reported_by"], "RSS: Example Feed")

    def test_entity_declaration_still_blocked(self):
        since = datetime(2099, 1, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            research_feeds.parse_feed(b'<!DOCTYPE foo [<!ENTITY x "bad">]><rss/>', "Unsafe", "research", since)

    def test_gzip_content_encoding_is_decompressed(self):
        payload = b"<rss><channel></channel></rss>"
        compressed = gzip.compress(payload)

        class FakeResponse:
            status = 200
            headers = {"Content-Encoding": "gzip"}
            def read(self, n):
                return compressed
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        with patch("urllib.request.urlopen", return_value=FakeResponse()):
            raw = research_feeds.fetch_feed("https://example.test/feed")
        self.assertEqual(raw, payload)

    def test_empty_challenge_response_raises_clear_diagnostic(self):
        class FakeResponse:
            status = 202
            headers = {}
            def read(self, n):
                return b""
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        with patch("urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(ValueError, "empty response body"):
                research_feeds.fetch_feed("https://example.test/feed")


class NvdPageCapTest(unittest.TestCase):
    def test_expanded_page_budget_covers_a_catch_up_window(self):
        # 5 pages of 3 (15 total) previously would have needed max_pages>=5;
        # the old default of 8 already covered that, so force a narrower
        # explicit cap here to prove pagination and the raise path both work.
        pages = []
        for i in range(5):
            pages.append({"totalResults": 15, "vulnerabilities": [
                {"cve": {"id": f"CVE-2099-8{i}{j}01", "vulnStatus": "Analyzed",
                         "descriptions": [{"lang": "en", "value": "fixture"}], "metrics": {}}}
                for j in range(3)]})

        def fetch(url, headers=None):
            parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            self.assertEqual(parsed["resultsPerPage"], ["500"])
            start = int(parsed["startIndex"][0])
            return pages[start // 3]

        since = until = datetime(2099, 1, 1, tzinfo=timezone.utc)
        rows = list(sources.collect_nvd(since, until, fetch=fetch, max_pages=5, rate_limit=False))
        self.assertEqual(len(rows), 15)

        with self.assertRaisesRegex(RuntimeError, "page cap"):
            list(sources.collect_nvd(since, until, fetch=fetch, max_pages=2, rate_limit=False))

    def test_oversized_nvd_response_retries_same_index_with_smaller_page(self):
        seen = []
        def fetch(url, headers=None):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            start, size = int(query["startIndex"][0]), int(query["resultsPerPage"][0])
            seen.append((start, size))
            if size > 2:
                raise ValueError("source response too large")
            return {"totalResults": 3, "vulnerabilities": [
                {"cve": {"id": f"CVE-2099-99{i:03d}", "vulnStatus": "Analyzed",
                         "descriptions": [{"lang": "en", "value": "fixture"}], "metrics": {}}}
                for i in range(start, min(start + size, 3))]}
        point = datetime(2099, 1, 1, tzinfo=timezone.utc)
        rows = sources.collect_nvd(point, point, fetch=fetch, page_size=8, max_pages=8, rate_limit=False)
        self.assertEqual(len(rows), 3)
        self.assertEqual(seen, [(0, 8), (0, 4), (0, 2), (2, 2)])


class DashboardHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        with patch.object(sources, "enrich_epss", return_value={}):
            poller.run_poll(self.path, adapters={"CISA KEV": lambda: [
                {**fictional_record(), "title": "<script>alert(1)</script> Fictional vuln"}]})
        self.evidence_id = core.add_behavior_evidence(
            "CVE-2099-70001", "https://example.test/report",
            "Observed web server launching cmd.exe in a fictional lab report", "web_server_shell", self.path)
        self.server, self.stop_event = dashboard.serve(host="127.0.0.1", port=0, path=self.path,
                                                        auto_refresh=False, block=False)
        self.port = self.server.server_address[1]

    def tearDown(self):
        dashboard.stop(self.server, self.stop_event)
        self.tmp.cleanup()

    def _get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
        return resp.status, body

    def _post(self, path, fields):
        body = urllib.parse.urlencode(fields)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        location = resp.getheader("Location")
        conn.close()
        return resp.status, location

    def test_sources_page_lists_card_with_error_escaped_title_elsewhere(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("CISA KEV", body)
        self.assertIn("Sources", body)
        self.assertIn("1</b> new leads", body)
        self.assertIn("View newest collected leads", body)
        self.assertIn("Items fetched last attempt", body)
        self.assertIn(str(self.path.resolve()), body)
        self.assertIn("Showing", body)
        filtered_status, filtered = self._get("/?source=CISA%20KEV")
        self.assertEqual(filtered_status, 200)
        self.assertIn("Showing 1 of", filtered)
        self.assertIn("CISA KEV", filtered)
        self.assertNotIn('class="name" href="/leads?source=NVD"', filtered)

    def test_navigation_tabs_and_source_filter_reach_a_page(self):
        paths = ("/", "/leads", "/leads?queue=research_backlog", "/leads?queue=raw_unreviewed",
                 "/leads?queue=triaged_open", "/leads?queue=research_completed",
                 "/rules?state=draft", "/rules?state=approved", "/rules?state=rejected",
                 "/reviews", "/errors", "/tools", "/attention", "/leads?source=CISA%20KEV")
        for target in paths:
            with self.subTest(target=target):
                status, body = self._get(target)
                self.assertEqual(status, 200)
                self.assertIn("Threat Research Dashboard", body)
        self.assertIn("CVE-2099-70001", self._get("/leads?source=CISA%20KEV")[1])

    def test_four_main_tabs_and_active_detail_context(self):
        _, home = self._get("/")
        self.assertEqual(home.count('class="count"'), 3)
        self.assertIn('href="/attention"', home)
        _, rules_page = self._get("/rules?state=draft")
        self.assertIn('Live validation and risk:', rules_page)
        self.assertIn('Stored research has not yet had an automatic draft review', rules_page)
        self.assertIn('Not connected.', rules_page)
        _, detail = self._get("/threat?id=CVE-2099-70001&from=rules")
        self.assertIn('href="/rules?state=draft" style="color:var(--text);font-weight:700"', detail)
        self.assertIn('Check cited patterns for a draft', detail)

    def test_propose_button_explains_missing_pattern_without_creating_rule(self):
        status, location = self._post("/threat/propose", {"id": "CVE-2099-70001"})
        self.assertEqual(status, 303)
        self.assertIn("No%20new%20draft", location)
        self.assertEqual(workflow.list_rules(self.path)["total"], 0)

    def test_recent_collection_is_visible_even_when_publication_is_older(self):
        core.ingest([{**fictional_record(), "id": "CVE-2098-70001", "published": "2098-01-01",
                      "title": "Newly collected older publication", "source": "https://example.test/older"}], self.path)
        with store.connection(self.path) as db:
            db.execute("UPDATE threats SET first_seen='2020-01-01T00:00:00Z' WHERE id='CVE-2099-70001'")
        _, newest = self._get("/leads")
        self.assertLess(newest.index("CVE-2098-70001"), newest.index("CVE-2099-70001"))
        _, published = self._get("/leads?sort=published")
        self.assertLess(published.index("CVE-2099-70001"), published.index("CVE-2098-70001"))
        status, body = self._get("/api/leads?sort=collected")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["items"][0]["id"], "CVE-2098-70001")

    def test_source_threats_and_threat_detail_pages(self):
        status, body = self._get("/source?name=" + urllib.parse.quote("CISA KEV"))
        self.assertEqual(status, 200)
        self.assertIn("CVE-2099-70001", body)

        status, body = self._get("/threat?id=CVE-2099-70001")
        self.assertEqual(status, 200)
        self.assertIn("Source and evidence", body)
        self.assertIn("Detection inventory", body)
        self.assertIn("Research and risk", body)
        self.assertIn("Analyst workspace", body)
        self.assertIn("Approval", body)
        # The malicious title must be escaped, never rendered as a live tag.
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

        status, body = self._get("/threat?id=CVE-2099-DOES-NOT-EXIST")
        self.assertEqual(status, 404)

    def test_unknown_route_is_404(self):
        status, _ = self._get("/nope")
        self.assertEqual(status, 404)

    def test_full_analyst_workflow_draft_approve_reject(self):
        status, location = self._post("/threat/note", {
            "id": "CVE-2099-70001", "note_type": "telemetry_fields", "content": "ParentImage, Image, CommandLine"})
        self.assertEqual(status, 303)
        self.assertIn("/threat?id=CVE-2099-70001", location)

        status, location = self._post("/threat/draft", {"id": "CVE-2099-70001", "evidence_id": str(self.evidence_id)})
        self.assertEqual(status, 303)
        self.assertIn("flash=Draft", location)

        _, body = self._get("/threat?id=CVE-2099-70001")
        self.assertIn("Approve and add to rule repository", body)
        _, drafts = self._get("/rules?state=draft")
        self.assertIn("View Sigma / KQL / SPL", drafts)
        self.assertIn("<h3>Sigma</h3>", drafts)

        with store.connection(self.path) as db:
            rule_row = db.execute("SELECT id FROM rules WHERE threat_id='CVE-2099-70001'").fetchone()
        rule_id = rule_row["id"]

        status, location = self._post("/rule/approve", {"id": rule_id, "threat_id": "CVE-2099-70001"})
        self.assertEqual(status, 303)
        self.assertIn("approved_in_local_inventory", location)
        self.assertEqual(rules.get_rule(rule_id, self.path)["status"], "approved")

        _, body = self._get("/threat?id=CVE-2099-70001")
        self.assertIn("Approved &mdash; not deployed to any SIEM", body)
        self.assertIn("YES", body.upper())

    def test_reject_via_http_and_never_deletes_draft(self):
        self._post("/threat/draft", {"id": "CVE-2099-70001", "evidence_id": str(self.evidence_id)})
        with store.connection(self.path) as db:
            rule_id = db.execute("SELECT id FROM rules WHERE threat_id='CVE-2099-70001'").fetchone()["id"]
        status, location = self._post("/rule/reject", {"id": rule_id, "threat_id": "CVE-2099-70001",
                                                        "reason": "Needs more corroborating evidence first."})
        self.assertEqual(status, 303)
        self.assertIn("kept for later review", urllib.parse.unquote_plus(location))
        stored = rules.get_rule(rule_id, self.path)
        self.assertEqual(stored["status"], "rejected")
        _, body = self._get("/threat?id=CVE-2099-70001")
        self.assertIn("Reopen for later review", body)

    def test_api_json_endpoints(self):
        status, body = self._get("/api/sources")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIn("sources", payload)

        status, body = self._get("/api/threat?id=CVE-2099-70001")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["threat"]["id"], "CVE-2099-70001")

    def test_research_needed_flash_when_evidence_unsupported(self):
        # A source_fact evidence row (not analyst_observation) cannot draft a rule.
        with store.connection(self.path) as db:
            source_evidence_id = db.execute(
                "SELECT id FROM evidence WHERE threat_id='CVE-2099-70001' AND kind='source_fact'").fetchone()["id"]
        status, location = self._post("/threat/draft", {"id": "CVE-2099-70001", "evidence_id": str(source_evidence_id)})
        self.assertEqual(status, 303)
        self.assertIn("Research%20needed", location)


if __name__ == "__main__":
    unittest.main()
