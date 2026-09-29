"""Regression tests for the exact source failures in the 2026-09-28T19:36Z poll:

- NVD: "NVD page cap reached; narrow the collection window"
- RSS: CISA advisories: "HTTP Error 403: Forbidden"
- RSS: Google Project Zero: "feed response too large"
- RSS: Zero Day Initiative: "unsupported or oversized XML"
- RSS: JFrog Security Research: "no element found: line 1, column 0"
- RSS: Malpedia: "[WinError 10061] ... actively refused it" (live re-check: TLS chain)
- Articles: "HTTP Error 301: Moved Permanently" / "HTTP Error 403: Forbidden"
- Frameworks: ATLAS/OWASP refresh failures must keep the last-known-good snapshot

Fixtures are fictional or local; nothing here contacts a network.
"""

import io
import json
import ssl
import tempfile
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from threat_research import (core, dashboard_data, frameworks, lead_queue, net, poller, report_inspection,
                             research_feeds, sources, store, workflow)


def rss(items, doctype=False, pad=0):
    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    head = b'<!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN" "http://my.netscape.com/publish/formats/rss-0.91.dtd">' if doctype else b""
    body = "".join(f"<item><title>Fictional research article {i}</title><link>https://example.test/post-{i}</link>"
                   f"<pubDate>{now}</pubDate><description>{'x' * pad}</description></item>" for i in range(items))
    return head + f'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{body}</channel></rss>'.encode()


class FakeResponse(io.BytesIO):
    def __init__(self, data, status=200, headers=None):
        super().__init__(data)
        self.status = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def nvd_page(count, total, prefix):
    return {"totalResults": total, "vulnerabilities": [
        {"cve": {"id": f"CVE-2099-{prefix}{i:04d}", "vulnStatus": "Analyzed",
                 "descriptions": [{"lang": "en", "value": "fictional"}], "metrics": {}}} for i in range(count)]}


class NvdPageCapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_catch_up_window_is_chunked_by_day_and_fully_collected(self):
        seen_windows = []

        def fetch(url, headers=None):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            seen_windows.append((q["lastModStartDate"][0], q["lastModEndDate"][0]))
            return nvd_page(3, 3, len(seen_windows))

        until = datetime(2099, 1, 8, tzinfo=timezone.utc)
        rows = sources.collect_nvd(until - timedelta(days=7), until, fetch=fetch, rate_limit=False)
        self.assertEqual(len(seen_windows), 7)
        self.assertEqual(len(rows), 21)
        # Chunks are contiguous and chronological.
        for (_, end), (start, _) in zip(seen_windows, seen_windows[1:]):
            self.assertEqual(end, start)

    def test_page_cap_ingests_fetched_records_and_checkpoints_only_complete_chunks(self):
        calls = []

        def fetch(url, headers=None):
            calls.append(url)
            return nvd_page(2, 2, len(calls))  # one full page per day

        until = datetime(2099, 1, 8, tzinfo=timezone.utc)
        adapters = {"NVD": lambda: sources.collect_nvd(until - timedelta(days=7), until, fetch=fetch,
                                                       max_pages=3, rate_limit=False)}
        with patch.object(sources, "enrich_epss", return_value={}):
            result = poller.run_poll(self.path, adapters=adapters)
        self.assertEqual(result["status"], "degraded")
        self.assertIn("NVD page cap reached", result["source_errors"]["NVD"])
        self.assertEqual(result["partial_sources"]["NVD"], "2099-01-04T00:00:00Z")
        self.assertEqual(result["new_records"], 6)
        with store.connection(self.path) as db:
            state = db.execute("SELECT last_success,last_error FROM source_state WHERE name='NVD'").fetchone()
            attempt = db.execute("SELECT status FROM source_attempts WHERE name='NVD'").fetchone()
        # Checkpoint is the end of the last fully paged day, never the window end.
        self.assertEqual(state["last_success"], "2099-01-04T00:00:00Z")
        self.assertIn("page cap", state["last_error"])
        self.assertEqual(attempt["status"], "partial")

    def test_partial_checkpoint_never_moves_backwards(self):
        with store.connection(self.path) as db:
            db.execute("INSERT INTO source_state(name,last_success) VALUES ('NVD','2099-02-01T00:00:00Z')")

        def partial():
            raise sources.PartialCollection("NVD page cap reached (1 pages)", [],
                                            datetime(2099, 1, 5, tzinfo=timezone.utc))
        with patch.object(sources, "enrich_epss", return_value={}):
            poller.run_poll(self.path, adapters={"NVD": partial})
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT last_success FROM source_state WHERE name='NVD'").fetchone()[0],
                             "2099-02-01T00:00:00Z")


class FeedFailureTest(unittest.TestCase):
    since = datetime.now(timezone.utc) - timedelta(days=2)

    def feed(self, name):
        return [f for f in research_feeds.FEEDS if f[0] == name]

    def test_cisa_advisories_use_tls12_and_other_feeds_do_not(self):
        seen = {}

        feed = rss(2)

        def urlopen(request, timeout=None, context=None):
            seen[request.full_url] = context.maximum_version
            return FakeResponse(feed)
        with patch.object(research_feeds.urllib.request, "urlopen", urlopen):
            _, counts, errors = research_feeds.collect_research(
                self.since, feeds=self.feed("CISA advisories") + self.feed("Cisco Talos research"))
        self.assertEqual(errors, {})
        self.assertEqual(counts["CISA advisories"], 2)
        cisa_url = self.feed("CISA advisories")[0][1]
        self.assertEqual(seen[cisa_url], ssl.TLSVersion.TLSv1_2)
        self.assertNotEqual(seen[self.feed("Cisco Talos research")[0][1]], ssl.TLSVersion.TLSv1_2)

    def test_cisa_block_is_still_reported_when_it_persists(self):
        def urlopen(request, timeout=None, context=None):
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", Message(), None)
        with patch.object(research_feeds.urllib.request, "urlopen", urlopen):
            _, counts, errors = research_feeds.collect_research(self.since, feeds=self.feed("CISA advisories"))
        self.assertEqual(errors, {"CISA advisories": "HTTP Error 403: Forbidden"})

    def test_project_zero_full_history_feed_fits_its_size_override(self):
        big = rss(40, pad=240_000)  # ~9.6MB, the observed full-history shape
        self.assertGreater(len(big), research_feeds.DEFAULT_MAX_BYTES)
        with patch.object(research_feeds.urllib.request, "urlopen", lambda *a, **k: FakeResponse(big)):
            _, counts, errors = research_feeds.collect_research(self.since, feeds=self.feed("Google Project Zero"))
        self.assertEqual(errors, {})
        self.assertEqual(counts["Google Project Zero"], 40)

    def test_zdi_squarespace_doctype_feed_parses(self):
        feed = rss(3, doctype=True)  # built before collect_research fixes its `until`
        with patch.object(research_feeds.urllib.request, "urlopen", lambda *a, **k: FakeResponse(feed)):
            _, counts, errors = research_feeds.collect_research(self.since, feeds=self.feed("Zero Day Initiative"))
        self.assertEqual(errors, {})
        self.assertEqual(counts["Zero Day Initiative"], 3)

    def test_jfrog_uses_official_research_feed_and_is_an_allowed_article_host(self):
        url = self.feed("JFrog Security Research")[0][1]
        self.assertEqual(urllib.parse.urlsplit(url).hostname, "research.jfrog.com")
        self.assertIn("research.jfrog.com", report_inspection.ALLOWED_HOSTS)

    def test_empty_202_challenge_is_reported_as_publisher_block_not_parse_error(self):
        with patch.object(research_feeds.urllib.request, "urlopen", lambda *a, **k: FakeResponse(b"", status=202)):
            _, _, errors = research_feeds.collect_research(self.since, feeds=self.feed("JFrog Security Research"))
        self.assertIn("publisher may block automated requests", errors["JFrog Security Research"])
        self.assertNotIn("no element found", errors["JFrog Security Research"])

    def test_tls_context_adds_mozilla_roots_and_keeps_verification(self):
        context = net.tls_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertIsNotNone(net.certifi, "certifi is a declared dependency (Malpedia's HARICA root)")
        baseline = ssl.create_default_context().cert_store_stats()["x509_ca"]
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)
        self.assertGreaterEqual(context.cert_store_stats()["x509_ca"], baseline)


class ArticleFetchTest(unittest.TestCase):
    def test_checkpoint_http_redirect_is_upgraded_to_https_same_host(self):
        handler = report_inspection._SameHostRedirectOnly()
        import urllib.request as ur
        request = ur.Request("https://research.checkpoint.com/2026/report", headers=report_inspection.ARTICLE_HEADERS)
        redirected = handler.redirect_request(request, None, 301, "Moved Permanently", {},
                                              "http://research.checkpoint.com/2026/report/")
        self.assertEqual(redirected.full_url, "https://research.checkpoint.com/2026/report/")
        self.assertIsNone(report_inspection._SameHostRedirectOnly().redirect_request(
            request, None, 301, "Moved", {}, "http://evil.example/2026/report/"))

    def test_slashless_403_retries_canonical_trailing_slash(self):
        tried = []

        def open_url(url):
            tried.append(url)
            if not url.endswith("/"):
                raise urllib.error.HTTPError(url, 403, "Forbidden", Message(), None)
            return b"<html><p>ok</p></html>"
        raw = report_inspection.fetch_article("https://www.securityweek.com/citrix-confirms-zero-days", open_url)
        self.assertEqual(raw, b"<html><p>ok</p></html>")
        self.assertEqual(tried, ["https://www.securityweek.com/citrix-confirms-zero-days",
                                 "https://www.securityweek.com/citrix-confirms-zero-days/"])

    def test_persistent_403_is_reported_as_publisher_block(self):
        def open_url(url):
            raise urllib.error.HTTPError(url, 403, "Forbidden", Message(), None)
        with self.assertRaisesRegex(ValueError, "publisher blocked the automated article fetch"):
            report_inspection.fetch_article("https://www.securityweek.com/a-story", open_url)

    def test_rate_limit_is_transient_not_a_block(self):
        def open_url(url):
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", Message(), None)
        with self.assertRaisesRegex(ValueError, "rate limit; the queue retries later") as caught:
            report_inspection.fetch_article("https://www.bleepingcomputer.com/news/a-story", open_url)
        self.assertNotIn("publisher blocked", str(caught.exception))

    def test_blocked_article_stops_retrying_after_confirmation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "db.sqlite3"
            url = "https://www.securityweek.com/fictional-story"
            core.ingest([{"id": "REPORT-FICTIONAL0001", "title": "Fictional story", "kind": "campaign",
                          "source": url, "claim": "fixture"}], path)
            lead_queue.queue_new_report_articles(["REPORT-FICTIONAL0001"], path)

            def blocked(url):
                raise urllib.error.HTTPError(url, 403, "Forbidden", Message(), None)

            def fetch(url):
                return report_inspection.fetch_article(url, blocked)
            for _ in range(2):
                with store.connection(path) as db:
                    db.execute("UPDATE article_inspection_queue SET next_try='2000-01-01T00:00:00Z'")
                lead_queue.inspect_due(path, fetch=fetch)
            with store.connection(path) as db:
                row = db.execute("SELECT status,attempts,last_error FROM article_inspection_queue").fetchone()
            self.assertEqual(row["status"], "publisher_blocked")
            self.assertEqual(row["attempts"], 2)
            self.assertEqual(len(workflow.source_errors(path)["article_fetches"]), 1)


class FrameworkLastKnownGoodTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        with store.connection(self.path) as db:
            db.execute("INSERT INTO framework_snapshots(name,version,source_url,sha256,fetched_at,entries) VALUES "
                       "('atlas','2026.08','https://example.test/atlas','abc','2000-01-01T00:00:00Z','{}')")

    def tearDown(self):
        self.tmp.cleanup()

    def test_failed_atlas_and_owasp_refresh_keep_snapshot_and_report_error(self):
        def fetch(url, limit):
            if "atlas" in url:
                return b"dist/v9/missing.yaml"  # pointer chain that never resolves to a mapping
            if "owasp" in url:
                raise ValueError("framework response exceeds size cap")
            raise OSError("offline")
        out = frameworks.refresh(self.path, force=True, fetch=fetch)
        self.assertEqual(out["sources"]["atlas"]["status"], "stale")
        self.assertEqual(out["sources"]["atlas"]["retained_snapshot"]["version"], "2026.08")
        self.assertEqual(out["sources"]["owasp"]["status"], "unavailable")
        with store.connection(self.path) as db:
            kept = db.execute("SELECT version,sha256 FROM framework_snapshots WHERE name='atlas'").fetchone()
            attempts = {r["name"]: dict(r) for r in db.execute("SELECT * FROM source_attempts")}
        self.assertEqual((kept["version"], kept["sha256"]), ("2026.08", "abc"))
        self.assertIn("kept last-known-good 2026.08", attempts["MITRE ATLAS"]["detail"])
        self.assertIn("no earlier snapshot", attempts["OWASP LLM Top 10"]["detail"])
        card = next(c for c in dashboard_data.sources_overview(self.path)["sources"] if c["name"] == "MITRE ATLAS")
        self.assertEqual(card["status"], "error")

    def test_later_success_clears_an_older_poll_error(self):
        with store.connection(self.path) as db:
            db.execute("INSERT INTO poll_state(id,last_completed,last_result) VALUES (1,?,?)",
                       ("2000-01-01T00:00:00Z", json.dumps({"framework_update": {"errors": {"atlas": "ATLAS document is not a mapping"}}})))
            db.execute("INSERT INTO source_attempts(name,attempted_at,status,records,detail) VALUES "
                       "('MITRE ATLAS','2099-01-01T00:00:00Z','ok',120,'refreshed')")
        card = next(c for c in dashboard_data.sources_overview(self.path)["sources"] if c["name"] == "MITRE ATLAS")
        self.assertIsNone(card["error"])


class StalePollResultTest(unittest.TestCase):
    def test_result_from_older_collector_is_flagged_stale(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "db.sqlite3"
            store.initialize(path)
            with store.connection(path) as db:
                db.execute("INSERT INTO poll_state(id,last_completed,last_result) VALUES (1,?,?)",
                           (core.now(), json.dumps({"status": "degraded", "source_errors": {"NVD": "old"}})))
            status = poller.poll_status(path)
            self.assertTrue(status["last_result_stale"])
            self.assertIn("older than 0.11.0", status["last_result_collector_version"])
            with patch.object(sources, "enrich_epss", return_value={}):
                poller.run_poll(path, adapters={"CISA KEV": lambda: []})
            status = poller.poll_status(path)
            self.assertFalse(status["last_result_stale"])
            self.assertEqual(status["source_attempts"][0]["name"], "CISA KEV")


if __name__ == "__main__":
    unittest.main()
