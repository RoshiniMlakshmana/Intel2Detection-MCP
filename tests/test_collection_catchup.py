"""Offline reproductions of the October catch-up's GitHub intake failures."""
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from threat_research import core, poller, repo_updates, sources, store


class Response(io.BytesIO):
    status = 200
    headers = {}


class CatchupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / 'lab.sqlite3'
        store.initialize(self.db)
        self.until = datetime.now(timezone.utc)
        self.since = self.until - timedelta(days=2)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sentinel_tree_over_eight_mb_bootstraps_without_raising_other_limits(self):
        sha = 'a' * 40
        tree = {'truncated': False, 'tree': [{'type': 'blob', 'path': 'Detections/Test.yaml', 'sha': 'b' * 40}],
                'padding': ' ' * 9_000_000}
        def open_url(request, **kwargs):
            url = request.full_url
            value = tree if '/git/trees/' in url else {'sha': sha} if '/commits/' in url else {'default_branch': 'master'}
            return Response(json.dumps(value).encode())
        with patch('threat_research.sources.urllib.request.urlopen', side_effect=open_url):
            rows = repo_updates.collect_catalog('Azure/Azure-Sentinel', 'Detections', 'community_rule',
                                                self.since, self.until, database=self.db)
        self.assertEqual(len(rows), 1)
        with store.connection(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM repo_bootstraps').fetchone()[0], 0)

    def test_json_default_and_absolute_size_limits_remain_enforced(self):
        with patch('threat_research.sources.urllib.request.urlopen', return_value=Response(b' ' * 8_000_001)):
            with self.assertRaisesRegex(ValueError, 'response too large'):
                sources.fetch_json('https://example.test/fixture')
        with self.assertRaisesRegex(ValueError, 'bounded JSON'):
            sources.fetch_json('https://example.test/fixture', max_bytes=33_000_000)

    def pages(self, calls):
        def fetch(url):
            calls.append(url)
            params = parse_qs(urlsplit(url).query)
            self.assertNotIn('page', params)
            offset = 2 if 'after' in params else 0
            rows = [{'cve_id': f'CVE-2099-{1000+i}', 'summary': 'Fictional advisory',
                     'updated_at': self.until.isoformat(), 'vulnerabilities': []} for i in range(offset, offset + 2)]
            link = '<https://api.github.com/advisories?after=fixture-cursor>; rel="next"' if not offset else None
            return rows, link
        return fetch

    def test_advisory_cursor_advances_only_after_ingestion_and_resumes_next_poll(self):
        calls = []
        adapter = lambda: sources.collect_ghsa(self.since, fetch=self.pages(calls), max_pages=1,
                                               until=self.until, database=self.db)
        with patch.object(sources, 'enrich_epss', return_value={}):
            first = poller.run_poll(self.db, adapters={'GitHub advisories': adapter}, notify=False)
            self.assertEqual(first['source_counts']['GitHub advisories'], 2)
            self.assertIn('GitHub advisories', first['partial_sources'])
            with store.connection(self.db) as db:
                state = json.loads(db.execute('SELECT state FROM collection_cursors').fetchone()[0])
                self.assertIn('after=fixture-cursor', state['next_url'])
                self.assertEqual(db.execute('SELECT count(*) FROM threats').fetchone()[0], 2)
            second = poller.run_poll(self.db, adapters={'GitHub advisories': adapter}, notify=False)
        self.assertEqual(second['new_records'], 2)
        self.assertEqual(second['status'], 'collected')
        self.assertEqual(len(calls), 2)
        with store.connection(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM threats').fetchone()[0], 4)
            self.assertEqual(db.execute('SELECT count(*) FROM collection_cursors').fetchone()[0], 0)

    def test_failed_ingestion_does_not_skip_an_advisory_page(self):
        adapter = lambda: sources.collect_ghsa(self.since, fetch=self.pages([]), max_pages=1,
                                               until=self.until, database=self.db)
        with patch.object(core, 'ingest', side_effect=ValueError('fixture disk failure')), \
             patch.object(sources, 'enrich_epss', return_value={}):
            result = core.collect_daily(self.db, adapters={'GitHub advisories': adapter})
        self.assertIn('disk failure', result['errors']['GitHub advisories'])
        with store.connection(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM collection_cursors').fetchone()[0], 0)

    def test_interrupted_fetch_retains_the_page_to_retry_and_fetched_records(self):
        calls = []
        first_page = self.pages(calls)
        def fetch(url):
            if 'after=' in url:
                raise OSError('fictional connection reset')
            return first_page(url)
        with self.assertRaises(sources.PartialCollection) as caught:
            sources.collect_ghsa(self.since, fetch=fetch, max_pages=2, until=self.until)
        self.assertEqual(len(caught.exception.records), 2)
        self.assertIn('after=', caught.exception.resume_state['next_url'])

    def test_foreign_cursor_is_not_followed(self):
        calls = []
        def fetch(url):
            calls.append(url)
            return [], '<https://example.test/steal>; rel="next"'
        with self.assertRaisesRegex(sources.PartialCollection, 'official endpoint'):
            sources.collect_ghsa(self.since, fetch=fetch, max_pages=2, until=self.until)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
