"""Local reproductions of zero stored counts hidden by historical fetch totals."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from threat_research import core, dashboard_data, poller, repo_updates, research_feeds, sources, store


class SourceAttributionHealthTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / 'fixture.sqlite3'
        store.initialize(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def record(self, ident, url, name=None):
        return {'id': ident, 'title': 'Fictional local attribution fixture',
                'source': url, 'claim': 'Synthetic source fact; URL not fetched.',
                'kind': 'community_rule' if ident.startswith('RULEPTR-') else 'campaign',
                'reported_by': name}

    def checkpoint(self, name, count):
        with store.connection(self.db) as db:
            db.execute('INSERT INTO source_state(name,last_success,total_records) VALUES (?,?,?)',
                       (name, '2099-01-01T00:00:00Z', count))
            db.execute("INSERT INTO source_attempts(name,attempted_at,status,records) VALUES (?,?,'ok',0)",
                       (name, '2099-01-01T00:00:00Z'))

    def cards(self):
        return {c['name']: c for c in dashboard_data.sources_overview(self.db)['sources']}

    def test_positive_fetch_counter_without_stored_facts_is_empty_in_poll_and_audit(self):
        name = 'GitHub: SigmaHQ community rules'
        self.checkpoint(name, 3152)
        card = self.cards()[name]
        self.assertEqual((card['status'], card['record_count'], card['records_fetched_total']),
                         ('empty_feed', 0, 3152))
        with patch.object(sources, 'enrich_epss', return_value={}):
            result = poller.run_poll(self.db, adapters={name: lambda: []}, notify=False)
        self.assertEqual(result['status'], 'degraded')
        self.assertIn(name, result['empty_sources'])
        self.assertEqual(poller.poll_status(self.db)['source_attempts'][0]['status'], 'empty_feed')

    def test_legacy_sigma_blob_commit_and_repo_alias_repair_counts_without_refetch(self):
        name = 'GitHub: SigmaHQ community rules'
        sha = 'a' * 40
        records = [self.record('RULEPTR-FICTION1', f'https://github.com/SigmaHQ/sigma/blob/{sha}/rules/f.yaml'),
                   self.record('REPO-FICTION2', f'https://github.com/SigmaHQ/sigma/commit/{sha}'),
                   self.record('RULEPTR-FICTION3', f'https://github.com/SigmaHQ/sigma/blob/{sha}/rules/g.yaml',
                               'GitHub: SigmaHQ/sigma')]
        core.ingest(records, self.db)
        self.checkpoint(name, 3)
        self.assertEqual(core.backfill_source_names(self.db), 3)
        self.assertEqual(core.backfill_source_names(self.db), 0)
        with patch.object(sources, 'enrich_epss', return_value={}):
            result = poller.run_poll(self.db, adapters={name: lambda: []}, notify=False)
        self.assertEqual(result['status'], 'collected')
        self.assertEqual((self.cards()[name]['record_count'], self.cards()[name]['status']), (3, 'ok'))

    def test_unlabeled_publisher_facts_are_repaired_and_quiet_feeds_stay_ok(self):
        names = {'The DFIR Report', 'SentinelOne Labs', 'Securelist', 'ESET WeLiveSecurity',
                 'Datadog Security Labs', 'Aqua Security', 'Objective-See', 'Zero Day Initiative',
                 'Google Project Zero', 'JFrog Security Research', 'Semgrep'}
        records, adapters = [], {}
        for index, (name, feed, _) in enumerate(research_feeds.FEEDS):
            if name not in names:
                continue
            canonical = 'RSS: ' + name
            host = (urlsplit(feed).hostname or '').removeprefix('www.')
            records.append(self.record(f'REPORT-FICTION{index}', f'https://www.{host}/fictional-attribution-fixture'))
            self.checkpoint(canonical, 10)
            adapters[canonical] = lambda: []
        core.ingest(records, self.db)
        with patch.object(sources, 'enrich_epss', return_value={}):
            result = poller.run_poll(self.db, adapters=adapters, notify=False)
        self.assertEqual(result['empty_sources'], [])
        self.assertEqual(result['status'], 'collected')
        cards = self.cards()
        for name in adapters:
            self.assertEqual((cards[name]['record_count'], cards[name]['status']), (1, 'ok'), name)

    def test_repeat_ingestion_labels_existing_fact_but_preserves_explicit_attribution(self):
        row = self.record('REPORT-FICTION', 'https://example.test/fictional-report')
        core.ingest([row], self.db)
        row['reported_by'] = 'RSS: The DFIR Report'
        self.assertEqual(core.ingest([row], self.db), 0)
        row['reported_by'] = 'RSS: Other explicit attribution'
        core.ingest([row], self.db)
        with store.connection(self.db) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT source_name FROM evidence').fetchone()[0], 'RSS: The DFIR Report')

    def test_unknown_hosts_never_attempted_sources_and_failures_are_not_reclassified(self):
        core.ingest([self.record('REPORT-UNKNOWN', 'https://github.com.evil.test/SigmaHQ/sigma/blob/a/rules/f.yaml')], self.db)
        self.assertEqual(core.backfill_source_names(self.db), 0)
        name = 'GitHub: SigmaHQ community rules'
        self.assertEqual(self.cards()[name]['status'], 'never_collected')
        self.checkpoint(name, 3)
        with store.connection(self.db) as db:
            db.execute("UPDATE source_attempts SET status='error',detail='fictional HTTP 403'")
        self.assertEqual(self.cards()[name]['status'], 'error')

    def test_sigma_bootstrap_with_no_stored_pointers_recovers_and_uses_canonical_name(self):
        sha = 'a' * 40
        with store.connection(self.db) as db:
            db.execute('INSERT INTO repo_bootstraps(repo,snapshot_sha,completed_at) VALUES (?,?,?)',
                       ('SigmaHQ/sigma', 'c' * 40, '2099-01-01T00:00:00Z'))
        def fetch(url, **kwargs):
            if '/commits/' in url:
                return {'sha': sha}
            if '/git/trees/' in url:
                return {'truncated': False, 'tree': [{'type': 'blob', 'path': 'rules/fictional.yaml', 'sha': 'b' * 40}]}
            return {'default_branch': 'master'}
        until = datetime.now(timezone.utc)
        rows = repo_updates.collect_catalog('SigmaHQ/sigma', 'rules', 'community_rule',
                                           until - timedelta(days=2), until, database=self.db, fetch=fetch)
        self.assertEqual(rows[0]['reported_by'], 'GitHub: SigmaHQ community rules')
        core.ingest(rows, self.db)
        self.assertEqual(self.cards()['GitHub: SigmaHQ community rules']['record_count'], 1)

    def test_fetch_history_does_not_shorten_an_empty_rss_initial_window(self):
        name = 'RSS: The DFIR Report'
        self.checkpoint(name, 10)
        until = datetime(2099, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(poller._source_windows(self.db, until)[name],
                         until - timedelta(days=research_feeds.INITIAL_LOOKBACK_DAYS))
        core.ingest([self.record('REPORT-FICTION', 'https://thedfirreport.com/fictional-fixture', name)], self.db)
        self.assertEqual(poller._source_windows(self.db, until)[name],
                         datetime(2098, 12, 31, 23, tzinfo=timezone.utc))


if __name__ == '__main__':
    unittest.main()
