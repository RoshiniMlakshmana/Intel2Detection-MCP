"""Regressions for observed extraction, collection and source refresh failures."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml
from threat_research import (core, custom_rules, drafting, environment, poller,
                            proposal_pass, publisher_queries, research_pass,
                            repo_updates, rules, soc_replay, store, workup)
from test_workup_drafting import Base, REPORT_URL, REPORT_HTML


class ExtractionFixes(Base):
    def test_report_backfill_does_not_spend_its_budget_on_cve_patch_reviews(self):
        ident = self.report()
        core.ingest([{'id': 'CVE-2099-99999', 'title': 'Fictional patch advisory',
                      'source': REPORT_URL, 'summary': 'fixture'}], self.path)
        with store.connection(self.path) as db:
            db.execute("INSERT INTO research_outcomes VALUES (?, 'completed_insufficient_detail', ?, '{}')",
                       ('CVE-2099-99999', core.now()))
        result = proposal_pass.propose_stored_batch(self.path, limit=1)
        self.assertEqual(result['results'][0]['threat_id'], ident)
        self.assertEqual(result['drafts_created'], 1)
        self.assertIsNone(result['next_cursor'])

    def test_rmm_chain_without_actor_word_creates_own_draft(self):
        html = b'<html><article><p>RMM.Agent.exe launched PowerShell with Invoke-WebRequest, then executed msiexec.exe with /qn to install the package.</p></article></html>'
        ident = self.report(html=html)
        result = proposal_pass.propose_from_stored(ident, self.path)
        self.assertEqual(len(result['proposals']), 1, result)
        rule = rules.get_rule(result['proposals'][0]['rule_id'], self.path)
        self.assertEqual(rule['status'], 'draft')
        self.assertEqual({p['field'] for p in rule['custom_spec']['predicates']}, {'ParentImage', 'Image', 'CommandLine'})
        self.assertTrue(drafting.source_link(rule['id'], self.path)['proposed_by'].startswith('bounded_research_pass'))
        again = proposal_pass.propose_from_stored(ident, self.path)
        self.assertEqual(again['proposals'][0]['status'], 'existing_draft')
        self.assertEqual(again['gaps'], [])

    def test_linux_report_produces_process_draft(self):
        ident = self.report(html=b'<html><article><p>The attacker used nginx to launch bash with curl to download the malicious payload on Linux.</p></article></html>')
        result = proposal_pass.propose_from_stored(ident, self.path)
        self.assertEqual(len(result['proposals']), 1, result)
        spec = custom_rules.get_spec(result['proposals'][0]['rule_id'], self.path)
        self.assertEqual(spec['platform'], 'linux')
        self.assertTrue(any(p['value'] == 'curl' for p in spec['predicates']))

    def test_system32_exclusion_is_a_real_path_filter(self):
        pattern = {'quoted_paragraph': 'The malicious loader helper.exe sideloads slc.dll, the backdoor.',
                   'observable': {'lexical_behavior': 'dll_sideloading'}}
        spec = custom_rules.validate_spec(proposal_pass.behavior_spec(pattern))
        rule = {'behavior': 'custom', 'custom_spec': json.dumps(spec)}
        event = {'event_type': 'image_load', 'Image': 'helper.exe', 'ImageLoaded': r'C:\Windows\System32\slc.dll'}
        self.assertFalse(soc_replay._matches(rule, event))
        for path in [r'C:\Users\Public\slc.dll', r'C:\Windows\System32evil\slc.dll']:
            self.assertTrue(soc_replay._matches(rule, {**event, 'ImageLoaded': path}))
        ident = self.report(html=('<html><article><p>' + pattern['quoted_paragraph'] + '</p></article></html>').encode())
        self.assertEqual(len(proposal_pass.propose_from_stored(ident, self.path)['proposals']), 1)
        query, missing = custom_rules._query(spec, {'table':'DeviceImageLoadEvents', 'fields':['InitiatingProcessFileName', 'FolderPath']}, 'defender')
        self.assertFalse(missing)
        self.assertIn('startswith', query)
        self.assertIn(r'c:\\windows\\system32\\', query)

    def test_source_refresh_invalidates_old_verification(self):
        ident = self.report()
        rid = self.propose()['rule_id']
        drafting.verify(rid, 'I verified this source paragraph', path=self.path)
        original = drafting.source_link(rid, self.path)['page_sha256']
        research_pass.research_lead(ident, self.path, fetch=lambda _: REPORT_HTML.replace(b'FictLoader.dll', b'ChangedLoader.dll'), refresh=True)
        link = drafting.source_link(rid, self.path)
        self.assertEqual(link['page_sha256'], original)
        self.assertTrue(link['source_changed_since_draft'])
        self.assertFalse(link['cited_values_still_present'])
        self.assertFalse(link['source_verification_current'])
        self.assertEqual(workup._draft_view(rid, self.path)['source_verification'], 'unverified')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            drafting.verify(rid, 'I verified this source paragraph', path=self.path)
        with self.assertRaisesRegex(ValueError, 'source changed'):
            rules.implement_rule(rid, 'implement this rule', path=self.path)

    def test_refresh_same_values_needs_reverification_and_preserves_provenance(self):
        ident = self.report()
        rid = self.propose()['rule_id']
        drafting.verify(rid, 'I verified this source paragraph', path=self.path)
        original = drafting.source_link(rid, self.path)['page_sha256']
        self.report(html=REPORT_HTML.replace(b'</article>', b'<p>Updated incident timeline.</p></article>'))
        self.assertFalse(drafting.source_link(rid, self.path)['source_verification_current'])
        drafting.verify(rid, 'I verified this source paragraph', path=self.path)
        link = drafting.source_link(rid, self.path)
        self.assertTrue(link['source_verification_current'])
        self.assertEqual(link['page_sha256'], original)


class QueryFixes(unittest.TestCase):
    def test_conhost_curl_and_term_semantics(self):
        spec = publisher_queries.bounded_spec('DeviceProcessEvents | where FileName =~ "conhost.exe" | where ProcessCommandLine has "curl"')
        self.assertIsNotNone(spec)
        rule = {'behavior':'custom', 'custom_spec':json.dumps(spec)}
        event = {'event_type':'process_creation','Image':'conhost.exe','CommandLine':'curl https://example.org'}
        self.assertTrue(soc_replay._matches(rule, event))
        self.assertFalse(soc_replay._matches(rule, {**event, 'CommandLine':'curling https://example.org'}))
        sigma = yaml.safe_load(custom_rules._sigma('Conhost curl', spec, 'Administrative commands'))
        self.assertTrue(any('|re' in k for k in sigma['detection']['selection']))

    def test_literal_and_lists_and_unsupported_clauses(self):
        for op in ['has_any', 'has_all']:
            spec = publisher_queries.bounded_spec(f'DeviceProcessEvents | where FileName == "conhost.exe" and ProcessCommandLine {op} ("curl", "wget")')
            self.assertIsNotNone(spec)
            rule = {'behavior':'custom', 'custom_spec':json.dumps(spec)}
            event = {'event_type':'process_creation','Image':'conhost.exe','CommandLine':'curl'}
            self.assertEqual(soc_replay._matches(rule, event), op == 'has_any')
        self.assertIsNotNone(publisher_queries.bounded_spec('DeviceProcessEvents | where FileName =~ "conhost.exe" and ProcessCommandLine contains "curl and wget"'))
        for tail in [' | summarize count()', ' and ProcessCommandLine != "safe"', ' or FileName == "safe.exe"', ' | project FileName | where FileName == "x.exe"']:
            self.assertIsNone(publisher_queries.bounded_spec('DeviceProcessEvents | where FileName =~ "conhost.exe" and ProcessCommandLine has "curl"' + tail))

    def test_sequence_sigma_ids_do_not_collide_with_standalone_or_other_sequence(self):
        first = [{'field':'Image','operator':'endswith','value':'powershell.exe'}, {'field':'CommandLine','operator':'contains','value':'curl'}]
        second = [{'field':'Image','operator':'endswith','value':'msiexec.exe'}, {'field':'CommandLine','operator':'contains','value':'/qn'}]
        spec = {'event_family':'process_creation','platform':'windows','sequence':{'group_by':'DeviceId','within_seconds':60,'steps':[first,second]}}
        docs = list(yaml.safe_load_all(custom_rules._sigma('Chain', custom_rules.validate_spec(spec), 'Admin installs')))
        standalone = yaml.safe_load(custom_rules._sigma('One stage', {'event_family':'process_creation','platform':'windows','predicates':first}, 'Admin installs'))
        self.assertEqual(len({d['id'] for d in docs} | {standalone['id']}), 4)
        spec['sequence']['within_seconds'] = 120
        other = list(yaml.safe_load_all(custom_rules._sigma('Other chain', custom_rules.validate_spec(spec), 'Admin installs')))
        self.assertTrue({d['id'] for d in docs}.isdisjoint(d['id'] for d in other))


class CollectionFixes(Base):
    def test_existing_attempt_statuses_survive_schema_upgrade(self):
        with store.connection(self.path) as db:
            db.execute('DROP TABLE source_attempts')
            db.execute("CREATE TABLE source_attempts(name TEXT PRIMARY KEY, attempted_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('ok','partial','error')), records INTEGER NOT NULL DEFAULT 0, detail TEXT)")
            db.execute("INSERT INTO source_attempts VALUES ('RSS: old','2099-01-01','ok',5,NULL)")
        store.initialize(self.path)
        with store.connection(self.path) as db:
            self.assertEqual(db.execute('SELECT records FROM source_attempts').fetchone()[0], 5)
            db.execute("UPDATE source_attempts SET status='empty_feed'")

    def test_never_populated_feed_reports_empty_and_known_feed_can_be_quiet(self):
        empty = poller.run_poll(self.path, adapters={'RSS: Test feed': lambda: []}, notify=False)
        self.assertEqual(empty['status'], 'degraded')
        self.assertEqual(poller.poll_status(self.path)['database'], str(self.path.resolve()))
        self.assertEqual(poller.poll_status(self.path)['interval_minutes'], empty['interval_minutes'])
        with store.connection(self.path) as db:
            self.assertEqual(db.execute('SELECT status FROM source_attempts').fetchone()[0], 'empty_feed')
            db.execute('UPDATE source_state SET total_records=10')
        quiet = poller.run_poll(self.path, adapters={'RSS: Test feed': lambda: []}, notify=False)
        self.assertEqual(quiet['status'], 'collected')
        with store.connection(self.path) as db:
            self.assertEqual(db.execute('SELECT status FROM source_attempts').fetchone()[0], 'ok')

    def test_bootstrap_includes_sentinel_solutions_and_deduplicates(self):
        sha = 'a' * 40
        def fetch(url, **kwargs):
            if '/commits/' in url: return {'sha':sha}
            if '/git/trees/' in url: return {'truncated':False,'tree':[{'type':'blob','path':'Solutions/Fiction/Analytic Rules/LinuxShell.yaml','sha':'b'*40}, {'type':'blob','path':'Detections/Execution.yaml','sha':'c'*40}, {'type':'blob','path':'README.md','sha':'d'*40}]}
            return {'default_branch':'master'}
        end = datetime.now(timezone.utc)
        rows = repo_updates.collect_catalog('Azure/Azure-Sentinel','Detections','community_rule', end-timedelta(days=2), end, database=self.path, fetch=fetch)
        self.assertEqual(len(rows), 2)
        core.ingest(rows, self.path)
        self.assertEqual(core.ingest(rows, self.path), 0)
        with store.connection(self.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM repo_bootstraps').fetchone()[0], 0)
        with patch.object(core.sources, "enrich_epss", return_value={}):
            result = core.collect_daily(self.path, adapters={"GitHub: fixture": lambda: rows}, include_ids=True)
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT snapshot_sha FROM repo_bootstraps").fetchone()[0], sha)
            db.execute("DELETE FROM repo_bootstraps")
        def truncated(url, **kwargs):
            data = fetch(url, **kwargs)
            if '/git/trees/' in url: data['truncated'] = True
            return data
        with self.assertRaisesRegex(ValueError, 'truncated'):
            repo_updates.collect_catalog('Azure/Azure-Sentinel','Detections','community_rule', end-timedelta(days=2), database=self.path, fetch=truncated)

    def test_lab_profile_configures_fields_without_fake_assets(self):
        profile = json.loads((Path(__file__).resolve().parents[1] / 'examples/splunk-sysmon-lab.profile.json').read_text())
        environment.configure_telemetry(profile, self.path)
        self.assertEqual(environment.status(self.path)['assets'], 0)
        self.assertEqual(environment.status(self.path)['siem'], 'splunk')
        spec = {'event_family':'process_creation','platform':'windows','predicates':[{'field':'Image','operator':'endswith','value':'conhost.exe'},{'field':'CommandLine','operator':'has','value':'curl'}]}
        query, missing = custom_rules._query(spec, profile['telemetry']['process_creation'], 'splunk')
        self.assertFalse(missing)
        self.assertIn('index=sysmon', query)
        self.assertNotIn('YOUR_', query)


if __name__ == '__main__':
    unittest.main()
