"""Isolated regressions for intake, complete stage hunts and mapped queries."""
import json
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch

from threat_research import core,custom_rules,drafting,proposal_pass,publisher_queries,research_feeds,research_pass,repo_updates,rules,soc_replay,store,sysmon_samples

URL='https://www.microsoft.com/en-us/security/blog/2099/01/01/fictional-rmm-regression'
TEXT='The attacker used RMM.Agent.exe to launch PowerShell. The PowerShell process changed the session settings and executed Invoke-WebRequest to download ClientSetup.msi. The downloaded package was installed silently through msiexec.exe with the /qn switch.'

class RemainingGapsTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name);self.db=self.path/'db.sqlite3';store.initialize(self.db)
 def tearDown(self):self.tmp.cleanup()
 def report(self,text=TEXT,query=False):
  core.ingest([{'id':'REPORT-FICTION','kind':'campaign','title':'Fictional report regression','source':URL}],self.db)
  tag='pre' if query else 'p'
  page=('<html><article><p>This fictional Windows report checks bounded publisher hunting translation. All content is an isolated regression fixture and no page is fetched remotely.</p><'+tag+'>'+text+'</'+tag+'></article></html>').encode() if query else ('<html><article><p>'+text+'</p></article></html>').encode()
  research_pass.run_pass(self.db,threat_ids=['REPORT-FICTION'],fetch=lambda _:page,max_fetches=1)
  return proposal_pass.propose_from_stored('REPORT-FICTION',self.db)
 def test_both_rmm_stages_package_and_false_positive_notes(self):
  result=self.report();self.assertEqual(len(result['proposals']),2)
  process=next(p for p in result['proposals'] if any(x['field']=='ParentImage' for x in p['candidate_spec']['predicates']))
  msi=next(p for p in result['proposals'] if p!=process)
  values={p['value'] for p in msi['candidate_spec']['predicates']}
  self.assertEqual(values,{'msiexec.exe','/qn','ClientSetup.msi'})
  p=rules.get_rule(process['rule_id'],self.db);m=rules.get_rule(msi['rule_id'],self.db)
  self.assertIn('Authorized RMM',p['sigma']);self.assertNotIn('Web administration',p['sigma'])
  self.assertIn('Authorized software deployment',m['sigma'])
  self.assertNotIn('sequence',msi['candidate_spec'])
  event={'event_type':'process_creation','Image':r'C:\Windows\System32\msiexec.exe','CommandLine':'msiexec /i ClientSetup.msi /qn'}
  rule={'behavior':'custom','custom_spec':json.dumps(msi['candidate_spec'])}
  self.assertTrue(soc_replay._matches(rule,event));self.assertFalse(soc_replay._matches(rule,{**event,'CommandLine':'msiexec /i Other.msi /qn'}))
 def test_existing_automatic_notes_are_repaired_but_analyst_notes_are_not(self):
  result=self.report();rid=result['proposals'][0]['rule_id']
  with store.connection(self.db) as db:db.execute("UPDATE rules SET sigma=replace(sigma,'Authorized RMM','Web administration') WHERE id=?",(rid,))
  proposal_pass.propose_from_stored('REPORT-FICTION',self.db)
  self.assertIn('Authorized RMM',rules.get_rule(rid,self.db)['sigma'])
  with store.connection(self.db) as db:
   db.execute("UPDATE rule_source_links SET proposed_by='claude_proposal_from_automated_inspection' WHERE rule_id=?",(rid,))
   db.execute("UPDATE rules SET sigma=replace(sigma,'Authorized RMM','Analyst chosen') WHERE id=?",(rid,))
  proposal_pass.propose_from_stored('REPORT-FICTION',self.db)
  self.assertIn('Analyst chosen',rules.get_rule(rid,self.db)['sigma'])
 def test_basename_alias_near_duplicate_is_reported_without_merging(self):
  self.report();old={'event_family':'process_creation','platform':'windows','predicates':[
   {'field':'ParentImage','operator':'endswith','value':'RMM.Agent.exe'},
   {'field':'Image','operator':'endswith','value':'PowerShell'},
   {'field':'CommandLine','operator':'contains','value':'Invoke-WebRequest'}]}
  created=drafting.propose('REPORT-FICTION',URL,1,old,'Fictional older process draft','The fictional source describes this process launch and download.','Authorized administration may match this activity.',self.db)
  self.assertTrue(any(r['relationship']=='possible_near_duplicate' for r in created['inventory_check']['overlapping_local_rules']))
  again=proposal_pass.proposal_gaps('REPORT-FICTION',self.db)
  self.assertTrue(any(p.get('inventory_check',{}).get('overlapping_local_rules') for p in again['proposals']))
 def test_kql_constants_comments_groups_lookback_and_projection(self):
  q='// A fictional hunt\nlet process="conhost.exe";\nDeviceProcessEvents | where Timestamp >= ago(30d) | where (FileName =~ process and (ProcessCommandLine has "curl")) | project FileName;'
  spec=publisher_queries.bounded_spec(q);self.assertIsNotNone(spec)
  self.assertEqual(spec['query_scope'],{'lookback_seconds':2592000})
  queries=custom_rules.generic_queries(spec)
  self.assertIn('ago(2592000s)',queries['kql']);self.assertIn('earliest=-2592000s',queries['spl'])
  sigma=custom_rules._sigma('Fictional scoped hunt',spec,'Authorized diagnostics')
  self.assertIn('apply this search scope separately',sigma)
  extras=custom_rules.sigma_extras(sigma)
  self.assertEqual(sigma,custom_rules._sigma('Fictional scoped hunt',spec,'Authorized diagnostics',**extras))
  event={'event_type':'process_creation','Image':r'C:\Windows\System32\conhost.exe','CommandLine':'curl https://example.test'}
  rule={'behavior':'custom','custom_spec':json.dumps(spec)}
  self.assertTrue(soc_replay._matches(rule,event))
  self.assertFalse(soc_replay._matches(rule,{**event,'Image':r'C:\Windows\evilconhost.exe'}))
 def test_publisher_scope_is_stored_verified_by_translation_and_not_silently_widened(self):
  q='// Hunt\nDeviceProcessEvents | where Timestamp >= ago(7d) | where FileName =~ "conhost.exe" and ProcessCommandLine contains "curl"'
  result=self.report(q,True);self.assertEqual(len(result['proposals']),1)
  rid=result['proposals'][0]['rule_id'];self.assertTrue(drafting.source_link(rid,self.db)['cited_values_still_present'])
  with self.assertRaisesRegex(ValueError,'complete supported selector'):
   changed={**custom_rules.get_spec(rid,self.db),'query_scope':{'lookback_seconds':3600}}
   drafting.propose('REPORT-FICTION',URL,2,changed,'Fictional wrong scope','This example intentionally changes the publisher query scope.','Benign command execution can match.',self.db,publisher_query=True)
 def test_unsupported_kql_is_not_partially_translated(self):
  base='DeviceProcessEvents | where FileName =~ "conhost.exe" and ProcessCommandLine has "curl"'
  for suffix in [' | join DeviceNetworkEvents on DeviceId',' or FileName =~ "other.exe"',' | summarize count()',' | where Timestamp > ago(7d)',' | where Timestamp >= ago(1000d)',' | where (FileName =~ "x.exe"']:
   self.assertIsNone(publisher_queries.bounded_spec(base+suffix),suffix)
 def test_native_schema_examples_are_mapped_but_not_claimed_as_configuration(self):
  result=self.report();rid=result['proposals'][0]['rule_id'];status=drafting.query_status(rid,self.db)
  self.assertEqual(status['status'],'generic_templates');self.assertEqual(status['native_test']['status'],'pending')
  kql=status['mapped_examples']['defender']['query'];spl=status['mapped_examples']['sysmon_splunk_lab']['query']
  self.assertIn('DeviceProcessEvents',kql);self.assertIn('InitiatingProcessFileName',kql)
  self.assertIn('index=sysmon_lab',spl);self.assertIn('EventCode=1',spl);self.assertNotIn('YOUR_',kql+spl)
 def test_hash_constant_hunt_uses_explicit_report_platform_context(self):
  q='let sample="'+'a'*64+'"; DeviceFileEvents | where Timestamp >= ago(30d) | where SHA256 =~ sample'
  self.assertIsNone(publisher_queries.bounded_spec(q))
  result=self.report(q,True);self.assertEqual(len(result['proposals']),1)
  rid=result['proposals'][0]['rule_id'];spec=custom_rules.get_spec(rid,self.db)
  self.assertEqual(spec['platform'],'windows');self.assertEqual(spec['predicates'][0]['value'],'a'*64)
  self.assertTrue(drafting.source_link(rid,self.db)['cited_values_still_present'])
 def test_escaped_literal_command_survives_translation_and_citation_check(self):
  q='DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine == '+json.dumps('"powershell.exe"')
  result=self.report(q,True);self.assertEqual(len(result['proposals']),1)
  rid=result['proposals'][0]['rule_id'];spec=custom_rules.get_spec(rid,self.db)
  self.assertTrue(drafting.source_link(rid,self.db)['cited_values_still_present'])
  rule={'behavior':'custom','custom_spec':json.dumps(spec)}
  event={'event_type':'process_creation','Image':r'C:\Windows\powershell.exe','CommandLine':'"powershell.exe"'}
  self.assertTrue(soc_replay._matches(rule,event));self.assertFalse(soc_replay._matches(rule,{**event,'CommandLine':'powershell.exe'}))
 def test_intel_bootstrap_indexes_data_files_and_checkpoints_only_after_ingest(self):
  for name,repo,path,kind in repo_updates.REPOSITORIES:
   if repo not in repo_updates.INTEL_BOOTSTRAP_REPOS:continue
   with self.subTest(repo=repo):
    def fetch(url,**kwargs):
     if '/commits/' in url:return {'sha':'a'*40}
     if '/git/trees/' in url:return {'truncated':False,'tree':[{'type':'blob','path':(path+'/' if path else '')+n,'sha':'b'*40} for n in ('fictional.csv','fictional.txt','fictional.json','readme.md','script.py')]}
     return {'default_branch':'main'}
    rows=repo_updates.collect_catalog(repo,path,kind,datetime.now(timezone.utc)-timedelta(days=2),database=self.db,fetch=fetch)
    self.assertEqual(len(rows),3)
    with store.connection(self.db) as db:self.assertIsNone(db.execute('SELECT 1 FROM repo_bootstraps WHERE repo=?',(repo,)).fetchone())
    with patch.object(core.sources,'enrich_epss',return_value={}):core.collect_daily(self.db,adapters={'GitHub: '+name:lambda:rows})
    with store.connection(self.db) as db:self.assertIsNotNone(db.execute('SELECT 1 FROM repo_bootstraps WHERE repo=?',(repo,)).fetchone())
    self.assertTrue(all(r['kind']=='research_update' and r['id'].startswith('INTELPTR-') for r in rows))
 def test_malpedia_undated_item_and_description_day_are_kept_without_fake_dates(self):
  xml=b'<rss><channel><item><title>Fictional library entry</title><link>https://malpedia.caad.fkie.fraunhofer.de/library/fictional-one</link><description>2010-01-01 - Fictional old report newly indexed</description></item><item><title>Fictional undated entry</title><link>https://malpedia.caad.fkie.fraunhofer.de/library/fictional-two</link></item></channel></rss>'
  rows=research_feeds.parse_feed(xml,'Malpedia','research',datetime.now(timezone.utc)-timedelta(days=1))
  self.assertEqual(len(rows),2);self.assertEqual(rows[0]['published'],'2010-01-01');self.assertIsNone(rows[1]['published'])
  self.assertEqual(research_feeds.parse_feed(xml,'Other RSS','research',datetime.now(timezone.utc)-timedelta(days=1)),[])
 def test_sysmon_xml_requires_truth_labels_and_never_calls_import_a_siem_test(self):
  xml=self.path/'events.xml'
  xml.write_text('<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><EventRecordID>42</EventRecordID><Computer>LAB</Computer><TimeCreated SystemTime="2099-01-01T00:00:00Z"/></System><EventData><Data Name="Image">msiexec.exe</Data><Data Name="CommandLine">msiexec /i ClientSetup.msi /qn</Data></EventData></Event></Events>')
  result=sysmon_samples.prepare(xml,self.path/'unlabeled');self.assertEqual(result['labeled_events'],0)
  row=json.loads((self.path/'unlabeled'/'events.jsonl').read_text());self.assertIsNone(row['expected_malicious'])
  with self.assertRaises(ValueError):soc_replay.replay([row],[])
  labels=self.path/'truth.csv';labels.write_text('event_id,expected_malicious\nsysmon:LAB:42,false\n')
  result=sysmon_samples.prepare(xml,self.path/'labeled',labels);self.assertEqual(result['labeled_events'],1)
  self.assertIn('no SIEM executed',result['scope'])
  with self.assertRaises(FileExistsError):sysmon_samples.prepare(xml,self.path/'labeled',labels)

if __name__=='__main__':unittest.main()
