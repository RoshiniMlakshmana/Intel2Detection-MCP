import tempfile
import unittest
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from threat_research import core, digest, enterprise, environment, leak_claims, live_validation, poller, report_inspection, repo_updates, research_feeds, rules, sources, store


def record(ident="CVE-2026-12345", source="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"):
    return {"id": ident, "title": "Example web vulnerability", "summary": "Synthetic example",
            "source": source, "claim": "CISA listed this CVE as known exploited in the wild.",
            "published": "2026-09-27", "updated": "2026-09-27", "kev": True,
            "affected": ["ExampleServer"]}


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_repeated_feed_is_idempotent_and_kev_does_not_imply_behavior(self):
        self.assertEqual(core.ingest([record()], self.path), 1)
        self.assertEqual(core.ingest([record()], self.path), 0)
        threat = core.get_threat("CVE-2026-12345", self.path)
        self.assertEqual(len(threat["evidence"]), 1)
        self.assertEqual(core.research_view(threat["id"], self.path)["detection_readiness"], "research_needed_no_behavior_rule")
        with self.assertRaisesRegex(ValueError, "cited analyst observation"):
            rules.propose_rule(threat["id"], threat["evidence"][0]["id"], self.path)

    def test_environment_scores_explain_and_unknown_is_not_low(self):
        core.ingest([record()], self.path)
        with store.connection(self.path) as db:
            db.execute("UPDATE threats SET epss=0.75,cvss=9.8 WHERE id='CVE-2026-12345'")
        unknown = core.assess_risk("CVE-2026-12345", {"affected": "unknown"}, self.path)
        high = core.assess_risk("CVE-2026-12345", {"affected": True, "internet_exposed": True, "criticality": "high"}, self.path)
        absent = core.assess_risk("CVE-2026-12345", {"affected": False}, self.path)
        self.assertEqual(unknown["priority"], "verify_affected_version")
        self.assertGreater(high["score"], unknown["score"])
        self.assertEqual(high["priority"], "critical")
        self.assertEqual(absent["priority"], "not_applicable_to_this_asset")
        scenarios = core.compare_environments("CVE-2026-12345", self.path)
        self.assertGreater(scenarios["affected_internet_facing_critical"]["score"], scenarios["affected_internal_low_criticality"]["score"])

    def test_approval_and_distinct_evidence_only_plus_one(self):
        core.ingest([record()], self.path)
        first = core.add_behavior_evidence("CVE-2026-12345", "https://vendor.example/advisory", "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2026-12345", first, self.path)
        self.assertEqual(draft["status"], "draft")
        rule = rules.get_rule(draft["rule_id"], self.path)
        self.assertIn("ParentImage", rule["sigma"])
        self.assertIn("DeviceProcessEvents", rule["kql"])
        self.assertIn("EventCode=1", rule["spl"])
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            rules.implement_rule(draft["rule_id"], "yes", path=self.path)
        approved = rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        self.assertEqual(approved["pattern_score"], 0)
        second = core.add_behavior_evidence("CVE-2026-12345", "https://research.example/report", "Independent observation of shell spawned by web service", "web_server_shell", self.path)
        self.assertEqual(rules.implement_rule(draft["rule_id"], "implement this rule", second, self.path)["pattern_score"], 1)
        self.assertEqual(rules.implement_rule(draft["rule_id"], "implement this rule", second, self.path)["pattern_score"], 1)
        self.assertEqual(rules.propose_rule("CVE-2026-12345", second, self.path)["status"], "existing_coverage")

    def test_source_failure_is_visible_and_other_source_survives(self):
        def fail():
            raise ValueError("rate limited")
        with patch.object(sources, "enrich_epss", return_value={}):
            result = core.collect_daily(self.path, adapters={"broken": fail, "good": lambda: [record()]})
        self.assertEqual(result["new_records"], 1)
        self.assertIn("broken", result["errors"])
        self.assertIsNotNone(core.get_threat("CVE-2026-12345", self.path))

    def test_ai_audit_rule_requires_contract_and_cited_observation(self):
        core.ingest([record()], self.path)
        evidence_id = core.add_behavior_evidence(
            "CVE-2026-12345", "https://research.example/mcp-report",
            "Audit evidence shows a tool execution after a deny decision for the same request",
            "mcp_unauthorized_execution", self.path)
        draft = rules.propose_rule("CVE-2026-12345", evidence_id, self.path)
        rule = rules.get_rule(draft["rule_id"], self.path)
        self.assertIn("MCPAudit_CL", rule["kql"])
        self.assertIn("authorization_decision", rule["sigma"])
        risk = core.assess_risk("CVE-2026-12345", {"affected": True, "asset_role": "mcp_server"}, self.path)
        self.assertIn("MCP audit", risk["ai_security_focus"])

    def test_imported_inventory_blocks_duplicate_and_scores_new_evidence_once(self):
        core.ingest([record()], self.path)
        rules.import_inventory([{"id": "EXT-1", "title": "Existing web shell hunt", "behavior": "web_server_shell", "source_url": "https://example.org/rule"}], self.path)
        eid = core.add_behavior_evidence("CVE-2026-12345", "https://vendor.example/report", "Observed web service spawning cmd.exe", "web_server_shell", self.path)
        proposal = rules.propose_rule("CVE-2026-12345", eid, self.path)
        self.assertEqual(proposal["status"], "existing_external_coverage")
        with self.assertRaises(ValueError):
            rules.acknowledge_existing("EXT-1", eid, "sure", self.path)
        self.assertEqual(rules.acknowledge_existing("EXT-1", eid, "implement this rule", self.path)["pattern_score"], 1)
        self.assertEqual(rules.acknowledge_existing("EXT-1", eid, "implement this rule", self.path)["pattern_score"], 1)
        self.assertEqual(rules.implement_or_corroborate("EXT-1", "implement this rule", eid, self.path)["pattern_score"], 1)

    def test_daily_digest_saved_once_without_smtp(self):
        core.ingest([record()], self.path)
        with patch.dict("os.environ", {"DIGEST_TZ": "America/Los_Angeles", "DIGEST_TO": "", "SMTP_HOST": ""}):
            first = digest.run_daily(self.path, collect=False)
            again = digest.run_daily(self.path, collect=False)
        self.assertEqual(first["status"], "saved_locally")
        self.assertEqual(again["status"], "already_saved")
        self.assertIn("CVE-2026-12345", Path(first["file"]).read_text())

    def test_adapters_normalize_records_and_paginate(self):
        since = datetime(2026, 9, 27, tzinfo=timezone.utc)
        def nvd_fetch(url, headers=None):
            return {"totalResults": 1, "vulnerabilities": [{"cve": {
                "id": "CVE-2026-12345", "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "test description"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]}
        nvd = list(sources.collect_nvd(since, since, fetch=nvd_fetch))
        self.assertEqual(nvd[0]["cvss"], 9.8)
        ghsa = list(sources.collect_ghsa(since, fetch=lambda url: [{"cve_id": "CVE-2026-12345", "ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": "test", "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "vulnerabilities": []}]))
        self.assertEqual(ghsa[0]["id"], nvd[0]["id"])

    def test_cna_references_are_pointers_not_observed_behavior(self):
        cna = sources.collect_cve_record("CVE-2026-12345", fetch=lambda url: {
            "cveMetadata": {"state": "PUBLISHED"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Synthetic advisory"}],
                                   "affected": [{"vendor": "Example", "product": "Server"}],
                                   "references": [{"url": "https://vendor.example/advisory"}]}}
        })
        core.ingest([cna], self.path)
        view = core.research_view("CVE-2026-12345", self.path)
        self.assertIn("https://vendor.example/advisory", view["research_references"])
        self.assertFalse(view["observed"])
        self.assertIn("Not calibrated", view["probability"])

    def test_emerging_c2_feed_drafts_expiring_detection_not_a_cve_rule(self):
        seen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        payload = {"query_status": "ok", "data": [
            {"id": "123", "ioc": "8.8.4.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "confidence_level": 90, "first_seen": seen, "malware_printable": "Example C2"},
            {"id": "124", "ioc": "192.168.1.1:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "confidence_level": 99, "first_seen": seen},
        ]}
        with patch.dict("os.environ", {"THREATFOX_AUTH_KEY": "test"}):
            records = list(sources.collect_threatfox(
                datetime.now(timezone.utc).replace(microsecond=0),
                post=lambda url, body, headers: payload))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["indicator"], "8.8.4.4:443")
        core.ingest(records, self.path)
        ident = records[0]["id"]
        view = core.research_view(ident, self.path)
        self.assertIn("C2 infrastructure", view["possible_next_steps"][0])
        risk = core.assess_risk(ident, {"seen_in_logs": "unknown", "criticality": "high"}, self.path)
        self.assertEqual(risk["priority"], "verify_network_telemetry")
        proposed = rules.propose_ioc_detection(ident, self.path)
        rule = rules.get_rule(proposed["rule_id"], self.path)
        self.assertIn("RemotePort == 443", rule["kql"])
        self.assertIn("DestinationIp", rule["sigma"])
        self.assertIn("DestinationPort=443", rule["spl"])
        self.assertEqual(rules.propose_ioc_detection(ident, self.path)["status"], "existing_coverage")
        with store.connection(self.path) as db:
            db.execute("UPDATE rules SET expires_at='2020-01-01T00:00:00Z' WHERE id=?", (proposed["rule_id"],))
        with self.assertRaisesRegex(ValueError, "expired"):
            rules.implement_rule(proposed["rule_id"], "implement this rule", path=self.path)

    def test_campaign_report_without_cve_can_be_behavior_detection(self):
        campaign = core.record_campaign_report(
            "Emerging agent abuse campaign", "A research report describes an MCP tool executing after a denied authorization decision.",
            "https://research.example/agent-campaign", self.path)
        self.assertTrue(campaign["id"].startswith("REPORT-"))
        self.assertEqual(core.list_emerging(self.path)[0]["id"], campaign["id"])
        assessment = core.assess_risk(campaign["id"], {"seen_in_logs": "unknown"}, self.path)
        self.assertEqual(assessment["priority"], "verify_environment_relevance")
        eid = core.add_behavior_evidence(
            campaign["id"], "https://research.example/agent-campaign",
            "Report documents an unauthorized tool execution with audit identifiers",
            "mcp_unauthorized_execution", self.path)
        self.assertEqual(rules.propose_rule(campaign["id"], eid, self.path)["status"], "draft")

    def test_external_ioc_inventory_prevents_duplicate_and_corrobates_once(self):
        expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
        core.ingest([{"id": "IOC-IP-EXAMPLE", "title": "Sourced C2", "summary": "Example C2 endpoint",
                      "kind": "ioc", "indicator": "8.8.4.4:443", "indicator_type": "ip:port",
                      "confidence": 90, "expires_at": expiry, "source": "https://threatfox.abuse.ch/ioc/123/",
                      "claim": "ThreatFox lists this endpoint as recent C2."}], self.path)
        rules.import_inventory([{"id": "EXT-C2", "title": "Existing C2 hunt", "behavior": "ioc_network",
                                "indicator": "8.8.4.4:443", "source_url": "https://example.org/rules/c2"}], self.path)
        self.assertEqual(rules.propose_ioc_detection("IOC-IP-EXAMPLE", self.path)["status"], "existing_external_coverage")
        eid = core.get_threat("IOC-IP-EXAMPLE", self.path)["evidence"][0]["id"]
        self.assertEqual(rules.acknowledge_existing("EXT-C2", eid, "implement this rule", self.path)["pattern_score"], 1)
        self.assertEqual(rules.acknowledge_existing("EXT-C2", eid, "implement this rule", self.path)["pattern_score"], 1)

    def test_rss_and_atom_intake_link_cve_without_inventing_observed_behavior(self):
        since = datetime(2026, 9, 27, tzinfo=timezone.utc)
        until = datetime(2026, 9, 29, tzinfo=timezone.utc)
        rss = b'''<rss><channel><item><title>CVE-2026-12345 campaign investigated</title>
          <link>https://research.example/report/?utm_source=rss</link>
          <pubDate>Sun, 27 Sep 2026 10:00:00 GMT</pubDate>
          <description>Researchers published an initial analysis of the campaign.</description>
        </item></channel></rss>'''
        atom = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry>
          <title>New agent tool abuse research</title><updated>2026-09-28T10:00:00Z</updated>
          <link rel="alternate" href="https://research.example/agent"/>
          <summary>Public research describing a potential emerging threat.</summary>
        </entry></feed>'''
        first = research_feeds.parse_feed(rss, "Research A", "research", since, until)
        second = research_feeds.parse_feed(atom, "Research B", "research", since, until)
        self.assertEqual(first[0]["mentioned_cves"], ["CVE-2026-12345"])
        self.assertEqual(second[0]["kind"], "campaign")
        core.ingest([record()], self.path)
        self.assertEqual(core.ingest(first + second, self.path), 2)
        self.assertEqual(core.ingest(first, self.path), 0)
        cve = core.get_threat("CVE-2026-12345", self.path)
        self.assertEqual(cve["related_reports"][0]["id"], first[0]["id"])
        report = core.get_threat(first[0]["id"], self.path)
        self.assertEqual(report["mentioned_cves"], ["CVE-2026-12345"])
        self.assertEqual(core.research_view(report["id"], self.path)["detection_readiness"], "research_needed_no_behavior_rule")
        with self.assertRaisesRegex(ValueError, "cited analyst observation"):
            rules.propose_rule(report["id"], report["evidence"][0]["id"], self.path)

    def test_feed_failures_and_stale_or_unsafe_entries_are_visible(self):
        since = datetime(2026, 9, 27, tzinfo=timezone.utc)
        until = datetime(2026, 9, 29, tzinfo=timezone.utc)
        data = b'''<rss><channel><item><title>Old malware analysis</title>
            <link>https://example.org/old</link><pubDate>Mon, 21 Sep 2026 10:00:00 GMT</pubDate></item>
            <item><title>Fresh malware analysis</title><link>https://example.org/fresh</link>
            <pubDate>Mon, 28 Sep 2026 10:00:00 GMT</pubDate></item></channel></rss>'''
        def fetch(url):
            if url.endswith("bad"):
                raise OSError("unavailable")
            return data
        rows, counts, errors = research_feeds.collect_research(since, until, feeds=(
            ("Good", "https://example.org/good", "research"),
            ("Bad", "https://example.org/bad", "research")), fetch=fetch)
        self.assertEqual(counts, {"Good": 1})
        self.assertIn("Bad", errors)
        self.assertEqual(len(rows), 1)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            research_feeds.parse_feed(b'<!DOCTYPE foo [<!ENTITY x "bad">]><rss/>', "Unsafe", "research", since, until)

    def test_collect_daily_combines_research_health_without_hiding_cve_failures(self):
        report = {"id": "REPORT-ABC", "title": "Sourced emerging threat report", "summary": "Metadata only",
                  "source": "https://example.org/report", "claim": "Feed title only", "kind": "campaign"}
        with (patch.object(sources, "collect_kev", side_effect=OSError("KEV down")),
              patch.object(sources, "collect_nvd", return_value=iter([record()])),
              patch.object(sources, "collect_ghsa", return_value=iter([])),
              patch.object(sources, "enrich_epss", return_value={}),
              patch.object(leak_claims, "collect_ransomlook", return_value=[]),
              patch.object(repo_updates, "collect_repo", return_value=[]),
              patch.object(research_feeds, "collect_research", return_value=([report], {"Research A": 1}, {"Research B": "unavailable"})),
              patch.dict("os.environ", {"THREATFOX_AUTH_KEY": ""})):
            result = core.collect_daily(self.path)
        self.assertEqual(result["new_records"], 2)
        self.assertEqual(result["sources"]["RSS: Research A"], 1)
        self.assertIn("RSS: Research B", result["errors"])
        self.assertIn("CISA KEV", result["errors"])

    def test_onboarding_fleet_risk_requires_explicit_confirmed_cve(self):
        profile = {"name": "Test SOC", "siem": "splunk", "telemetry": {
            "process_creation": {"index": "my_edr", "sourcetype": "sysmon:process", "fields": [
                "EventCode", "ParentImage", "Image", "CommandLine", "User"]}}}
        csv_data = ("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                    "a-1,web-1,ExampleServer,1.0,CVE-2026-12345,true,high,general\n"
                    "a-2,ai-1,AgentServer,2.0,,false,low,agent_runtime\n")
        assets = environment.parse_assets(csv_data)
        self.assertEqual(environment.onboard(profile, assets, self.path)["assets"], 2)
        core.ingest([record()], self.path)
        result = environment.risk_from_assets("CVE-2026-12345", self.path)
        self.assertEqual(result["confirmed_affected_count"], 1)
        self.assertEqual(result["confirmed_affected"][0]["asset_id"], "a-1")
        self.assertEqual(result["unmatched_asset_priority"], "verify_affected_version")
        self.assertIn("unknown", result["other_assets"])
        with self.assertRaisesRegex(ValueError, "invalid or duplicate"):
            environment.onboard(profile, environment.parse_assets(csv_data) + [assets[0]], self.path)
        self.assertEqual(environment.status(self.path)["assets"], 2)

    def test_mapping_rebind_and_missing_fields_before_rule_approval(self):
        profile = {"name": "Test SOC", "siem": "splunk", "telemetry": {
            "process_creation": {"index": "custom_edr", "sourcetype": "my:sysmon", "fields": [
                "EventCode", "Image", "CommandLine"]}}}
        assets = environment.parse_assets("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                                          "a-1,web-1,ExampleServer,1.0,,true,high,general\n")
        environment.onboard(profile, assets, self.path)
        core.ingest([record()], self.path)
        evidence_id = core.add_behavior_evidence("CVE-2026-12345", "https://research.example/report",
                                                  "Observed web service spawning shell from audit records", "web_server_shell", self.path)
        draft = rules.propose_rule("CVE-2026-12345", evidence_id, self.path)
        result = environment.check_rule_fit(draft["rule_id"], self.path)
        self.assertFalse(result["ready"])
        self.assertEqual(result["missing_declared_fields"], ["ParentImage"])
        self.assertIsNone(result["mapped_query"])
        profile["telemetry"]["process_creation"]["fields"].append("ParentImage")
        environment.onboard(profile, assets, self.path)
        result = environment.check_rule_fit(draft["rule_id"], self.path)
        self.assertTrue(result["ready"])
        self.assertIn("index=custom_edr sourcetype=my:sysmon", result["mapped_query"])
        self.assertIn("need SIEM testing", result["validation"])

    def test_optional_splunk_probe_is_bounded_and_read_only(self):
        profile = {"name": "Test SOC", "siem": "splunk", "splunk_url": "https://splunk.example.org:8089",
                   "telemetry": {"process_creation": {"index": "endpoint", "sourcetype": "sysmon:process",
                     "fields": ["EventCode", "Image", "ParentImage"]}}}
        assets = environment.parse_assets("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                                          "a-1,web-1,ExampleServer,1.0,,true,high,general\n")
        environment.onboard(profile, assets, self.path)
        called = []
        def fake_fetch(url, body):
            called.append((url, body.decode()))
            return (json.dumps({"result": {"EventCode": "1", "Image": "cmd.exe"}}) + "\n").encode()
        result = environment.probe_splunk("process_creation", self.path, fetch=fake_fetch)
        self.assertEqual(result["missing_configured_fields"], ["ParentImage"])
        self.assertEqual(result["status"], "sample_checked")
        self.assertIn("/services/search/v2/jobs/export", called[0][0])
        self.assertIn("earliest_time=-24h", called[0][1])
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            environment.validate_profile({**profile, "splunk_url": "http://splunk.example.org:8089"})

    def test_digest_prioritizes_confirmed_asset_exposure(self):
        profile = {"name": "Test SOC", "siem": "defender", "telemetry": {
            "process_creation": {"table": "DeviceProcessEvents", "fields": ["Timestamp", "FileName"]}}}
        assets = environment.parse_assets("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                                          "a-1,web-1,ExampleServer,1.0,CVE-2026-12345,true,high,general\n")
        environment.onboard(profile, assets, self.path)
        core.ingest([record(), {**record("CVE-2026-99999"), "kev": False}], self.path)
        with patch.dict("os.environ", {"DIGEST_TO": "", "SMTP_HOST": ""}):
            result = digest.run_daily(self.path, collect=False)
        content = Path(result["file"]).read_text()
        self.assertIn("1 confirmed affected asset(s)", content)
        self.assertLess(content.index("CVE-2026-12345"), content.index("CVE-2026-99999"))

    def test_darkweb_claim_metadata_stays_unverified_and_cannot_become_a_rule(self):
        current = datetime.now(timezone.utc)
        data = [{"post_title": "Example organization", "group_name": "Example actor",
                 "discovered": current.isoformat()}]
        records = leak_claims.collect_ransomlook(current - timedelta(days=1),
                                                  fetch=lambda url: data)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "leak_claim")
        core.ingest(records, self.path)
        ident = records[0]["id"]
        self.assertIn(ident, [x["id"] for x in core.list_emerging(self.path)])
        assessment = core.assess_risk(ident, {"affected": True, "seen_in_logs": True}, self.path)
        self.assertIsNone(assessment["score"])
        self.assertEqual(assessment["priority"], "verify_claim_and_entity")
        self.assertEqual(core.research_view(ident, self.path)["detection_readiness"], "claim_only_no_behavior_rule")
        self.assertEqual(core.ingest(records, self.path), 0)
        with self.assertRaisesRegex(ValueError, "does not document observed behavior"):
            core.add_behavior_evidence(ident, "https://www.ransomlook.io/recent",
                                       "Claim proves shell spawned by web worker", "web_server_shell", self.path)
        source_evidence = core.get_threat(ident, self.path)["evidence"][0]["id"]
        with self.assertRaisesRegex(ValueError, "cited analyst observation"):
            rules.propose_rule(ident, source_evidence, self.path)

        profile = {"name": "Test SOC", "siem": "defender",
                   "organization_aliases": ["Example organization"], "supplier_aliases": ["Vendor Partner"],
                   "telemetry": {"process_creation": {"table": "DeviceProcessEvents", "fields": []}}}
        assets = environment.parse_assets("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                                          "a-1,web-1,ExampleServer,1.0,,true,high,general\n")
        environment.onboard(profile, assets, self.path)
        relevance = environment.leak_claim_relevance(ident, self.path)
        self.assertEqual(relevance["priority"], "verify_organization_identity")
        self.assertIsNone(relevance["score"])
        with patch.dict("os.environ", {"DIGEST_TO": "", "SMTP_HOST": ""}):
            digest_result = digest.run_daily(self.path, collect=False)
        self.assertIn("Possible name match", Path(digest_result["file"]).read_text())

    def test_stale_or_malformed_claims_are_not_collected(self):
        current = datetime.now(timezone.utc)
        data = [{"post_title": "Old victim", "group_name": "Example actor",
                 "discovered": (current - timedelta(days=90)).isoformat()},
                {"post_title": "No date", "group_name": "Example actor"}]
        self.assertEqual(leak_claims.collect_ransomlook(current - timedelta(days=2), fetch=lambda url: data), [])
        with self.assertRaisesRegex(ValueError, "unexpected"):
            leak_claims.collect_ransomlook(current - timedelta(days=2), fetch=lambda url: {"error": "unavailable"})

    def test_community_repo_update_is_cited_pointer_and_cve_link(self):
        now_utc = datetime.now(timezone.utc)
        stamp = (now_utc - timedelta(hours=1)).isoformat()
        repo = "SigmaHQ/sigma"
        received = []
        def fake_fetch(url, headers):
            received.append(url)
            return [{"sha": "a" * 40, "commit": {"message": "Add detection for CVE-2026-12345\nFull commit details",
                       "committer": {"date": stamp}}}]
        rows = repo_updates.collect_repo(repo, "rules", "community_rule", now_utc - timedelta(days=2), now_utc,
                                         fetch=fake_fetch)
        self.assertEqual(len(rows), 1)
        self.assertIn("path=rules", received[0])
        self.assertEqual(rows[0]["mentioned_cves"], ["CVE-2026-12345"])
        core.ingest([record()], self.path)
        self.assertEqual(core.ingest(rows, self.path), 1)
        self.assertEqual(core.ingest(rows, self.path), 0)
        self.assertEqual(core.get_threat("CVE-2026-12345", self.path)["related_reports"][0]["id"], rows[0]["id"])
        self.assertEqual(core.list_community_updates(self.path)[0]["id"], rows[0]["id"])
        self.assertEqual(core.research_view(rows[0]["id"], self.path)["detection_readiness"], "external_update_needs_review")
        self.assertIsNone(core.assess_risk(rows[0]["id"], {}, self.path)["score"])
        evidence_id = core.get_threat(rows[0]["id"], self.path)["evidence"][0]["id"]
        with self.assertRaisesRegex(ValueError, "cited analyst observation"):
            rules.propose_rule(rows[0]["id"], evidence_id, self.path)

    def test_github_repo_error_is_isolated_in_daily_collection(self):
        def failing_repo(*args):
            raise ValueError("GitHub rate limited")
        with (patch.object(sources, "collect_kev", return_value=iter([record()])),
              patch.object(sources, "collect_nvd", return_value=iter([])),
              patch.object(sources, "collect_ghsa", return_value=iter([])),
              patch.object(sources, "enrich_epss", return_value={}),
              patch.object(leak_claims, "collect_ransomlook", return_value=[]),
              patch.object(repo_updates, "collect_repo", side_effect=failing_repo),
              patch.object(research_feeds, "collect_research", return_value=([], {}, {})),
              patch.dict("os.environ", {"THREATFOX_AUTH_KEY": ""})):
            result = core.collect_daily(self.path)
        self.assertEqual(result["new_records"], 1)
        self.assertIn("GitHub: SigmaHQ community rules", result["errors"])

    def _rule_with_profile(self, siem):
        fields = ["EventCode", "ParentImage", "Image", "CommandLine"] if siem == "splunk" else [
            "Timestamp", "InitiatingProcessFileName", "FileName", "ProcessCommandLine"]
        cfg = {"index": "endpoint", "sourcetype": "sysmon:process", "fields": fields} if siem == "splunk" else {
            "table": "DeviceProcessEvents", "fields": fields}
        profile = {"name": "Example SOC", "siem": siem, "telemetry": {"process_creation": cfg}}
        if siem == "splunk":
            profile["splunk_url"] = "https://splunk.example.org:8089"
        assets = environment.parse_assets("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                                          "a-1,host-1,Example,1.0,,false,medium,general\n")
        environment.onboard(profile, assets, self.path)
        core.ingest([record()], self.path)
        eid = core.add_behavior_evidence("CVE-2026-12345", "https://thedfirreport.com/example",
                                         "Observed web service creating a command shell in a report", "web_server_shell", self.path)
        return rules.propose_rule("CVE-2026-12345", eid, self.path)["rule_id"]

    def test_cited_article_inspection_is_bounded_and_never_evidence(self):
        url = "https://thedfirreport.com/sample"
        core.ingest([record(source=url)], self.path)
        article = (b"<html><nav>Ignore navigation</nav><script>powershell malicious injection</script>"
                   b"<p>Investigators saw the web server process launch cmd.exe after exploitation,"
                   b" and collected process creation events from the host.</p></html>")
        result = report_inspection.inspect_report("CVE-2026-12345", url, self.path, fetch=lambda _: article)
        self.assertEqual(result["status"], "research_leads_only")
        self.assertEqual(result["paragraphs_scanned"], 1)
        self.assertIn("cmd.exe", result["excerpts"][0]["excerpt"])
        self.assertNotIn("injection", result["excerpts"][0]["excerpt"])
        self.assertEqual(core.research_view("CVE-2026-12345", self.path)["detection_readiness"], "research_needed_no_behavior_rule")
        with self.assertRaisesRegex(ValueError, "not cited"):
            report_inspection.inspect_report("CVE-2026-12345", "https://thedfirreport.com/other", self.path,
                                             fetch=lambda _: article)
        with self.assertRaisesRegex(ValueError, "publisher"):
            report_inspection.inspect_report("CVE-2026-12345", "https://127.0.0.1/internal", self.path,
                                             fetch=lambda _: article)
        with self.assertRaisesRegex(ValueError, "limit"):
            report_inspection.inspect_report("CVE-2026-12345", url, self.path,
                                             fetch=lambda _: b"<html><p>" + b"a" * 600_001)

    def test_native_splunk_check_counts_only_and_surfaces_errors(self):
        rule_id = self._rule_with_profile("splunk")
        called = []
        def fake(endpoint, data):
            called.append((endpoint, data.decode()))
            return (json.dumps({"result": {"host": "private-device", "Image": "cmd.exe"}}) + "\n").encode()
        result = live_validation.check_live_query(rule_id, self.path, splunk_fetch=fake)
        self.assertEqual(result["sample_matches"], 1)
        self.assertNotIn("private-device", json.dumps(result))
        self.assertIn("earliest_time=-24h", called[0][1])
        self.assertIn("%7C+head+5", called[0][1])
        with self.assertRaisesRegex(ValueError, "rejected search"):
            live_validation.check_live_query(rule_id, self.path, splunk_fetch=lambda u, d: (
                json.dumps({"messages": [{"type": "ERROR", "text": "bad field"}]}).encode()))
        with store.connection(self.path) as db:
            db.execute("UPDATE rules SET spl=spl||' | outputlookup dangerous.csv' WHERE id=?", (rule_id,))
        with self.assertRaisesRegex(ValueError, "differs from the generated"):
            live_validation.check_live_query(rule_id, self.path, splunk_fetch=fake)
        self.assertEqual(len(called), 1)

    def test_native_defender_graph_check_uses_one_day_and_no_raw_events(self):
        rule_id = self._rule_with_profile("defender")
        called = []
        def fake(endpoint, data):
            called.append((endpoint, json.loads(data)))
            return json.dumps({"schema": [], "results": [{"DeviceName": "sensitive-host"}]}).encode()
        result = live_validation.check_live_query(rule_id, self.path, graph_fetch=fake)
        self.assertEqual(result["siem"], "defender_graph")
        self.assertNotIn("sensitive-host", json.dumps(result))
        self.assertEqual(called[0][1]["Timespan"], "P1D")
        self.assertIn("| take 5", called[0][1]["Query"])
        with self.assertRaisesRegex(ValueError, "unexpected Graph hunting response"):
            live_validation.check_live_query(rule_id, self.path, graph_fetch=lambda u, d: b'{"error":"access denied"}')

    def test_live_splunk_inventory_is_possible_match_not_automatic_coverage(self):
        rule_id = self._rule_with_profile("splunk")
        def fake(endpoint):
            self.assertIn("/servicesNS/-/-/saved/searches?", endpoint)
            return json.dumps({"entry": [
                {"name": "Web shell candidate", "id": "https://splunk.example.org:8089/servicesNS/admin/search/saved/searches/Web",
                 "content": {"search": "index=edr ParentImage=w3wp.exe Image=cmd.exe", "disabled": "0"}},
                {"name": "Other dashboard", "content": {"search": "index=other status=200"}}
            ]}).encode()
        result = live_validation.compare_splunk_inventory(rule_id, self.path, fetch=fake)
        self.assertEqual(result["saved_searches_checked"], 2)
        self.assertEqual(len(result["possible_matches"]), 1)
        self.assertIn("unverified", result["coverage"])
        self.assertEqual(rules.get_rule(rule_id, self.path)["status"], "draft")

    def test_live_poll_sends_fresh_kev_once_and_records_health(self):
        sent = []
        def fake_send(body, subject, recipient):
            sent.append((body, subject, recipient))
        with (patch.dict("os.environ", {"DIGEST_TO": "soc@example.org", "SMTP_HOST": "smtp.example.org"}),
              patch.object(sources, "enrich_epss", return_value={})):
            first = poller.run_poll(self.path, adapters={"KEV": lambda: [record()]}, send=fake_send)
            second = poller.run_poll(self.path, adapters={"KEV": lambda: [record()]}, send=fake_send)
        self.assertEqual(first["new_records"], 1)
        self.assertEqual(first["notification"]["sent"], 1)
        self.assertEqual(second["new_records"], 0)
        self.assertEqual(len(sent), 1)
        self.assertIn("CVE-2026-12345", sent[0][0])
        self.assertEqual(poller.poll_status(self.path)["pending_alerts"], 0)

    def test_existing_cve_newly_added_to_kev_triggers_alert(self):
        core.ingest([{**record(), "kev": False}], self.path)
        sent = []
        with (patch.dict("os.environ", {"DIGEST_TO": "soc@example.org", "SMTP_HOST": "smtp.example.org"}),
              patch.object(sources, "enrich_epss", return_value={})):
            result = poller.run_poll(self.path, adapters={"KEV": lambda: [record()]},
                                     send=lambda body, subject, address: sent.append(body))
        self.assertEqual(result["new_records"], 0)
        self.assertEqual(result["alert_leads_queued"], 1)
        self.assertEqual(len(sent), 1)

    def test_failed_live_alert_remains_queued_and_retries(self):
        def broken(*args):
            raise OSError("smtp unavailable")
        with (patch.dict("os.environ", {"DIGEST_TO": "soc@example.org", "SMTP_HOST": "smtp.example.org"}),
              patch.object(sources, "enrich_epss", return_value={})):
            with self.assertRaisesRegex(OSError, "smtp unavailable"):
                poller.run_poll(self.path, adapters={"KEV": lambda: [record()]}, send=broken)
            self.assertEqual(poller.poll_status(self.path)["pending_alerts"], 1)
            result = poller.run_poll(self.path, adapters={"KEV": lambda: [record()]}, send=lambda *args: None)
        self.assertEqual(result["notification"]["sent"], 1)
        self.assertEqual(poller.poll_status(self.path)["pending_alerts"], 0)

    def test_poll_tracks_partial_failure_and_blocks_overlap(self):
        with store.connection(self.path) as db:
            db.execute("INSERT INTO poll_state(id,lease_until) VALUES (1,'2099-01-01T00:00:00Z')")
        self.assertEqual(poller.run_poll(self.path, adapters={})["status"], "already_running")
        with store.connection(self.path) as db:
            db.execute("UPDATE poll_state SET lease_until=NULL WHERE id=1")
        result = poller.run_poll(self.path, adapters={"broken": lambda: (_ for _ in ()).throw(ValueError("offline"))})
        self.assertEqual(result["status"], "degraded")
        self.assertIn("broken", poller.poll_status(self.path)["last_result"]["source_errors"])
        self.assertEqual(poller.poll_status(self.path)["sources_with_successful_checkpoint"], 0)

    def test_successful_source_checkpoint_is_durable_and_overlapping(self):
        poller.run_poll(self.path, adapters={"healthy": lambda: []})
        self.assertEqual(poller.poll_status(self.path)["sources_with_successful_checkpoint"], 1)
        windows = poller._source_windows(self.path, datetime.now(timezone.utc))
        self.assertIn("healthy", windows)
        self.assertLess(windows["healthy"], datetime.now(timezone.utc))

    def test_failed_ingest_does_not_advance_source_checkpoint(self):
        with patch.object(core, "ingest", side_effect=ValueError("store failure")):
            result = poller.run_poll(self.path, adapters={"broken_ingest": lambda: [record()]})
        self.assertEqual(result["status"], "degraded")
        self.assertIn("broken_ingest", result["source_errors"])
        self.assertNotIn("broken_ingest", result["source_counts"])
        self.assertEqual(poller.poll_status(self.path)["sources_with_successful_checkpoint"], 0)

    def test_enterprise_packs_isolate_state_and_keep_secrets_out_of_claude_config(self):
        root = Path(self.tmp.name)
        a = enterprise.create_pack(root / "org-a", "Org A", "generic")
        b = enterprise.create_pack(root / "org-b", "Org B", "splunk")
        self.assertNotEqual(a["database"], b["database"])
        self.assertFalse(enterprise.inspect_pack(root / "org-a")["ready_to_onboard"])
        config = json.loads((root / "org-a" / "claude-mcp.json").read_text())
        self.assertEqual(config["mcpServers"]["threat-research"]["env"],
                         {"THREAT_RESEARCH_DB": a["database"]})
        self.assertNotIn("TOKEN", json.dumps(config))
        core.ingest([record()], Path(a["database"]))
        self.assertIsNone(core.get_threat("CVE-2026-12345", Path(b["database"])))
        with self.assertRaisesRegex(ValueError, "new or empty"):
            enterprise.create_pack(root / "org-a", "Org A", "generic")

    def test_generic_mapping_supports_review_without_claiming_native_query(self):
        profile = {"name": "Non-Splunk SOC", "siem": "generic", "telemetry": {
            "process_creation": {"source": "custom-edr", "field_map": {
                "ParentImage": "parent.path", "Image": "process.path", "CommandLine": "process.command_line"}}}}
        assets = environment.parse_assets("asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
                                          "a-1,host-1,Example,1.0,CVE-2026-12345,true,high,general\n")
        environment.onboard(profile, assets, self.path)
        core.ingest([record()], self.path)
        eid = core.add_behavior_evidence("CVE-2026-12345", "https://thedfirreport.com/example",
                                         "Observed web worker launching cmd.exe in process logs", "web_server_shell", self.path)
        rule_id = rules.propose_rule("CVE-2026-12345", eid, self.path)["rule_id"]
        fit = environment.check_rule_fit(rule_id, self.path)
        self.assertTrue(fit["ready"])
        self.assertIsNone(fit["mapped_query"])
        self.assertIn("ParentImage", fit["sigma"])
        self.assertEqual(live_validation.check_live_query(rule_id, self.path)["status"], "target_backend_required")
        self.assertEqual(environment.risk_from_assets("CVE-2026-12345", self.path)["confirmed_affected_count"], 1)
        with self.assertRaisesRegex(ValueError, "field_map"):
            environment.validate_profile({**profile, "telemetry": {"process_creation": {
                "source": "custom-edr", "field_map": {"Image": "path | delete"}}}})

    def test_onboard_pack_checks_assets_and_inventory_before_changing_state(self):
        target = Path(self.tmp.name) / "customer"
        created = enterprise.create_pack(target, "Customer SOC", "generic")
        profile = json.loads((target / "profile.json").read_text())
        profile["telemetry"] = {"process_creation": {"source": "custom-edr", "field_map": {
            "ParentImage": "parent.path", "Image": "process.path", "CommandLine": "command.line"}}}
        (target / "profile.json").write_text(json.dumps(profile))
        (target / "assets.csv").write_text(enterprise.ASSET_HEADER +
                                           "a-1,host-1,Example,1.0,CVE-2026-12345,true,high,general\n")
        (target / "inventory.json").write_text('[{"id":"bad"}]')
        with self.assertRaisesRegex(ValueError, "mapped behavior"):
            enterprise.onboard_pack(target)
        self.assertFalse(environment.status(Path(created["database"]))["configured"])
        (target / "inventory.json").write_text("[]")
        self.assertTrue(enterprise.inspect_pack(target)["ready_to_onboard"])
        result = enterprise.onboard_pack(target)
        self.assertEqual(result["status"], "onboarded")
        self.assertEqual(environment.status(Path(created["database"]))["assets"], 1)
        core.ingest([record()], Path(created["database"]))
        eid = core.add_behavior_evidence("CVE-2026-12345", "https://thedfirreport.com/example",
                                         "Observed web worker launching cmd.exe in process logs", "web_server_shell",
                                         Path(created["database"]))
        rule_id = rules.propose_rule("CVE-2026-12345", eid, Path(created["database"]))["rule_id"]
        bundle = enterprise.export_sigma_bundle(target, rule_id)
        self.assertIn('"ParentImage": "parent.path"', Path(bundle["field_pipeline"]).read_text())
        self.assertIn("type: logsource", Path(bundle["field_pipeline"]).read_text())
        self.assertIn("detection:", Path(bundle["rule"]).read_text())


if __name__ == "__main__":
    unittest.main()
