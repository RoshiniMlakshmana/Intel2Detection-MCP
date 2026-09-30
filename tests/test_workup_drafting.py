"""Raw triage, pattern analysis, Claude-assisted unverified drafts, separated
risk, custom corroboration and the lead_workup tool.

Fixtures are fictional (FictLoader, example hosts, CVE-2099-*); report pages
use allowlisted hosts with fictional paths and every fetch is injected, so
nothing contacts a network. Approvals here act only on fictional rules.
"""

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from threat_research import (browser_research, core, corroboration, custom_rules, dashboard_data, drafting, environment, live_validation,
                             research_pass, rules, server, soc_replay, store, workflow, workup)

HASH = "e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e"
OTHER = "9cb68f986043a576e19d32184c583b7d8f571c7219d8dc0065dced1c13f077ef"
REPORT_URL = "https://www.microsoft.com/en-us/security/blog/2099/01/01/fictloader-analysis"
FRESH_URL = "https://unit42.paloaltonetworks.com/fictional-fictloader-followup"
PARA = (f"In the analyzed sample, the loader DLL was named FictLoader.dll (SHA-256: {HASH}) and its file "
        f"archive was named FictArchive (SHA-256: {OTHER}).")
REPORT_HTML = ("<html><body><article><h1>FictMantis: a fictional post-compromise malware family</h1>"
               "<p>Fictional Threat Intelligence identified FictMantis, a modular post-compromise malware family.</p>"
               f"<p>{PARA}</p>"
               "<p>dnsapi.dll is not a dnsapi.dll, but contains the malware's configuration.</p>"
               "</article></body></html>").encode()
FRESH_HTML = ("<html><body><article><p>Our fictional incident response team recovered the malicious loader "
              f"FictLoader.dll with SHA-256 {HASH} from a compromised host.</p></article></body></html>").encode()
SPEC = {"event_family": "file_event", "platform": "windows",
        "predicates": [{"field": "SHA256", "operator": "equals", "value": HASH},
                       {"field": "TargetFilename", "operator": "endswith", "value": "FictLoader.dll"}]}
TEXT = {"title": "FictLoader loader DLL by SHA-256 (fictional report)",
        "rationale": "The cited paragraph names the loader DLL FictLoader.dll with its SHA-256 in the analyzed sample.",
        "false_positives": "A legitimate file with the same name differs by hash; exact hash match only."}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, ident="REPORT-FICTLOADER0001", url=REPORT_URL, html=REPORT_HTML):
        core.ingest([{"id": ident, "title": "FictMantis: a fictional post-compromise malware family",
                      "summary": "fixture", "kind": "campaign", "source": url, "claim": "Feed listed this report.",
                      "published": "2099-01-01T00:00:00Z"}], self.path)
        research_pass.research_lead(ident, self.path, fetch=lambda u: html, refresh=True)
        return ident

    def propose(self, ident="REPORT-FICTLOADER0001", spec=SPEC, paragraph=3):
        return drafting.propose(ident, REPORT_URL, paragraph, spec, TEXT["title"], TEXT["rationale"],
                                TEXT["false_positives"], self.path)


class BrowserHandoffTest(Base):
    def test_cited_browser_text_stays_unverified_and_can_support_an_unverified_draft(self):
        ident = "REPORT-FICTBROWSER001"
        core.ingest([{"id": ident, "title": "Fictional browser-only report", "summary": "fixture",
                      "kind": "campaign", "source": REPORT_URL, "claim": "Feed listed this report."}], self.path)
        research_pass.triage_raw(self.path, max_leads=1, fetch=lambda url: (_ for _ in ()).throw(
            ValueError("HTTP 403: publisher blocked the automated article fetch")))
        queue = browser_research.review_queue(self.path)
        self.assertIn(ident, [item["threat_id"] for item in queue["items"]])
        with self.assertRaisesRegex(ValueError, "cited"):
            browser_research.capture(ident, "https://other.example/hidden", PARA, self.path)
        body = ("Fictional incident response report on compromised devices.\n\n" + PARA +
                " The attacker replaced the updater component with this loader DLL in the analyzed sample."
                "\n\nDeviceFileEvents\n| where FileName == 'FictLoader.dll'\n| project Timestamp, FileName")
        capture = browser_research.capture(ident, REPORT_URL, body, self.path)
        self.assertEqual(capture["status"], "assistant_browser_capture_unverified")
        self.assertEqual(capture["publisher_hunting_queries"][0]["status"], "publisher_query_unverified")
        self.assertEqual(browser_research.capture(ident, REPORT_URL, body, self.path)["browser_capture_id"],
                         capture["browser_capture_id"])
        view = workup.lead_workup(ident, self.path)
        self.assertEqual(view["browser_captures"][0]["analyst_verified"], False)
        self.assertEqual(view["browser_captures"][0]["publisher_hunting_queries"][0]["language"], "kql")
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'").fetchone()[0], 0)
        draft = drafting.propose(ident, REPORT_URL, 2, SPEC, TEXT["title"], TEXT["rationale"],
                                 TEXT["false_positives"], self.path,
                                 browser_capture_id=capture["browser_capture_id"])
        self.assertEqual(draft["status"], "draft_unverified")
        self.assertEqual(draft["source"]["provenance"], "assistant_browser_capture_unverified")
        with self.assertRaisesRegex(ValueError, "has not verified"):
            rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)

    def test_blocked_pages_come_before_outside_allowlist_and_can_be_filtered(self):
        outside = "REPORT-FICTOUTSIDE001"
        blocked = "REPORT-FICTBLOCKED001"
        core.ingest([{"id": outside, "title": "Outside host", "summary": "fixture", "kind": "campaign",
                      "source": "https://vuldb.com/fictional", "claim": "Feed listed it."}], self.path)
        core.ingest([{"id": blocked, "title": "Blocked report", "summary": "fixture", "kind": "campaign",
                      "source": REPORT_URL, "claim": "Feed listed it."}], self.path)
        research_pass.triage_raw(self.path, max_leads=2, fetch=lambda url: (_ for _ in ()).throw(
            ValueError("HTTP 403: publisher blocked the automated article fetch")))
        all_items = browser_research.review_queue(self.path)["items"]
        self.assertEqual(all_items[0]["threat_id"], blocked)
        self.assertEqual(all_items[0]["category"], "publisher_blocked")
        filtered = browser_research.review_queue(self.path, category="publisher_blocked")
        self.assertEqual([item["threat_id"] for item in filtered["items"]], [blocked])
        with self.assertRaisesRegex(ValueError, "category must be"):
            browser_research.review_queue(self.path, category="unknown")

        article_only = "REPORT-FICTARTICLE001"
        article_url = "https://www.darkreading.com/fictional-blocked-article"
        core.ingest([{"id": article_only, "title": "Article fetch blocked", "summary": "fixture",
                      "kind": "campaign", "source": article_url, "claim": "Feed listed it."}], self.path)
        with store.connection(self.path) as db:
            db.execute("INSERT INTO article_inspection_queue (threat_id,source_url,status,attempts,next_try) "
                       "VALUES (?,?,?,?,?)", (article_only, article_url, "publisher_blocked", 2,
                                              "2099-01-01T00:00:00Z"))
        filtered = browser_research.review_queue(self.path, category="publisher_blocked")
        self.assertIn(article_only, [item["threat_id"] for item in filtered["items"]])
        self.assertEqual(next(item for item in filtered["items"] if item["threat_id"] == article_only)
                         ["cited_urls"], [article_url])


class FileEventFamilyTest(Base):
    def test_file_event_spec_sigma_and_replay(self):
        normalized = custom_rules.validate_spec(SPEC)
        sigma = custom_rules._sigma("t" * 10, normalized, "fp text long enough", "desc", ("https://example.test/a",))
        self.assertIn("category: file_event", sigma)
        self.assertEqual(custom_rules.sigma_extras(sigma), {"description": "desc", "references": ("https://example.test/a",)})
        rule = {"behavior": "custom", "custom_spec": json.dumps(normalized)}
        event = {"event_type": "file_event", "SHA256": HASH.upper(), "TargetFilename": "C:\\Temp\\FictLoader.dll"}
        self.assertTrue(soc_replay._matches(rule, event))
        self.assertFalse(soc_replay._matches(rule, {**event, "SHA256": OTHER}))
        environment.validate_profile({"name": "defender lab", "siem": "defender", "telemetry": {
            "file_event": {"table": "DeviceFileEvents", "fields": ["SHA256", "FolderPath"]}}})


class NeedyMantisSyntheticReplayTest(Base):
    def test_matches_and_misses_are_explicitly_synthetic_and_do_not_approve(self):
        ident = self.report("REPORT-FICTNEEDYMANTIS", html=REPORT_HTML.replace(b"FictLoader.dll", b"WinSparkle.dll"))
        spec = {**SPEC, "predicates": [SPEC["predicates"][0],
                {"field": "TargetFilename", "operator": "endswith", "value": "WinSparkle.dll"}]}
        draft = drafting.propose(ident, REPORT_URL, 3, spec, "WinSparkle sample selector (synthetic test)",
                                 "The fictional cited paragraph names this DLL and hash.",
                                 "A genuine same-name DLL has a different hash.", self.path)
        with patch.dict("os.environ", {"THREAT_RESEARCH_DB": str(self.path)}):
            result = server.test_rule_against_samples(draft["rule_id"], "bundled:needymantis")
        self.assertEqual(result["sample_provenance"], "bundled_synthetic_fixture")
        self.assertEqual(result["counts"], {"tp": 2, "fp": 0, "fn": 2, "tn": 2})
        self.assertEqual([case["event_id"] for case in result["cases"] if case["outcome"] == "fn"],
                         ["NM-SYN-03", "NM-SYN-04"])
        self.assertEqual(rules.get_rule(draft["rule_id"], self.path)["status"], "draft")
        with self.assertRaisesRegex(ValueError, "has not verified"):
            rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        with patch.dict("os.environ", {"THREAT_RESEARCH_DB": str(self.path)}):
            missing = server.test_rule_against_samples(draft["rule_id"], str(Path(self.tmp.name) / "absent.jsonl"))
        self.assertEqual(missing["status"], "refused")
        self.assertIn("cannot read labeled events file", missing["reason"])


class ProposalTest(Base):
    def test_proposal_requires_an_inspected_paragraph_with_every_value(self):
        core.ingest([{"id": "REPORT-FICTUNREAD001", "title": "Fictional unread report", "summary": "fixture",
                      "kind": "campaign", "source": REPORT_URL, "claim": "listed"}], self.path)
        with self.assertRaisesRegex(ValueError, "not inspected for this lead"):
            self.propose("REPORT-FICTUNREAD001")
        ident = self.report()
        with self.assertRaisesRegex(ValueError, "not found in the cited paragraph"):
            self.propose(ident, {**SPEC, "predicates": [SPEC["predicates"][0],
                                                        {"field": "TargetFilename", "operator": "endswith",
                                                         "value": "Invented.dll"}]})
        with self.assertRaisesRegex(ValueError, "file name alone is not an attack pattern"):
            self.propose(ident, {"event_family": "file_event", "platform": "windows", "predicates": [
                {"field": "TargetFilename", "operator": "endswith", "value": "dnsapi.dll"},
                {"field": "Image", "operator": "endswith", "value": "dnsapi.dll"}]}, paragraph=4)
        with self.assertRaisesRegex(ValueError, "was not stored as cited text"):
            self.propose(ident, paragraph=99)
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)

    def test_unverified_draft_then_explicit_verification_before_approval(self):
        ident = self.report()
        result = self.propose(ident)
        self.assertEqual(result["status"], "draft_unverified")
        self.assertEqual(result["required_fields"], ["SHA256", "TargetFilename"])
        self.assertIn("Unverified", result["sigma"])
        self.assertIn(REPORT_URL, result["sigma"])
        self.assertEqual(result["source"]["quoted_text"], PARA)
        self.assertEqual((result["queries"]["query"], result["queries"]["native_test"]["status"]), (None, "pending"))
        self.assertIsNone(result["inventory_check"]["exact_local"])
        rule_id = result["rule_id"]
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)
        with self.assertRaisesRegex(ValueError, "has not verified"):
            rules.implement_rule(rule_id, "implement this rule", path=self.path)
        with self.assertRaisesRegex(ValueError, "I verified this source paragraph"):
            drafting.verify(rule_id, "yes", path=self.path)
        verified = drafting.verify(rule_id, "I verified this source paragraph", path=self.path)
        self.assertEqual((verified["status"], verified["rule_status"]), ("source_verified", "draft"))
        rule = rules.get_rule(rule_id, self.path)
        self.assertEqual((rule["status"], rule["pattern_score"]), ("draft", 0))
        self.assertEqual(rules.inventory_status(ident, self.path)["behaviors"][0]["rule_id"], rule_id)
        # Unchanged generated draft is still accepted by the native-test guard.
        live_validation._generated_rule_only(rule, self.path)
        with self.assertRaisesRegex(ValueError, "no labeled-event check"):
            rules.implement_rule(rule_id, "implement this rule", path=self.path)
        events = Path(self.tmp.name) / "analyst_labeled.jsonl"
        events.write_text(json.dumps({"event_id": "A1", "timestamp": "2099-01-01T00:00:00Z", "event_type": "file_event",
                                      "SHA256": HASH, "TargetFilename": "C:\\Temp\\FictLoader.dll",
                                      "expected_malicious": True, "scenario": "loader written"}) + "\n",
                          encoding="utf-8")
        soc_replay.test_rule_against_samples(rule_id, str(events), self.path)
        self.assertEqual(rules.implement_rule(rule_id, "implement this rule", path=self.path)["status"],
                         "approved_in_local_inventory")

    def test_inventory_compared_before_any_duplicate(self):
        ident = self.report()
        first = self.propose(ident)
        again = self.propose(ident)
        self.assertEqual((again["status"], again["rule_id"]), ("existing_coverage", first["rule_id"]))
        overlap = self.propose(ident, {"event_family": "file_event", "platform": "windows", "predicates": [
            {"field": "SHA256", "operator": "equals", "value": HASH},
            {"field": "TargetFilename", "operator": "contains", "value": "FictLoader"}]})
        self.assertEqual(overlap["inventory_check"]["overlapping_local_rules"][0]["rule_id"], first["rule_id"])
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 2)


class CustomCorroborationTest(Base):
    def test_fresh_matching_source_queues_review_and_plus_one_only_on_approval(self):
        ident = self.report()
        rule_id = self.propose(ident)["rule_id"]
        # Re-reading the draft's own source never queues a self-corroboration.
        research_pass.research_lead(ident, self.path, fetch=lambda u: REPORT_HTML, refresh=True)
        self.assertEqual(corroboration.list_pending(self.path), [])
        core.ingest([{"id": "REPORT-FICTFOLLOWUP1", "title": "Fictional follow-up", "summary": "fixture",
                      "kind": "campaign", "source": FRESH_URL, "claim": "listed"}], self.path)
        research_pass.research_lead("REPORT-FICTFOLLOWUP1", self.path, fetch=lambda u: FRESH_HTML, refresh=True)
        research_pass.research_lead("REPORT-FICTFOLLOWUP1", self.path, fetch=lambda u: FRESH_HTML, refresh=True)
        pending = corroboration.list_pending(self.path)
        self.assertEqual([(r["rule_id"], r["behavior"], r["current_pattern_score"]) for r in pending],
                         [(rule_id, "custom", 0)])
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 0)
        with self.assertRaises(ValueError):
            corroboration.approve(pending[0]["id"], "ok", self.path)
        result = corroboration.approve(pending[0]["id"], "implement this rule", self.path)
        self.assertEqual((result["pattern_score"], result["rule_status"]), (1, "draft"))
        with self.assertRaisesRegex(ValueError, "already approved"):
            corroboration.approve(pending[0]["id"], "implement this rule", self.path)
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 1)


class RiskSeparationTest(Base):
    def test_no_score_without_assets_and_context(self):
        ident = self.report()
        risk = workup.risk_view(ident, self.path)
        env = risk["environment_risk"]
        self.assertEqual((env["score"], env["status"]), (None, "score unavailable"))
        self.assertEqual(len(env["missing_inputs"]), 2)  # inventory, then context naming the asset checked
        self.assertIsNone(risk["threat_priority"]["numeric"])
        # The dashboard no longer derives a number from default inputs for a report.
        self.assertIsNone(dashboard_data.threat_detail_view(ident, self.path)["environment_risk"]["score"])

    def test_numeric_score_only_with_confirmed_asset_and_local_context(self):
        fixtures = resources.files("threat_research") / "lab_fixtures"
        environment.onboard(json.loads((fixtures / "profile.json").read_text(encoding="utf-8")),
                            environment.parse_assets((fixtures / "assets.csv").read_text(encoding="utf-8")),
                            self.path)
        core.ingest([{"id": "CVE-2099-99999", "title": "Fictional", "summary": "fixture", "kev": True,
                      "source": "https://example.test/advisory", "claim": "fixture"}], self.path)
        env = workup.risk_view("CVE-2099-99999", self.path)["environment_risk"]
        self.assertIsNone(env["score"])
        self.assertIn("Local event context", env["missing_inputs"][0])
        with self.assertRaises(ValueError):
            workup.record_local_event_context("CVE-2099-99999", "maybe", "x" * 30, path=self.path)
        workup.record_local_event_context("CVE-2099-99999", "no", "Sysmon EID 1 on lab-web-01, last 7 days, "
                                          "no child process of the web worker", "lab-web-01", self.path)
        env = workup.risk_view("CVE-2099-99999", self.path)["environment_risk"]
        self.assertEqual(env["components"], {"affected_version_confirmed": 30, "internet_exposed": 20,
                                             "asset_criticality": 20, "local_event_observed": 0})
        self.assertEqual(env["score"], 70)


class TriageTest(Base):
    def test_round_robin_resumable_triage_keeps_kev_first(self):
        core.ingest([{"id": "CVE-2099-00001", "title": "Fictional KEV", "summary": "fixture", "kev": True,
                      "source": "https://nvd.nist.gov/vuln/detail/CVE-2099-00001", "claim": "fixture"}], self.path)
        for n in range(3):
            core.ingest([{"id": f"CVE-2099-1000{n}", "title": "Fictional non-KEV", "summary": "fixture",
                          "source": f"https://nvd.nist.gov/vuln/detail/CVE-2099-1000{n}", "claim": "fixture",
                          "reported_by": "NVD", "references": ["https://github.com/example/fictional"]}], self.path)
        core.ingest([{"id": "LEAK-FICT-0001", "title": "Fictional leak claim", "summary": "fixture",
                      "kind": "leak_claim", "source": "https://www.ransomlook.io/recent", "claim": "fixture",
                      "reported_by": "RansomLook leak claims"}], self.path)
        core.ingest([{"id": "REPORT-FICTLOADER0001", "title": "FictMantis report", "summary": "fixture",
                      "kind": "campaign", "source": REPORT_URL, "claim": "listed",
                      "reported_by": "RSS: Microsoft Security Blog"}], self.path)
        candidates = research_pass.raw_triage_candidates(self.path)
        self.assertNotIn("CVE-2099-00001", [c["id"] for c in candidates])  # KEV is the priority pass's
        self.assertEqual(len({c["source_name"] for c in candidates[:3]}), 3)  # interleaved across sources
        first = research_pass.triage_raw(self.path, max_leads=1, fetch=lambda u: REPORT_HTML)
        results = {p["threat_id"]: p for p in first["processed"]}
        self.assertEqual(results["LEAK-FICT-0001"]["result"], "skipped_not_researchable")
        self.assertEqual(results["REPORT-FICTLOADER0001"]["result"], "moved_to_research_backlog")
        self.assertIn("github.com", next(p["reason"] for p in first["processed"]
                                         if p["result"] == "no_allowlisted_source"))
        self.assertEqual(first["before"]["raw_unreviewed_leads"], 5)
        self.assertGreater(first["after"]["triaged_open"], 0)
        second = research_pass.triage_raw(self.path, max_leads=1, fetch=lambda u: REPORT_HTML)
        self.assertFalse({p["threat_id"] for p in second["processed"]} & set(results))  # resumes, no repeats
        self.assertEqual(research_pass.due_leads(self.path)[0], "CVE-2099-00001")
        summary = research_pass.triage_summary(self.path)
        self.assertTrue(all(ex["reason"] for g in summary["groups"].values() for ex in g["examples"]))
        self.assertEqual(workflow.list_leads(self.path, queue="triaged_open")["total"],
                         workflow.workflow_counts(self.path)["triaged_open"])


class HashShapeTest(Base):
    def test_reporter_handle_is_not_a_hash_but_a_labeled_md5_is(self):
        from threat_research import behavior_leads
        handle = ("[$43000][ 493319454 ] Critical CVE-2099-5858: Heap buffer overflow in WebML. Reported by "
                  "c6eed09fc8b174b0f3eebedcceb1e792 on 2099-03-17")
        labeled = "MD5 : 116346cace7f00ba557034b534d40791 (sample, September 2099)"
        self.assertEqual(behavior_leads.specific_details([handle]), [])
        self.assertEqual(behavior_leads.specific_details([labeled])[0]["artifacts_as_written"],
                         ["116346cace7f00ba557034b534d40791"])

    def test_reread_without_artifacts_clears_the_stale_backlog_lead(self):
        ident = self.report()
        self.assertEqual(workflow.list_leads(self.path, queue="research_backlog")["total"], 1)
        plain = b"<html><body><p>Fictional vendor post with no indicators, only a product update note.</p></body></html>"
        research_pass.research_lead(ident, self.path, fetch=lambda u: plain, refresh=True)
        self.assertEqual(workflow.list_leads(self.path, queue="research_backlog")["total"], 0)


class WorkupTest(Base):
    def test_generic_queries_source_support_and_connection_states(self):
        ident = self.report()
        before = workup.lead_workup(ident, self.path)
        self.assertEqual(before["inventory"]["connection"]["status"], "not_connected")
        self.assertEqual(before["inventory"]["answer"], "Unknown")
        self.assertEqual(before["risk"]["environment_risk"]["connection"]["status"], "not_connected")
        result = self.propose(ident)
        view = workup.lead_workup(ident, self.path)
        draft = view["drafts"][0]
        self.assertEqual(draft["supporting_text"]["quoted_text"], PARA)
        self.assertEqual({item["source_value"] for item in draft["supporting_text"]["predicates"]},
                         {HASH, "FictLoader.dll"})
        self.assertEqual(draft["queries"]["status"], "generic_templates")
        templates = draft["queries"]["templates"]
        self.assertIn("YOUR_EVENT_TABLE", templates["kql"])
        self.assertIn("YOUR_INDEX", templates["spl"])
        self.assertIn(HASH, templates["kql"])
        self.assertIn("fictloader.dll", templates["spl"])
        self.assertIn("publisher identifies", next(p for p in view["pattern_analysis"]["patterns"]
                                                 if p["paragraph"] == 3)
                      ["why_malicious_per_source"]["explanation"].lower())
        rule = rules.get_rule(result["rule_id"], self.path)
        self.assertEqual(rule["kql"], templates["kql"])
        self.assertEqual(rule["spl"], templates["spl"])
        with store.connection(self.path) as db:
            db.execute("UPDATE rules SET kql=?, spl=? WHERE id=?",
                       ("Not generated: requires a configured SIEM field mapping (check_detection_fit).",
                        "Not generated: requires a configured SIEM field mapping (check_detection_fit).",
                        result["rule_id"]))
        legacy = rules.get_rule(result["rule_id"], self.path)
        self.assertEqual(legacy["kql"], templates["kql"])
        self.assertEqual(legacy["spl"], templates["spl"])
        with store.connection(self.path) as db:
            self.assertTrue(db.execute("SELECT kql FROM rules WHERE id=?", (result["rule_id"],))
                            .fetchone()[0].startswith("Not generated:"))
        profile = {"name": "Fixture Defender", "siem": "defender", "telemetry": {
            "file_event": {"table": "DeviceFileEvents", "fields": ["SHA256", "FolderPath"]}}}
        environment.onboard(profile, [{"asset_id": "fixture-1", "hostname": "fixture-1", "product": "Fixture",
                                      "version": "1", "confirmed_cves": [], "internet_exposed": False,
                                      "criticality": "low", "asset_role": "general"}], self.path)
        mapped = workup.lead_workup(ident, self.path)
        self.assertEqual(mapped["drafts"][0]["queries"]["status"], "generated_from_mapping")
        self.assertIn("DeviceFileEvents", mapped["drafts"][0]["queries"]["mapped_query"])
        self.assertIn("FolderPath", mapped["drafts"][0]["queries"]["mapped_query"])
        self.assertEqual(mapped["risk"]["environment_risk"]["connection"]["status"], "connected")
        self.assertIsNone(mapped["risk"]["environment_risk"]["score"])
        rules.import_inventory([{"id": "EXT-FICT", "title": "Existing reviewed fixture rule",
                                "source_url": "https://example.org/fixture-rule", "behavior": "custom",
                                "spec": SPEC}], self.path)
        still_unverified = workup.lead_workup(ident, self.path)
        self.assertEqual(still_unverified["inventory"]["connection"]["status"], "connected_partial")
        self.assertEqual(still_unverified["inventory"]["answer"], "Unknown")
        drafting.verify(result["rule_id"], "I verified this source paragraph", path=self.path)
        compared = workup.lead_workup(ident, self.path)
        self.assertEqual(compared["inventory"]["answer"], "Yes")
        self.assertEqual(compared["inventory"]["behaviors"][0]["rule_id"], "EXT-FICT")

    def test_workup_sections_and_pattern_reasoning(self):
        ident = self.report()
        before = workup.lead_workup(ident, self.path)
        pattern = next(p for p in before["pattern_analysis"]["patterns"] if p["paragraph"] == 3)
        self.assertEqual((pattern["source_url"], pattern["published"]), (REPORT_URL, "2099-01-01T00:00:00Z"))
        self.assertEqual(pattern["quoted_paragraph"], PARA)
        kinds = {a["value"]: a["kind"] for a in pattern["observable"]["artifacts"]}
        self.assertEqual(kinds[HASH], "sha256")
        self.assertIn("loader", pattern["why_malicious_per_source"]["cue_words"])
        self.assertIn("Not evidence of activity in your environment", pattern["claim_scope"])
        self.assertEqual(pattern["draftable"]["suggested_spec"]["predicates"][0]["value"], HASH)
        name_only = next(p for p in before["pattern_analysis"]["patterns"] if p["paragraph"] == 4)
        self.assertIn("name alone is not an attack pattern", name_only["draftable"]["reason"])
        self.assertIn("propose_detection_from_paragraph", before["drafting_blocker"])
        self.assertEqual(before["risk"]["environment_risk"]["status"], "score unavailable")
        self.propose(ident)
        after = workup.lead_workup(ident, self.path)
        self.assertEqual(after["drafts"][0]["source_verification"], "unverified")
        self.assertEqual(after["tests"][0]["native_siem_test"]["status"], "pending")
        self.assertIn("verify_draft_source", after["next_analyst_decision"])
        with patch.dict("os.environ", {"THREAT_RESEARCH_DB": str(self.path)}):
            self.assertEqual(server.lead_workup(ident)["drafts"][0]["rule_id"], after["drafts"][0]["rule_id"])
            refused = server.propose_detection_from_paragraph(ident, REPORT_URL, 99, SPEC, TEXT["title"],
                                                              TEXT["rationale"], TEXT["false_positives"])
        self.assertEqual(refused["status"], "refused")


if __name__ == "__main__":
    unittest.main()
