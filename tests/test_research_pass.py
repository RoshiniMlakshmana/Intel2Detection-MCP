"""Automatic, bounded research pass (regression for the 2026-09-29 Claude Desktop run).

That run listed 1,584 "research_needed" leads, named two NetScaler KEV CVEs and
a Fortinet report, then stopped to ask whether it should read the report. The
research pass now reads cited primary pages without asking, records each page
and when, reports publisher blocks separately, and concludes with
"insufficient detection detail" instead of inventing indicators or a rule.

Fixtures are fictional (CVE-2099-*); page URLs use allowlisted hosts with
fictional paths, and every fetch is injected, so nothing contacts a network.
"""

import io
import json
import ssl
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from threat_research import core, report_inspection, research_pass, rules, server, store, workflow, workup

CVE = "CVE-2099-88771"
CVE2 = "CVE-2099-88772"
VENDOR = "https://support.citrix.com/external/article/CTX999001/fictional-bulletin.html"
SCRIPTED = "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX999002"
KEV_ENTRY = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={CVE}"
CISA_ALERT = "https://www.cisa.gov/news-events/alerts/2099/01/01/fictional-netscaler-alert"
GUIDANCE = "https://support.citrix.com/external/article/CTX999003/steps-if-compromised.html"
BLOCKED_GUIDANCE = "https://community.citrix.com/fictional-bulletin"
FORTINET = "https://fortiguard.fortinet.com/threat-signal-report/99999"
NEWS = "https://www.bleepingcomputer.com/news/security/fictional-netscaler-story"


def page(*paragraphs, links=()):
    body = "".join(f"<p>{p}</p>" for p in paragraphs) + "".join(f'<a href="{u}">link</a>' for u in links)
    return f"<html><body><article>{body}</article></body></html>".encode()


VENDOR_HTML = page(
    f"{CVE} is an improper input validation vulnerability in NetScaler ADC and Gateway that could allow an "
    "unauthenticated attacker to execute arbitrary commands.",
    "Exploits of this vulnerability on unmitigated appliances have been observed. Upgrade to 14.1-73.37 or later.")
CISA_HTML = page(
    f"CISA has added {CVE} and {CVE2} to its Known Exploited Vulnerabilities Catalog based on evidence of active "
    "exploitation.",
    "Users should review the vendor advisory and check for indication of compromise prior to patching.",
    links=(GUIDANCE, BLOCKED_GUIDANCE + "/", BLOCKED_GUIDANCE + "?utm_source=cisa", BLOCKED_GUIDANCE,
           "https://www.cisa.gov/about", "https://twitter.com/intent/tweet?x=1"))
GUIDANCE_HTML = page(
    "If you suspect that your NetScaler ADC has been compromised, take a snapshot for forensic analysis.",
    "Investigate all servers and systems that the appliance connected to for signs of further compromise.")
FORTINET_HTML = page(
    f"Threat actors are actively exploiting {CVE} and {CVE2}, affecting NetScaler ADC and Gateway appliances.",
    "Organizations should immediately identify exposed appliances and apply the vendor security updates.")
# Shape of the observed THN article: a news report quoting a third-party firm's
# findings with concrete artifacts. Verbatim here so the test can prove the
# pass only ever repeats cited text.
QUOTED_HTML = page(
    f"Attackers are exploiting {CVE} in NetScaler appliances, according to the vendor.",
    '"The threat actor attempted to set the setuid bit on /bin/sh and install a password-protected webshell," '
    "the FictionalResearch firm said.",
    'The actor is also said to have routed requests for a stylesheet to their dot file (".fict.receiver").',
    links=("https://www.fictionalresearch.example/blog/netscaler-honeypot",
           "https://twitter.com/intent/tweet?text=fictionalresearch", "https://ads.unrelated.example/x"))
SCRIPT_ONLY_HTML = b"<html><head><script>window.app={}</script></head><body><div id=root></div></body></html>"
WEB_SHELL_HTML = page(
    "During the intrusion the attacker's request caused w3wp.exe to have spawned cmd.exe on the server, "
    "which then executed a reconnaissance command.")


FETCH_ARTICLE = report_inspection.fetch_article


def blocked(url):
    raise urllib.error.HTTPError(url, 403, "Forbidden", Message(), None)


class Fetcher:
    """Injected publisher: maps URL -> HTML bytes or 'blocked'; records every fetch."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        value = self.pages.get(url, "blocked")
        if value == "blocked":
            return FETCH_ARTICLE(url, blocked)
        return value


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def kev(self, ident=CVE, refs=(VENDOR, KEV_ENTRY)):
        core.ingest([{"id": ident, "title": "Fictional NetScaler Improper Input Validation Vulnerability",
                      "summary": "Improper input validation in NetScaler ADC before 14.1-73.37 lets an "
                                 "unauthenticated attacker execute arbitrary commands.",
                      "kev": True, "affected": ["Citrix", "NetScaler ADC"],
                      "source": f"https://nvd.nist.gov/vuln/detail/{ident}",
                      "claim": "CISA listed this CVE as known exploited in the wild.",
                      "references": list(refs)}], self.path)

    def report(self, ident, url, cves=(CVE,)):
        core.ingest([{"id": ident, "title": f"Fictional report {ident}", "summary": "fixture", "kind": "campaign",
                      "source": url, "claim": "Feed listed this report.", "mentioned_cves": list(cves)}], self.path)

    def raw(self, count=3):
        for n in range(count):
            core.ingest([{"id": f"CVE-2099-{n:05d}", "title": "Fictional non-KEV advisory", "summary": "fixture",
                          "source": f"https://nvd.nist.gov/vuln/detail/CVE-2099-{n:05d}", "claim": "NVD record."}],
                        self.path)


class AutomaticSourceReviewTest(Base):
    def test_news_report_follows_only_cited_original_on_configured_host(self):
        original = "https://support.citrix.com/external/article/CTX999991/technical-analysis.html"
        news = "https://www.bleepingcomputer.com/news/security/fictional-investigation"
        raw = page("Citrix published an original technical analysis of the intrusion.", links=(
            original, "https://support.citrix.com/about", "https://outside.example/other"))
        cited = research_pass._linked_originals(raw, {"excerpts": [
            {"excerpt": "Citrix published an original technical analysis of the intrusion."}]}, news)
        self.assertEqual(cited, [original])

    def test_vendor_behavior_and_hunts_are_visible_without_creating_a_rule(self):
        ident = "REPORT-FICTMALWARE001"
        url = "https://www.microsoft.com/en-us/security/blog/2099/01/01/fictional-loader"
        self.report(ident, url, cves=())
        html = ("<html><body><article>"
                "<p>The malware's first-stage loader was DLL sideloaded by the legitimate application and "
                "launched when the application ran.</p>"
                "<p>The initial C2 beacon sent an HTTPS GET request to fictional.example.</p>"
                "<pre>DeviceNetworkEvents\n| where RemoteUrl == 'fictional.example'\n"
                "| project Timestamp, DeviceName, RemoteUrl</pre>"
                "</article></body></html>").encode()
        result = research_pass.research_lead(ident, self.path, fetch=Fetcher({url: html}))
        self.assertEqual(result["status"], "observables_need_analyst_verification")
        self.assertEqual([p["behavior"] for p in result["behavior_patterns_to_verify"]],
                         ["dll_sideloading", "c2_communication"])
        self.assertEqual(result["observables_found"], [])  # no false fixed-template match
        self.assertEqual(result["publisher_hunting_queries"][0]["status"], "publisher_query_unverified")
        view = workup.lead_workup(ident, self.path)
        self.assertEqual([p["observable"]["lexical_behavior"] for p in view["pattern_analysis"]["patterns"]
                         if not p["publisher_query"]],
                         ["dll_sideloading", "c2_communication"])
        self.assertTrue(all(not p["draftable"]["suggested_spec"] for p in view["pattern_analysis"]["patterns"]))
        self.assertEqual(len(view["research"]["publisher_hunting_queries"]), 1)
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)

    def test_negated_behavior_does_not_create_a_research_pattern(self):
        html = page("No evidence of a malicious loader DLL sideloading was observed in this investigation.",
                    "The C2 beacon did not connect to the HTTPS host in this test.")
        found = report_inspection.extract_report_html("REPORT-FICTNEGATED01", FORTINET, html)
        self.assertEqual(found["behavior_patterns"], [])

    def test_pass_reads_primary_pages_linked_guidance_and_cited_reports_without_asking(self):
        self.kev()
        self.report("REPORT-FICTCISA0001", CISA_ALERT)
        self.report("REPORT-FICTFORTI001", FORTINET)
        self.raw()
        before = workflow.workflow_counts(self.path)
        self.assertEqual((before["actionable_research_backlog"], before["raw_unreviewed_leads"]), (3, 3))

        fetch = Fetcher({VENDOR: VENDOR_HTML, KEV_ENTRY: CISA_HTML, CISA_ALERT: CISA_HTML,
                         GUIDANCE: GUIDANCE_HTML, FORTINET: FORTINET_HTML})
        result = research_pass.run_pass(self.path, fetch=fetch)

        self.assertEqual(result["results"][0]["threat_id"], CVE)  # KEV CVE is researched first
        # Primary vendor and CISA pages first, then vendor guidance linked from them, then cited reports.
        self.assertEqual(fetch.calls[:3], [VENDOR, KEV_ENTRY, CISA_ALERT])
        self.assertLess(fetch.calls.index(GUIDANCE), fetch.calls.index(FORTINET))
        self.assertNotIn("https://www.cisa.gov/about", fetch.calls)  # site navigation is never followed
        self.assertEqual(len(fetch.calls), len(set(fetch.calls)))  # one fetch per page per pass

        status = research_pass.status(CVE, self.path)
        pages = {p["url"]: p for p in status["pages"]}
        self.assertEqual(pages[VENDOR]["status"], "inspected")
        self.assertEqual(pages[GUIDANCE]["role"], "linked_guidance")
        self.assertEqual(pages[GUIDANCE]["via"], KEV_ENTRY)
        self.assertEqual(pages[FORTINET]["via"], "REPORT-FICTFORTI001")
        for record in status["pages"]:
            self.assertRegex(record["inspected_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(all(p["sha256"] for p in status["pages"] if p["status"] == "inspected"))

        # Reports read while researching the CVE are concluded too; the raw queue is untouched.
        self.assertEqual(research_pass.status("REPORT-FICTFORTI001", self.path)["status"], "completed_insufficient_detail")
        after = workflow.workflow_counts(self.path)
        self.assertEqual(after["actionable_research_backlog"], 0)
        self.assertEqual(after["raw_unreviewed_leads"], 3)
        self.assertEqual(after["research_completed_insufficient_detail"], 3)
        self.assertEqual(after["leads_total"], 6)
        self.assertEqual(result["backlog_remaining"], 0)
        self.assertIn("no analyst permission is needed", result["note"])

    def test_queues_are_disjoint_and_listable(self):
        self.kev()
        self.raw(2)
        backlog = workflow.list_leads(self.path, queue="research_backlog")
        self.assertEqual([i["id"] for i in backlog["items"]], [CVE])
        self.assertEqual(workflow.list_leads(self.path, queue="raw_unreviewed")["total"], 2)
        with self.assertRaises(ValueError):
            workflow.list_leads(self.path, queue="everything")

    def test_bounded_pass_budget(self):
        for n in range(6):
            self.kev(f"CVE-2099-7{n:04d}", refs=(f"https://support.citrix.com/external/article/CTX9{n}/b.html",))
        fetch = Fetcher({})
        result = research_pass.run_pass(self.path, max_leads_=2, fetch=fetch)
        self.assertEqual(result["leads_researched"], 2)
        self.assertLessEqual(len(fetch.calls), research_pass.MAX_FETCHES_PER_PASS)

    def test_deep_batch_stays_bounded_and_publisher_hunt_is_unverified(self):
        ident = "REPORT-FICTHUNT0001"
        self.report(ident, FORTINET, cves=())
        query = "DeviceFileEvents\n| where FileName == 'fictional-loader.dll'\n| project Timestamp, DeviceName, FileName"
        html = ("<html><body><article><p>Fictional threat actors used a suspicious loader during the "
                "investigation of compromised machines.</p><pre>" + query + "</pre></article></body></html>").encode()
        result = research_pass.run_pass(self.path, max_leads_=20, max_fetches=120,
                                        threat_ids=[ident], fetch=Fetcher({FORTINET: html}))
        self.assertEqual(result["pages_fetched"], 1)
        hunt = research_pass.status(ident, self.path)["publisher_hunting_queries"][0]
        self.assertEqual(hunt["text"], query)
        self.assertEqual(hunt["status"], "publisher_query_unverified")
        self.assertEqual(workflow.workflow_counts(self.path)["draft_rules"], 0)
        self.assertEqual(research_pass.status(ident, self.path)["status"],
                         "observables_need_analyst_verification")

        # An already researched lead remains actionable for verification, but
        # is not repeatedly fetched. An older extractor result is reread once.
        again = research_pass.run_pass(self.path, max_leads_=20, max_fetches=120,
                                       fetch=Fetcher({FORTINET: html}))
        self.assertEqual((again["leads_researched"], again["pages_fetched"]), (0, 0))
        self.assertEqual(again["selection"]["not_due"][0]["reason"], "awaiting_analyst_verification")
        self.assertIn("No lead is due", again["no_work_reason"])
        with store.connection(self.path) as db:
            old = json.loads(db.execute("SELECT detail FROM research_outcomes WHERE threat_id=?",
                                        (ident,)).fetchone()[0])
            old.pop("extraction_version")
            db.execute("UPDATE research_outcomes SET detail=? WHERE threat_id=?", (json.dumps(old), ident))
        self.assertTrue(research_pass.status(ident, self.path)["needs_extraction_refresh"])
        view = workup.lead_workup(ident, self.path)
        self.assertTrue(view["research"]["needs_extraction_refresh"])
        self.assertIn("refresh=True", view["research"]["refresh_action"])
        refreshed = research_pass.run_pass(self.path, max_leads_=20, max_fetches=120,
                                           fetch=Fetcher({FORTINET: html}))
        self.assertEqual((refreshed["leads_researched"], refreshed["pages_fetched"]), (1, 1))
        self.assertFalse(research_pass.status(ident, self.path)["needs_extraction_refresh"])

    def test_cisa_pages_are_fetched_over_tls12(self):
        seen = {}

        class Opener:
            def open(self, request, timeout=None):
                raise urllib.error.URLError("stop")

        def build_opener(https_handler, *handlers):
            seen["tls"] = https_handler._context.maximum_version
            return Opener()
        with patch.object(report_inspection.urllib.request, "build_opener", build_opener):
            for url, expect_tls12 in ((CISA_ALERT, True), (FORTINET, False)):
                with self.assertRaises(urllib.error.URLError):
                    report_inspection._open_article(url)
                self.assertEqual(seen["tls"] == ssl.TLSVersion.TLSv1_2, expect_tls12, url)

    def test_fortinet_and_vendor_hosts_are_allowlisted_but_arbitrary_hosts_are_not(self):
        for url in (FORTINET, VENDOR, "https://thehackernews.com/2099/01/story.html"):
            self.assertTrue(report_inspection.allowed_url(url), url)
        for url in ("https://attacker.example/x", "http://support.citrix.com/x", "https://support.citrix.com:8443/x"):
            self.assertFalse(report_inspection.allowed_url(url), url)


class InaccessibleArticleTest(Base):
    def test_blocked_and_script_rendered_primary_pages_are_reported_separately(self):
        self.kev(refs=(SCRIPTED, KEV_ENTRY))
        self.report("REPORT-FICTNEWS0001", NEWS)
        fetch = Fetcher({SCRIPTED: SCRIPT_ONLY_HTML, NEWS: FORTINET_HTML})  # KEV entry: publisher 403
        research_pass.run_pass(self.path, fetch=fetch)
        status = research_pass.status(CVE, self.path)

        # A readable news story alone does not complete research on a KEV CVE.
        self.assertEqual(status["status"], "no_readable_source")
        self.assertEqual([p["url"] for p in status["publisher_blocked"]], [KEV_ENTRY])
        self.assertIn("publisher blocked", status["publisher_blocked"][0]["detail"])
        self.assertEqual([p["url"] for p in status["unreadable"]], [SCRIPTED])
        self.assertIn("rendered by script", status["unreadable"][0]["detail"])
        self.assertTrue(any(SCRIPTED in m and KEV_ENTRY in m for m in status["missing_for_detection"]))

        counts = workflow.workflow_counts(self.path)
        self.assertEqual(counts["actionable_research_backlog"], 1)  # still needs a human read
        self.assertEqual(counts["backlog_detail"]["no_readable_source"], 1)
        self.assertEqual(counts["research_publisher_blocked_pages"], 1)
        errors = workflow.source_errors(self.path)
        self.assertEqual([r["url"] for r in errors["research_publisher_blocks"]], [KEV_ENTRY])
        self.assertEqual([r["url"] for r in errors["research_unreadable_pages"]], [SCRIPTED])

        # Not retried on the next poll; retried after the back-off window.
        self.assertEqual(research_pass.due_leads(self.path), [])
        with store.connection(self.path) as db:
            db.execute("UPDATE research_outcomes SET completed_at='2000-01-01T00:00:00Z'")
        self.assertEqual(research_pass.due_leads(self.path), [CVE])

    def test_host_outside_allowlist_is_listed_not_fetched(self):
        self.kev(refs=("https://attacker.example/advisory", KEV_ENTRY))
        fetch = Fetcher({KEV_ENTRY: CISA_HTML})
        status = research_pass.research_lead(CVE, self.path, fetch=fetch)
        self.assertNotIn("https://attacker.example/advisory", fetch.calls)
        self.assertEqual(status["not_fetched_host_not_allowlisted"], ["https://attacker.example/advisory"])


class CompletedInsufficientDetailTest(Base):
    def setUp(self):
        super().setUp()
        self.kev()
        self.kev(CVE2, refs=(VENDOR,))
        self.report("REPORT-FICTCISA0001", CISA_ALERT, cves=(CVE, CVE2))
        self.fetch = Fetcher({VENDOR: VENDOR_HTML, KEV_ENTRY: CISA_HTML, CISA_ALERT: CISA_HTML,
                              GUIDANCE: GUIDANCE_HTML})
        self.result = research_pass.run_pass(self.path, fetch=self.fetch)

    def test_research_completes_with_evidence_missing_telemetry_and_exposure_offer(self):
        for ident in (CVE, CVE2):
            status = research_pass.status(ident, self.path)
            self.assertEqual(status["status"], "completed_insufficient_detail", ident)
            self.assertIn("Insufficient detection detail", status["summary"])
            self.assertTrue(status["evidence"])
            self.assertTrue(all(e["url"].startswith("https://") and e["excerpt"] for e in status["evidence"]))
            self.assertEqual(status["observables_found"], [])
            self.assertIn("Cannot be determined yet", status["missing_telemetry"][0])
            self.assertIn("No telemetry profile is configured", status["missing_telemetry"][1])
            offer = status["exposure_patch_review"]
            self.assertTrue(offer["offered"])
            self.assertIsNone(offer["numeric_risk_score"])
            self.assertIn(ident, offer["cves"])
            # Linked with and without slash/tracking parameters: one page, one block.
            self.assertEqual([p["url"] for p in status["publisher_blocked"]], [BLOCKED_GUIDANCE])
        # Shared pages are fetched once for both CVEs.
        self.assertEqual(self.fetch.calls.count(CISA_ALERT), 1)

    def test_progression_marks_research_done_and_blocks_on_evidence(self):
        prog = workflow.lead_progression(CVE, self.path)
        research = next(s for s in prog["steps"] if s["key"] == "research")
        self.assertEqual(research["state"], "done")
        self.assertEqual(research["research"]["status"], "completed_insufficient_detail")
        self.assertEqual(prog["next_step"], "evidence")
        self.assertFalse(prog["can_draft"])
        self.assertEqual(prog["research_status"], "completed_insufficient_detail")

    def test_completed_leads_are_not_re_researched_until_a_new_report_cites_them(self):
        self.assertEqual(research_pass.due_leads(self.path), [])
        with store.connection(self.path) as db:
            db.execute("UPDATE research_outcomes SET completed_at='2000-01-01T00:00:00Z'")
        self.report("REPORT-FICTNEW00001", FORTINET, cves=(CVE,))
        self.assertIn(CVE, research_pass.due_leads(self.path))

    def test_completed_readable_report_is_revisited_once_for_new_extractor(self):
        ident = "REPORT-FICTOLDER001"
        self.report(ident, FORTINET, cves=())
        first = research_pass.research_lead(ident, self.path, fetch=Fetcher({FORTINET: page(
            "The fictional team published an overview with no measurable behavior or file artifacts.")}))
        self.assertEqual(first["status"], "completed_insufficient_detail")
        with store.connection(self.path) as db:
            old = json.loads(db.execute("SELECT detail FROM research_outcomes WHERE threat_id=?",
                                        (ident,)).fetchone()[0])
            old["extraction_version"] = research_pass.EXTRACTION_VERSION - 1
            db.execute("UPDATE research_outcomes SET detail=? WHERE threat_id=?", (json.dumps(old), ident))
        self.assertIn(ident, research_pass.due_leads(self.path))
        second = research_pass.run_pass(self.path, max_leads_=20, max_fetches=120,
                                        fetch=Fetcher({FORTINET: page(
                                            "The fictional team published an overview with no measurable behavior or file artifacts.")}))
        self.assertEqual((second["leads_researched"], second["pages_fetched"]), (1, 1))
        self.assertNotIn(ident, research_pass.due_leads(self.path))

    def test_research_detection_plan_runs_research_itself(self):
        with patch.dict("os.environ", {"THREAT_RESEARCH_DB": str(self.path)}):
            with store.connection(self.path) as db:
                db.execute("DELETE FROM research_outcomes WHERE threat_id=?", (CVE2,))
            with patch.object(report_inspection, "fetch_article", self.fetch):
                plan = server.research_detection_plan(CVE2)
        self.assertEqual(plan["automatic_research"]["status"], "completed_insufficient_detail")
        self.assertIn("Do not draft a rule", plan["next_step"])
        self.assertIsNone(plan["client_risk"]["score"])


class QuotedSecondaryClaimsTest(Base):
    def test_quoted_artifacts_are_listed_verbatim_without_changing_primary_based_status(self):
        self.kev()
        self.report("REPORT-FICTNEWS0001", NEWS)
        fetch = Fetcher({VENDOR: VENDOR_HTML, KEV_ENTRY: CISA_HTML, GUIDANCE: GUIDANCE_HTML, NEWS: QUOTED_HTML})
        research_pass.run_pass(self.path, fetch=fetch)
        status = research_pass.status(CVE, self.path)
        # Primary vendor/CISA pages decide the CVE: still insufficient detail.
        self.assertEqual(status["status"], "completed_insufficient_detail")
        self.assertIn("secondary reports quote third-party findings", status["summary"])
        quoted = status["specific_details_to_verify"]
        self.assertEqual({d["url"] for d in quoted}, {NEWS})
        self.assertEqual([d["artifacts_as_written"] for d in quoted], [["/bin/sh"], ['".fict.receiver"']])
        for item in quoted:
            self.assertIn(item["excerpt"], QUOTED_HTML.decode())
            self.assertEqual(item["status"], "unverified_quoted_claim")
        self.assertTrue(any("original researcher's publication" in m for m in status["missing_for_detection"]))
        # The quoting page's link to the named firm's own post is listed, not fetched.
        original = "https://www.fictionalresearch.example/blog/netscaler-honeypot"
        self.assertEqual(quoted[0]["original_publication_candidates"], [original])
        self.assertNotIn(original, fetch.calls)
        self.assertTrue(any(original in m for m in status["missing_for_detection"]))
        # The report whose own page carries the claims goes to analyst verification, not to a rule.
        report = research_pass.status("REPORT-FICTNEWS0001", self.path)
        self.assertEqual(report["status"], "observables_need_analyst_verification")
        counts = workflow.workflow_counts(self.path)
        self.assertEqual((counts["actionable_research_backlog"], counts["research_completed_insufficient_detail"]), (1, 1))
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)

    def test_lexical_lead_in_a_secondary_report_stays_on_that_report(self):
        self.kev()
        self.report("REPORT-FICTNEWS0001", NEWS)
        fetch = Fetcher({VENDOR: VENDOR_HTML, KEV_ENTRY: CISA_HTML, GUIDANCE: GUIDANCE_HTML, NEWS: WEB_SHELL_HTML})
        research_pass.run_pass(self.path, fetch=fetch)
        cve = research_pass.status(CVE, self.path)
        self.assertEqual(cve["status"], "completed_insufficient_detail")
        self.assertIn("queued on those reports for analyst verification", cve["summary"])
        report = research_pass.status("REPORT-FICTNEWS0001", self.path)
        self.assertEqual(report["status"], "observables_need_analyst_verification")
        with store.connection(self.path) as db:
            self.assertEqual([tuple(r) for r in db.execute("SELECT threat_id,behavior FROM article_behavior_leads")],
                             [("REPORT-FICTNEWS0001", "web_server_shell")])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)

    def test_primary_pages_drop_site_boilerplate_from_evidence(self):
        self.kev()
        boilerplate = page("Search all Known Exploited Vulnerabilities Catalog and stay up to date on exploitation.",
                           f"{CVE} Fictional NetScaler Improper Input Validation Vulnerability was added.")
        fetch = Fetcher({VENDOR: VENDOR_HTML, KEV_ENTRY: boilerplate})
        status = research_pass.research_lead(CVE, self.path, fetch=fetch)
        self.assertTrue(status["evidence"])
        self.assertTrue(all(CVE in e["excerpt"] or "NetScaler" in e["excerpt"] for e in status["evidence"]))


class NoFabricatedDraftTest(Base):
    def test_insufficient_research_never_creates_evidence_rules_indicators_or_scores(self):
        self.kev()
        fetch = Fetcher({VENDOR: VENDOR_HTML, KEV_ENTRY: CISA_HTML, GUIDANCE: GUIDANCE_HTML})
        research_pass.run_pass(self.path, fetch=fetch)
        status = research_pass.status(CVE, self.path)
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM article_behavior_leads").fetchone()[0], 0)
            source_ids = [r[0] for r in db.execute("SELECT id FROM evidence WHERE threat_id=?", (CVE,))]
        # Every excerpt is verbatim text from a fetched page, never generated.
        fetched = b"".join(v for v in (VENDOR_HTML, CISA_HTML, GUIDANCE_HTML)).decode()
        for item in status["evidence"]:
            self.assertIn(item["excerpt"], fetched)
        text = json.dumps(status).lower()
        for invented in ("web shell", "webshell", "powershell", "cmd.exe"):
            self.assertNotIn(invented, text)
        self.assertNotIn('"score": ', text.replace('"numeric_risk_score": null', ""))
        for evidence_id in source_ids:
            with self.assertRaises(ValueError):
                rules.propose_rule(CVE, evidence_id, self.path)
        with patch.dict("os.environ", {"THREAT_RESEARCH_DB": str(self.path)}):
            refused = server.draft_detection(CVE, source_ids[0])
        self.assertEqual((refused["status"], refused["rule_id"]), ("research_needed", None))
        self.assertIn("Not drafted", status["rule_drafting"])

    def test_lexical_observable_goes_to_analyst_review_not_to_a_rule(self):
        self.kev(refs=(VENDOR,))
        fetch = Fetcher({VENDOR: WEB_SHELL_HTML})
        status = research_pass.research_lead(CVE, self.path, fetch=fetch)
        self.assertEqual(status["status"], "observables_need_analyst_verification")
        self.assertEqual(status["observables_found"][0]["behavior"], "web_server_shell")
        self.assertIn("While the leads above are verified", status["exposure_patch_review"]["question"])
        with store.connection(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM article_behavior_leads").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence WHERE kind='analyst_observation'")
                             .fetchone()[0], 0)
        counts = workflow.workflow_counts(self.path)
        self.assertEqual(counts["actionable_research_backlog"], 1)
        self.assertEqual(counts["backlog_detail"]["awaiting_analyst_verification"], 1)
        self.assertEqual(workflow.lead_progression(CVE, self.path)["next_step"], "research")


if __name__ == "__main__":
    unittest.main()
