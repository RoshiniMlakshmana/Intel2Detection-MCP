"""Automatic corroboration review: a newly collected, cited behavior lead
that lexically matches an existing rule's fingerprint becomes a durable
pending review -- never an automatic evidence link or score change.
Approval links distinct evidence and adds exactly +1; rejection leaves the
rule untouched; repeated polls/retries/repeated approval never double-count.
"""

import http.client
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from threat_research import core, corroboration, dashboard, environment, lead_queue, rules, store

ARTICLE = (b"<html><body><p>Investigators found that w3wp.exe spawned cmd.exe to execute attacker "
           b"commands, then collected process creation events from the host for further analysis.</p>"
           b"</body></html>")


def fictional_cve(ident="CVE-2099-80001"):
    return {"id": ident, "title": "Fictional example vulnerability", "summary": "Synthetic fixture.",
            "source": "https://example.test/advisory", "claim": "Example advisory source.",
            "published": "2099-01-01", "updated": "2099-01-01", "kev": True, "affected": []}


class CorroborationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def _existing_rule(self, cve="CVE-2099-80001", approve=True):
        core.ingest([fictional_cve(cve)], self.path)
        eid = core.add_behavior_evidence(cve, "https://example.test/original-report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        draft = rules.propose_rule(cve, eid, self.path)
        if approve:
            rules.implement_rule(draft["rule_id"], "implement this rule", path=self.path)
        return draft["rule_id"]

    def _new_campaign_with_lead(self, url="https://thedfirreport.com/newarticle"):
        report_id = core.record_campaign_report(
            "Fictional new campaign report", "A fictional research report used only for this test's fixtures.",
            url, self.path)["id"]
        lead_queue.queue_new_report_articles([report_id], self.path)
        result = lead_queue.inspect_due(self.path, fetch=lambda u: ARTICLE)
        return report_id, result

    # -- pending review creation, tied to a real matching rule ------------

    def test_lead_matching_approved_rule_queues_pending_review(self):
        rule_id = self._existing_rule(approve=True)
        report_id, result = self._new_campaign_with_lead()
        self.assertEqual(result["corroboration_reviews_queued"], 1)
        pending = corroboration.list_pending(self.path)
        self.assertEqual(len(pending), 1)
        review = pending[0]
        self.assertEqual(review["rule_id"], rule_id)
        self.assertEqual(review["rule_kind"], "local")
        self.assertEqual(review["threat_id"], report_id)
        self.assertEqual(review["behavior"], "web_server_shell")
        self.assertEqual(review["current_pattern_score"], 0)
        self.assertEqual(review["proposed_pattern_score"], 1)
        self.assertEqual(review["rule_current_status"], "approved")
        # No evidence or score change happened just from queueing.
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 0)
        self.assertEqual(len(rules.get_rule(rule_id, self.path)["supporting_evidence"]), 1)

    def test_no_existing_rule_means_no_review_queued(self):
        # No rule exists anywhere for this behavior yet -- nothing to corroborate.
        report_id, result = self._new_campaign_with_lead()
        self.assertEqual(result["corroboration_reviews_queued"], 0)
        self.assertEqual(corroboration.list_pending(self.path), [])

    # -- explicit approval / rejection -------------------------------------

    def test_approval_links_evidence_adds_exactly_one_and_records_audit(self):
        rule_id = self._existing_rule(approve=True)
        self._new_campaign_with_lead()
        review_id = corroboration.list_pending(self.path)[0]["id"]
        with self.assertRaisesRegex(ValueError, "explicit approval phrase"):
            corroboration.approve(review_id, "yes", self.path)
        result = corroboration.approve(review_id, "implement this rule", self.path)
        self.assertEqual(result["pattern_score"], 1)
        rule = rules.get_rule(rule_id, self.path)
        self.assertEqual(rule["pattern_score"], 1)
        self.assertEqual(rule["status"], "approved")  # unchanged, corroboration never (re-)approves
        self.assertEqual(len(rule["supporting_evidence"]), 2)  # original + newly linked
        with store.connection(self.path) as db:
            audit = db.execute("SELECT action FROM audit WHERE target=?", (str(review_id),)).fetchall()
        self.assertIn("corroboration_review_approved", [a["action"] for a in audit])
        self.assertEqual(corroboration.list_pending(self.path), [])  # no longer pending

    def test_corroboration_never_changes_a_drafts_status(self):
        rule_id = self._existing_rule(approve=False)  # still a draft
        self._new_campaign_with_lead()
        review_id = corroboration.list_pending(self.path)[0]["id"]
        corroboration.approve(review_id, "implement this rule", self.path)
        rule = rules.get_rule(rule_id, self.path)
        self.assertEqual(rule["status"], "draft")  # corroborating evidence never approves the rule
        self.assertEqual(rule["pattern_score"], 1)

    def test_rejection_leaves_rule_fully_unchanged(self):
        rule_id = self._existing_rule(approve=True)
        self._new_campaign_with_lead()
        review_id = corroboration.list_pending(self.path)[0]["id"]
        with self.assertRaisesRegex(ValueError, "5-500 characters"):
            corroboration.reject(review_id, "no", self.path)
        result = corroboration.reject(review_id, "Excerpt reads as routine deployment tooling, not exploitation.", self.path)
        self.assertEqual(result["status"], "rejected")
        rule = rules.get_rule(rule_id, self.path)
        self.assertEqual(rule["pattern_score"], 0)
        self.assertEqual(len(rule["supporting_evidence"]), 1)  # only the original evidence
        self.assertEqual(corroboration.list_pending(self.path), [])

    def test_repeated_decision_on_the_same_review_is_refused(self):
        rule_id = self._existing_rule(approve=True)
        self._new_campaign_with_lead()
        review_id = corroboration.list_pending(self.path)[0]["id"]
        corroboration.approve(review_id, "implement this rule", self.path)
        with self.assertRaisesRegex(ValueError, "already approved"):
            corroboration.approve(review_id, "implement this rule", self.path)
        # Score did not move again on the repeated approval attempt.
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 1)

    def test_rejecting_an_already_decided_review_is_refused(self):
        self._existing_rule(approve=True)
        self._new_campaign_with_lead()
        review_id = corroboration.list_pending(self.path)[0]["id"]
        corroboration.reject(review_id, "Not credible enough to corroborate.", self.path)
        with self.assertRaisesRegex(ValueError, "already rejected"):
            corroboration.reject(review_id, "trying again", self.path)

    # -- idempotency: repeat polling, retries -------------------------------

    def test_repeat_polling_does_not_duplicate_the_pending_review(self):
        self._existing_rule(approve=True)
        report_id, first = self._new_campaign_with_lead()
        self.assertEqual(first["corroboration_reviews_queued"], 1)
        # Re-poll: the article is already 'inspected', so nothing new happens,
        # and even a forced re-insert of the identical lead must not requeue.
        second = lead_queue.inspect_due(self.path, fetch=lambda u: ARTICLE)
        self.assertEqual(second["attempted"], 0)  # nothing left in the queue to retry
        self.assertEqual(len(corroboration.list_pending(self.path)), 1)
        # Directly forcing the exact same lead identity through queue_from_lead
        # again (simulating a retry/backoff re-insert) must still be a no-op.
        review_id = corroboration.list_pending(self.path)[0]["id"]
        again = corroboration.queue_from_lead(report_id, "https://thedfirreport.com/newarticle", 1,
                                              "web_server_shell", "same excerpt", self.path)
        self.assertEqual(again, review_id)
        self.assertEqual(len(corroboration.list_pending(self.path)), 1)

    def test_mirrored_source_across_two_reviews_is_blocked_after_first_approval(self):
        rule_id = self._existing_rule(approve=True)
        core.ingest([{**fictional_cve("CVE-2099-80002")}], self.path)
        core.ingest([{**fictional_cve("CVE-2099-80003")}], self.path)
        mirrored_url = "https://thedfirreport.com/syndicated-mirror"
        review_a = corroboration.queue_from_lead("CVE-2099-80002", mirrored_url, 3, "web_server_shell",
                                                  "A mirrored excerpt describing the same behavior.", self.path)
        review_b = corroboration.queue_from_lead("CVE-2099-80003", mirrored_url, 3, "web_server_shell",
                                                  "The same mirrored excerpt, filed under a different threat.", self.path)
        self.assertNotEqual(review_a, review_b)
        corroboration.approve(review_a, "implement this rule", self.path)
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 1)
        with self.assertRaisesRegex(ValueError, "must not increment the score again"):
            corroboration.approve(review_b, "implement this rule", self.path)
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 1)  # unchanged

    # -- inventory Unknown / uncertain match: honest wording, no overclaim --

    def test_draft_only_match_queues_review_without_claiming_confirmed_coverage(self):
        rule_id = self._existing_rule(approve=False)  # draft only
        status = rules.inventory_status("CVE-2099-80001", self.path)
        self.assertEqual(status["status"], "unknown")  # gap-3: a draft alone is never a confirmed match
        self._new_campaign_with_lead()
        review = corroboration.list_pending(self.path)[0]
        self.assertEqual(review["matched_rule_status"], "draft")
        self.assertIn("draft", review["match_confidence"])
        self.assertNotIn("confirmed", review["match_confidence"].lower())
        self.assertNotIn("existing rule match", review["match_confidence"].lower())

    def test_external_inventory_match_also_queues_and_can_be_approved(self):
        rules.import_inventory([{"id": "EXT-WSS-1", "title": "Existing external web shell hunt",
                                 "behavior": "web_server_shell", "source_url": "https://example.org/rule"}], self.path)
        self._new_campaign_with_lead()
        review = corroboration.list_pending(self.path)[0]
        self.assertEqual(review["rule_kind"], "external")
        self.assertEqual(review["rule_id"], "EXT-WSS-1")
        self.assertEqual(review["current_pattern_score"], 0)
        result = corroboration.approve(review["id"], "implement this rule", self.path)
        self.assertEqual(result["pattern_score"], 1)

    # -- environment/asset risk scoring stays completely separate -----------

    def test_environment_risk_is_never_touched_by_corroboration(self):
        profile = {"name": "Test SOC", "siem": "generic", "telemetry": {
            "process_creation": {"source": "edr", "field_map": {"Image": "process.path"}}}}
        assets = environment.parse_assets(
            "asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
            "a-1,host-1,ExampleServer,1.0,CVE-2099-80001,true,high,general\n")
        environment.onboard(profile, assets, self.path)
        rule_id = self._existing_rule(approve=True)
        before = environment.risk_from_assets("CVE-2099-80001", self.path)
        self._new_campaign_with_lead()
        review_id = corroboration.list_pending(self.path)[0]["id"]
        corroboration.approve(review_id, "implement this rule", self.path)
        after = environment.risk_from_assets("CVE-2099-80001", self.path)
        self.assertEqual(before, after)  # untouched by the +1 pattern_score change
        self.assertEqual(rules.get_rule(rule_id, self.path)["pattern_score"], 1)


class CorroborationDashboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        core.ingest([fictional_cve()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-80001", "https://example.test/original-report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        self.rule_id = rules.propose_rule("CVE-2099-80001", eid, self.path)["rule_id"]
        rules.implement_rule(self.rule_id, "implement this rule", path=self.path)
        report_id = core.record_campaign_report(
            "Fictional new campaign report", "A fictional research report used only for this test's fixtures.",
            "https://thedfirreport.com/newarticle", self.path)["id"]
        lead_queue.queue_new_report_articles([report_id], self.path)
        lead_queue.inspect_due(self.path, fetch=lambda u: ARTICLE)
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

    def test_reviews_page_lists_pending_review_and_nav_shows_count(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn('Pending reviews<span class="count">1</span>', body)
        status, body = self._get("/reviews")
        self.assertEqual(status, 200)
        self.assertIn("w3wp.exe", body)
        self.assertIn("Approve (+1 pattern_score)", body)

    def test_approve_via_http_adds_exactly_one(self):
        review_id = corroboration.list_pending(self.path)[0]["id"]
        status, location = self._post("/review/approve", {"review_id": str(review_id)})
        self.assertEqual(status, 303)
        self.assertIn("/reviews", location)
        self.assertEqual(rules.get_rule(self.rule_id, self.path)["pattern_score"], 1)
        _, body = self._get("/reviews")
        self.assertIn("No pending corroboration reviews", body)

    def test_reject_via_http_leaves_rule_unchanged(self):
        review_id = corroboration.list_pending(self.path)[0]["id"]
        status, location = self._post("/review/reject", {"review_id": str(review_id), "reason": "Not credible enough."})
        self.assertEqual(status, 303)
        self.assertEqual(rules.get_rule(self.rule_id, self.path)["pattern_score"], 0)

    def test_repeated_approval_via_http_shows_refusal_not_a_crash(self):
        review_id = corroboration.list_pending(self.path)[0]["id"]
        self._post("/review/approve", {"review_id": str(review_id)})
        status, location = self._post("/review/approve", {"review_id": str(review_id)})
        self.assertEqual(status, 303)
        self.assertIn("Not applied", urllib.parse.unquote_plus(location))
        self.assertEqual(rules.get_rule(self.rule_id, self.path)["pattern_score"], 1)


if __name__ == "__main__":
    unittest.main()
